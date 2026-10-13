"""Ghidra-free frontend: Mach-O parse + disasm + function discovery.

Replaces the Ghidra analysis stage for ingest. Function boundaries come from
LC_FUNCTION_STARTS (the uleb128 delta list dyld uses — survives stripping),
supplemented by direct `bl` call-targets and `b` tail-call targets discovered
in the disassembly. External stubs (__stubs/__auth_stubs) are resolved to real
symbol names via the indirect symbol table. Produces FunctionRecords whose
`decompiled` field holds raw arm64 assembly — the same shape the rest of the
pipeline consumes.
"""

from __future__ import annotations

import bisect
import re
import struct
import subprocess
from pathlib import Path
from typing import Callable, Iterator

from .models import FunctionRecord

_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x2
_LC_DYSYMTAB = 0xB
_LC_FUNCTION_STARTS = 0x26


def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    val = shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, off
        shift += 7


class MachO:
    """Minimal MH_MAGIC_64 parse: __text + stubs sections, function starts,
    defined symbols, and the indirect->symtab map for stub names.

    Fat (universal) binaries are unwrapped to their arm64 slice.
    """

    def __init__(self, path: Path):
        raw = Path(path).read_bytes()
        (magic_be,) = struct.unpack_from(">I", raw, 0)
        if magic_be == 0xCAFEBABE:  # fat — find the arm64 slice
            (nfat,) = struct.unpack_from(">I", raw, 4)
            for i in range(nfat):
                cputype, _sub, s_off, size, _al = struct.unpack_from(
                    ">IIIII", raw, 8 + i * 20
                )
                if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                    raw = raw[s_off : s_off + size]
                    break
            else:
                raise ValueError("fat binary has no arm64 slice")
        self.raw = raw
        (magic,) = struct.unpack_from("<I", self.raw, 0)
        if magic != 0xFEEDFACF:
            raise ValueError("not a 64-bit Mach-O")

        (ncmds,) = struct.unpack_from("<I", self.raw, 16)
        self.text_seg_base = 0
        self.text_addr = self.text_size = self.text_off = 0
        self.stubs: dict[str, tuple[int, int, int]] = {}  # name->(addr,size,rsv1)
        self.cstring: tuple[int, int, int] | None = None  # (addr,size,fileoff)
        self.func_starts: list[int] = []
        self.symbols: dict[int, str] = {}
        self.sym_names: list[str] = []     # symtab index -> name
        self.indirect: list[int] = []      # indirect tab -> symtab index
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.raw, off)
            if cmd == _LC_SEGMENT_64:
                self._segment(off)
            elif cmd == _LC_FUNCTION_STARTS:
                dataoff, datasize = struct.unpack_from("<II", self.raw, off + 8)
                self._fs_blob = self.raw[dataoff : dataoff + datasize]
            elif cmd == _LC_SYMTAB:
                self._symtab(off)
            elif cmd == _LC_DYSYMTAB:
                self._dysymtab(off)
            off += cmdsize
        self.func_starts = self._decode_starts()

    def read_cstring(self, addr: int) -> str | None:
        """Read the NUL-terminated string at a vmaddr inside __cstring."""
        if not self.cstring:
            return None
        base, size, fileoff = self.cstring
        if not (base <= addr < base + size):
            return None
        start = fileoff + (addr - base)
        end = self.raw.index(b"\0", start)
        s = self.raw[start:end].decode(errors="replace")
        return s if s and all(c.isprintable() or c in "\t\n" for c in s) else None

    def _segment(self, off: int):
        segname = self.raw[off + 8 : off + 24].split(b"\0")[0].decode()
        (vmaddr,) = struct.unpack_from("<Q", self.raw, off + 24)
        nsects = struct.unpack_from("<I", self.raw, off + 64)[0]
        if segname == "__TEXT":
            self.text_seg_base = vmaddr
        so = off + 72
        for i in range(nsects):
            sect = self.raw[so + i * 80 : so + (i + 1) * 80]
            name = sect[:16].split(b"\0")[0].decode()
            addr, size = struct.unpack_from("<QQ", sect, 32)
            fileoff, = struct.unpack_from("<I", sect, 48)
            reserved1, = struct.unpack_from("<I", sect, 68)
            if name == "__text" and segname == "__TEXT":
                self.text_addr, self.text_size, self.text_off = (
                    addr, size, fileoff,
                )
            elif name == "__cstring":
                self.cstring = (addr, size, fileoff)
            elif name in ("__stubs", "__auth_stubs"):
                self.stubs[name] = (addr, size, reserved1)

    def _decode_starts(self) -> list[int]:
        addrs, addr, off = [], self.text_seg_base, 0
        blob = getattr(self, "_fs_blob", b"")
        while off < len(blob):
            delta, off = _uleb128(blob, off)
            addr += delta
            addrs.append(addr)
        return addrs

    def _symtab(self, off: int):
        symoff, nsyms, stroff, _strsz = struct.unpack_from(
            "<IIII", self.raw, off + 8
        )
        for i in range(nsyms):
            strx, _typ, _sect, _desc, value = struct.unpack_from(
                "<IBBHQ", self.raw, symoff + i * 16
            )
            name = ""
            if strx:
                end = self.raw.index(b"\0", stroff + strx)
                name = self.raw[stroff + strx : end].decode(errors="replace")
            self.sym_names.append(name)
            if name:
                self.symbols[value] = name

    def _dysymtab(self, off: int):
        ioff, n = struct.unpack_from("<II", self.raw, off + 56)
        self.indirect = list(
            struct.unpack_from(f"<{n}I", self.raw, ioff)
        )

    def stub_functions(self) -> list[tuple[int, str]]:
        """(stub_addr, extern_name) for each __stubs/__auth_stubs entry."""
        out = []
        for sname, (addr, size, rsv1) in self.stubs.items():
            stride = 16 if sname == "__auth_stubs" else 12
            n = min(size // stride, len(self.indirect) - rsv1)
            for i in range(n):
                sym_idx = (
                    self.indirect[rsv1 + i]
                    if rsv1 + i < len(self.indirect) else -1
                )
                name = (
                    self.sym_names[sym_idx]
                    if 0 <= sym_idx < len(self.sym_names)
                    else f"EXT_{addr + i * stride:08x}"
                )
                out.append((addr + i * stride, name))
        return sorted(out)


_BL_RE = re.compile(r"\bb(l|)\s+(0x?[0-9a-f]+)", re.I)
_ADDR_RE = re.compile(r"^([0-9a-f]{8,16})\s")
# otool annotates resolved references: `adrp x8, 12 ; 0x10000c000`,
# `add x8, x8, #0x2c ; literal pool for: "…"`,
# `bl 0x… ; symbol stub for: _name`
_ADRP_RE = re.compile(r"\badrp\s+(x\d+),\s*\d+\s*;\s*(0x[0-9a-f]+)")
_ADD_RE = re.compile(r"\badd\s+x\d+,\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)")
_ADR_RE = re.compile(r"\badr\s+x\d+,\s*(0x[0-9a-f]+)")
_LIT_RE = re.compile(r';\s*literal pool for:\s*"?([^";]*)"?$')
_STUB_RE = re.compile(r";\s*symbol stub for:\s*(\w+)")


def _fn_strings(mo: MachO, body_ins: list[str]) -> list[str]:
    """Resolve string references per function body: literal-pool comments
    first, adrp+add / adr address resolution as fallback."""
    pages: dict[str, int] = {}
    out: list[str] = []
    for ins in body_ins:
        if m := _LIT_RE.search(ins):
            if m.group(1).strip():
                out.append(m.group(1).strip())
        if m := _ADRP_RE.search(ins):
            pages[m.group(1)] = int(m.group(2), 0)
        elif m := _ADR_RE.search(ins):
            s = mo.read_cstring(int(m.group(1), 0))
            if s:
                out.append(s)
        elif m := _ADD_RE.search(ins):
            page = pages.get(m.group(1))
            if page is not None:
                s = mo.read_cstring(page + int(m.group(2), 0))
                if s:
                    out.append(s)
    return list(dict.fromkeys(out))[:20]


def disasm_text(binary: Path) -> dict[int, str]:
    """addr -> instruction (mnemonic + operands) via `otool -tv`."""
    out = subprocess.run(
        ["otool", "-tv", str(binary)], capture_output=True, text=True
    ).stdout
    insns: dict[int, str] = {}
    for line in out.splitlines():
        m = _ADDR_RE.match(line)
        if not m:
            continue
        ins = line[m.end() :].strip()
        ins = re.sub(r"^[0-9a-f]{8}\s+", "", ins)  # raw-bytes column
        insns[int(m.group(1), 16)] = ins
    return insns


def extract_disasm(
    binary: Path,
    binary_sha256: str,
    binary_name: str,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> Iterator[FunctionRecord]:
    """Ghidra-free function records: boundaries + asm, no decompile."""
    mo = MachO(binary)
    insns = disasm_text(binary)
    insn_addrs = sorted(insns)
    stub_by_addr = dict(mo.stub_functions())
    # `; symbol stub for: _name` comments name stub call targets directly
    for ins in insns.values():
        m = _BL_RE.search(ins)
        if m and (s := _STUB_RE.search(ins)):
            stub_by_addr.setdefault(int(m.group(2), 0), s.group(1))

    # boundaries: LC_FUNCTION_STARTS ∪ bl-targets in __text or stubs.
    # `bl` is always a call target; a bare `b` inside an existing region is an
    # intra-function jump — only accept it (tail call) outside known regions.
    text_hi = mo.text_addr + mo.text_size
    starts = set(mo.func_starts)
    branch_tgts: set[int] = set()
    for ins in insns.values():
        m = _BL_RE.search(ins)
        if m:
            tgt = int(m.group(2), 0)
            if mo.text_addr <= tgt < text_hi:
                (branch_tgts if m.group(1) == "" else starts).add(tgt)
            elif tgt in stub_by_addr:
                starts.add(tgt)
    starts = sorted(starts)
    known = set(starts)
    for tgt in branch_tgts:
        if tgt in known:
            continue
        i = bisect.bisect_right(starts, tgt) - 1
        in_region = (
            i >= 0
            and starts[i] < tgt
            and (i + 1 == len(starts) or tgt < starts[i + 1])
        )
        if not in_region:
            starts.insert(i + 1, tgt)
            known.add(tgt)

    def _fn_of(addr: int) -> int | None:
        i = bisect.bisect_right(starts, addr) - 1
        return starts[i] if i >= 0 else None

    def _name_of(addr: int) -> str:
        return (
            stub_by_addr.get(addr)
            or mo.symbols.get(addr)
            or f"FUN_{addr:08x}"
        )

    # callees per function from bl targets
    total = len(starts)
    recs: list[FunctionRecord] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < total else text_hi
        lo = bisect.bisect_left(insn_addrs, start)
        hi = bisect.bisect_left(insn_addrs, end)
        body_ins = [insns[a] for a in insn_addrs[lo:hi]]
        name = _name_of(start)
        is_stub = start in stub_by_addr
        if not body_ins and not is_stub:
            continue
        callees = []
        for ins in body_ins:
            m = _BL_RE.search(ins)
            if m:
                tgt_fn = _fn_of(int(m.group(2), 0))
                if tgt_fn is not None:
                    callees.append(_name_of(tgt_fn))
        asm = "\n".join(f"0x{a:x}: {insns[a]}" for a in insn_addrs[lo:hi])
        if on_progress:
            on_progress(i + 1, total, name)
        recs.append(FunctionRecord(
            binary_sha256=binary_sha256,
            binary_name=binary_name,
            address=f"0x{start:x}",
            name=name,
            signature=f"void {name}(void)",
            decompiled=asm or f"external stub -> {name}",
            callees=sorted(set(callees)),
            callers=[],
            strings=_fn_strings(mo, body_ins),
            is_external=is_stub,
            is_thunk=is_stub,
            size=max(0, end - start),
        ))
    by_name = {r.name: r for r in recs}
    for r in recs:
        for c in r.callees:
            if c in by_name:
                by_name[c].callers.append(r.name)
    yield from recs
