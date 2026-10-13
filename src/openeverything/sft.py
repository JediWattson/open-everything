"""SFT pair generator: (decompiled, original-source) training pairs.

For each C source file and optimization level, compiles a binary, decompiles
it with the normal Ghidra path, and aligns decompiled functions back to their
original source by name (clang AST dump gives exact byte ranges). The emitted
JSONL is chat-format for mlx_lm.lora — system+user prompts replicate
lift._lift_prompt so the model trains on the real task distribution, and the
assistant target is lift's JSON output schema with `code` = original source.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from .disasm import extract_disasm
from .embed import build_embed_text
from .extractor import extract_functions
from .lift import _SYSTEM as LIFT_SYSTEM

_DEFAULT_OPTS = ("O0", "O1", "O2", "Os")

# fno-inline keeps static-function boundaries at higher opt levels — most
# identity signal lives in O0-vs-optimized, not O1-vs-O2
_IDENT_OPTS = ("O0", "O1", "O2", "Os")


def source_functions(src: Path) -> dict[str, str]:
    """name -> full source text of each function definition (clang AST)."""
    out = subprocess.run(
        [
            "cc", "-Xclang", "-ast-dump=json", "-fsyntax-only",
            "-Wno-everything", str(src),
        ],
        capture_output=True, text=True,
    ).stdout
    ast = json.loads(out)
    raw = src.read_bytes()
    fns: dict[str, str] = {}

    def _has_body(node: dict) -> bool:
        return any(
            isinstance(c, dict) and c.get("kind") == "CompoundStmt"
            for c in node.get("inner") or []
        )

    def walk(node):
        if isinstance(node, dict):
            if node.get("kind") == "FunctionDecl" and _has_body(node):
                rng = node.get("range") or {}
                b, e = rng.get("begin") or {}, rng.get("end") or {}
                if "file" not in b and "file" not in e and \
                        b.get("offset") is not None and e.get("offset") is not None:
                    end = e["offset"] + e.get("tokLen", 0)
                    fns[node["name"]] = raw[b["offset"]:end].decode(
                        errors="replace"
                    )
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(ast)
    return fns


def _signature_of(src_fn: str) -> str:
    """'ret name(args)' — the source text before the first '{', on one line."""
    head = src_fn.split("{", 1)[0]
    return " ".join(head.split()).rstrip()


def _user_prompt(rec: dict, src_sigs: dict[str, str]) -> str:
    """Mirror lift._lift_prompt — same input distribution the model sees."""
    parts = [f"signature: {rec.signature}"]
    callee_sigs = [
        src_sigs[c.lstrip("_")] for c in rec.callees if c.lstrip("_") in src_sigs
    ]
    if callee_sigs:
        parts.append(
            "callees (already lifted — call these names):\n  "
            + "\n  ".join(callee_sigs)
        )
    if rec.strings:
        parts.append("strings: " + " | ".join(rec.strings[:10]))
    parts += ["decompiled:", "```c", rec.decompiled, "```"]
    return "\n".join(parts)


def generate_pairs(
    sources: list[Path],
    out_path: Path,
    opts: tuple[str, ...] = _DEFAULT_OPTS,
    on_progress=None,
) -> dict:
    """Compile→decompile→align each source; append pairs to out_path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"files": 0, "binaries": 0, "pairs": 0,
             "unmatched": {}, "missing": {}}
    with tempfile.TemporaryDirectory() as td:
        for src in sources:
            src = Path(src)
            src_fns = source_functions(src)
            stats["files"] += 1
            for opt in opts:
                binary = Path(td) / f"{src.stem}-{opt}"
                cp = subprocess.run(
                    ["cc", f"-{opt}", "-o", str(binary), str(src)],
                    capture_output=True, text=True,
                )
                if cp.returncode != 0:
                    continue
                stats["binaries"] += 1
                sha = hashlib.sha256(binary.read_bytes()).hexdigest()
                recs = list(
                    extract_functions(
                        binary, sha, f"{src.stem}-{opt}",
                        on_progress=on_progress,
                    )
                )
                src_sigs = {
                    n: _signature_of(t) for n, t in src_fns.items()
                }
                with out_path.open("a") as f:
                    for rec in recs:
                        if rec.is_external or rec.is_thunk or not rec.decompiled:
                            continue
                        key = rec.name.lstrip("_")
                        if key == "entry":
                            key = "main"  # CRT entry point names
                        body = src_fns.get(key)
                        if body is None:
                            stats["unmatched"].setdefault(
                                f"{src.name}:{opt}", []
                            ).append(rec.name)
                            continue
                        target = {
                            "name": key,
                            "signature": src_sigs[key],
                            "doc": "",
                            "code": body.strip(),
                        }
                        f.write(
                            json.dumps(
                                {
                                    "messages": [
                                        {"role": "system",
                                         "content": LIFT_SYSTEM},
                                        {"role": "user",
                                         "content": _user_prompt(
                                             rec, src_sigs)},
                                        {"role": "assistant",
                                         "content": json.dumps(target)},
                                    ],
                                    "meta": {
                                        "src": str(src), "opt": opt,
                                        "func": key, "addr": rec.address,
                                    },
                                }
                            )
                            + "\n"
                        )
                        stats["pairs"] += 1
                stats["missing"][f"{src.name}:{opt}"] = len(recs)
    return stats


_IDENT_FLAGS = {
    "O0": ["-O0"],
    "O1": ["-O1", "-fno-inline"],
    "O2": ["-O2", "-fno-inline"],
    "Os": ["-Os", "-fno-inline"],
}

# BSD userland sources reference sandboxing/libutil symbols macOS lacks —
# function-like -D macros only expand where referenced, harmless elsewhere.
_BSD_STUBS = [
    "-Dpledge(a,b)=0", "-Dunveil(a,b)=0", "-Du_long=unsigned long",
    "-Dreallocarray(p,n,s)=realloc(p,(n)*(s))",
    "-Dtimespecclear(t)=((t)->tv_sec=(t)->tv_nsec=0)",
    "-Dtimespecisset(t)=((t)->tv_sec||(t)->tv_nsec)",
    "-Dchflagsat(a,b,c,d)=0", "-Duid_from_user(n,u)=0",
    "-Dgid_from_group(n,g)=0",
    "-Dfmt_scaled(n,b)=snprintf(b,16,\"%lld\",(long long)n)",
    "-DMACHINE_ARCH=\"arm64\"", "-DFMT_SCALED_STRSIZE=16",
]


def generate_identity_pairs(
    sources: list[Path],
    out_path: Path,
    opts: tuple[str, ...] = _IDENT_OPTS,
    on_progress=None,
) -> dict:
    """Cross-opt-level identity triplets: for each source function that
    survives as a distinct symbol in >=2 opt builds, emit
    {anchor: asm@optA, positive: asm@optB, negative: asm@optA of another fn}.
    Both directions emitted (anchor@B, positive@A) — symmetric pairs."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"files": 0, "binaries": 0, "pairs": 0, "funcs": {}}
    with tempfile.TemporaryDirectory() as td:
        for src in sources:
            src = Path(src)
            stats["files"] += 1
            by_opt: dict[str, dict[str, object]] = {}
            for opt in opts:
                binary = Path(td) / f"{src.stem}-{opt}"
                cp = subprocess.run(
                    ["cc", *_IDENT_FLAGS[opt], *_BSD_STUBS,
                     "-o", str(binary), str(src)],
                    capture_output=True, text=True,
                )
                if cp.returncode != 0:
                    continue
                stats["binaries"] += 1
                sha = hashlib.sha256(binary.read_bytes()).hexdigest()
                by_opt[opt] = {}
                for rec in extract_disasm(
                    binary, sha, f"{src.stem}-{opt}", on_progress=on_progress
                ):
                    key = rec.name.lstrip("_")
                    if (rec.is_external or rec.is_thunk
                            or not rec.decompiled or key in by_opt[opt]):
                        continue
                    by_opt[opt][key] = rec
            present = set.intersection(
                *(set(v) for v in by_opt.values())) if by_opt else set()
            stats["funcs"][src.name] = len(present)
            with out_path.open("a") as f:
                for name in sorted(present):
                    for i, a in enumerate(opts):
                        for b in opts[i + 1:]:
                            if a not in by_opt or b not in by_opt:
                                continue
                            ra, rb = by_opt[a][name], by_opt[b][name]
                            negs = [
                                r for n2, r in by_opt[a].items() if n2 != name
                            ]
                            if not negs:
                                continue
                            neg = build_embed_text(
                                negs[hash(name) % len(negs)])
                            ta, tb = (build_embed_text(ra),
                                      build_embed_text(rb))
                            meta = {"src": str(src), "func": name,
                                    "opt_a": a, "opt_b": b}
                            f.write(json.dumps({
                                "anchor": ta, "positive": tb,
                                "negative": neg, "meta": meta}) + "\n")
                            f.write(json.dumps({
                                "anchor": tb, "positive": ta,
                                "negative": neg,
                                "meta": {**meta, "opt_a": b,
                                         "opt_b": a}}) + "\n")
                            stats["pairs"] += 2
    return stats


def _src_doc(name: str, sig: str, body: str) -> str:
    """Source-side document in embed_text layout — asm anchors map onto the
    same shape the embedder sees for source-ish input."""
    return f"function: {name}\nsignature: {sig}\n---\n{body.strip()}"


def generate_emb_pairs(
    sources: list[Path],
    out_path: Path,
    opts: tuple[str, ...] = _DEFAULT_OPTS,
    on_progress=None,
) -> dict:
    """Compile → disasm → name-align each source; emit
    {anchor(asm), positive(source), negative(other-source)} triplets."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"files": 0, "binaries": 0, "pairs": 0,
             "unmatched": {}, "missing": {}}
    with tempfile.TemporaryDirectory() as td:
        for src in sources:
            src = Path(src)
            src_fns = source_functions(src)
            src_sigs = {n: _signature_of(t) for n, t in src_fns.items()}
            stats["files"] += 1
            for opt in opts:
                binary = Path(td) / f"{src.stem}-{opt}"
                cp = subprocess.run(
                    ["cc", f"-{opt}", "-o", str(binary), str(src)],
                    capture_output=True, text=True,
                )
                if cp.returncode != 0:
                    continue
                stats["binaries"] += 1
                sha = hashlib.sha256(binary.read_bytes()).hexdigest()
                recs = list(
                    extract_disasm(
                        binary, sha, f"{src.stem}-{opt}",
                        on_progress=on_progress,
                    )
                )
                names = list(src_fns)
                with out_path.open("a") as f:
                    for rec in recs:
                        if rec.is_external or rec.is_thunk or not rec.decompiled:
                            continue
                        key = rec.name.lstrip("_")
                        body = src_fns.get(key)
                        if body is None:
                            stats["unmatched"].setdefault(
                                f"{src.name}:{opt}", []
                            ).append(rec.name)
                            continue
                        others = [n for n in names if n != key]
                        neg = _src_doc(
                            others[0], src_sigs[others[0]],
                            src_fns[others[0]],
                        ) if others else ""
                        f.write(
                            json.dumps(
                                {
                                    "anchor": build_embed_text(rec),
                                    "positive": _src_doc(
                                        key, src_sigs[key], body),
                                    "negative": neg,
                                    "meta": {
                                        "src": str(src), "opt": opt,
                                        "func": key, "addr": rec.address,
                                    },
                                }
                            )
                            + "\n"
                        )
                        stats["pairs"] += 1
                stats["missing"][f"{src.name}:{opt}"] = len(recs)
    return stats
