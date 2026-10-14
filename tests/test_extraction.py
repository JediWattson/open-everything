"""Extraction regressions with no JVM, native tools, or model dependencies."""

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys

import pytest

from openeverything import disasm, extractor


class Address:
    def __init__(self, offset, space="ram"):
        self.offset, self.space = offset, space

    def getOffset(self):
        return self.offset

    def __str__(self):
        return f"{self.space}:{self.offset:x}"


class Function:
    def __init__(self, qualified, offset, space="ram", thunk=None):
        self.qualified = qualified
        self.address = Address(offset, space)
        self.called, self.calling = [], []
        self.thunk = thunk

    def getName(self, qualified=False):
        return self.qualified if qualified else self.qualified.split("::")[-1]

    def getEntryPoint(self):
        return self.address

    def getCalledFunctions(self, monitor):
        return self.called

    def getCallingFunctions(self, monitor):
        return self.calling

    def isExternal(self):
        return self.address.space == "external"

    def isThunk(self):
        return self.thunk is not None

    def getThunkedFunction(self, recursive):
        return self.thunk

    def getSignature(self):
        return SimpleNamespace(getPrototypeString=lambda: f"void {self.getName()}(void)")

    def getBody(self):
        return SimpleNamespace(getNumAddresses=lambda: 16)


def test_qualified_function_identities_preserve_c_and_distinguish_overloads():
    functions = [
        Function("main", 0x1000),
        Function("A::helper", 0x1010),
        Function("B::helper", 0x1020),
        Function("A::overload", 0x1030),
        Function("A::overload", 0x1040),
    ]
    names = extractor._function_names(functions)
    assert list(names.values()) == [
        "main", "A::helper", "B::helper",
        "A::overload__0x1030", "A::overload__0x1040",
    ]


def test_generated_names_do_not_collide_with_existing_names_or_address_spaces():
    functions = [
        Function("overload", 0x1000),
        Function("overload", 0x1000, "external"),
        Function("overload__0x1000", 0x1010),
    ]
    names = extractor._function_names(functions)
    assert len(set(names.values())) == 3
    assert names["ram:1010"] == "overload__0x1000"


def test_extraction_uses_same_names_for_records_and_noniterated_references(monkeypatch):
    a, b = Function("A::helper", 0x1000), Function("B::helper", 0x1010)
    main = Function("main", 0x1020)
    ext_a = Function("Lib::overload", 1, "external")
    ext_b = Function("Lib::overload", 2, "external")
    thunk = Function("wrapper", 0x1030, thunk=ext_b)
    main.called = [a, b, ext_a, ext_b]
    a.calling = b.calling = [main]
    program = SimpleNamespace(getFunctionManager=lambda: SimpleNamespace(
        getFunctions=lambda forward: [a, b, main, thunk]))
    decompiler = SimpleNamespace(
        openProgram=lambda p: None, decompileFunction=lambda *args: None,
        dispose=lambda: None)
    monkeypatch.setattr(extractor, "start_ghidra", lambda: None)
    monkeypatch.setattr(extractor, "_func_strings", lambda *args: [])
    monkeypatch.setitem(sys.modules, "pyghidra", SimpleNamespace(
        open_program=lambda *args, **kwargs: nullcontext(SimpleNamespace(
            getCurrentProgram=lambda: program))))
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", SimpleNamespace(
        DecompInterface=lambda: decompiler))
    monkeypatch.setitem(sys.modules, "ghidra.util.task", SimpleNamespace(
        TaskMonitor=SimpleNamespace(DUMMY=object())))

    records = list(extractor.extract_functions(Path("dummy"), "sha", "binary"))
    by_name = {r.name: r for r in records}
    assert set(by_name) == {"A::helper", "B::helper", "main", "wrapper"}
    assert by_name["main"].callees == [
        "A::helper", "B::helper", "Lib::overload__0x1", "Lib::overload__0x2",
    ]
    assert by_name["A::helper"].callers == ["main"]
    assert by_name["B::helper"].callers == ["main"]
    assert by_name["wrapper"].decompiled == "thunk -> Lib::overload__0x2"


def test_otool_selects_arm64_and_resolves_forward_named_branches(monkeypatch):
    output = """demo:
(__TEXT,__text) section
_main:
0000000100001000 bl _helper
0000000100001004 b _helper+0x4
0000000100001008 bl _hidden
_helper:
0000000100001010 ret
"""
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(disasm.subprocess, "run", run)
    insns = disasm.disasm_text(Path("demo"), {0x100001020: "_hidden"})
    assert calls[0][0] == ["otool", "-arch", "arm64", "-tv", "demo"]
    assert calls[0][1]["check"] is True
    assert insns[0x100001000] == "bl 0x100001010"
    assert insns[0x100001004] == "b 0x100001014"
    assert insns[0x100001008] == "bl 0x100001020"


def test_otool_failures_are_not_silently_ingested_as_empty_binaries(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr="no arm64 slice")

    monkeypatch.setattr(disasm.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        disasm.disasm_text(Path("x86-only"))


def test_local_jumps_do_not_create_calls_but_recursion_and_tail_calls_do(monkeypatch):
    mo = SimpleNamespace(
        text_addr=0x1000, text_size=0x30, func_starts=[0x1000, 0x1020],
        symbols={0x1000: "main", 0x1020: "helper"},
        stub_functions=lambda: [], read_cstring=lambda addr: None,
    )
    insns = {
        0x1000: "b 0x1008",  # local branch
        0x1004: "bl 0x1000",  # actual recursion
        0x1008: "b 0x1020",  # tail call
        0x1020: "b 0x1024",  # local branch only
        0x1024: "ret",
    }
    monkeypatch.setattr(disasm, "MachO", lambda binary: mo)
    monkeypatch.setattr(disasm, "disasm_text", lambda *args: insns)
    records = list(disasm.extract_disasm(Path("demo"), "sha", "binary"))
    by_name = {r.name: r for r in records}
    assert by_name["main"].callees == ["helper", "main"]
    assert by_name["helper"].callees == []
    assert by_name["helper"].callers == ["main"]
    assert by_name["main"].callers == ["main"]
