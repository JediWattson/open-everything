"""Extract function records from a binary using Ghidra headless via PyGhidra.

Requires a Ghidra install (GHIDRA_INSTALL_DIR or a standard location) plus a
JDK on the machine. The JVM is started once per process; binaries are opened
as Ghidra programs inside a shared project dir under ~/.open-everything.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterator

from . import config
from .models import FunctionRecord

_started = False


def _ensure_java_home() -> None:
    """Point JAVA_HOME at an installed JDK if the env doesn't already provide one."""
    if os.environ.get("JAVA_HOME"):
        return
    roots = [
        Path("/opt/homebrew/opt"),
        Path("/Library/Java/JavaVirtualMachines"),
    ]
    homes: list[Path] = []
    for root in roots:
        if root.is_dir():
            homes += list(root.glob("openjdk*/libexec/openjdk.jdk/Contents/Home"))
            homes += list(root.glob("*/Contents/Home"))
    if homes:
        os.environ["JAVA_HOME"] = str(sorted(homes)[-1])


def start_ghidra() -> None:
    global _started
    if _started:
        return
    install = config.find_ghidra_install()
    if install is None:
        raise RuntimeError(
            "Ghidra not found. Install it and/or set GHIDRA_INSTALL_DIR to the "
            "directory containing support/analyzeHeadless."
        )
    _ensure_java_home()
    os.environ["GHIDRA_INSTALL_DIR"] = str(install)
    import pyghidra

    pyghidra.start()
    _started = True


def _func_strings(program, func) -> list[str]:
    """Collect defined string values referenced from the function body."""
    out: list[str] = []
    listing = program.getListing()
    refmgr = program.getReferenceManager()
    for instr in listing.getInstructions(func.getBody(), True):
        for ref in refmgr.getReferencesFrom(instr.getAddress()):
            data = listing.getDataAt(ref.getToAddress()) or listing.getDataContaining(
                ref.getToAddress()
            )
            if data is None:
                continue
            try:
                if data.hasStringValue():
                    val = str(data.getValue())
                    if val and val not in out:
                        out.append(val)
            except Exception:
                continue
    return out


def extract_functions(
    binary: Path,
    binary_sha256: str,
    binary_name: str,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> Iterator[FunctionRecord]:
    """Decompile every function in `binary` and yield FunctionRecords."""
    start_ghidra()
    import pyghidra
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    monitor = TaskMonitor.DUMMY
    project_name = f"oe-{binary_sha256[:12]}"
    program_name = f"{binary_name}-{binary_sha256[:8]}"

    with pyghidra.open_program(
        str(binary),
        project_location=config.PROJECTS_DIR,
        project_name=project_name,
        program_name=program_name,
        analyze=True,
    ) as flatapi:
        program = flatapi.getCurrentProgram()
        fm = program.getFunctionManager()
        decomp = DecompInterface()
        decomp.openProgram(program)

        funcs = list(fm.getFunctions(True))
        total = len(funcs)
        try:
            for i, func in enumerate(funcs):
                name = func.getName()
                if on_progress:
                    on_progress(i + 1, total, name)

                is_external = func.isExternal()
                is_thunk = func.isThunk()
                decompiled = ""
                if not is_external and not is_thunk:
                    try:
                        res = decomp.decompileFunction(
                            func, config.DECOMPILE_TIMEOUT_S, monitor
                        )
                        if res and res.decompileCompleted():
                            df = res.getDecompiledFunction()
                            if df:
                                decompiled = df.getC() or ""
                    except Exception:
                        pass

                callees = sorted(
                    {c.getName() for c in func.getCalledFunctions(monitor)}
                )
                callers = sorted(
                    {c.getName() for c in func.getCallingFunctions(monitor)}
                )

                strings = [] if is_external else _func_strings(program, func)

                if is_thunk:
                    thunked = func.getThunkedFunction(True)
                    decompiled = (
                        f"thunk -> {thunked.getName()}" if thunked else "thunk"
                    )

                yield FunctionRecord(
                    binary_sha256=binary_sha256,
                    binary_name=binary_name,
                    address=f"0x{func.getEntryPoint().getOffset():x}",
                    name=name,
                    signature=func.getSignature().getPrototypeString(),
                    decompiled=decompiled,
                    callees=callees,
                    callers=callers,
                    strings=strings,
                    is_external=is_external,
                    is_thunk=is_thunk,
                    size=int(func.getBody().getNumAddresses())
                    if not is_external
                    else 0,
                )
        finally:
            decomp.dispose()
