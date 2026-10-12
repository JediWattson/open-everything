"""Source-level splicing: graft a donor binary's subsystem into a target.

Pulls the callee-closure of the donor's seed functions, renames the donor
namespace (d_<name> for internals, shared externals keep their names so both
sides bind to the same decl), merges code into the target's lifted output,
and reports references that still need manual binding (globals, function
pointers, anything outside the slice).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .graph import GraphStore
from .store import Store

_LIFTED_ROOT = Path("lifted")


_LIFT_BLOCK = re.compile(r"^// (\S+) @ (0x[0-9a-f]+).*$", re.M)


def _lifted_code(path: Path) -> dict[str, str]:
    """orig_name -> lifted code block, parsed from lifted.cpp markers."""
    if not path.is_file():
        return {}
    src = path.read_text()
    marks = list(_LIFT_BLOCK.finditer(src))
    out = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(src)
        out[m.group(1)] = src[m.end() : end].strip()
    return out


def load_symbols(store: Store, sha: str, binary_name: str) -> dict[str, dict]:
    """Best available symbol map: lift_report.json if present, else raw rows."""
    report = _LIFTED_ROOT / binary_name / "lift_report.json"
    if report.is_file():
        data = json.loads(report.read_text())
        lifted = _lifted_code(_LIFTED_ROOT / binary_name / "lifted.cpp")
        return {
            orig: {
                "name": s["name"],
                "signature": s["signature"],
                "doc": s.get("doc", ""),
                "code": lifted.get(orig, ""),
            }
            for orig, s in data["functions"].items()
        }
    return {
        r["name"]: {
            "name": r["name"],
            "signature": r["signature"],
            "doc": "",
            "code": r["decompiled"],
        }
        for r in store.list_functions(sha, limit=100000)
        if r["decompiled"] and not _is_stub(r)
    }


def _is_stub(r: dict) -> bool:
    """Externals, thunks, and Mach-O stub bodies ('thunk -> _name')."""
    return (
        r["is_external"]
        or r["is_thunk"]
        or r["decompiled"].strip().startswith("thunk ->")
    )


def _externals(store: Store, sha: str) -> dict[str, str]:
    """name -> signature for externals/thunks (unify across binaries)."""
    return {
        r["name"]: r["signature"]
        for r in store.list_functions(sha, limit=100000)
        if _is_stub(r)
    }


def splice(
    store: Store,
    graph: GraphStore,
    target_sha: str,
    target_name: str,
    donor_sha: str,
    donor_name: str,
    seeds: list[str],
    out_dir: Path,
    prefix: str = "d",
) -> dict:
    t_syms = load_symbols(store, target_sha, target_name)
    d_syms = load_symbols(store, donor_sha, donor_name)
    t_ext = _externals(store, target_sha)
    d_ext = _externals(store, donor_sha)

    # donor slice: transitive callees of each seed that have bodies
    slice_names: list[str] = []
    for seed in seeds:
        for name, _depth in graph.reachable(
            donor_sha, seed, direction="callees", max_depth=25
        ):
            if name in d_syms and name not in slice_names:
                slice_names.append(name)
        if seed in d_syms and seed not in slice_names:
            slice_names.insert(0, seed)
    missing = [s for s in seeds if s not in d_syms and s not in d_ext]
    if not slice_names:
        raise ValueError(f"nothing in slice — seeds {seeds} produced no bodies")

    # rename donor internals: d_<name>; externals keep their names (unify)
    rename = {
        orig: f"{prefix}_{s['name']}" for orig, s in d_syms.items()
        if orig in slice_names
    }
    taken = {s["name"] for s in t_syms.values()}
    for orig, new in rename.items():
        n = 2
        base = new
        while new in taken:
            new = f"{base}_{n}"
            n += 1
        rename[orig] = new

    # rewrite donor bodies: lifted names AND originals -> renamed
    def _rewrite(code: str) -> str:
        for orig, new in rename.items():
            lifted_name = d_syms[orig]["name"]
            code = re.sub(rf"\b{re.escape(lifted_name)}\b", new, code)
            code = re.sub(rf"\b{re.escape(orig)}\b", new, code)
        return code

    # global/unresolved refs needing manual binding
    slice_set = set(slice_names)
    unresolved: dict[str, list[str]] = {}
    global_re = re.compile(r"\b(DAT_\w+|PTR_\w+|FUN_\w+)\b")
    for name in slice_names:
        code = _rewrite(d_syms[name]["code"])
        d_syms[name]["_spliced_code"] = code
        leftovers = sorted(
            {m for m in global_re.findall(code)
             if m not in rename and m not in slice_set}
        )
        if leftovers:
            unresolved[name] = leftovers

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    decls = [f"// spliced decls: {target_name} <- {donor_name}({', '.join(seeds)})",
           "#pragma once", ""]
    # shared externals (union, single decl each)
    ext_sigs = dict(t_ext)
    ext_sigs.update(d_ext)
    decls.append("// externals")
    for name, sig in sorted(ext_sigs.items()):
        decls.append(f"{sig.rstrip(';')};")
    decls += ["", f"// {target_name} internals"]
    for orig, s in t_syms.items():
        decls.append(f"{s['signature'].rstrip(';')};")
    decls += ["", f"// {donor_name} slice"]
    for orig in slice_names:
        s = d_syms[orig]
        new_sig = re.sub(
            rf"\b{re.escape(s['name'])}\b", rename[orig], s["signature"], count=1
        )
        decls.append(f"{new_sig.rstrip(';')};  // from {orig}")
    (out_dir / "decls.h").write_text("\n".join(decls))

    src = [
        f"// spliced: {target_name} + {donor_name} slice {seeds}",
        '#include "decls.h"',
        "",
        f"// ===== {target_name} =====",
    ]
    for orig, s in t_syms.items():
        src.append(f"// {orig} ({target_name})")
        src.append(s["code"])
        src.append("")
    src.append(f"// ===== {donor_name} slice =====")
    for orig in slice_names:
        src.append(f"// {orig} -> {rename[orig]} ({donor_name})")
        src.append(d_syms[orig]["_spliced_code"])
        src.append("")
    (out_dir / "spliced.cpp").write_text("\n".join(src))

    report = {
        "target": target_name, "donor": donor_name,
        "seeds": seeds, "slice_size": len(slice_names),
        "missing_seeds": missing,
        "renames": {o: n for o, n in rename.items()},
        "unresolved_refs": unresolved,
    }
    (out_dir / "splice_report.json").write_text(json.dumps(report, indent=2))
    return report
