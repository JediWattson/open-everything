"""Whole-binary lift: decompiled functions -> coherent C++-flavored output.

Not a free-roaming agent — a deterministic pipeline. Functions are visited in
call-graph post-order (callees before callers), each is rewritten by the LLM
into a named, documented function, and the results feed a shared symbol table
so later (caller) chunks see real signatures instead of FUN_* names.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .store import Store

_SYSTEM = """You rewrite decompiled binary functions as clean C++.

You will be given ONE decompiled function plus the signatures of the lifted
functions it calls. Respond with EXACTLY one JSON object, nothing else:

{"name": "snake_case_name", "signature": "ret name(args)",
 "doc": "one-line description", "code": "the rewritten function"}

Rules:
- Call callees by their NEW names from the signatures given.
- NEVER invent callee names — anything without a given signature keeps its
  original FUN_*/DAT_* token verbatim.
- Keep the logic identical; only rename, retype, and restructure for clarity.
- `code` must be a complete function definition (with braces)."""


def topo_order(rows: list[dict]) -> list[dict]:
    """Callee-first order via iterative post-order DFS over callees."""
    by_name = {r["name"]: r for r in rows}
    order: list[str] = []
    visited: set[str] = set()

    for start in by_name:
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            name, expanded = stack.pop()
            if expanded:
                order.append(name)
                continue
            if name in visited or name not in by_name:
                continue
            visited.add(name)
            stack.append((name, True))
            for c in by_name[name].get("callees", []):
                stack.append((c, False))
    return [by_name[n] for n in order]


_INTRINSICS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "CONCAT44", "CONCAT22", "SUB41", "SUB81", "ZEXT14", "ZEXT24", "ZEXT48",
    "SEXT14", "SEXT24", "SEXT48", "SBORROW4", "SBORROW8", "CARRY4", "CARRY8",
    "halt_baddata", "undefined", "byte", "uint", "ulong", "ushort", "char",
    "int", "long", "void", "bool", "float", "double",
}


def _body_hash(body: str) -> str:
    return hashlib.sha1(" ".join(body.split()).encode()).hexdigest()


def _extract_json(text: str) -> dict | None:
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text[i:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "code" in obj:
            return obj
    return None


def _lift_prompt(rec: dict, symbols: dict) -> list[dict]:
    callee_sigs = [
        symbols[c]["signature"] for c in rec["callees"] if c in symbols
    ]
    parts = [f"signature: {rec['signature']}"]
    if callee_sigs:
        parts.append("callees (already lifted — call these names):\n  "
                     + "\n  ".join(callee_sigs))
    if rec["strings"]:
        parts.append("strings: " + " | ".join(rec["strings"][:10]))
    parts += ["decompiled:", "```c", rec["decompiled"], "```"]
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": "\n".join(parts)},
    ]


def lift_binary(
    store: Store,
    sha256: str,
    binary_name: str,
    chat,
    out_dir: Path,
    limit: int = 0,
    on_progress=None,
) -> tuple[Path, dict]:
    """Lift every decompiled function in `sha256`. Returns (out_dir, symbols)."""
    rows = [
        r for r in store.list_functions(sha256, limit=100000)
        if not r["is_external"] and not r["is_thunk"] and r["decompiled"]
    ]
    # exact-body dedupe: identical pseudocode => alias, don't double-lift
    seen: dict[str, str] = {}
    uniq, aliases = [], {}
    for r in rows:
        h = _body_hash(r["decompiled"])
        if h in seen:
            aliases[r["name"]] = seen[h]
        else:
            seen[h] = r["name"]
            uniq.append(r)

    order = topo_order(uniq)
    if limit:
        order = order[:limit]

    symbols: dict[str, dict] = {}
    used_names: set[str] = set()
    for i, rec in enumerate(order):
        if on_progress:
            on_progress(i + 1, len(order), rec["name"])
        raw = "".join(chat(_lift_prompt(rec, symbols)))
        res = _extract_json(raw) or {}
        new_name = res.get("name") or rec["name"]
        signature = res.get("signature") or rec["signature"]
        code = res.get("code") or rec["decompiled"]
        if new_name in used_names:
            n = 2
            while f"{new_name}_{n}" in used_names:
                n += 1
            renamed = f"{new_name}_{n}"
            signature = signature.replace(new_name, renamed, 1)
            code = re.sub(rf"\b{re.escape(new_name)}\b", renamed, code)
            new_name = renamed
        used_names.add(new_name)
        symbols[rec["name"]] = {
            "name": new_name,
            "signature": signature,
            "doc": res.get("doc") or "",
            "code": code,
            "address": rec["address"],
            "failed": "code" not in res,
        }

    # Post-pass: rewrite every lifted original name anywhere it appears in
    # emitted code — covers LLM non-compliance and non-callee references
    # (function pointers, thunks) the per-function prompt can't see.
    renames = {
        orig: s["name"] for orig, s in symbols.items() if s["name"] != orig
    }
    for fn in order:
        code = symbols[fn["name"]]["code"]
        for orig, new in renames.items():
            if orig != fn["name"] and orig in code:
                code = re.sub(rf"\b{re.escape(orig)}\b", new, code)
        symbols[fn["name"]]["code"] = code

    # Unresolved call sites: names called in code that have no lifted symbol
    # or decl — mostly LLM-invented names; recorded as a quality metric.
    known = {s["name"] for s in symbols.values()}
    known |= {c for r in uniq for c in r["callees"]}
    # Ghidra Mach-O names keep the '_' prefix — LLM output uses the C name
    known |= {n.lstrip("_") for n in known}
    known |= set(_INTRINSICS)
    for fn in order:
        s = symbols[fn["name"]]
        called = set(re.findall(r"\b([a-zA-Z_]\w*)\s*\(", s["code"]))
        s["unresolved"] = sorted(called - known - {s["name"]})

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    decls = ["#pragma once", f"// declarations lifted from {binary_name}", ""]
    for fn in order:
        s = symbols[fn["name"]]
        sig = s["signature"].rstrip(";")
        decls.append(f"{sig};  // {s['doc']}" if s["doc"] else f"{sig};")
    # Declarations for referenced-but-unlifted functions (externals, thunks,
    # body-less FUN_*) so lifted.cpp is self-contained.
    all_rows = {r["name"]: r for r in store.list_functions(sha256, limit=100000)}
    unlifted = sorted(
        {c for r in uniq for c in r["callees"] if c not in symbols}
    )
    if unlifted:
        decls += ["", "// unlifted/external functions:"]
        for name in unlifted:
            sig = all_rows.get(name, {}).get("signature") or f"void {name}(void)"
            decls.append(f"{sig.rstrip(';')};")
    # Enforce unresolved call-sites: give them a visibly-flagged stub decl so
    # lifted.cpp stays self-contained while the report still counts them.
    invented = sorted({n for s in symbols.values() for n in s["unresolved"]})
    if invented:
        decls += ["", "// call sites with no matching symbol in the binary:"]
        for n in invented:
            decls.append(f"void {n}(void);  // unresolved — likely LLM-invented")
    if aliases:
        decls += ["", "// unresolved originals:"]
        for fun, alias in aliases.items():
            decls.append(f"//   {fun} == {alias}")
    (out_dir / "decls.h").write_text("\n".join(decls))

    body = [
        f'// lifted from {binary_name} (sha256:{sha256[:16]}…)',
        "// ordered callee-first (call-graph post-order)",
        '#include "decls.h"',
        "",
    ]
    for fn in order:
        s = symbols[fn["name"]]
        body.append(
            f"// {fn['name']} @ {fn['address']}"
            + ("  [LLM output failed — raw decompile]" if s["failed"] else "")
        )
        body.append(s["code"])
        body.append("")
    (out_dir / "lifted.cpp").write_text("\n".join(body))

    n_unresolved = sum(len(s["unresolved"]) for s in symbols.values())
    report = {
        "binary": binary_name,
        "sha256": sha256,
        "n_functions": len(symbols),
        "n_failed": sum(1 for s in symbols.values() if s["failed"]),
        "n_unresolved_calls": n_unresolved,
        "functions": {
            orig: {k: v for k, v in s.items() if k != "code"}
            for orig, s in symbols.items()
        },
        "aliases": aliases,
    }
    (out_dir / "lift_report.json").write_text(json.dumps(report, indent=2))
    return out_dir, symbols


# ---------------------------------------------------------------------------
# Clustered lift (arch v2): module prepass -> per-function lift with module
# context -> modules/*.h/.cpp emit. Cross-function coherence (shared types,
# consistent naming) is the point — a per-function lift can't see that
# `param_1 + 0x10` appearing in five siblings is one struct.
# ---------------------------------------------------------------------------

_CLUSTER_SYSTEM = """You are analyzing a cluster of decompiled functions that
belong to one subsystem of a binary. Given each function's name, signature,
callees and strings, respond with EXACTLY one JSON object, nothing else:

{"label": "two_word_module_name",
 "summary": "one line describing the subsystem's role",
 "types": "shared struct/type declarations the functions plausibly use, or empty string"}

Rules:
- Only declare types strongly implied by member offsets / call patterns.
- Types must be valid C declarations — no commentary."""


def _cluster_prompt(members: list[dict]) -> list[dict]:
    lines = []
    for m in members[:20]:
        ln = f"{m['name']}  sig[{m['signature']}]  calls[{','.join(m['callees'][:8])}]"
        if m["strings"]:
            ln += f"  strs[{','.join(m['strings'][:6])}]"
        lines.append(ln)
    return [
        {"role": "system", "content": _CLUSTER_SYSTEM},
        {"role": "user", "content": "\n".join(lines)},
    ]


def _lift_prompt_ctx(rec: dict, symbols: dict, module: dict | None) -> list[dict]:
    """_lift_prompt augmented with module context."""
    msgs = _lift_prompt(rec, symbols)
    if module and (module.get("label") or module.get("types")):
        ctx = f"module: {module.get('label', '?')} — {module.get('summary', '')}"
        if module.get("types"):
            ctx += f"\nmodule decls:\n{module['types']}"
        msgs[1]["content"] = ctx + "\n\n" + msgs[1]["content"]
    return msgs


def _cluster_order(groups: list[list[dict]]) -> list[list[dict]]:
    """Callees' clusters first: topo over the inter-cluster call graph."""
    owner = {}
    for i, g in enumerate(groups):
        for m in g:
            owner[m["name"]] = i
    deps: dict[int, set[int]] = {i: set() for i in range(len(groups))}
    for i, g in enumerate(groups):
        for m in g:
            for c in m.get("callees", []):
                j = owner.get(c)
                if j is not None and j != i:
                    deps[i].add(j)  # i calls j → i depends on j
    order, done = [], set()
    while len(done) < len(groups):
        for i in range(len(groups)):
            if i not in done and deps[i] <= done:
                done.add(i)
                order.append(i)
                break
        else:
            # cycle — take the remaining cluster with fewest deps
            i = min((i for i in deps if i not in done),
                    key=lambda i: len(deps[i] - done))
            done.add(i)
            order.append(i)
    return [groups[i] for i in order]


def lift_binary_clustered(
    store: Store,
    sha256: str,
    binary_name: str,
    chat,
    out_dir: Path,
    threshold: float = 0.25,
    limit: int = 0,
    on_progress=None,
) -> tuple[Path, dict]:
    """Clustered whole-binary lift. Returns (out_dir, symbols)."""
    from .cluster import cluster_functions

    rows = [
        r for r in store.list_functions(sha256, limit=100000)
        if not r["is_external"] and not r["is_thunk"] and r["decompiled"]
    ]
    # vectors needed for clustering — pull from the table rows themselves
    vec_rows = (
        store._table()
        .search()
        .where(f"binary_sha256 = '{sha256}'")
        .to_list()
    )
    vecs = {r["name"]: r["vector"] for r in vec_rows}
    for r in rows:
        r["vector"] = vecs.get(r["name"], [])
    rows = [r for r in rows if r["vector"]]

    seen: dict[str, str] = {}
    uniq, aliases = [], {}
    for r in rows:
        h = _body_hash(r["decompiled"])
        if h in seen:
            aliases[r["name"]] = seen[h]
        else:
            seen[h] = r["name"]
            uniq.append(r)

    groups = _cluster_order(cluster_functions(uniq, threshold))

    symbols: dict[str, dict] = {}
    used_names: set[str] = set()
    modules: list[dict] = []
    done_fns = 0
    for ci, members in enumerate(groups):
        if limit and done_fns >= limit:
            break
        res = _extract_json("".join(chat(_cluster_prompt(members)))) or {}
        module = {
            "id": ci,
            "label": res.get("label") or f"module_{ci}",
            "summary": res.get("summary") or "",
            "types": res.get("types") or "",
            "members": [m["name"] for m in members],
        }
        modules.append(module)
        for rec in topo_order(members):
            if limit and done_fns >= limit:
                break
            done_fns += 1
            if on_progress:
                on_progress(done_fns, len(uniq),
                            f"{module['label']}:{rec['name']}")
            raw = "".join(chat(_lift_prompt_ctx(rec, symbols, module)))
            r2 = _extract_json(raw) or {}
            new_name = r2.get("name") or rec["name"]
            signature = r2.get("signature") or rec["signature"]
            code = r2.get("code") or rec["decompiled"]
            if new_name in used_names:
                n = 2
                while f"{new_name}_{n}" in used_names:
                    n += 1
                renamed = f"{new_name}_{n}"
                signature = signature.replace(new_name, renamed, 1)
                code = re.sub(rf"\b{re.escape(new_name)}\b", renamed, code)
                new_name = renamed
            used_names.add(new_name)
            symbols[rec["name"]] = {
                "name": new_name,
                "signature": signature,
                "doc": r2.get("doc") or "",
                "code": code,
                "address": rec["address"],
                "module": module["label"],
                "module_id": module["id"],
                "failed": "code" not in r2,
            }

    # post-pass rename (same as flat lift)
    renames = {
        orig: s["name"] for orig, s in symbols.items() if s["name"] != orig
    }
    for orig, s in symbols.items():
        code = s["code"]
        for o, new in renames.items():
            if o != orig and o in code:
                code = re.sub(rf"\b{re.escape(o)}\b", new, code)
        s["code"] = code

    known = {s["name"] for s in symbols.values()}
    known |= {c for r in uniq for c in r["callees"]}
    known |= {n.lstrip("_") for n in known}
    known |= set(_INTRINSICS)
    for orig, s in symbols.items():
        called = set(re.findall(r"\b([a-zA-Z_]\w*)\s*\(", s["code"]))
        s["unresolved"] = sorted(called - known - {s["name"]})

    out_dir = Path(out_dir)
    mod_dir = out_dir / "modules"
    mod_dir.mkdir(parents=True, exist_ok=True)

    # module files
    mod_headers = []
    for module in modules:
        label = re.sub(r"\W+", "_", module["label"]).strip("_") or f"m{module['id']}"
        hname = f"{module['id']:02d}_{label}"
        hdr = ["#pragma once",
               f"// module: {module['label']} — {module['summary']}", ""]
        if module["types"]:
            hdr += ["// inferred shared types:", module["types"], ""]
        for orig, s in symbols.items():
            if s["module_id"] == module["id"]:
                sig = s["signature"].rstrip(";")
                hdr.append(f"{sig};  // {s['doc']}" if s["doc"] else f"{sig};")
        (mod_dir / f"{hname}.h").write_text("\n".join(hdr))
        mod_headers.append(f'{hname}.h')
        src = [f'// {binary_name} :: {module["label"]}',
               f'#include "{hname}.h"', ""]
        for orig, s in symbols.items():
            if s["module_id"] == module["id"]:
                src.append(
                    f"// {orig} @ {s['address']}"
                    + ("  [LLM output failed — raw decompile]"
                       if s["failed"] else "")
                )
                src.append(s["code"])
                src.append("")
        (mod_dir / f"{hname}.cpp").write_text("\n".join(src))

    # top-level decls: module includes + externals + unresolved stubs
    decls = ["#pragma once", f"// declarations lifted from {binary_name}", ""]
    decls += [f'#include "modules/{h}"' for h in mod_headers]
    all_rows = {r["name"]: r for r in store.list_functions(sha256, limit=100000)}
    unlifted = sorted(
        {c for r in uniq for c in r["callees"] if c not in symbols}
    )
    if unlifted:
        decls += ["", "// unlifted/external functions:"]
        for name in unlifted:
            sig = all_rows.get(name, {}).get("signature") or f"void {name}(void)"
            decls.append(f"{sig.rstrip(';')};")
    invented = sorted({n for s in symbols.values() for n in s["unresolved"]})
    if invented:
        decls += ["", "// call sites with no matching symbol in the binary:"]
        for n in invented:
            decls.append(f"void {n}(void);  // unresolved — likely LLM-invented")
    if aliases:
        decls += ["", "// unresolved originals:"]
        for fun, alias in aliases.items():
            decls.append(f"//   {fun} == {alias}")
    (out_dir / "decls.h").write_text("\n".join(decls))

    report = {
        "binary": binary_name,
        "sha256": sha256,
        "mode": "clustered",
        "threshold": threshold,
        "n_functions": len(symbols),
        "n_clusters": len(modules),
        "n_failed": sum(1 for s in symbols.values() if s["failed"]),
        "n_unresolved_calls": sum(
            len(s["unresolved"]) for s in symbols.values()
        ),
        "modules": [
            {k: v for k, v in m.items() if k != "members"}
            | {"members": m["members"]}
            for m in modules
        ],
        "functions": {
            orig: {k: v for k, v in s.items() if k != "code"}
            for orig, s in symbols.items()
        },
        "aliases": aliases,
    }
    (out_dir / "lift_report.json").write_text(json.dumps(report, indent=2))
    return out_dir, symbols
