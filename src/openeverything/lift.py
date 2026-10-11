"""Whole-binary lift: decompiled functions -> coherent C++-flavored output.

Not a free-roaming agent — a deterministic pipeline. Functions are visited in
call-graph post-order (callees before callers), each is rewritten by the LLM
into a named, documented function, and the results feed a shared symbol table
so later (caller) chunks see real signatures instead of FUN_* names.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .store import Store

_SYSTEM = """You rewrite decompiled binary functions as clean C++.

You will be given ONE decompiled function plus the signatures of the lifted
functions it calls. Respond with EXACTLY one JSON object, nothing else:

{"name": "snake_case_name", "signature": "ret name(args)",
 "doc": "one-line description", "code": "the rewritten function"}

Rules:
- Call callees by their NEW names from the signatures given.
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
    for i, rec in enumerate(order):
        if on_progress:
            on_progress(i + 1, len(order), rec["name"])
        raw = "".join(chat(_lift_prompt(rec, symbols)))
        res = _extract_json(raw) or {}
        symbols[rec["name"]] = {
            "name": res.get("name") or rec["name"],
            "signature": res.get("signature") or rec["signature"],
            "doc": res.get("doc") or "",
            "code": res.get("code") or rec["decompiled"],
            "address": rec["address"],
            "failed": "code" not in res,
        }

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    decls = ["#pragma once", f"// declarations lifted from {binary_name}", ""]
    for fn in order:
        s = symbols[fn["name"]]
        sig = s["signature"].rstrip(";")
        decls.append(f"{sig};  // {s['doc']}" if s["doc"] else f"{sig};")
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

    report = {
        "binary": binary_name,
        "sha256": sha256,
        "functions": {
            orig: {k: v for k, v in s.items() if k != "code"}
            for orig, s in symbols.items()
        },
        "aliases": aliases,
    }
    (out_dir / "lift_report.json").write_text(json.dumps(report, indent=2))
    return out_dir, symbols
