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

from pydantic import BaseModel, ValidationError

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


def _unresolved(code: str, known: set[str], self_name: str) -> list[str]:
    """Callees in emitted code with no matching symbol — LLM confabulation
    detector: real callees come from the record, so invented names show up
    here immediately. String literals are stripped first — 'malloc()' inside
    \"malloc() failure\" is text, not a call."""
    bare = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
    called = set(re.findall(r"\b([a-zA-Z_]\w*)\s*\(", bare))
    return sorted(called - known - {self_name})


def _dropped(rec: dict, code: str, symbols: dict) -> list[str]:
    """Real callees that vanished from the emitted code — the degenerate
    'fix' for confabulation is deleting every call, which passes
    _unresolved but loses the function. Flag when most callees dropped.
    A callee counts as present under its raw name, its lifted name, or
    its underscore-stripped variant."""
    bare = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
    called = set(re.findall(r"\b([a-zA-Z_]\w*)\s*\(", bare))
    dropped = []
    for c in rec["callees"]:
        aliases = {c, c.lstrip("_"), symbols.get(c, {}).get("name", c)}
        if not aliases & called:
            dropped.append(c)
    return dropped if len(dropped) >= max(2, len(rec["callees"]) - 1) else []


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


# --- tier-3 lift: constrained mini-agent for confabulating functions ---
#
# Tools are deliberately tiny: the only thing the flat lift lacks is the
# binary's real name surface, so the agent can `functions`/`show` to look
# names up, then MUST finish by calling `emit` — a pydantic-validated
# tool call, not free-form JSON, so the output shape is enforced.

_LIFT_AGENT_SYSTEM = """You rewrite ONE decompiled function as clean C++.

Call a tool by emitting exactly one block per turn, nothing else:
<tool_call>
{"name": "<tool>", "arguments": {...}}
</tool_call>

Tools:
  functions()        — list every function name in this binary
  show(name)         — signature, callees, strings, body of one function
  emit(name, signature, doc, code)
                     — your final answer; code = complete C++ function

Rules:
- Only call names you saw via functions()/show() or that were given as
  signatures — anything else keeps its original FUN_* token.
- When confident, finish with emit(). Do not narrate."""

_AGENT_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "functions",
            "description": "list every function name in this binary",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "show",
            "description": "signature, callees, strings, body of one function",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "emit",
            "description": "final lifted function (name, signature, doc, code)",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "signature": {"type": "string"},
                    "doc": {"type": "string"},
                    "code": {"type": "string"},
                },
                "required": ["name", "signature", "code"],
            },
        },
    },
]


def _agent_lift(
    rec: dict,
    symbols: dict,
    bad: list[str],
    store: Store,
    sha256: str,
    chat,
    max_turns: int = 6,
) -> dict | None:
    """Tool-using lift for functions the flat pass confabulates on.
    Returns {name, signature, doc, code} or None if it never emits."""
    from .agent import _extract_action  # same <tool_call>/json parser

    def functions() -> str:
        names = [
            r["name"]
            for r in store.list_functions(sha256, limit=100000)
        ]
        return json.dumps(names)

    def show(name: str) -> str:
        row = store.get_function(name, sha256)
        if not row:
            return f"no function {name!r}"
        return json.dumps({
            "name": row["name"], "signature": row["signature"],
            "callees": row["callees"], "strings": row["strings"][:15],
            "decompiled": row["decompiled"][:3000],
        })

    msgs = _lift_prompt(rec, symbols)
    msgs[0] = {"role": "system", "content": _LIFT_AGENT_SYSTEM}
    if bad:
        msgs[1]["content"] += (
            "\n\nYour previous attempt mishandled these names — invented "
            f"calls or dropped real callees: {', '.join(bad)}. Use "
            "functions()/show() to check real names before emitting, and "
            "keep every callee the assembly actually calls."
        )
    else:
        msgs[1]["content"] += (
            "\n\nYour previous attempt produced no valid JSON. Use "
            "functions()/show() to check real names, then finish with "
            "emit()."
        )
    for _ in range(max_turns):
        raw = "".join(chat(msgs, tools=_AGENT_SCHEMAS, temp=0.0))
        action = _extract_action(raw)
        if action is None:
            msgs += [{"role": "assistant", "content": raw},
                     {"role": "user", "content":
                      "Emit exactly one <tool_call> block."}]
            continue
        name = action.get("tool", "")
        args = action.get("args") or {}
        if name == "emit":
            try:
                return _LiftEmit.model_validate(args).model_dump()
            except ValidationError as e:
                msgs += [{"role": "assistant", "content": raw},
                         {"role": "user", "content":
                          f"emit rejected ({e.errors()[0]['msg']}) — retry."}]
                continue
        if name == "functions":
            obs = functions()
        elif name == "show":
            try:
                obs = show(_NameArg.model_validate(args).name)
            except ValidationError as e:
                obs = f"invalid show args: {e.errors()[0]['msg']}"
        else:
            obs = f"unknown tool {name!r} — use functions/show/emit"
        msgs += [{"role": "assistant", "content": raw},
                 {"role": "user", "content": f"OBSERVATION: {obs}"}]
    return None


class _NameArg(BaseModel):
    name: str


class _LiftEmit(BaseModel):
    name: str
    signature: str
    doc: str = ""
    code: str


# --- tier-4 lift: regional decomposition for functions too big to emit ---
#
# A ~140-insn function fails the monolithic JSON emit. Instead: basic
# blocks (cfg.blocks_of) are grouped into contiguous regions cut at loop
# heads, regions are embedded+clustered so same-role blocks share an
# LLM-assigned label, each region is lifted separately as labeled C
# statements, and the function is stitched with goto edges.

_REGION_MAX = 28   # insns per region
_LIFT_BIG = 80     # asm-line floor for the regional path


def _is_big(rec: dict) -> bool:
    return sum(1 for l in rec["decompiled"].splitlines()
               if re.match(r"\s*0x[0-9a-f]+:", l)) >= _LIFT_BIG


def _regions(rec: dict, addr_names: dict | None = None) -> list[dict]:
    """Contiguous basic-block runs (≤ _REGION_MAX insns), split at loop
    heads so a loop body stays in one region."""
    from .cfg import blocks_of

    blocks = blocks_of(rec["decompiled"])
    if len(blocks) < 4:
        return []
    back_heads = {d for b in blocks for d in b["succs"] if d <= b["addr"]}
    regs, cur, n = [], [], 0
    for b in blocks:
        if cur and (n + len(b["insns"]) > _REGION_MAX
                    or b["addr"] in back_heads):
            regs.append(cur)
            cur, n = [], 0
        cur.append(b)
        n += len(b["insns"])
    if cur:
        regs.append(cur)
    label_of = {b["addr"]: f"L_{r[0]['addr']:x}"
                for r in regs for b in r}
    names = addr_names or {}

    def render(b) -> str:
        lines = []
        for a, mn, ops in b["insns"]:
            note = ""
            if mn in ("bl", "b"):
                t = re.search(r"0x[0-9a-f]+", ops)
                if t and int(t.group(0), 16) in names:
                    note = f"  // {names[int(t.group(0), 16)]}"
            lines.append(f"0x{a:x}: {mn} {ops}{note}")
        return "\n".join(lines)

    out = []
    for r in regs:
        me = f"L_{r[0]['addr']:x}"
        out.append({
            "label": me,
            "asm": "\n".join(render(b) for b in r),
            "succs": sorted({label_of[d] for b in r for d in b["succs"]
                             if label_of.get(d) != me}),
            "end": r[-1]["end"],
        })
    return out


def _region_roles(rec: dict, regions: list[dict], chat, embed) -> dict:
    """Embed regions, cluster, and let the LLM name each group's role —
    same-role regions (e.g. every escape-char case in a dispatch) get the
    same label, which steadies per-region lifting. label → role."""
    try:
        from .cluster import cluster_functions

        rows = [
            {"name": r["label"], "vector": v}
            for r, v in zip(regions, embed(
                [f"asm region in {rec['name']}:\n{r['asm']}"
                 for r in regions]))
        ]
        groups = cluster_functions(rows, threshold=0.20)
    except Exception:
        return {}
    roles = {}
    for g in groups:
        sample = "\n---\n".join(
            next(r["asm"] for r in regions if r["label"] == m["name"])
            for m in g[:2]
        )
        res = _extract_json("".join(chat([
            {"role": "user", "content": (
                "These asm regions share a role inside one function. "
                "Reply with JSON {\"label\": \"2-4 word role\"}.\n\n"
                + sample)
            },
        ], temp=0.0))) or {}
        for m in g:
            roles[m["name"]] = res.get("label") or "unlabeled"
    return roles


def _lift_region_once(
    rec: dict, region: dict, role: str | None,
    symbols: dict, known: set, chat,
) -> str | None:
    """One region → labeled C statements (validated like a whole lift)."""
    callee_sigs = [
        symbols[c]["signature"] for c in rec["callees"] if c in symbols
    ]
    prompt = (
        f"You are lifting region {region['label']} of {rec['name']} "
        f"({rec['signature']}) to C.\n"
        + (f"Region role: {role}.\n" if role else "")
        + (f"Already-lifted callees — call these names:\n  "
           + "\n  ".join(callee_sigs) + "\n" if callee_sigs else "")
        + "Call targets are annotated `// name` in the asm — call those "
        "exact names; DAT_* tokens stay verbatim.\n"
        "Emit ONLY the C statements — no function header, no label, no "
        "JSON, no markdown fence, no __asm__. Registers are locals: "
        "`mov x20, x0` → `long v20 = a0;`, stack setup can collapse to a "
        "short comment.\n"
        "End the block to match its control flow:\n"
        f"  successors: {', '.join(region['succs']) or 'none'}; "
        f"exit kind: {region['end']}\n"
        "  jump  → `goto L_x;`\n"
        "  cond  → `if (cond) goto L_t;` then fallthrough statements\n"
        "  ret   → `return ...;`\n"
        "  indirect → `/* indirect branch (jump table?) */` + best-effort "
        "switch or goto\n\n```asm\n" + region["asm"] + "\n```"
    )
    def grab(raw: str) -> str:
        # raw C text expected — tolerate a fence or a stray JSON wrapper
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```\w*\n?|\n?```\s*$", "", raw).strip()
        j = _extract_json(raw)
        if j and isinstance(j.get("code"), str):
            return j["code"].strip()
        return raw

    msgs = [
        {"role": "system", "content":
         "Lift one asm region to C statements. Emit ONLY the statements — "
         "no function header, no label, no JSON, no markdown, no prose."},
        {"role": "user", "content": prompt},
    ]
    nested = re.compile(
        r"\b(?:void|int|char|long|static|bool|FILE|size_t)\b"
        r"[\w\s\*]*\w+\s*\([^;{}]*\)\s*\{"
    )

    def violations(c: str) -> list[str]:
        v = [f"invented calls: {', '.join(b)}"
             for b in [_unresolved(c, known, "")] if b]
        if nested.search(c):
            v.append("function definition inside statements — emit "
                     "statements only")
        return v

    raw = "".join(chat(msgs))
    code = grab(raw)
    if not code or "0x" not in code and ";" not in code:
        return None
    why = violations(code)
    if why:
        msgs += [
            {"role": "assistant", "content": raw},
            {"role": "user", "content":
             "Rejected: " + "; ".join(why) +
             ". Emit the corrected statements."},
        ]
        raw2 = "".join(chat(msgs))
        c2 = grab(raw2)
        if c2 and not violations(c2):
            code = c2
    return code


def _lift_regions(
    rec: dict, symbols: dict, known: set, chat, embed=None,
    store: Store | None = None, sha256: str = "",
) -> dict | None:
    """Region-by-region lift for functions too large for one emit."""
    addr_names = {}
    if store is not None and sha256:
        addr_names = {
            int(r["address"], 16): r["name"]
            for r in store.list_functions(sha256, limit=100000)
            if r.get("address")
        }
    regions = _regions(rec, addr_names)
    if len(regions) < 2:
        return None
    roles = _region_roles(rec, regions, chat, embed) if embed else {}
    pieces = []
    for r in regions:
        code = _lift_region_once(rec, r, roles.get(r["label"]),
                                 symbols, known, chat)
        # a region that won't lift keeps its asm inline — degrades the
        # function instead of failing it outright
        if code is None:
            code = "/* unlifted asm:\n" + r["asm"] + "\n*/"
        pieces.append(f"{r['label']}:\n{code}")
    res = _extract_json("".join(chat([
        {"role": "user", "content": (
            f"A function was lifted region-by-region; region roles: "
            f"{sorted(set(roles.values())) or ['unknown']}. Its asm does: "
            f"{'; '.join(rec['strings'][:5]) or 'no strings'}. Reply with "
            "JSON {\"name\": \"snake_case_name\", \"doc\": \"one line\"}."
        )},
    ], temp=0.0))) or {}
    name = re.sub(r"\W+", "_", res.get("name") or "").strip("_") \
        or rec["name"]
    sig = rec["signature"].replace(rec["name"], name, 1)
    return {
        "name": name,
        "signature": sig,
        "doc": res.get("doc") or "",
        "code": f"{sig} {{\n" + "\n".join(pieces) + "\n}",
    }


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
    is_asm = rec["decompiled"].startswith("0x")
    parts += [
        "disassembled:" if is_asm else "decompiled:",
        "```asm" if is_asm else "```c",
        rec["decompiled"],
        "```",
    ]
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
    embed=None,
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

    # known-callable universe: real callees from the records (incl. external
    # stubs like _err) + intrinsics; lifted names accrete as we go.
    base_known = {c for r in uniq for c in r["callees"]}
    base_known |= {n.lstrip("_") for n in base_known}
    base_known |= set(_INTRINSICS)

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
        # Confabulation check + one corrective retry: code calling a name
        # that isn't a real callee gets bounced back with the offenders.
        known = base_known | {s["name"] for s in symbols.values()}
        # defects = invented calls + deleted real callees (an empty body
        # 'fixes' confabulation by deleting everything — count both)
        def defects(c: str, n: str) -> int:
            return (len(_unresolved(c, known, n))
                    + len(_dropped(rec, c, symbols)))

        n_bad = defects(code, new_name)
        if "code" in res and n_bad:
            bad = _unresolved(code, known, new_name)
            dropped = _dropped(rec, code, symbols)
            why = []
            if bad:
                why.append(f"called functions that do not exist: {', '.join(bad)}")
            if dropped:
                why.append(f"dropped real callees: {', '.join(dropped)}")
            msgs = _lift_prompt(rec, symbols) + [{
                "role": "user",
                "content": (
                    "Your code " + "; ".join(why) + ". Only call names from "
                    "the callee list or the given signatures, and keep every "
                    "real callee — anything else must keep its original "
                    "FUN_* token. Emit the corrected JSON object."
                ),
            }]
            r2 = _extract_json("".join(chat(msgs)))
            if r2 and "code" in r2:
                # adopt the retry only if it strictly reduces defects —
                # a worse rewrite (e.g. asm-as-calls) gets dropped
                n2 = r2.get("name") or new_name
                if defects(r2["code"], n2) < n_bad:
                    res, code = r2, r2["code"]
                    new_name, signature = n2, r2.get("signature") or signature
                    n_bad = defects(code, new_name)
            # tier 3: still defective → mini-agent looks names up via
            # functions()/show() then emits a validated lift
            if "code" in res and n_bad:
                agent_res = _agent_lift(
                    rec, symbols,
                    _unresolved(code, known, new_name)
                    + _dropped(rec, code, symbols),
                    store, sha256, chat,
                )
                if agent_res:
                    a_new = agent_res.get("name") or new_name
                    if defects(agent_res["code"], a_new) < n_bad:
                        res, code = agent_res, agent_res["code"]
                        new_name = a_new
                        signature = agent_res.get("signature") or signature
        if "code" not in res:
            # flat emit produced nothing parseable — the agent's emit()
            # is itself a lift attempt with tool feedback
            agent_res = _agent_lift(rec, symbols, [], store, sha256, chat)
            if agent_res:
                res, code = agent_res, agent_res["code"]
                new_name = agent_res.get("name") or new_name
                signature = agent_res.get("signature") or signature
                n_bad = defects(code, new_name)
        # tier 4: big functions the monolithic emit can't hold → split into
        # embedded+clustered regions, lift each, stitch with goto edges
        if ("code" not in res or n_bad) and _is_big(rec):
            reg = _lift_regions(rec, symbols, known, chat, embed,
                                store, sha256)
            if reg and "code" in reg:
                r_new = reg.get("name") or new_name
                if ("code" not in res
                        or defects(reg["code"], r_new) < n_bad):
                    res, code = reg, reg["code"]
                    new_name = r_new
                    signature = reg.get("signature") or signature
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

    # LLMs lowercase FUN_ tokens; restore them so the rename pass sees them.
    fun_pat = re.compile(r"\bfun_([0-9a-f]{8,})\b")
    orig_names = set(symbols)
    for fn in order:
        code = symbols[fn["name"]]["code"]
        symbols[fn["name"]]["code"] = fun_pat.sub(
            lambda m: f"FUN_{m.group(1)}"
            if f"FUN_{m.group(1)}" in orig_names else m.group(0),
            code,
        )

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
    known = {s["name"] for s in symbols.values()} | base_known
    for fn in order:
        s = symbols[fn["name"]]
        s["unresolved"] = _unresolved(s["code"], known, s["name"])
        # raw-asm fallbacks reference addresses, not names — dropped is
        # meaningless there, and a failed row is already honest
        s["dropped"] = [] if s["failed"] else _dropped(
            fn, s["code"],
            {k: {"name": v["name"]} for k, v in symbols.items()},
        )

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
    embed=None,
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

    base_known = {c for r in uniq for c in r["callees"]}
    base_known |= {n.lstrip("_") for n in base_known}
    base_known |= set(_INTRINSICS)

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
            known = base_known | {s["name"] for s in symbols.values()}

            def defects(c: str, n: str) -> int:
                return (len(_unresolved(c, known, n))
                        + len(_dropped(rec, c, symbols)))

            n_bad = defects(code, new_name)
            if "code" in r2 and n_bad:
                bad = _unresolved(code, known, new_name)
                dropped = _dropped(rec, code, symbols)
                why = []
                if bad:
                    why.append(
                        f"called functions that do not exist: {', '.join(bad)}"
                    )
                if dropped:
                    why.append(f"dropped real callees: {', '.join(dropped)}")
                msgs = _lift_prompt_ctx(rec, symbols, module) + [{
                    "role": "user",
                    "content": (
                        "Your code " + "; ".join(why) + ". Only call names "
                        "from the callee list or the given signatures, and "
                        "keep every real callee — anything else must keep "
                        "its original FUN_* token. Emit the corrected JSON "
                        "object."
                    ),
                }]
                r3 = _extract_json("".join(chat(msgs)))
                if r3 and "code" in r3:
                    n3 = r3.get("name") or new_name
                    if defects(r3["code"], n3) < n_bad:
                        r2, code = r3, r3["code"]
                        new_name = n3
                        signature = r3.get("signature") or signature
                        n_bad = defects(code, new_name)
                if "code" in r2 and n_bad:
                    agent_res = _agent_lift(
                        rec, symbols,
                        _unresolved(code, known, new_name)
                        + _dropped(rec, code, symbols),
                        store, sha256, chat,
                    )
                    if agent_res:
                        a_new = agent_res.get("name") or new_name
                        if defects(agent_res["code"], a_new) < n_bad:
                            r2, code = agent_res, agent_res["code"]
                            new_name = a_new
                            signature = agent_res.get("signature") or signature
            if "code" not in r2:
                agent_res = _agent_lift(
                    rec, symbols, [], store, sha256, chat
                )
                if agent_res:
                    r2, code = agent_res, agent_res["code"]
                    new_name = agent_res.get("name") or new_name
                    signature = agent_res.get("signature") or signature
                    n_bad = defects(code, new_name)
            # tier 4: oversized member → regional decomposition + stitch
            if ("code" not in r2 or n_bad) and _is_big(rec):
                reg = _lift_regions(rec, symbols, known, chat, embed,
                                    store, sha256)
                if reg and "code" in reg:
                    r_new = reg.get("name") or new_name
                    if ("code" not in r2
                            or defects(reg["code"], r_new) < n_bad):
                        r2, code = reg, reg["code"]
                        new_name = r_new
                        signature = reg.get("signature") or signature
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

    # LLMs lowercase FUN_ tokens; restore them so the rename pass sees them.
    fun_pat = re.compile(r"\bfun_([0-9a-f]{8,})\b")
    orig_names = set(symbols)
    for s in symbols.values():
        s["code"] = fun_pat.sub(
            lambda m: f"FUN_{m.group(1)}"
            if f"FUN_{m.group(1)}" in orig_names else m.group(0),
            s["code"],
        )

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

    known = {s["name"] for s in symbols.values()} | base_known
    for orig, s in symbols.items():
        s["unresolved"] = _unresolved(s["code"], known, s["name"])

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
