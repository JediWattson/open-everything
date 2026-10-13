"""Control-flow reconstruction from stored disassembly.

Parses the "addr: mnemonic operands ; comment" lines produced by the disasm
frontend into a basic-block CFG, then derives structural metrics:

  - cyclomatic complexity  CC = E - N + 2   (decision points + 1)
  - loop count             back edges to a dominating block start
  - block/edge counts, indirect-branch count (jump tables / switch)

Pure text parsing — works on any already-indexed record, no re-ingest.
"""

from __future__ import annotations

import re

# conditional branches: b.eq, b.ne, ... plus compare-and-branch / test-and-branch
_COND = re.compile(r"^(b\.[a-z]+|cbz|cbnz|tbz|tbnz)\b")


def _parse_instructions(asm: str) -> list[tuple[int, str, str]]:
    """(addr, mnemonic, operand-string) per disassembled line."""
    out = []
    for line in asm.splitlines():
        m = re.match(r"\s*(0x[0-9a-f]+):\s*([a-z0-9.]+)\s*(.*?)\s*(?:;|$)",
                     line)
        if m:
            out.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return out


def _branch_target(ops: str) -> int | None:
    # last hex literal is the target — tbz w8, #0x3, 0x10000abcd has the
    # bit number first
    ms = re.findall(r"(0x[0-9a-f]+)", ops)
    return int(ms[-1], 16) if ms else None


def function_cfg(asm: str) -> dict:
    """Return {blocks, edges, cyclomatic, loops, indirect_branches} for one
    function's stored asm text."""
    insns = _parse_instructions(asm)
    if not insns:
        return {"blocks": 0, "edges": 0, "cyclomatic": 0, "loops": 0,
                "indirect": 0}

    lo, hi = insns[0][0], insns[-1][0]
    targets = {
        t for _, mn, ops in insns
        if (mn == "b" or _COND.match(mn))
        for t in [_branch_target(ops)] if t is not None and lo <= t <= hi
    }
    leaders = {insns[0][0]} | targets | {
        insns[i + 1][0]
        for i, (_, mn, _) in enumerate(insns[:-1])
        if mn in ("b", "br") or mn.startswith("ret") or _COND.match(mn)
    }
    # block id = the leader address that starts it
    leader_of = {}
    cur = insns[0][0]
    for a, _, _ in insns:
        if a in leaders:
            cur = a
        leader_of[a] = cur

    edges: set[tuple[int, int]] = set()
    back: set[tuple[int, int]] = set()
    indirect = 0
    for i, (a, mn, ops) in enumerate(insns):
        src = leader_of[a]
        fall = insns[i + 1][0] if i + 1 < len(insns) else None
        last_of_block = fall is None or leader_of.get(fall) != src
        if not last_of_block:
            continue
        if mn.startswith("ret"):  # ret / retaa / retab
            edges.add((src, -1))  # virtual exit node — multi-return funcs
            continue  #           otherwise E-N+2 undercounts
        if mn == "br":
            indirect += 1
            edges.add((src, -1))
            continue  # jump table: targets unknowable from linear asm
        t = _branch_target(ops) if (mn == "b" or _COND.match(mn)) else None
        if t is not None and lo <= t <= hi:
            e = (src, leader_of[t])
            edges.add(e)
            if leader_of[t] <= src:
                back.add(e)
            if _COND.match(mn) and fall is not None:
                edges.add((src, leader_of[fall]))
        elif mn == "b" and fall is not None:
            pass  # tail call / exits function
        elif fall is not None:
            edges.add((src, leader_of[fall]))

    n = len({l for l in leader_of.values()})
    n_graph = n + (1 if any(dst == -1 for _, dst in edges) else 0)
    e = len(edges)
    return {
        "blocks": n,
        "edges": e,
        "cyclomatic": e - n_graph + 2,
        "loops": len({dst for _, dst in back}),
        "indirect": indirect,
    }
