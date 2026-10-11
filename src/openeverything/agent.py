"""Agent loop: lets a local LLM drive the harness tools to answer RE goals.

The model responds with exactly one JSON action per turn:
    {"tool": "<name>", "args": {...}}   -> executes, result fed back as OBSERVATION
    {"answer": "<text>"}                -> terminates the loop

Tool results are truncated to keep the context small — `show` bodies are the
biggest context consumer.
"""

from __future__ import annotations

import json
from typing import Callable

from .graph import GraphStore
from .store import Store

_MAX_SHOW_CHARS = 3000
_MAX_LIST = 200

SYSTEM = """You are a reverse-engineering agent analyzing a binary. You answer the
user's goal by calling tools, one per turn.

Respond with EXACTLY one JSON object per turn, nothing else:
  {"tool": "<name>", "args": {...}}   to call a tool
  {"answer": "<final answer>"}        when you can answer the goal

Tools:
  search(query, k=5)        — semantic search over functions; returns name, address, distance
  show(name)                — decompiled body + signature of one function
  graph(name, direction, depth=3) — transitive call graph; direction is "callees" (what it calls) or "callers" (who reaches it)
  functions()               — list function names in the binary

Strategy: search for the capability in question, `show` the best hits to
confirm, use `graph` to understand how they fit together. Cite function names
and addresses in your answer. Do not guess — gather evidence first."""


def _extract_action(text: str) -> dict | None:
    """Find the first balanced JSON object containing 'tool' or 'answer'."""
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text[i:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("tool" in obj or "answer" in obj):
            return obj
    return None


class Agent:
    def __init__(
        self,
        store: Store,
        graph: GraphStore,
        binary_sha256: str,
        embedder,
        chat: Callable,
    ):
        self._store = store
        self._graph = graph
        self._sha = binary_sha256
        self._embedder = embedder
        self._chat = chat

    def _tool_search(self, query: str, k: int = 5) -> str:
        vec = self._embedder.embed_query(query)
        hits = self._store.search(
            vec, k=k, binary_sha256=self._sha, model=self._embedder.model_name
        )
        return json.dumps(
            [
                {
                    "name": h["name"],
                    "address": h["address"],
                    "dist": round(h["_distance"], 3),
                    "calls": h["callees"][:8],
                }
                for h in hits
            ]
        )

    def _tool_show(self, name: str) -> str:
        row = self._store.get_function(name, self._sha)
        if not row:
            return f"no function {name!r}"
        return json.dumps(
            {
                "name": row["name"],
                "address": row["address"],
                "signature": row["signature"],
                "callees": row["callees"],
                "strings": row["strings"][:15],
                "decompiled": row["decompiled"][:_MAX_SHOW_CHARS],
            }
        )

    def _tool_graph(self, name: str, direction: str = "callees",
                    depth: int = 3) -> str:
        try:
            rows = self._graph.reachable(
                self._sha, name, direction=direction, max_depth=depth
            )
        except ValueError as e:
            return str(e)
        return json.dumps([{"name": n, "depth": d} for n, d in rows])

    def _tool_functions(self) -> str:
        rows = self._store.list_functions(self._sha, limit=_MAX_LIST)
        names = [r["name"] for r in rows]
        return json.dumps({"count": len(rows), "names": names})

    _TOOLS = {
        "search": _tool_search,
        "show": _tool_show,
        "graph": _tool_graph,
        "functions": _tool_functions,
    }

    def run(self, goal: str, max_iters: int = 12, on_step=None) -> str:
        """Run the agent loop. on_step(i, action, observation) per iteration."""
        messages = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Goal: {goal}"},
        ]
        for i in range(max_iters):
            raw = "".join(self._chat(messages))
            action = _extract_action(raw)
            if action is None:
                messages.append(
                    {
                        "role": "user",
                        "content": "Invalid response. Reply with exactly one "
                                   'JSON object: {"tool": ...} or {"answer": ...}',
                    }
                )
                if on_step:
                    on_step(i, {"parse_error": raw[:200]}, "")
                continue
            if "answer" in action:
                return action["answer"]
            tool = self._TOOLS.get(action.get("tool", ""))
            if tool is None:
                obs = f"unknown tool {action.get('tool')!r}"
            else:
                try:
                    obs = tool(self, **action.get("args", {}))
                except Exception as e:
                    obs = f"error: {e}"
            if on_step:
                on_step(i, action, obs[:400])
            messages += [
                {"role": "assistant", "content": json.dumps(action)},
                {"role": "user", "content": f"OBSERVATION: {obs}"},
            ]
        return "(reached iteration limit without an answer)"
