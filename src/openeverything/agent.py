"""Agent loop: lets a local LLM drive the harness tools to answer RE goals.

Two protocols are supported:

  * native — tool schemas are passed through the chat template and the model
    emits <tool_call> blocks (the format it was instruction-tuned on);
    anything else it emits counts as the answer.
  * json   — the model must emit one {"tool": ..., "args": ...} or
    {"answer": ...} object per turn (fallback for templates without tools).

Args are validated against pydantic schemas before dispatch — a ValidationError
becomes a legible observation the model can self-correct from. Repeat calls
with identical args replay the cached observation instead of re-executing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ValidationError

from .graph import GraphStore
from .store import Store

_MAX_SHOW_CHARS = 3000
_MAX_LIST = 200

_SYSTEM_BODY = """You are a reverse-engineering agent analyzing a binary. You answer the
user's questions by calling tools to gather evidence.

Strategy: search for the capability in question, `show` the best hits to
confirm, use `graph` to understand how they fit together. Cite function names
and addresses in your answer. Do not guess — gather evidence first."""

SYSTEM_NATIVE = _SYSTEM_BODY + """

To call a tool emit exactly one block and NOTHING else:

<tool_call>
{"name": "search", "arguments": {"query": "xor cipher"}}
</tool_call>

You will receive the real tool result in the next message — never write
tool results yourself. When you have enough evidence, answer in prose."""

SYSTEM_JSON = _SYSTEM_BODY + """

Respond with EXACTLY one JSON object per turn, nothing else:
  {"tool": "<name>", "args": {...}}   to call a tool
  {"answer": "<final answer>"}        when you can answer the goal

Tools:
  search(query, k=5)        — semantic search over functions; returns name, address, distance
  show(name)                — decompiled body + signature of one function
  graph(name, direction, depth=3) — transitive call graph; direction is "callees" (what it calls) or "callers" (who reaches it)
  functions()               — list function names in the binary"""


class SearchArgs(BaseModel):
    query: str
    k: int = 5


class ShowArgs(BaseModel):
    name: str


class GraphArgs(BaseModel):
    name: str
    direction: Literal["callees", "callers"] = "callees"
    depth: int = 3


class FunctionsArgs(BaseModel):
    pass


_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S
)

# Small models sometimes simulate the whole loop — narrating fake tool calls
# AND fake results in prose — instead of emitting a real <tool_call>. Detect
# and reject rather than treating the fabricated transcript as the answer.
_FAKE_OBS_RE = re.compile(
    r"OBSERVATION:|<tool_response|\*\*\w+\s+(Args|Results)\*\*|Step \d+:",
    re.I,
)


def _extract_action(text: str) -> dict | None:
    """Native <tool_call> block first, then legacy {"tool"/"answer"} object."""
    m = _TOOL_CALL_RE.search(text)
    if m:
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and "name" in obj:
            return {"tool": obj["name"], "args": obj.get("arguments") or {}}
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text[i:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            if "tool" in obj or "answer" in obj:
                return obj
            if "name" in obj and ("arguments" in obj or "args" in obj):
                return {
                    "tool": obj["name"],
                    "args": obj.get("arguments") or obj.get("args") or {},
                }
    return None


class Agent:
    def __init__(
        self,
        store: Store,
        graph: GraphStore,
        binary_sha256: str,
        embedder,
        chat: Callable,
        native: bool = True,
        log_path=None,
    ):
        self._store = store
        self._graph = graph
        self._sha = binary_sha256
        self._embedder = embedder
        self._chat = chat
        self._native = native
        self._log = Path(log_path) if log_path else None
        system = SYSTEM_NATIVE if native else SYSTEM_JSON
        self.messages = [{"role": "system", "content": system}]

    def _write_log(self, user_msg: str, answer: str):
        if not self._log:
            return
        self._log.parent.mkdir(parents=True, exist_ok=True)
        with self._log.open("a") as f:
            f.write(
                json.dumps(
                    {
                        "user": user_msg,
                        "answer": answer,
                        "messages": self.messages,
                    }
                )
                + "\n"
            )

    @classmethod
    def tool_schemas(cls) -> list[dict]:
        """OpenAI-style function schemas for the chat template's tools arg."""
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": desc,
                    "parameters": model.model_json_schema(),
                },
            }
            for name, (model, desc, _fn) in cls._TOOLS.items()
        ]

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

    # name -> (args schema, description, method)
    _TOOLS = {
        "search": (
            SearchArgs,
            "semantic search over decompiled functions; returns name, address, distance",
            _tool_search,
        ),
        "show": (
            ShowArgs,
            "decompiled body + signature of one function",
            _tool_show,
        ),
        "graph": (
            GraphArgs,
            "transitive call graph; direction is 'callees' (what it calls) or 'callers' (who reaches it)",
            _tool_graph,
        ),
        "functions": (
            FunctionsArgs,
            "list function names in the binary",
            _tool_functions,
        ),
    }

    def _dispatch(self, action: dict) -> str:
        spec = self._TOOLS.get(action.get("tool", ""))
        if spec is None:
            return f"unknown tool {action.get('tool')!r}"
        model, _desc, method = spec
        try:
            args = model.model_validate(action.get("args") or {})
        except ValidationError as e:
            errs = "; ".join(
                f"{'.'.join(str(p) for p in x['loc'])}: {x['msg']}"
                for x in e.errors()
            )
            return f"invalid args for {action['tool']}: {errs}"
        try:
            return method(self, **args.model_dump())
        except Exception as e:
            return f"error: {e}"

    def turn(
        self, user_msg: str, max_iters: int = 12, strict: bool = True,
        on_step=None,
    ) -> str:
        """One conversational turn: the model may call tools then answer.

        Appends to self.messages so multi-turn context persists. In native
        mode (or strict=False) non-tool output counts as the answer.
        Identical repeat calls replay the cached observation.
        """
        self.messages.append({"role": "user", "content": user_msg})
        messages = self.messages
        seen: dict[tuple, str] = {}
        tools = self.tool_schemas() if self._native else None
        for i in range(max_iters):
            raw = "".join(self._chat(messages, tools=tools, temp=0.0))
            action = _extract_action(raw)
            if action is None:
                if self._native and raw.strip() and _FAKE_OBS_RE.search(raw):
                    messages += [
                        {"role": "assistant", "content": raw},
                        {
                            "role": "user",
                            "content": "Do not narrate or fabricate tool calls "
                                       "or their results. Emit a real "
                                       "<tool_call> block, or answer in "
                                       "plain prose.",
                        },
                    ]
                    if on_step:
                        on_step(i, {"fabricated": raw[:160]}, "")
                    continue
                if (self._native or not strict) and raw.strip():
                    messages.append({"role": "assistant", "content": raw})
                    self._write_log(user_msg, raw)
                    return raw
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
                messages.append(
                    {"role": "assistant", "content": json.dumps(action)}
                )
                self._write_log(user_msg, action["answer"])
                return action["answer"]
            key = (
                action.get("tool"),
                json.dumps(action.get("args") or {}, sort_keys=True),
            )
            if key in seen:
                obs = ("(repeat call — identical result, do not call this "
                       "tool with these args again): " + seen[key])
            else:
                obs = self._dispatch(action)
                seen[key] = obs
            if on_step:
                on_step(i, action, obs[:400])
            messages += [
                {"role": "assistant", "content": json.dumps(action)},
                {"role": "user", "content": f"OBSERVATION: {obs}"},
            ]
        answer = "(reached iteration limit without an answer)"
        self._write_log(user_msg, answer)
        return answer

    def run(self, goal: str, max_iters: int = 12, on_step=None) -> str:
        """Single-shot agent run (back-compat wrapper around turn())."""
        return self.turn(f"Goal: {goal}", max_iters, strict=True,
                         on_step=on_step)
