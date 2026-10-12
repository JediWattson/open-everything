"""Interactive chat REPL — multi-turn agent session over the binary index.

Each user message runs through the agent loop (the LLM may call tools or just
answer). Binary context is sticky; slash commands bypass the LLM for direct
tool calls. The embedder is loaded lazily — no 3GB model until a search tool
is actually invoked.
"""

from __future__ import annotations

import json
import shlex

from rich.console import Console
from rich.markdown import Markdown

from .agent import Agent
from .graph import GraphStore
from .store import Store

console = Console()

_HELP = """\
  /bin <name>        switch target binary
  /binaries          list indexed binaries
  /search <query>    semantic search (loads embedder on first use)
  /show <fn>         decompiled body
  /graph <fn> [-d N] [--callers]
  /funcs [N]         list function names
  /clear             reset conversation history
  /quit              exit

anything else is sent to the agent — it can use the same tools itself."""


class _LazyEmbedder:
    """Defers loading the embedder until the agent actually calls search."""

    def __init__(self, model: str | None):
        self._model = model
        self._e = None

    def _load(self):
        if self._e is None:
            from .config import DEFAULT_EMBED_MODEL
            from .embed import Embedder

            model = self._model
            if model is None:
                indexed = Store().distinct_models()
                model = indexed.pop() if len(indexed) == 1 else DEFAULT_EMBED_MODEL
            console.print(f"[dim]loading embedder {model}…[/]")
            self._e = Embedder(model_name=model)
        return self._e

    def embed_query(self, text):
        return self._load().embed_query(text)

    @property
    def model_name(self):
        return self._load().model_name


def _resolve(store: Store, name: str) -> tuple[str, str] | None:
    for b in store.list_binaries():
        if b["binary_name"] == name or b["binary_sha256"].startswith(name):
            return b["binary_sha256"], b["binary_name"]
    return None


def _print_step(i: int, action: dict, obs: str):
    if "parse_error" in action:
        console.print(f"[dim]  step {i}: {action['parse_error'][:80]}[/]")
        return
    console.print(
        f"[dim]  step {i}: {action.get('tool')}("
        + ", ".join(f"{k}={v!r}" for k, v in action.get("args", {}).items())
        + ")[/]"
    )
    if obs.startswith("error:") or obs.startswith("unknown tool"):
        console.print(f"[red]    {obs[:160]}[/]")


def _direct_command(store: Store, graph: GraphStore, sha: str, line: str) -> bool:
    """Handle /-commands. Returns True if the line was a command."""
    try:
        args = shlex.split(line)
    except ValueError:
        return False
    cmd = args[0]
    if cmd == "/help":
        console.print(_HELP)
    elif cmd == "/binaries":
        for b in store.list_binaries():
            console.print(f"  {b['binary_name']:16} {b['n_functions']} fns")
    elif cmd == "/funcs":
        n = int(args[1]) if len(args) > 1 else 50
        rows = store.list_functions(sha, limit=n)
        console.print(" ".join(r["name"] for r in rows))
    elif cmd == "/show" and len(args) > 1:
        row = store.get_function(args[1], sha)
        console.print(row["decompiled"] if row else f"no function {args[1]!r}")
    elif cmd == "/graph" and len(args) > 1:
        depth = 3
        if "-d" in args:
            depth = int(args[args.index("-d") + 1])
        direction = "callers" if "--callers" in args else "callees"
        try:
            rows = graph.reachable(sha, args[1], direction, depth)
        except ValueError as e:
            console.print(str(e))
            return True
        for name, d in rows:
            console.print(f"  {'  ' * d}{name}")
    elif cmd == "/search" and len(args) > 1:
        emb = _lazy.embed_query(" ".join(args[1:]))
        hits = store.search(emb, k=5, binary_sha256=sha,
                            model=_lazy.model_name)
        for h in hits:
            console.print(f"  {h['_distance']:.3f}  {h['name']}")
    elif cmd in ("/quit", "/exit"):
        raise EOFError
    else:
        console.print(f"unknown command {cmd!r} — /help for list")
    return True


def repl(
    store: Store,
    graph: GraphStore,
    sha: str,
    binary_name: str,
    embedder_model: str | None,
    llm_chat,
    log_path=None,
) -> None:
    global _lazy
    _lazy = _LazyEmbedder(embedder_model)
    agent = Agent(store, graph, sha, _lazy, llm_chat, log_path=log_path)
    if log_path:
        console.print(f"[dim]logging turns to {log_path}[/]")
    console.print(
        f"[bold]oe chat[/] — binary [cyan]{binary_name}[/]. "
        "Type /help for commands, /quit to exit."
    )
    while True:
        try:
            line = console.input(f"[bold green]oe[{binary_name}]>[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\nbye")
            return
        if not line:
            continue
        if line.startswith("/bin "):
            hit = _resolve(store, line[5:].strip())
            if hit:
                sha, binary_name = hit
                agent._sha = sha
                console.print(f"context → {binary_name}")
            else:
                console.print(f"no binary matching {line[5:]!r} — /binaries")
            continue
        if line == "/clear":
            agent.messages = agent.messages[:1]
            console.print("history cleared")
            continue
        if line.startswith("/"):
            try:
                if _direct_command(store, graph, sha, line):
                    continue
            except EOFError:
                return
        answer = agent.turn(line, strict=False, on_step=_print_step)
        console.print(Markdown(answer))
        console.print()
