"""oe — decompilation harness CLI."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from . import config
from .graph import GraphStore
from .store import Store

app = typer.Typer(help="Decompile binaries into a function-level embedding index (Ghidra + LanceDB).")
console = Console()
err = Console(stderr=True)


def _embedder(model: str | None = None):
    from .embed import Embedder

    return Embedder(model)


def _run_log(kind: str) -> Path:
    import time

    p = Path("runs")
    p.mkdir(exist_ok=True)
    return p / f"{kind}-{int(time.time())}.jsonl"


def _resolve_sha(store: Store, binary: str) -> str:
    """Accept a sha256 prefix or a binary name."""
    for b in store.list_binaries():
        if b["binary_sha256"].startswith(binary) or b["binary_name"] == binary:
            return b["binary_sha256"]
    raise typer.BadParameter(f"unknown binary: {binary}")


@app.command()
def ingest(
    binaries: list[Path],
    name: str | None = typer.Option(None, help="Override binary name (single file only)"),
    force: bool = typer.Option(False, "--force", "-f", help="Re-ingest even if sha256 already indexed"),
    model: str | None = typer.Option(None, "--model", "-m", help="Embedding model (default: OE_EMBED_MODEL)"),
):
    """Decompile binaries and index their functions."""
    store = Store()
    graph = GraphStore()
    embedder = None
    for binary in binaries:
        from . import pipeline

        with Progress() as prog:
            task = prog.add_task(f"[cyan]{binary.name}", total=None)

            def on_prog(i, total, fname):
                if prog.tasks[task].total != total:
                    prog.update(task, total=total)
                prog.update(task, completed=i, description=f"[cyan]{binary.name}[/] {fname}")

            if embedder is None:
                prog.update(task, description=f"[cyan]{binary.name}[/] loading model…")
                embedder = _embedder(model)
            sha, n = pipeline.ingest(
                binary, store, embedder, name=name if len(binaries) == 1 else None,
                force=force, on_progress=on_prog, graph=graph,
            )
        if n == 0:
            console.print(f"[yellow]skip[/] {binary.name} (already indexed, use --force)")
        else:
            console.print(f"[green]ok[/] {binary.name}: {n} functions (sha {sha[:12]}…)")


@app.command()
def search(
    query: str,
    k: int = typer.Option(8, "-k"),
    binary: str | None = typer.Option(None, "--binary", "-b", help="Restrict to one binary (name or sha prefix)"),
    show_code: bool = typer.Option(False, "--code", "-c", help="Print decompiled bodies"),
    include_stubs: bool = typer.Option(False, "--all", help="Include external/thunk stubs"),
    model: str | None = typer.Option(None, "--model", "-m", help="Embedding model (must match ingested vectors)"),
):
    """Semantic search over indexed functions."""
    store = Store()
    sha = _resolve_sha(store, binary) if binary else None
    indexed = store.distinct_models()
    if model is None and len(indexed) == 1:
        model = indexed.pop()
    emb = _embedder(model)
    vec = emb.embed_query(query)
    hits = store.search(vec, k=k, binary_sha256=sha, include_stubs=include_stubs,
                        model=emb.model_name)

    table = Table("dist", "name", "address", "binary", "calls", title=f"results for: {query}")
    for h in hits:
        table.add_row(
            f"{h['_distance']:.3f}", h["name"], h["address"],
            h["binary_name"], ", ".join(h["callees"][:6]),
        )
    console.print(table)
    if show_code:
        for h in hits:
            console.rule(f"{h['name']} @ {h['address']}")
            console.print(h["decompiled"] or "(no body)")


_ASK_SYSTEM = (
    "You are a reverse-engineering assistant analyzing decompiled binary "
    "functions. Answer ONLY from the functions provided — cite function names "
    "and addresses. If the evidence is insufficient, say so plainly instead "
    "of guessing."
)

_ASK_BODY_CHARS = 4000


def _ask_context(hits: list[dict]) -> str:
    blocks = []
    for i, h in enumerate(hits, 1):
        lines = [
            f"### {i}. {h['name']} @ {h['address']}  ({h['binary_name']})",
            f"signature: {h['signature']}",
        ]
        if h["callees"]:
            lines.append("calls: " + ", ".join(h["callees"]))
        if h["callers"]:
            lines.append("called by: " + ", ".join(h["callers"]))
        if h["strings"]:
            lines.append("strings: " + " | ".join(h["strings"][:15]))
        lines.append("```c")
        lines.append(h["decompiled"][:_ASK_BODY_CHARS] or "(no body)")
        lines.append("```")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


@app.command()
def ask(
    question: str,
    binary: str | None = typer.Option(None, "--binary", "-b"),
    k: int = typer.Option(6, "-k", help="Functions to retrieve as context"),
    model: str | None = typer.Option(None, "--model", "-m", help="Embedding model (must match index)"),
    llm_model: str | None = typer.Option(None, "--llm", help="LLM model name (mlx or ollama id)"),
    show_context: bool = typer.Option(False, "--context", help="Print retrieved context too"),
    context_only: bool = typer.Option(False, "--context-only", help="Print prompt and exit (pipe to any LLM)"),
):
    """RAG over the index: retrieve functions, ask a local LLM about them."""
    store = Store()
    sha = _resolve_sha(store, binary) if binary else None
    indexed = store.distinct_models()
    if model is None and len(indexed) == 1:
        model = indexed.pop()
    emb = _embedder(model)
    vec = emb.embed_query(question)
    hits = store.search(vec, k=k, binary_sha256=sha, model=emb.model_name)

    context = _ask_context(hits)
    messages = [
        {"role": "system", "content": _ASK_SYSTEM},
        {"role": "user", "content": f"Decompiled functions:\n\n{context}\n\nQuestion: {question}"},
    ]
    if show_context or context_only:
        console.rule("context")
        console.print(messages[1]["content"])
        console.rule()
    if context_only:
        return

    from . import llm

    for chunk in llm.chat(messages, model=llm_model):
        console.print(chunk, end="")
    console.print()


@app.command()
def agent(
    goal: str,
    binary: str | None = typer.Option(None, "--binary", "-b", help="Target binary (required if >1 indexed)"),
    iters: int = typer.Option(12, "--iters", help="Max agent steps"),
    model: str | None = typer.Option(None, "--model", "-m"),
    llm_model: str | None = typer.Option(None, "--llm"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Hide step trace"),
    log: bool = typer.Option(False, "--log", help="Append JSONL trajectory to runs/agent-<ts>.jsonl"),
):
    """Let a local LLM drive search/show/graph tools to answer a goal."""
    from . import llm
    from .agent import Agent
    from .graph import GraphStore

    store = Store()
    if binary:
        sha = _resolve_sha(store, binary)
    else:
        bins = store.list_binaries()
        if len(bins) != 1:
            err.print("pass --binary (more than one binary indexed)")
            raise typer.Exit(1)
        sha = bins[0]["binary_sha256"]
    indexed = store.distinct_models()
    if model is None and len(indexed) == 1:
        model = indexed.pop()
    emb = _embedder(model)

    ag = Agent(
        store, GraphStore(), sha, emb,
        chat=lambda m, tools=None, temp=None: llm.chat(m, model=llm_model, tools=tools, temp=temp),
        log_path=_run_log("agent") if log else None,
    )

    def on_step(i, action, obs):
        if quiet:
            return
        console.print(f"[dim]step {i}: {action}[/]")
        console.print(f"[dim]{obs[:200]}[/]")

    answer = ag.run(goal, max_iters=iters, on_step=on_step)
    console.rule("answer")
    console.print(answer)


@app.command()
def chat(
    binary: str | None = typer.Option(None, "--binary", "-b", help="Target binary (required if >1 indexed)"),
    model: str | None = typer.Option(None, "--model", "-m"),
    llm_model: str | None = typer.Option(None, "--llm"),
    log: bool = typer.Option(False, "--log", help="Append JSONL trajectory to runs/chat-<ts>.jsonl"),
):
    """Interactive chat REPL — the agent drives tools, context persists."""
    from . import llm
    from .chat import repl
    from .graph import GraphStore

    store = Store()
    if binary:
        sha, name = _resolve_sha(store, binary), binary
        for b in store.list_binaries():
            if b["binary_sha256"] == sha:
                name = b["binary_name"]
    else:
        bins = store.list_binaries()
        if not bins:
            err.print("no binaries indexed — run `oe ingest` first")
            raise typer.Exit(1)
        if len(bins) != 1:
            err.print("pass --binary (more than one binary indexed)")
            raise typer.Exit(1)
        sha, name = bins[0]["binary_sha256"], bins[0]["binary_name"]
    repl(store, GraphStore(), sha, name, model,
         lambda m, tools=None, temp=None: llm.chat(m, model=llm_model, tools=tools, temp=temp),
         log_path=_run_log("chat") if log else None)


@app.command()
def lift(
    binary: str,
    out: Path = typer.Option(Path("lifted"), "--out", "-o", help="Output root (gets <out>/<binary>/)"),
    limit: int = typer.Option(0, "--limit", "-n", help="Lift only first N functions (callee-first order)"),
    llm_model: str | None = typer.Option(None, "--llm"),
):
    """Lift all functions to coherent C++ via a shared symbol table."""
    from . import llm
    from .lift import lift_binary

    store = Store()
    sha = _resolve_sha(store, binary)
    name = next(b["binary_name"] for b in store.list_binaries()
                if b["binary_sha256"] == sha)

    with Progress() as prog:
        task = prog.add_task(f"[cyan]lifting {name}", total=None)

        def on_prog(i, total, fname):
            if prog.tasks[task].total != total:
                prog.update(task, total=total)
            prog.update(task, completed=i,
                        description=f"[cyan]lifting {name}[/] {fname}")

        out_dir, symbols = lift_binary(
            store, sha, name,
            chat=lambda m, tools=None, temp=None: llm.chat(m, model=llm_model, tools=tools, temp=temp),
            out_dir=out / name,
            limit=limit,
            on_progress=on_prog,
        )
    failed = sum(1 for s in symbols.values() if s["failed"])
    console.print(
        f"[green]ok[/] {len(symbols)} functions → {out_dir} "
        f"({failed} fell back to raw decompile)"
    )


@app.command()
def match(
    a: str,
    b: str,
    limit: int = typer.Option(40, "-n"),
    model: str | None = typer.Option(None, "--model", "-m"),
):
    """Align functions across two binaries by embedding similarity."""
    store = Store()
    sha_a, sha_b = _resolve_sha(store, a), _resolve_sha(store, b)
    indexed = store.distinct_models()
    if model is None and len(indexed) == 1:
        model = indexed.pop()
    from .match import match_binaries

    rows = match_binaries(store, sha_a, sha_b, model or "")
    table = Table(a, "→", b, "sim", "verdict", title=f"{a} × {b}")
    for r in rows[:limit]:
        color = {"same": "green", "similar": "yellow", "novel": "red"}[r["verdict"]]
        table.add_row(r["a_name"], "→", r["b_name"], f"{r['sim']:.3f}",
                      f"[{color}]{r['verdict']}[/]")
    console.print(table)
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    console.print(counts)


@app.command()
def splice(
    target: str,
    donor: str = typer.Option(..., "--from", "-f", help="Donor binary"),
    seeds: list[str] = typer.Option(..., "--seed", "-s", help="Donor seed function(s)"),
    out: Path = typer.Option(Path("spliced"), "--out", "-o"),
):
    """Graft donor function(s) + their callee closure into a target binary."""
    from .graph import GraphStore
    from .splice import splice as do_splice

    store = Store()
    t_sha = _resolve_sha(store, target)
    d_sha = _resolve_sha(store, donor)
    names = {b["binary_sha256"]: b["binary_name"] for b in store.list_binaries()}
    report = do_splice(
        store, GraphStore(), t_sha, names[t_sha], d_sha, names[d_sha],
        seeds, out / f"{names[t_sha]}+{names[d_sha]}",
    )
    console.print(
        f"[green]ok[/] slice of {report['slice_size']} functions → "
        f"{out}/{names[t_sha]}+{names[d_sha]} "
        f"({sum(len(v) for v in report['unresolved_refs'].values())} unresolved refs)"
    )
    if report["missing_seeds"]:
        err.print(f"seeds with no bodies: {report['missing_seeds']}")


@app.command()
def mksft(
    sources: list[Path],
    out: Path = typer.Option(Path("sft/lift-pairs.jsonl"), "--out", "-o"),
    opts: str = typer.Option("O0,O1,O2,Os", "--opts", help="Optimization levels"),
):
    """Generate (decompiled, source) SFT pairs by compiling C sources."""
    from .sft import generate_pairs

    srcs: list[Path] = []
    for s in sources:
        s = Path(s)
        if s.is_dir():
            for pat in ("*.c", "*.cc", "*.cpp", "*.cxx"):
                srcs.extend(sorted(s.rglob(pat)))
        else:
            srcs.append(s)
    srcs = sorted(set(srcs))
    if not srcs:
        err.print("no C/C++ sources found")
        raise typer.Exit(1)
    console.print(f"[dim]{len(srcs)} source files[/]")

    stats = generate_pairs(
        srcs, out, tuple(opts.split(",")),
        on_progress=lambda i, n, name: err.print(
            f"[dim]{i}/{n} {name}[/]"),
    )
    console.print(
        f"[green]ok[/] {stats['pairs']} pairs → {out} "
        f"({stats['binaries']} binaries from {stats['files']} files)"
    )
    for k, names in stats["unmatched"].items():
        if names:
            err.print(f"  unmatched in {k}: {names}")


@app.command()
def binaries():
    """List indexed binaries."""
    rows = Store().list_binaries()
    table = Table("binary", "sha256", "functions", "path")
    for r in rows:
        table.add_row(r["binary_name"], r["binary_sha256"][:16] + "…", str(r["n_functions"]), r["path"])
    console.print(table)


@app.command()
def functions(binary: str, limit: int = typer.Option(200, "-n")):
    """List functions in an indexed binary."""
    store = Store()
    sha = _resolve_sha(store, binary)
    table = Table("name", "address", "size", "calls")
    for f in store.list_functions(sha, limit=limit):
        table.add_row(f["name"], f["address"], str(f["size"]), ", ".join(f["callees"][:5]))
    console.print(table)


@app.command()
def show(function: str, binary: str = typer.Option(..., "--binary", "-b")):
    """Print the decompiled body of one function."""
    store = Store()
    sha = _resolve_sha(store, binary)
    row = store.get_function(function, sha)
    if not row:
        err.print(f"no function {function!r} in {binary}")
        raise typer.Exit(1)
    console.rule(f"{row['name']} @ {row['address']}  ({row['binary_name']})")
    console.print(row["decompiled"] or "(no body)")


@app.command()
def graph(
    function: str,
    binary: str = typer.Option(..., "--binary", "-b"),
    depth: int = typer.Option(6, "--depth", "-d", help="Max traversal depth"),
    callers: bool = typer.Option(False, "--callers", help="Walk callers (who reaches it) instead of callees"),
):
    """Show the call graph around a function (transitive)."""
    store = Store()
    sha = _resolve_sha(store, binary)
    direction = "callers" if callers else "callees"
    rows = GraphStore().reachable(sha, function, direction=direction, max_depth=depth)
    if not rows:
        if store.get_function(function, sha):
            console.print(f"{function!r} is a leaf — no {direction}")
        else:
            err.print(f"no function {function!r} in {binary}")
        raise typer.Exit(1)
    title = f"callers of {function}" if callers else f"calls from {function}"
    table = Table("depth", "name", title=f"{title}  (depth <= {depth})")
    for name, d in rows:
        table.add_row(str(d), name)
    console.print(table)


@app.command()
def rm(binary: str):
    """Remove a binary and its functions from the index."""
    store = Store()
    sha = _resolve_sha(store, binary)
    n = store.drop_binary(sha)
    m = GraphStore().drop_binary(sha)
    console.print(f"removed {n} functions, {m} edges for {binary}")


@app.command()
def doctor():
    """Check the environment: Ghidra, model, DB."""
    g = config.find_ghidra_install()
    console.print(f"ghidra:    {g or '[red]not found[/]'}")
    console.print(f"db:        {config.DB_DIR}")
    console.print(f"graph:     {config.GRAPH_DB}")
    console.print(f"projects:  {config.PROJECTS_DIR}")
    console.print(f"model:     {config.DEFAULT_EMBED_MODEL}")
    console.print(f"java:      {os.environ.get('JAVA_HOME', '(java_home unset)')}")
