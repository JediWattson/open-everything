"""oe — decompilation harness CLI."""

from __future__ import annotations

import json
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
    from .embed import make_embedder

    return make_embedder(model)


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
    frontend: str = typer.Option("ghidra", "--frontend", help="ghidra | disasm (Ghidra-free: LC_FUNCTION_STARTS + otool)"),
    defer_embed: bool = typer.Option(False, "--defer-embed", help="Extract only — store rows with NULL vectors, backfill later with `oe embed`"),
):
    """Decompile binaries and index their functions."""
    # NB: load the embedder BEFORE opening LanceDB/SQLite — importing those
    # native libs first makes torch's CPU->MPS weight upload take a
    # pathological per-tensor sync-copy path on this platform.
    embedder = None if defer_embed else _embedder(model)
    store = Store()
    graph = GraphStore()
    for binary in binaries:
        from . import pipeline

        with Progress() as prog:
            task = prog.add_task(f"[cyan]{binary.name}", total=None)

            def on_prog(i, total, fname):
                if prog.tasks[task].total != total:
                    prog.update(task, total=total)
                prog.update(task, completed=i, description=f"[cyan]{binary.name}[/] {fname}")

            sha, n = pipeline.ingest(
                binary, store, embedder, name=name if len(binaries) == 1 else None,
                force=force, on_progress=on_prog, graph=graph,
                frontend=frontend,
                model_name=model or config.DEFAULT_EMBED_MODEL,
            )
        if n == 0:
            console.print(f"[yellow]skip[/] {binary.name} (already indexed, use --force)")
        else:
            console.print(f"[green]ok[/] {binary.name}: {n} functions (sha {sha[:12]}…)")


@app.command()
def embed(
    binaries: list[str] = typer.Argument(None, help="Restrict to these binaries (default: all rows missing vectors)"),
    model: str | None = typer.Option(None, "--model", "-m", help="Embedding model (default: OE_EMBED_MODEL)"),
):
    """Backfill vectors for rows ingested with --defer-embed."""
    store = Store()
    shas = [_resolve_sha(store, b) for b in binaries] if binaries else [None]
    pending = []
    for sha in shas:
        pending += store.missing_vectors(binary_sha256=sha)
    if not pending:
        console.print("[green]nothing to embed[/] — all rows have vectors")
        return

    # Rows are stamped with their intended model at ingest; one `oe embed`
    # run per distinct model so dims never mix.
    by_model: dict[str, list[dict]] = {}
    for r in pending:
        by_model.setdefault(r["model"] or config.DEFAULT_EMBED_MODEL, []).append(r)
    for m, rows in by_model.items():
        console.print(f"[cyan]embedding[/] {len(rows)} functions with {m}")
        emb = _embedder(model or m)
        batch = int(os.environ.get("OE_EMBED_BATCH", "16"))
        with Progress() as prog:
            task = prog.add_task(m, total=len(rows))
            for i in range(0, len(rows), batch):
                chunk = rows[i : i + batch]
                vecs = emb.embed_docs([r["embed_text"] for r in chunk])
                for r, v in zip(chunk, vecs):
                    store.set_vector(r["name"], r["binary_sha256"], list(v))
                prog.advance(task, len(chunk))
    console.print(f"[green]ok[/] {len(pending)} vectors written")


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
    clustered: bool = typer.Option(False, "--clustered", help="Cluster-aware module lift (arch v2)"),
    threshold: float = typer.Option(0.25, "-t", help="Cluster merge threshold (clustered mode)"),
):
    """Lift all functions to coherent C++ via a shared symbol table."""
    from . import llm
    from .lift import lift_binary, lift_binary_clustered

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

        lift_fn = lift_binary_clustered if clustered else lift_binary
        kw = {"threshold": threshold} if clustered else {}
        # embedder loads lazily — only the tier-4 regional path needs it
        # (oversized functions that fail the monolithic emit)
        _emb = {}

        def embed(texts):
            if "e" not in _emb:
                _emb["e"] = _embedder()
            return _emb["e"].embed(texts)

        out_dir, symbols = lift_fn(
            store, sha, name,
            chat=lambda m, tools=None, temp=None: llm.chat(
                m, model=llm_model, tools=tools, temp=temp,
                max_tokens=4096),
            out_dir=out / name,
            limit=limit,
            on_progress=on_prog,
            embed=embed,
            **kw,
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
    table = Table(a, "→", b, "sim", "fpd", "verdict", title=f"{a} × {b}")
    for r in rows[:limit]:
        color = {"same": "green", "similar": "yellow",
                 "structural": "cyan", "novel": "red"}[r["verdict"]]
        table.add_row(r["a_name"], "→", r["b_name"],
                      "-" if r["sim"] is None else f"{r['sim']:.3f}",
                      "-" if r["fpd"] is None else f"{r['fpd']:.2f}",
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
    emb: bool = typer.Option(False, "--emb", help="Emit {anchor,positive,negative} asm↔source triplets (embedder SFT)"),
    ident: bool = typer.Option(False, "--ident", help="Emit asm@optA↔asm@optB identity pairs for the same source function"),
):
    """Generate (decompiled, source) SFT pairs by compiling C sources."""
    from .sft import (
        generate_emb_pairs, generate_identity_pairs, generate_pairs,
    )

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

    gen = (generate_identity_pairs if ident
           else generate_emb_pairs if emb
           else generate_pairs)
    stats = gen(
        srcs, out, tuple(opts.split(",")),
        on_progress=lambda i, n, name: err.print(
            f"[dim]{i}/{n} {name}[/]"),
    )
    console.print(
        f"[green]ok[/] {stats['pairs']} pairs → {out} "
        f"({stats['binaries']} binaries from {stats['files']} files)"
    )
    for k, names in stats.get("unmatched", {}).items():
        if names:
            err.print(f"  unmatched in {k}: {names}")
    for k, n in stats.get("funcs", {}).items():
        console.print(f"[dim]{k}: {n} fns in >=2 opt builds[/]")


@app.command()
def clusters(
    binary: str,
    threshold: float = typer.Option(0.35, "-t", help="Cosine-distance merge threshold"),
    label: bool = typer.Option(False, "--label", help="LLM-label each cluster"),
    llm_model: str | None = typer.Option(None, "--llm"),
    model: str | None = typer.Option(None, "--model", "-m"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write cluster map JSON"),
    graph: bool = typer.Option(False, "--graph", help="Call-graph communities instead of embedding clusters"),
):
    """Group a binary's functions into subsystem clusters (embedding-based)."""
    from .cluster import (
        cluster_functions, graph_communities, label_clusters, load_rows,
    )

    store = Store()
    sha = _resolve_sha(store, binary)
    indexed = store.distinct_models()
    if model is None and len(indexed) == 1:
        model = indexed.pop()
    rows = load_rows(store, sha, model or "")
    groups = (
        graph_communities(rows) if graph
        else cluster_functions(rows, threshold)
    )

    labels = [""] * len(groups)
    if label:
        from . import llm

        labels = label_clusters(
            groups,
            lambda m, tools=None, temp=None: llm.chat(
                m, model=llm_model, tools=tools, temp=temp),
            binary,
        )

    table = Table("cluster", "size", "members", title=f"{binary} subsystems")
    for i, members in enumerate(groups):
        names = ", ".join(m["name"] for m in members[:8])
        if len(members) > 8:
            names += f", +{len(members) - 8} more"
        table.add_row(
            f"{i}: {labels[i]}" if labels[i] else str(i),
            str(len(members)), names,
        )
    console.print(table)

    if out:
        data = [
            {"id": i, "label": labels[i] or None,
             "members": [m["name"] for m in members]}
            for i, members in enumerate(groups)
        ]
        Path(out).write_text(json.dumps(data, indent=2))
        console.print(f"[dim]wrote {out}[/]")


@app.command()
def mkemb(
    binaries: list[str],
    out: Path = typer.Option(Path("emb/pairs.jsonl"), "--out", "-o"),
    max_pos: int = typer.Option(4, "--max-pos", help="Positives per anchor"),
    supcon: bool = typer.Option(False, "--supcon", help="Emit {label,text} community rows for multi-positive contrastive training"),
):
    """Emit contrastive triplets from call-graph neighborhoods (embedder SFT)."""
    from .cluster import (
        community_labels, graph_communities, load_rows, neighbor_pairs,
    )

    store = Store()
    indexed = store.distinct_models()
    model = next(iter(indexed)) if len(indexed) == 1 else ""
    out.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with out.open("a") as f:
        for b in binaries:
            sha = _resolve_sha(store, b)
            rows = load_rows(store, sha, model)
            pairs = (community_labels(graph_communities(rows), b)
                     if supcon else neighbor_pairs(rows, max_pos=max_pos))
            for p in pairs:
                f.write(json.dumps(p) + "\n")
            total += len(pairs)
            console.print(f"[dim]{b}: {len(pairs)} rows[/]")
    console.print(f"[green]ok[/] {total} rows → {out}")


@app.command()
def trainemb(
    pairs: list[Path],
    out: Path = typer.Option(Path("emb/qodo-lora"), "--out", "-o"),
    epochs: int = typer.Option(1, "--epochs"),
    batch: int = typer.Option(1, "--batch", help="Triplets per step"),
    lr: float = typer.Option(2e-5, "--lr"),
    model: str | None = typer.Option(None, "--model", "-m"),
    eval_binary: str | None = typer.Option(None, "--eval", help="Cluster-ARI eval vs graph communities on this binary"),
    threshold: float = typer.Option(0.25, "-t"),
    ckpt_every: int = typer.Option(0, "--ckpt-every", help="Snapshot adapter+optimizer every N steps into out/checkpoint-N"),
    resume: Path | None = typer.Option(None, "--resume", help="Resume weights+optimizer from a checkpoint dir"),
):
    """LoRA-tune the embedder on {anchor,positive,negative} triplets."""
    from .embed_train import eval_clusters, train
    from .cluster import load_rows

    model_name = model or config.DEFAULT_EMBED_MODEL

    def _prog(s, n, l):
        if s % 10 == 0 or s == n:
            err.print(f"[dim]{s}/{n} loss={l:.3f}[/]", highlight=False)
            err.file.flush()

    out_dir = train(
        list(pairs), out, model_name, epochs=epochs,
        batch_size=batch, lr=lr, ckpt_every=ckpt_every, resume=resume,
        on_progress=_prog,
    )
    console.print(f"[green]ok[/] adapter → {out_dir}")
    if eval_binary:
        store = Store()
        sha = _resolve_sha(store, eval_binary)
        rows = load_rows(store, sha, model_name)
        res = eval_clusters(out_dir, rows, threshold=threshold)
        console.print(res)


@app.command()
def binaries():
    """List indexed binaries."""
    rows = Store().list_binaries()
    table = Table("binary", "sha256", "functions", "path")
    for r in rows:
        table.add_row(r["binary_name"], r["binary_sha256"][:16] + "…", str(r["n_functions"]), r["path"])
    console.print(table)


@app.command()
def functions(binary: str, limit: int = typer.Option(200, "-n"),
              cfg: bool = typer.Option(False, "--cfg", help="Show CFG metrics (cyclomatic complexity, loops, blocks)")):
    """List functions in an indexed binary."""
    store = Store()
    sha = _resolve_sha(store, binary)
    cols = ["name", "address", "size", "calls"] + (["CC", "loops", "blocks"] if cfg else [])
    table = Table(*cols)
    for f in store.list_functions(sha, limit=limit):
        row = [f["name"], f["address"], str(f["size"]), ", ".join(f["callees"][:5])]
        if cfg:
            from .cfg import function_cfg
            c = function_cfg(f["decompiled"]) if f["decompiled"] else {}
            row += [str(c.get("cyclomatic", "")), str(c.get("loops", "")), str(c.get("blocks", ""))]
        table.add_row(*row)
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
