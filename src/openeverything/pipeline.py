"""Ingest orchestration: sha256 -> ghidra extract -> embed -> lancedb."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .embed import Embedder, build_embed_text
from .extractor import extract_functions
from .graph import GraphStore
from .models import FunctionRecord
from .store import Store


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest(
    binary: Path,
    store: Store,
    embedder: Embedder,
    name: str | None = None,
    force: bool = False,
    on_progress=None,
    graph: GraphStore | None = None,
    frontend: str = "ghidra",
) -> tuple[str, int]:
    """Ingest one binary. Returns (binary_sha256, n_functions)."""
    binary = binary.resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    sha = sha256_file(binary)
    name = name or binary.name

    if store.indexed_sha(sha) and not force:
        return sha, 0

    if force:
        store.drop_binary(sha)
        if graph is not None:
            graph.drop_binary(sha)

    if frontend == "disasm":
        from .disasm import extract_disasm as extract
    else:
        extract = extract_functions
    recs: list[FunctionRecord] = list(
        extract(binary, sha, name, on_progress=on_progress)
    )
    for r in recs:
        r.model = embedder.model_name
        r.embed_text = build_embed_text(r)

    batch = 16  # keeps activation memory sane for large models on MPS
    for i in range(0, len(recs), batch):
        vecs = embedder.embed_docs([r.embed_text for r in recs[i : i + batch]])
        for r, v in zip(recs[i : i + batch], vecs):
            r.vector = v

    store.add_functions(recs)
    if graph is not None:
        graph.add_edges(sha, ((r.name, c) for r in recs for c in r.callees))
    store.register_binary(sha, name, str(binary), len(recs))
    return sha, len(recs)
