"""Subsystem clustering: group a binary's functions into modules.

Embeddings encode "does similar things / talks to similar callees" — so
clustering in vector space groups functions by subsystem without any model
calls. Agglomerative clustering with a cosine-distance threshold needs no
preset k. An optional LLM pass labels each cluster for readability.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from .store import Store


def cluster_functions(
    rows: list[dict], threshold: float = 0.35
) -> list[list[dict]]:
    """Agglomerative cluster on embedding cosine distance. No k required."""
    from sklearn.cluster import AgglomerativeClustering

    if len(rows) < 2:
        return [rows]
    vecs = np.array([r["vector"] for r in rows])
    # cosine distance on normalized vectors: 1 - dot
    sim = vecs @ vecs.T
    np.fill_diagonal(sim, 1.0)
    dist = 1.0 - np.clip(sim, -1.0, 1.0)
    labels = AgglomerativeClustering(
        metric="precomputed", linkage="average",
        distance_threshold=threshold, n_clusters=None,
    ).fit_predict(dist)
    groups: dict[int, list[dict]] = defaultdict(list)
    for r, lab in zip(rows, labels):
        groups[int(lab)].append(r)
    return sorted(groups.values(), key=len, reverse=True)


def load_rows(store: Store, sha: str, model: str) -> list[dict]:
    rows = (
        store._table()
        .search()
        .where(
            f"binary_sha256 = '{sha}' AND model = '{model}'"
            " AND is_external = false AND is_thunk = false"
        )
        .to_list()
    )
    return [r for r in rows if r["decompiled"]]


def describe_cluster(members: list[dict]) -> str:
    """Compact evidence blob for an LLM label call."""
    parts = []
    for m in members[:12]:
        s = f"{m['name']} calls[{','.join(m['callees'][:6])}]"
        if m["strings"]:
            s += f" strs[{','.join(m['strings'][:5])}]"
        parts.append(s)
    return "\n".join(parts)


def label_clusters(
    clusters: list[list[dict]], chat, binary_name: str
) -> list[str]:
    """One LLM call per cluster -> short module label."""
    sys = (
        "You label groups of decompiled functions from a stripped binary "
        f"({binary_name}). Reply with a 1-3 word subsystem name like "
        "'crypto', 'cli parsing', 'file traversal', 'output formatting' — "
        "nothing else."
    )
    labels = []
    for members in clusters:
        msgs = [
            {"role": "system", "content": sys},
            {"role": "user", "content": describe_cluster(members)},
        ]
        labels.append("".join(chat(msgs)).strip().split("\n")[0])
    return labels
