"""Subsystem clustering: group a binary's functions into modules.

Embeddings encode "does similar things / talks to similar callees" — so
clustering in vector space groups functions by subsystem without any model
calls. Agglomerative clustering with a cosine-distance threshold needs no
preset k. An optional LLM pass labels each cluster for readability.
"""

from __future__ import annotations

import json
from collections import defaultdict

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


def graph_communities(
    rows: list[dict], max_rounds: int = 50
) -> list[list[dict]]:
    """Label-propagation communities on the call graph — no embeddings.

    Two functions are related if they share a neighbor (same callee like
    `_strcoll`, same caller like a sort dispatcher) or are directly linked.
    Score weight: 2 per shared neighbor + 3 for a direct edge.
    """
    names = [r["name"] for r in rows]
    in_bin = set(names)
    neighbors = {
        r["name"]: set(r["callees"]) | set(r["callers"]) for r in rows
    }
    direct = {
        r["name"]: {
            c for c in r["callees"] if c in in_bin
        } | {
            c for c in r["callers"] if c in in_bin
        }
        for r in rows
    }
    labels = {n: n for n in names}  # deterministic: own name as seed
    for _ in range(max_rounds):
        changed = False
        for n in names:  # stable order
            scores: dict[str, int] = defaultdict(int)
            nset = neighbors[n]
            for other in names:
                if other == n:
                    continue
                shared = len(nset & neighbors[other])
                w = 2 * shared + (3 if other in direct[n] else 0)
                if w:
                    scores[labels[other]] += w
            if not scores:
                continue
            best = max(scores, key=lambda k: (scores[k], k))
            if best != labels[n]:
                labels[n] = best
                changed = True
        if not changed:
            break
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[labels[r["name"]]].append(r)
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
