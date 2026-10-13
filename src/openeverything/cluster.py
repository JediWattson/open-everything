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
    # hub filter: a neighbor shared by too many functions is glue noise
    # (_printf, _malloc, the entry dispatcher) — drop it from every set so
    # it can't merge communities. Small fan-ins (_strcoll, _fts_read) keep
    # their semantic signal.
    fan_in: dict[str, int] = {}
    for s in neighbors.values():
        for n in s:
            fan_in[n] = fan_in.get(n, 0) + 1
    cap = max(8, len(rows) // 4)
    hubs = {n for n, k in fan_in.items() if k > cap}
    neighbors = {n: s - hubs for n, s in neighbors.items()}
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


def _row_text(r: dict) -> str:
    from .embed import build_embed_text
    from .models import FunctionRecord

    return build_embed_text(FunctionRecord(**{
        k: r[k] for k in (
            "binary_sha256", "binary_name", "address", "name",
            "signature", "decompiled", "callees", "callers",
            "strings", "is_external", "is_thunk", "size",
        )
    }))


def _neighbor_scores(rows: list[dict]) -> dict[str, dict[str, int]]:
    """anchor -> {other: relatedness} — 2 per shared neighbor + 3 direct."""
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
    out: dict[str, dict[str, int]] = {}
    for n in names:
        sc: dict[str, int] = {}
        for other in names:
            if other == n:
                continue
            w = 2 * len(neighbors[n] & neighbors[other]) + (
                3 if other in direct[n] else 0
            )
            if w:
                sc[other] = w
        out[n] = sc
    return out


def community_pairs(
    groups: list[list[dict]],
    max_pos: int = 4,
) -> list[dict]:
    """Emit contrastive triplets from communities: anchor = a member's embed
    text, positive = another same-community member's, negative = a member of
    a different community. sentence-transformers (TripletLoss / MNRL) shape."""
    pairs = []
    multi = [g for g in groups if len(g) >= 2]
    for gi, g in enumerate(multi):
        negs = [m for j, gg in enumerate(multi) if j != gi for m in gg]
        for a_i, a in enumerate(g):
            for p in g[a_i + 1 : a_i + 1 + max_pos]:
                if not negs:
                    continue
                pairs.append({
                    "anchor": _row_text(a),
                    "positive": _row_text(p),
                    "negative": _row_text(negs[(a_i + gi) % len(negs)]),
                })
    return pairs


def community_labels(
    groups: list[list[dict]], bin_name: str, min_size: int = 3
) -> list[dict]:
    """Emit {label, text} rows for supervised-contrastive training: one row
    per member of each community with >= min_size members. Label keying by
    community id makes every same-community member a positive."""
    rows = []
    for gi, g in enumerate(groups):
        if len(g) < min_size:
            continue
        for m in g:
            rows.append({"label": f"{bin_name}:{gi}", "text": _row_text(m)})
    return rows


def neighbor_pairs(rows: list[dict], max_pos: int = 4) -> list[dict]:
    """Contrastive triplets from local call-graph neighborhoods — works even
    when global communities collapse: positives = top-scored neighbors,
    negatives = unrelated functions."""
    scores = _neighbor_scores(rows)
    by_name = {r["name"]: r for r in rows}
    pairs = []
    for r in rows:
        sc = scores[r["name"]]
        ranked = sorted(sc, key=lambda n: -sc[n])[:max_pos]
        unrelated = [
            m for m in by_name if m != r["name"] and m not in sc
        ]
        for pi, p in enumerate(ranked):
            if not unrelated:
                break
            pairs.append({
                "anchor": _row_text(r),
                "positive": _row_text(by_name[p]),
                "negative": _row_text(
                    by_name[unrelated[(pi + len(r["name"])) % len(unrelated)]]
                ),
            })
    return pairs


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
