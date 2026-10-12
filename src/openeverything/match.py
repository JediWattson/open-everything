"""Cross-binary function alignment: which functions exist in both binaries?

Embeddings make this a cosine-similarity matrix — near-1.0 pairs are the same
code (shared library helpers, vendored code), low-sim functions are unique to
each binary. Useful on its own for diffing, and it tells `oe splice` what the
donor and target already share.
"""

from __future__ import annotations

from .store import Store

_STUB_FILTER = ("is_external = false", "is_thunk = false")


def _body_rows(store: Store, sha: str, model: str) -> list[dict]:
    rows = (
        store._table()
        .search()
        .where(
            f"binary_sha256 = '{sha}' AND model = '{model}'"
            + "".join(f" AND {c}" for c in _STUB_FILTER)
        )
        .to_list()
    )
    return [r for r in rows if r["decompiled"]]


def match_binaries(
    store: Store, sha_a: str, sha_b: str, model: str
) -> list[dict]:
    """For each function in A: best-matching function in B by cosine sim."""
    import numpy as np

    rows_a = _body_rows(store, sha_a, model)
    rows_b = _body_rows(store, sha_b, model)
    if not rows_a or not rows_b:
        return []

    va = np.array([r["vector"] for r in rows_a])
    vb = np.array([r["vector"] for r in rows_b])
    sims = va @ vb.T  # vectors are normalized => dot == cosine

    out = []
    for i, ra in enumerate(rows_a):
        j = int(sims[i].argmax())
        sim = float(sims[i, j])
        rb = rows_b[j]
        verdict = (
            "same" if sim >= 0.98 else
            "similar" if sim >= 0.90 else
            "novel"
        )
        out.append(
            {
                "a_name": ra["name"], "a_addr": ra["address"],
                "b_name": rb["name"], "b_addr": rb["address"],
                "sim": sim, "verdict": verdict,
            }
        )
    out.sort(key=lambda r: r["sim"], reverse=True)
    return out
