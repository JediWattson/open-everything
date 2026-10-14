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


_FP_WEIGHT = 0.05  # fused = cosine - w * fdist; fdist ~0-3 typical


def match_binaries(
    store: Store, sha_a: str, sha_b: str, model: str
) -> list[dict]:
    """For each function in A: best-matching function in B by cosine sim,
    fused with CFG-fingerprint distance (callee sets are near-opt-invariant,
    so structurally-different candidates get demoted even when cosine is
    high)."""
    import numpy as np

    from .cfg import fdist, fingerprint

    rows_a = _body_rows(store, sha_a, model)
    rows_b = _body_rows(store, sha_b, model)
    if not rows_a or not rows_b:
        return []

    # Rows ingested with --defer-embed have vector=None: no semantic evidence.
    # NaN sims get zero cosine contribution but can still rank on fingerprint.
    vecs_a = [np.array(r["vector"]) if r["vector"] is not None else None
              for r in rows_a]
    vecs_b = [np.array(r["vector"]) if r["vector"] is not None else None
              for r in rows_b]
    emb_b = [j for j, v in enumerate(vecs_b) if v is not None]
    vb = np.array([vecs_b[j] for j in emb_b]) if emb_b else None
    fps_a = [fingerprint(r) for r in rows_a]
    fps_b = [fingerprint(r) for r in rows_b]

    out = []
    for i, ra in enumerate(rows_a):
        sims = np.full(len(rows_b), np.nan)
        if vecs_a[i] is not None and vb is not None:
            for j, v in zip(emb_b, vb):
                sims[j] = float(vecs_a[i] @ v)  # normalized => dot == cosine

        fpd = np.full(len(rows_b), np.nan)
        if fps_a[i] is not None:
            for j, fb in enumerate(fps_b):
                if fb is not None:
                    fpd[j] = fdist(fps_a[i], fb)

        fused = np.nan_to_num(sims, nan=0.0) - _FP_WEIGHT * np.nan_to_num(
            fpd, nan=0.0
        )
        if np.isnan(sims).all() and np.isnan(fpd).all():
            continue  # this A-row has no evidence channel at all
        j = int(fused.argmax())
        sim, d = float(sims[j]), float(fpd[j])
        no_sim, no_fp = np.isnan(sim), np.isnan(d)
        rb = rows_b[j]
        verdict = (
            "same" if not no_sim and sim >= 0.98 and (no_fp or d <= 0.5) else
            "similar" if not no_sim and sim >= 0.90 and (no_fp or d <= 1.5)
            else
            "structural" if no_sim and not no_fp and d <= 0.5 else
            "novel"
        )
        out.append(
            {
                "a_name": ra["name"], "a_addr": ra["address"],
                "b_name": rb["name"], "b_addr": rb["address"],
                "sim": None if no_sim else sim,
                "fpd": None if no_fp else d,
                "verdict": verdict,
            }
        )
    out.sort(key=lambda r: ((r["sim"] or 0.0)
                            - _FP_WEIGHT * (r["fpd"] or 0.0)),
             reverse=True)
    return out
