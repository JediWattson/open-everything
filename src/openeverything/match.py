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

    va = np.array([r["vector"] for r in rows_a])
    vb = np.array([r["vector"] for r in rows_b])
    sims = va @ vb.T  # vectors are normalized => dot == cosine
    fps_a = [fingerprint(r) for r in rows_a]
    fps_b = [fingerprint(r) for r in rows_b]

    out = []
    for i, ra in enumerate(rows_a):
        fa = fps_a[i]
        fused = np.copy(sims[i])
        # None = "no structural evidence" (e.g. Ghidra-side pseudocode rows
        # have no asm to build a CFG from), not "maximally different"
        fpd = np.full(len(rows_b), np.nan)
        if fa is not None:
            for j, fb in enumerate(fps_b):
                if fb is not None:
                    fpd[j] = fdist(fa, fb)
            fused = fused - _FP_WEIGHT * np.nan_to_num(fpd, nan=0.0)
        j = int(fused.argmax())
        sim, d = float(sims[i, j]), float(fpd[j])
        rb = rows_b[j]
        no_fp = np.isnan(d)
        verdict = (
            "same" if sim >= 0.98 and (no_fp or d <= 0.5) else
            "similar" if sim >= 0.90 and (no_fp or d <= 1.5) else
            "novel"
        )
        out.append(
            {
                "a_name": ra["name"], "a_addr": ra["address"],
                "b_name": rb["name"], "b_addr": rb["address"],
                "sim": sim,
                "fpd": None if no_fp else d,
                "verdict": verdict,
            }
        )
    out.sort(key=lambda r: (r["sim"]
                            - _FP_WEIGHT * (r["fpd"] or 0.0)),
             reverse=True)
    return out
