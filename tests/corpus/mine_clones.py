"""Mine cross-binary clone pairs: sweep all binary pairs, emit every
(a,b) function pair whose fused cosine+fingerprint score clears the clone
thresholds — not just the per-row argmax (one function can legitimately
clone into several counterparts).

Output: JSONL with both asm bodies — directly usable as training/eval data
for the "same algorithm, different binary" recognition problem.

Usage: .venv/bin/python tests/corpus/mine_clones.py [--out emb/clones.jsonl]
"""

from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import numpy as np

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from openeverything.cfg import fdist, fingerprint
from openeverything.store import Store

_SAME = dict(sim=0.98, fpd=0.5)
_SIMILAR = dict(sim=0.90, fpd=1.5)
# watch tier: weaker cosine but strong structure (calibration data)
_WATCH_SIM, _WATCH_FPD = 0.80, 0.30


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="emb/clones.jsonl")
    args = ap.parse_args()

    store = Store()
    bins = {
        b["binary_sha256"]: b["binary_name"] for b in store.list_binaries()
    }
    by_sha: dict[str, list[dict]] = {s: [] for s in bins}
    for r in store._table().search().to_list():
        if r["binary_sha256"] in by_sha:
            by_sha[r["binary_sha256"]].append(r)

    # keep real functions with a vector and a body; fingerprints once.
    # <8 insns: stub/trampoline territory — structurally indistinguishable,
    # pure match noise
    for sha, rows in by_sha.items():
        rows[:] = [
            r for r in rows
            if r["vector"] is not None and r["decompiled"]
            and not r["is_external"] and not r["is_thunk"]
            and len(r["decompiled"].splitlines()) >= 8
        ]
        for r in rows:
            r["fp"] = fingerprint(r)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    n_lines = 0
    with out_path.open("w") as f:
        for sha_a, sha_b in itertools.permutations(by_sha, 2):
            rows_a, rows_b = by_sha[sha_a], by_sha[sha_b]
            if not rows_a or not rows_b:
                continue
            va = np.array([r["vector"] for r in rows_a])
            vb = np.array([r["vector"] for r in rows_b])
            sims = va @ vb.T
            for i, ra in enumerate(rows_a):
                for j, rb in enumerate(rows_b):
                    sim = float(sims[i, j])
                    if sim < _WATCH_SIM and (
                        ra["fp"] is None or rb["fp"] is None
                    ):
                        continue
                    d = (
                        fdist(ra["fp"], rb["fp"])
                        if ra["fp"] is not None and rb["fp"] is not None
                        else None
                    )
                    if sim >= _SAME["sim"] and (d is None or d <= _SAME["fpd"]):
                        verdict = "same"
                    elif sim >= _SIMILAR["sim"] and (
                        d is None or d <= _SIMILAR["fpd"]
                    ):
                        verdict = "similar"
                    elif sim >= _WATCH_SIM and d is not None and d <= _WATCH_FPD:
                        verdict = "watch"
                    else:
                        continue
                    counts[verdict] = counts.get(verdict, 0) + 1
                    f.write(json.dumps({
                        "a_bin": bins[sha_a], "a_name": ra["name"],
                        "a_addr": ra["address"],
                        "b_bin": bins[sha_b], "b_name": rb["name"],
                        "b_addr": rb["address"],
                        "sim": round(sim, 4),
                        "fpd": None if d is None else round(d, 3),
                        "verdict": verdict,
                        "a_asm": ra["decompiled"], "b_asm": rb["decompiled"],
                    }) + "\n")
                    n_lines += 1
    print(f"{n_lines} pairs -> {out_path}  {counts}")


if __name__ == "__main__":
    main()
