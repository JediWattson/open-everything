"""Cross-opt-level function-identity eval: does a CFG fingerprint recover
the same source function across optimization levels?

Ground truth = symbol names (self-compiled binaries keep symtab).
For each function in binary A, rank candidates in binary B by
fingerprint distance; measure rank@1 + MRR. Embedding cosine is
scored in parallel for comparison.

Run: .venv/bin/python tests/corpus/eval_cfgid.py tests/corpus/*.c
"""

from __future__ import annotations

import hashlib
import math
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from openeverything.cfg import function_cfg
from openeverything.disasm import extract_disasm

# -fi = -fno-inline: keeps function boundaries while bodies are optimized —
# the interesting regime for fingerprint matching. Pure O2/Os inline most
# static functions into main and vanish.
OPTS = ("O0", "O1-fi", "O2-fi", "Os-fi", "O2")

_OPTFLAGS = {
    "O0": ["-O0"], "O1": ["-O1"], "O2": ["-O2"], "Os": ["-Os"],
    "O1-fi": ["-O1", "-fno-inline"],
    "O2-fi": ["-O2", "-fno-inline"],
    "Os-fi": ["-Os", "-fno-inline"],
}

# BSD sources reference sandboxing/libutil symbols macOS lacks — stub them.
# Function-like -D macros only expand where referenced, so harmless elsewhere.
_STUBS = [
    "-Dpledge(a,b)=0", "-Dunveil(a,b)=0", "-Du_long=unsigned long",
    "-Dreallocarray(p,n,s)=realloc(p,(n)*(s))",
    "-Dtimespecclear(t)=((t)->tv_sec=(t)->tv_nsec=0)",
    "-Dtimespecisset(t)=((t)->tv_sec||(t)->tv_nsec)",
    "-Dchflagsat(a,b,c,d)=0", "-Duid_from_user(n,u)=0",
    "-Dgid_from_group(n,g)=0",
    "-Dfmt_scaled(n,b)=snprintf(b,16,\"%lld\",(long long)n)",
    "-DMACHINE_ARCH=\"arm64\"", "-DFMT_SCALED_STRSIZE=16",
]


def fingerprint(rec) -> tuple | None:
    if not rec.decompiled or rec.is_external or rec.is_thunk:
        return None
    c = function_cfg(rec.decompiled)
    if not c["blocks"]:
        return None
    vec = (
        c["cyclomatic"], c["blocks"], c["edges"], c["loops"],
        c["indirect"], math.log1p(rec.size), len(rec.callees),
    )
    # callee multiset: which externs/local fns it calls — nearly opt-invariant
    callees = frozenset(rec.callees)
    return vec, callees


def fdist(a: tuple, b: tuple) -> float:
    (va, ca), (vb, cb) = a, b
    num = sum(abs(x - y) / (x + y + 1.0) for x, y in zip(va, vb))
    if ca or cb:
        num += 2.0 * (1 - len(ca & cb) / len(ca | cb))
    return num


def rank_stats(queries: dict, cands: dict) -> dict:
    """queries/cands: name -> (fp, embed_text). Score fingerprint + cosine."""
    import numpy as np
    hits1_f = hits1_e = 0
    mrr_f = mrr_e = 0.0
    n = 0
    names = sorted(set(queries) & set(cands))
    if len(names) < 2:
        return {}
    cmat = np.array([cands[nm][1] for nm in names]) if cands[names[0]][1] is not None else None
    for nm in names:
        qf, qv = queries[nm]
        scored = sorted(names, key=lambda c: fdist(qf, cands[c][0]))
        r = scored.index(nm) + 1
        hits1_f += r == 1
        mrr_f += 1.0 / r
        if cmat is not None and qv is not None:
            sims = cmat @ qv
            r2 = int((sims > sims[names.index(nm)]).sum()) + 1
            hits1_e += r2 == 1
            mrr_e += 1.0 / r2
        n += 1
    out = {"n": n, "fp_top1": hits1_f / n, "fp_mrr": mrr_f / n}
    if cmat is not None:
        out.update({"emb_top1": hits1_e / n, "emb_mrr": mrr_e / n})
    return out


def main() -> None:
    srcs = [Path(a) for a in sys.argv[1:]]
    use_emb = "--emb" in [a for a in sys.argv[1:]]
    srcs = [s for s in srcs if s.suffix == ".c"]
    embedder = None
    if use_emb:
        from openeverything.embed import Embedder
        embedder = Embedder()
        from openeverything.embed import build_embed_text

    with tempfile.TemporaryDirectory() as td:
        for src in srcs:
            per_opt: dict[str, dict] = {}
            for opt in OPTS:
                binary = Path(td) / f"{src.stem}-{opt}"
                cp = subprocess.run(
                    ["cc", *_OPTFLAGS[opt], *_STUBS,
                     "-o", str(binary), str(src)],
                    capture_output=True, text=True)
                if cp.returncode != 0:
                    print(f"{src.name}:{opt} compile failed", file=sys.stderr)
                    continue
                sha = hashlib.sha256(binary.read_bytes()).hexdigest()
                fns = {}
                for rec in extract_disasm(binary, sha, binary.name):
                    key = rec.name.lstrip("_")
                    fp = fingerprint(rec)
                    if fp is None or key in fns:
                        continue
                    vec = None
                    if embedder is not None:
                        vec = embedder.embed([build_embed_text(rec)])[0]
                    fns[key] = (fp, vec)
                per_opt[opt] = fns
            opts = [o for o in OPTS if o in per_opt]
            for i, a in enumerate(opts):
                for b in opts[i + 1:]:
                    r = rank_stats(per_opt[a], per_opt[b])
                    if not r:
                        continue
                    line = (f"{src.name} {a}->{b}: fp top1={r['fp_top1']:.2f} "
                            f"mrr={r['fp_mrr']:.2f}")
                    if "emb_top1" in r:
                        line += (f" | emb top1={r['emb_top1']:.2f} "
                                 f"mrr={r['emb_mrr']:.2f}")
                    line += f"   (n={r['n']})"
                    print(line)


if __name__ == "__main__":
    main()
