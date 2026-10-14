"""Name propagation: clone-catalog matches let a named function donate its
symbol to an unnamed FUN_* twin in another binary.

`oe match` finds the pairs; this module turns same/similar verdicts into a
name map the lift can consult — an anonymous helper in `cpio` inherits
`_lafe_warnc` from its `bsdtar` twin because the matcher already established
they're the same code. Model-guessed names lose to evidence-backed ones.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_ANON = re.compile(r"^(FUN_|DAT_|LAB_|sub_|func_|unk_)")

_SOURCE_VERDICTS = ("same", "similar")
# fpd≈0 = structurally identical — the FUN_* vs real-name token alone can
# drag cosine below `similar`, so watch-tier pairs with zero fingerprint
# distance are legitimate donors too
_WATCH_FPD_MAX = 0.1


def _clean(name: str) -> str:
    """Turn a symbol name into a plausible C identifier."""
    n = name.lstrip("_")
    n = re.sub(r"\W+", "_", n).strip("_")
    return n or name.lstrip("_")


def propagate_names(
    clones_path: Path | str,
    binary: str,
    verdicts: tuple[str, ...] = _SOURCE_VERDICTS,
    store=None,
) -> dict[str, dict]:
    """Read a clones.jsonl catalog; return
    {FUN_x: {"name": clean_name, "symbol": orig, "via": "bin:name",
             "sim": float, "fpd": float}} for anonymous functions in
    `binary` whose best clone twin has a real symbol name."""
    best: dict[str, dict] = {}
    with open(clones_path) as f:
        for line in f:
            row = json.loads(line)
            if row["verdict"] in verdicts:
                pass
            elif row["verdict"] == "watch" and float(row["fpd"]) <= _WATCH_FPD_MAX:
                pass
            else:
                continue
            for me, other in (("a", "b"), ("b", "a")):
                if row[f"{me}_bin"] != binary:
                    continue
                mine, theirs = row[f"{me}_name"], row[f"{other}_name"]
                if not _ANON.match(mine) or _ANON.match(theirs):
                    continue
                sim = float(row["sim"])
                cur = best.get(mine)
                if cur is not None and sim <= cur["sim"]:
                    continue
                prop = {
                    "name": _clean(theirs),
                    "symbol": theirs,
                    "via": f"{row[f'{other}_bin']}:{theirs}",
                    "sim": sim,
                    "fpd": float(row["fpd"]),
                    "verdict": row["verdict"],
                }
                if store is not None:
                    sha = _sha_of(store, row[f"{other}_bin"])
                    donor = sha and store.get_function(theirs, sha)
                    if donor and donor.get("signature"):
                        prop["signature"] = _rename_sig(
                            donor["signature"], theirs, prop["name"]
                        )
                best[mine] = prop
    return best


def _sha_of(store, binary: str) -> str | None:
    for b in store.list_binaries():
        if b["binary_name"] == binary:
            return b["binary_sha256"]
    return None


def _rename_sig(sig: str, old: str, new: str) -> str:
    """Donor signature with the donor symbol swapped for the clean name."""
    for cand in (old, old.lstrip("_")):
        if re.search(rf"(?<![\w:]){re.escape(cand)}(?=\s*\()", sig):
            return re.sub(
                rf"(?<![\w:]){re.escape(cand)}(?=\s*\()", new, sig, count=1
            )
    return sig
