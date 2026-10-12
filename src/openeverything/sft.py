"""SFT pair generator: (decompiled, original-source) training pairs.

For each C source file and optimization level, compiles a binary, decompiles
it with the normal Ghidra path, and aligns decompiled functions back to their
original source by name (clang AST dump gives exact byte ranges). The emitted
JSONL is chat-format for mlx_lm.lora — system+user prompts replicate
lift._lift_prompt so the model trains on the real task distribution, and the
assistant target is lift's JSON output schema with `code` = original source.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from .extractor import extract_functions
from .lift import _SYSTEM as LIFT_SYSTEM

_DEFAULT_OPTS = ("O0", "O1", "O2", "Os")


def source_functions(src: Path) -> dict[str, str]:
    """name -> full source text of each function definition (clang AST)."""
    out = subprocess.run(
        [
            "cc", "-Xclang", "-ast-dump=json", "-fsyntax-only",
            "-Wno-everything", str(src),
        ],
        capture_output=True, text=True,
    ).stdout
    ast = json.loads(out)
    raw = src.read_bytes()
    fns: dict[str, str] = {}

    def _has_body(node: dict) -> bool:
        return any(
            isinstance(c, dict) and c.get("kind") == "CompoundStmt"
            for c in node.get("inner") or []
        )

    def walk(node):
        if isinstance(node, dict):
            if node.get("kind") == "FunctionDecl" and _has_body(node):
                rng = node.get("range") or {}
                b, e = rng.get("begin") or {}, rng.get("end") or {}
                if "file" not in b and "file" not in e and \
                        b.get("offset") is not None and e.get("offset") is not None:
                    end = e["offset"] + e.get("tokLen", 0)
                    fns[node["name"]] = raw[b["offset"]:end].decode(
                        errors="replace"
                    )
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(ast)
    return fns


def _signature_of(src_fn: str) -> str:
    """'ret name(args)' — the source text before the first '{', on one line."""
    head = src_fn.split("{", 1)[0]
    return " ".join(head.split()).rstrip()


def _user_prompt(rec: dict, src_sigs: dict[str, str]) -> str:
    """Mirror lift._lift_prompt — same input distribution the model sees."""
    parts = [f"signature: {rec.signature}"]
    callee_sigs = [
        src_sigs[c.lstrip("_")] for c in rec.callees if c.lstrip("_") in src_sigs
    ]
    if callee_sigs:
        parts.append(
            "callees (already lifted — call these names):\n  "
            + "\n  ".join(callee_sigs)
        )
    if rec.strings:
        parts.append("strings: " + " | ".join(rec.strings[:10]))
    parts += ["decompiled:", "```c", rec.decompiled, "```"]
    return "\n".join(parts)


def generate_pairs(
    sources: list[Path],
    out_path: Path,
    opts: tuple[str, ...] = _DEFAULT_OPTS,
    on_progress=None,
) -> dict:
    """Compile→decompile→align each source; append pairs to out_path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"files": 0, "binaries": 0, "pairs": 0,
             "unmatched": {}, "missing": {}}
    with tempfile.TemporaryDirectory() as td:
        for src in sources:
            src = Path(src)
            src_fns = source_functions(src)
            stats["files"] += 1
            for opt in opts:
                binary = Path(td) / f"{src.stem}-{opt}"
                cp = subprocess.run(
                    ["cc", f"-{opt}", "-o", str(binary), str(src)],
                    capture_output=True, text=True,
                )
                if cp.returncode != 0:
                    continue
                stats["binaries"] += 1
                sha = hashlib.sha256(binary.read_bytes()).hexdigest()
                recs = list(
                    extract_functions(
                        binary, sha, f"{src.stem}-{opt}",
                        on_progress=on_progress,
                    )
                )
                src_sigs = {
                    n: _signature_of(t) for n, t in src_fns.items()
                }
                with out_path.open("a") as f:
                    for rec in recs:
                        if rec.is_external or rec.is_thunk or not rec.decompiled:
                            continue
                        key = rec.name.lstrip("_")
                        if key == "entry":
                            key = "main"  # CRT entry point names
                        body = src_fns.get(key)
                        if body is None:
                            stats["unmatched"].setdefault(
                                f"{src.name}:{opt}", []
                            ).append(rec.name)
                            continue
                        target = {
                            "name": key,
                            "signature": src_sigs[key],
                            "doc": "",
                            "code": body.strip(),
                        }
                        f.write(
                            json.dumps(
                                {
                                    "messages": [
                                        {"role": "system",
                                         "content": LIFT_SYSTEM},
                                        {"role": "user",
                                         "content": _user_prompt(
                                             rec, src_sigs)},
                                        {"role": "assistant",
                                         "content": json.dumps(target)},
                                    ],
                                    "meta": {
                                        "src": str(src), "opt": opt,
                                        "func": key, "addr": rec.address,
                                    },
                                }
                            )
                            + "\n"
                        )
                        stats["pairs"] += 1
                stats["missing"][f"{src.name}:{opt}"] = len(recs)
    return stats
