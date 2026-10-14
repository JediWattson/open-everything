"""Paths and tunables. Everything user-visible is overridable via env vars."""

import os
from pathlib import Path

# NB: Ghidra's ProjectLocator rejects path elements starting with '.', so the
# default home must not live under a hidden directory.
APP_DIR = Path(os.environ.get("OE_HOME", Path.home() / "open-everything")).expanduser()
DB_DIR = APP_DIR / "lancedb"
GRAPH_DB = APP_DIR / "graph.db"
PROJECTS_DIR = APP_DIR / "ghidra-projects"
TABLE_NAME = "functions"

# Code-specialized 1.5B embedder (Qwen2-based, bidirectional attention).
# unsloth/embeddinggemma-300m is the lighter fallback — ungated mirror of the
# license-gated google/embeddinggemma-300m.
DEFAULT_EMBED_MODEL = os.environ.get(
    "OE_EMBED_MODEL", "Qodo/Qodo-Embed-1-1.5B"
)

# Embedding dims per model — needed to declare the fixed-size vector column
# when the first ingest is deferred (no model loaded to ask).
MODEL_DIMS = {
    "Qodo/Qodo-Embed-1-1.5B": 1536,
    "unsloth/embeddinggemma-300m": 768,
    "google/embeddinggemma-300m": 768,
}
DECOMPILE_TIMEOUT_S = int(os.environ.get("OE_DECOMPILE_TIMEOUT", "60"))

_DIRECT_CANDIDATES = [
    Path("/opt/homebrew/opt/ghidra/libexec"),  # homebrew formula (built natives)
    Path("/usr/local/opt/ghidra/libexec"),
]
_SEARCH_ROOTS = [
    Path("/opt/homebrew/Caskroom/ghidra"),
    Path("/Applications"),
    Path("/opt"),
    Path.home(),
]


def find_ghidra_install() -> Path | None:
    """Locate a Ghidra install dir (the one containing support/analyzeHeadless)."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and (Path(env) / "support" / "analyzeHeadless").exists():
        return Path(env)
    for cand in _DIRECT_CANDIDATES:
        if (cand / "support" / "analyzeHeadless").exists():
            return cand
    for root in _SEARCH_ROOTS:
        if not root.is_dir():
            continue
        for cand in sorted(root.glob("**/ghidra*_PUBLIC")):
            if (cand / "support" / "analyzeHeadless").exists():
                return cand
    return None
