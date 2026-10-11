# open-everything

Decompilation harness for research: Ghidra headless extracts per-function
pseudocode + call-graph context, functions are embedded with a local model,
and stored in LanceDB for semantic search — RAG over a binary.

- `oe ingest` decompiles every function in a binary (PyGhidra + Ghidra headless),
  collects callees/callers, referenced strings, thunks/externals
- Each function is embedded as a structured document (signature + calls +
  called-by + strings + body) with a code-specialized local model
- Vectors land in LanceDB; a SQLite call-graph index enables multi-hop
  caller/callee traversal
- `oe ask` / `oe agent` run RAG and a tool-use loop over the index with a
  local LLM (mlx-lm on Metal, or Ollama)

## Requirements

- Python >= 3.11
- JDK 17+ (Ghidra requirement)
- Ghidra — on macOS install the Homebrew **formula** (`brew install ghidra`),
  not the cask or the release zip: only the bottle ships macOS decompiler
  natives. `GHIDRA_INSTALL_DIR` overrides autodiscovery.
- macOS or Linux; Apple Silicon recommended for embeddings (MPS)

## Setup

```sh
./setup.sh            # or: make setup / cmake -S . -B build && cmake --build build --target setup
./setup.sh --check    # verify the environment, install nothing
```

Manual equivalent:

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,llm]"
brew install openjdk@21 ghidra
```

## Usage

```sh
.venv/bin/oe ingest /bin/ls                    # decompile + embed + index (~1 min after model is cached)
.venv/bin/oe search "print file size" -k 5     # semantic search
.venv/bin/oe show <func> -b <binary>           # print pseudocode
.venv/bin/oe graph <func> -b <binary> -d 3     # transitive call graph
.venv/bin/oe ask "<question>" -b <binary>      # RAG → local LLM
.venv/bin/oe agent "<goal>" -b <binary>        # agentic tool-use loop
.venv/bin/oe lift <binary> -o lifted           # lift functions to coherent C++
.venv/bin/oe functions <binary>                # list functions
.venv/bin/oe binaries                          # list indexed binaries
.venv/bin/oe rm <binary>                       # drop from index
.venv/bin/oe doctor                            # environment check
```

## How it works

| File | Role |
| --- | --- |
| `src/openeverything/extractor.py` | PyGhidra extractor: decompiles every function, collects call context + strings |
| `src/openeverything/embed.py` | `build_embed_text` + SentenceTransformer `Embedder` |
| `src/openeverything/store.py` | LanceDB `functions` + `binaries` tables |
| `src/openeverything/graph.py` | SQLite `edges` table, recursive-CTE traversal |
| `src/openeverything/llm.py` | local LLM backend (mlx-lm on Metal, or Ollama) |
| `src/openeverything/agent.py` | one-JSON-action-per-turn agent loop |
| `src/openeverything/pipeline.py` | ingest orchestration |
| `src/openeverything/cli.py` | `oe` CLI (typer + rich) |

## Notes

- `OE_HOME` (default `~/open-everything`) holds `lancedb/`, `graph.db`, and
  `ghidra-projects/`. It must not contain hidden path elements (`.*`) —
  Ghidra's `ProjectLocator` rejects them.
- Default embedding model is `Qodo/Qodo-Embed-1-1.5B` (code-specialized,
  1536-dim). Rows are tagged per-model; switching models requires re-ingesting
  (vector dims differ). `OE_EMBED_MODEL` overrides;
  `unsloth/embeddinggemma-300m` is a lighter ungated option.
- MPS is auto-detected; `OE_DEVICE=cpu` forces CPU. On MPS the model loads
  bf16 — fp32 OOMs a 16 GB unified-memory Mac.
- LLM backend for `ask`/`agent`/`lift`: `OE_LLM_BACKEND=mlx|ollama`,
  `OE_LLM_MODEL`.

## Tests

```sh
.venv/bin/python -m pytest tests/ -q   # unit tests (no Ghidra/model needed)
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
