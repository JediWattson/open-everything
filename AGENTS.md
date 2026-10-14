# open-everything

Decompilation harness for research: Ghidra headless extracts per-function
pseudocode + call-graph context, functions are embedded with a local model,
and stored in LanceDB for semantic search ("RAG over a binary").

## Layout

- `src/openeverything/extractor.py` — PyGhidra extractor: decompiles every
  function, collects callees/callers, referenced strings, thunks/externals.
- `src/openeverything/embed.py` — `build_embed_text` (signature + calls +
  called-by + strings + body) and the SentenceTransformer `Embedder`.
- `src/openeverything/store.py` — LanceDB tables `functions` (one row per
  function incl. vector) and `binaries` (registry keyed by sha256).
- `src/openeverything/graph.py` — SQLite `edges` table (name-keyed
  caller→callee per binary) for multi-hop call-graph traversal via
  recursive CTEs. Derived index — rebuilt from `callees` on ingest.
- `src/openeverything/llm.py` — LLM backends for `oe ask`/`agent`/`chat`/
  `lift`: in-process mlx-lm on Metal (default), a running Ollama server,
  or any OpenAI-compatible endpoint (`OE_LLM_BACKEND=api` +
  `OE_API_BASE`/`OE_API_KEY` — works with LM Studio, llama.cpp,
  OpenRouter, …; `tools`/`temperature` forwarded, `tool_calls` deltas
  translated back to internal `<tool_call>` text). `OE_LLM_MODEL` picks
  the model; 14B-4bit is the practical ceiling on 16 GB.
- `src/openeverything/agent.py` — agent loop for `oe agent`: the LLM emits one
  JSON action per turn (`{"tool": ..., "args": ...}` / `{"answer": ...}`) and
  can call search/show/graph/functions; observations are fed back truncated.
- `src/openeverything/agent.py` — tool loop. Tool args are validated by
  pydantic schemas (validation errors become self-correctable observations);
  identical repeat calls replay cached results; fabricated tool transcripts
  are rejected. Native `<tool_call>` format via chat-template `tools=` is the
  default (`native=True`); legacy `{"tool": ...}` JSON parsing remains as a
  fallback path. `llm.chat(..., temp=0)` for deterministic tool emission.
  `--log` on `oe agent`/`oe chat` appends JSONL turn records
  (`runs/<kind>-<ts>.jsonl`) — full message history per turn, ready to curate
  into a LoRA SFT dataset (mlx_lm.lora chat format).
- `src/openeverything/lift.py` — whole-binary lift for `oe lift`: visits
  functions callee-first (call-graph post-order), rewrites each via the LLM
  into a named/typed/documented function, and threads a shared symbol table
  so callers see lifted callee signatures. Emits `lifted/<bin>/{decls.h,
  lifted.cpp, lift_report.json}`. Exact-body dedupe merges identical bodies;
  output is best-effort readable C++, not guaranteed-compilable.
  Confabulation guard: emitted calls not in the real callee set, and real
  callees deleted from the body, both count as defects — one corrective
  retry, then a constrained mini-agent tier (functions()/show() to look up
  real names, mandatory pydantic-validated emit() as the final action).
  Retries/agent output are adopted only on strict defect reduction;
  leftovers stay in `lift_report.json` unresolved/dropped fields.
- `src/openeverything/pipeline.py` — ingest orchestration.
- `src/openeverything/cli.py` — `oe` CLI (typer + rich).

## Setup

```sh
./setup.sh            # or: make setup / cmake --build build --target setup
./setup.sh --check    # verify only, install nothing
```

setup.sh also symlinks `oe` into `~/.local/bin` (`OE_BIN_DIR` to override),
so it runs from any directory. `make global` re-creates just the symlink.

which wraps (manual equivalent):

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,llm]"
brew install openjdk@21 ghidra   # formula, not cask — bottle builds mac natives
```

Notes:
- The official Ghidra release zip does NOT ship macOS decompiler natives;
  the Homebrew formula bottle does. Point `GHIDRA_INSTALL_DIR` at any install
  containing `support/analyzeHeadless` to override autodiscovery.
- `JAVA_HOME` is auto-resolved to a keg-only openjdk install if unset.
- `OE_HOME` (default `~/open-everything`) holds `lancedb/`, `graph.db`, and
  `ghidra-projects/`. It must not contain hidden path elements (`.*`) —
  Ghidra's `ProjectLocator` rejects them.
- Embedding model: `Qodo/Qodo-Embed-1-1.5B` by default (code-specialized,
  bidirectional attention, 1536-dim). Two backends (`OE_EMBED_BACKEND`):
  `mlx` (default) loads the bare Qwen2 backbone + safetensors via mlx_lm
  with a padding-mask patch for bidirectional attention (`embed.py:
  MlxEmbedder`); `st`/`torch` is the SentenceTransformer path, which falls
  back to the native qwen2 arch and patches `create_causal_mask` ->
  `create_bidirectional_mask` (`embed.py:_force_bidirectional`) since the
  bundled remote code predates transformers 5.x. Vectors are
  interchangeable across backends (cosine ~0.999 on the same doc).
- `oe ingest --defer-embed` stores function rows with `vector = NULL` —
  extraction is seconds and model-free; `oe embed` backfills later.
  `oe match` treats a NULL vector as "no semantic evidence" and can rank
  on fingerprint alone (fpd column). Rows remember their intended `model`
  so `oe embed` batches by model.
- Device: MPS (Metal) is auto-detected; `OE_DEVICE=cpu` forces CPU. On MPS the
  model loads bf16 — fp32 OOMs a 16 GB unified-memory Mac. Embed batch is 16
  for the same reason.
- Rows are tagged with `model` and search filters on it. Vector dims differ
  per model (qodo 1536, gemma 768), so switching models requires wiping or
  re-ingesting the whole index — mixing dims in one table errors.
- Other options: `unsloth/embeddinggemma-300m` (ungated ST mirror of the
  license-gated `google/embeddinggemma-300m`), `google/embeddinggemma-2`
  (multimodal, needs pillow + torchvision). jina-embeddings-v2-* breaks on
  transformers 5.x (remote-code import error).
- `graph.db` edges are derived from the `callees` column at ingest time.
  Binaries indexed before the graph store existed can be backfilled from
  LanceDB (`name` + `callees` per row) without re-decompiling.

## Commands

```sh
oe ingest <binary>... [--force] [-m model]      # decompile + embed + index
oe ingest --frontend disasm <bin>...            # Ghidra-free: LC_FUNCTION_STARTS
                                    # + otool arm64 asm + stub names (no JVM)
oe ingest --defer-embed <bin>...                # extract only, vectors=NULL
oe embed [bin...] [-m model]                    # backfill NULL vectors
oe search "<query>" [-k N] [-b bin] [-m model] [--code] [--all]
oe show <func> -b <binary>          # print pseudocode
oe graph <func> -b <binary> [-d N] [--callers]   # transitive call graph
oe ask "<question>" [-b bin] [-k N] [--llm M] [--context-only]  # RAG → local LLM
oe agent "<goal>" [-b bin] [--iters N] [-q]     # agentic tool-use loop
oe chat [-b bin]                    # interactive REPL — persistent agent session
                                    #   /bin /binaries /search /show /graph /funcs /clear /quit
oe lift <binary> [-o dir] [-n N] [--llm M]      # whole-binary → lifted/*.cpp
oe lift <binary> --clustered [-t 0.25]          # arch v2: module prepass →
                                    # per-fn lift with module context →
                                    # modules/NN_label.{h,cpp} + decls.h
oe match <a> <b> [-n N]             # cross-binary function alignment (cosine sim)
oe clusters <bin> [-t 0.25] [--label] [--out map.json]
                                    # subsystem clustering on embeddings
oe clusters <bin> --graph           # call-graph communities instead — exact,
                                    # no embedder needed (shared-callee signal)
oe splice <target> --from <donor> --seed <fn>...   # graft donor subsystem into target
oe mksft <src.c>... [-o sft/pairs.jsonl] [--opts O0,O1,O2,Os]
                                    # SFT pair gen: compile→decompile→align
oe mkemb <binary>... [-o emb/pairs.jsonl]     # embedder SFT: community
                                    # {anchor,positive,negative} triplets
oe mksft <src.c>... --emb [-o out.jsonl]      # embedder SFT: compile → disasm
                                    # → name-align → asm↔source triplets
oe functions <binary>               # list functions
oe binaries                         # list indexed binaries
oe rm <binary>                      # drop from index
oe doctor                           # environment check
```

## Verify

```sh
.venv/bin/python -m pytest tests/ -q   # unit tests (no Ghidra/model needed)
.venv/bin/oe ingest /bin/ls            # smoke test, ~1 min after model cached
.venv/bin/oe search "print file size" -k 5
.venv/bin/oe graph entry -b ls -d 3    # NB: leaf functions legitimately print "no callees"
```
