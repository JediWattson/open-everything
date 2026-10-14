"""Build embedding documents and run a local SentenceTransformer model.

Each function is embedded as a structured document: signature, call-graph
context (callees + callers), referenced strings, then the decompiled body.
The call context up front is what makes 'function calls as embeddings' work —
retrieval matches on both what a function does and who it talks to.
"""

from __future__ import annotations

import os
import re

import tabulate  # noqa: F401  pre-imported so torch's atexit handler doesn't hit jpype's dead import hook

from . import config
from .models import FunctionRecord

_MAX_BODY_CHARS = 8000
_MAX_STRINGS = 20

_LOCAL_TOK = re.compile(r"\b(FUN_[0-9a-fA-F]+|DAT_[0-9a-fA-F]+)\b")


def build_embed_text(
    rec: FunctionRecord, external_names: set[str] | None = None
) -> str:
    """Structured doc for one function. Local function names are masked to
    FUNC — an anonymous twin must embed like its named twin, so identity
    tokens carry no signal (a FUN_* vs _foo pair is the same code).
    External stubs (_printf) keep their names: they're semantic anchors
    shared across binaries."""
    if external_names is None:
        external_names = set()

    def mask(name: str) -> str:
        return name if name in external_names else "FUNC"

    sig = re.sub(
        rf"(?<![\w:]){re.escape(rec.name)}(?=\s*\()", "FUNC", rec.signature
    )
    parts = ["function: FUNC", f"signature: {sig}"]
    if rec.callees:
        parts.append("calls: " + ", ".join(mask(c) for c in rec.callees))
    if rec.callers:
        parts.append("called by: " + ", ".join(mask(c) for c in rec.callers))
    if rec.strings:
        shown = rec.strings[:_MAX_STRINGS]
        parts.append("strings: " + " | ".join(s.replace("\n", " ") for s in shown))
    parts.append("---")
    # Ghidra pseudocode bodies reference FUN_*/DAT_* tokens by name
    body = _LOCAL_TOK.sub(
        lambda m: "FUNC" if m.group(1).startswith("FUN_") else "DATA",
        rec.decompiled[:_MAX_BODY_CHARS],
    )
    parts.append(body or "(no decompiled body)")
    return "\n".join(parts)


def _force_bidirectional(auto_model) -> None:
    """Patch a native-loaded decoder arch into bidirectional attention.

    Some embedding models (e.g. Qodo-Embed, is_causal=false) were trained for
    full bidirectional attention but ship remote code that transformers 5.x
    can't run. Loaded natively, they get causal masks instead — this swaps
    create_causal_mask for create_bidirectional_mask during forward and clears
    the per-layer is_causal flags SDPA consults.
    """
    import sys

    from transformers.masking_utils import create_bidirectional_mask

    if getattr(auto_model.config, "is_causal", True) is not False:
        return
    mod = sys.modules[type(auto_model).__module__]
    orig_mask_fn = getattr(mod, "create_causal_mask", None)
    if orig_mask_fn is None or orig_mask_fn is create_bidirectional_mask:
        return
    orig_forward = type(auto_model).forward

    def forward(*args, **kwargs):
        mod.create_causal_mask = create_bidirectional_mask
        try:
            return orig_forward(*args, **kwargs)
        finally:
            mod.create_causal_mask = orig_mask_fn

    type(auto_model).forward = forward
    for m in auto_model.modules():
        if getattr(m, "is_causal", None) is True:
            m.is_causal = False


def _pick_device() -> str:
    import torch

    if os.environ.get("OE_DEVICE"):
        return os.environ["OE_DEVICE"]
    return "mps" if torch.backends.mps.is_available() else "cpu"


class Embedder:
    def __init__(self, model_name: str | None = None):
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name or config.DEFAULT_EMBED_MODEL
        device = _pick_device()
        try:
            self._model = SentenceTransformer(
                self.model_name, trust_remote_code=True, device=device,
            )
        except (AttributeError, ImportError, ModuleNotFoundError):
            # remote code predating transformers 5.x — use the native arch
            self._model = SentenceTransformer(
                self.model_name, trust_remote_code=False, device=device,
            )
        if device == "mps" and os.environ.get("OE_EMBED_DTYPE", "bf16") == "bf16":
            # bf16 halves weight memory — fp32 doesn't fit a 16 GB Mac's
            # unified-memory cap for >1B models. Cast post-load on-device:
            # dtype-at-load takes a pathological per-tensor sync-copy path.
            # OE_EMBED_DTYPE=fp32 skips the cast (faster but ~6 GB resident).
            import torch

            self._model.to(torch.bfloat16)
        _force_bidirectional(self._model[0].model)
        self.dim = int(self._model.get_embedding_dimension())
        prompts = getattr(self._model, "prompts", {}) or {}
        self._doc_prompt = "document" if "document" in prompts else None
        for cand in ("CodeRetrieval", "Retrieval-query", "query"):
            if cand in prompts:
                self._query_prompt = cand
                break
        else:
            self._query_prompt = None

    def _encode(self, texts: list[str], prompt_name: str | None):
        vecs = self._model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
            prompt_name=prompt_name,
        )
        return [v.tolist() for v in vecs]

    def embed_docs(self, texts: list[str]) -> list[list[float]]:
        return self._encode(texts, self._doc_prompt)

    def embed_query(self, text: str) -> list[float]:
        return self._encode([text], self._query_prompt)[0]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.embed_docs(texts)


def _make_bidirectional_qwen2(args):
    """Build a local embedding backbone without changing Qwen2's decoder code."""
    import mlx.core as mx
    from mlx_lm.models import qwen2

    class BidirectionalQwen2Model(qwen2.Qwen2Model):
        def __call__(self, inputs, lengths):
            h = self.embed_tokens(inputs)
            keep = mx.arange(h.shape[1])[None, :] < lengths[:, None]
            mask = mx.where(keep, 0.0, -mx.inf)[:, None, None, :].astype(
                h.dtype
            )
            # Embeddings use the local backbone without generation caches or
            # pipeline sharding. Pass our mask directly to these layers so
            # concurrent language models retain their causal attention.
            for layer in self.layers:
                h = layer(h, mask, None)
            return self.norm(h)

    return BidirectionalQwen2Model(args)


class MlxEmbedder:
    """mlx-lm-backed embedder — same interface as Embedder, Apple-silicon
    native memory behaviour (lazy weights, cache limits) instead of MPS.

    Qodo-Embed is Qwen2-arch with is_causal=false: bidirectional attention.
    mlx's scaled_dot_product_attention with mask=None is already full
    attention. Its embedding-specific backbone passes a padding-only mask
    directly to the layers, leaving Qwen2's language-model forward unchanged.
    Pooling is last-non-pad-token (1_Pooling: pooling_mode_lasttoken).
    """

    def __init__(self, model_name: str | None = None):
        import glob
        import json

        import mlx.core as mx
        from huggingface_hub import snapshot_download
        from mlx_lm.models import qwen2

        self._mx = mx
        self.model_name = model_name or config.DEFAULT_EMBED_MODEL
        path = snapshot_download(self.model_name, allow_patterns=[
            "*.safetensors", "*.json", "*.txt"])
        with open(f"{path}/config.json") as f:
            args = qwen2.ModelArgs.from_dict(json.load(f))
        self._model = _make_bidirectional_qwen2(args)  # no lm_head
        weights = {}
        for shard in sorted(glob.glob(f"{path}/*.safetensors")):
            weights.update(mx.load(shard))
        self._model.load_weights(list(weights.items()), strict=True)
        self._bf16()

        from transformers import AutoTokenizer

        self._tokenizer = AutoTokenizer.from_pretrained(path)
        # max window for tokenization — docs are already capped by
        # _MAX_BODY_CHARS, so this only bounds pathological inputs
        self._max_len = int(os.environ.get("OE_MLX_MAX_LEN", "2048"))
        self.dim = int(args.hidden_size)

    def _bf16(self) -> None:
        from mlx.utils import tree_map

        mx = self._mx
        params = tree_map(
            lambda p: p.astype(mx.bfloat16), self._model.parameters()
        )
        self._model.update(params)

    def _encode(self, texts: list[str]) -> list[list[float]]:
        mx = self._mx
        ids = [
            self._tokenizer.encode(t)[: self._max_len] for t in texts
        ]
        lens = mx.array([len(i) for i in ids])
        L = max(len(i) for i in ids)
        pad = getattr(self._tokenizer, "pad_token_id", None) or 0
        batch = mx.array(
            [i + [pad] * (L - len(i)) for i in ids], dtype=mx.int32
        )
        h = self._model(batch, lengths=lens)  # [B, L, D] post-norm states
        pooled = h[mx.arange(len(ids)), lens - 1]
        pooled = pooled / mx.linalg.norm(pooled, axis=-1, keepdims=True)
        mx.eval(pooled)
        return pooled.tolist()

    def embed_docs(self, texts: list[str]) -> list[list[float]]:
        return self._encode(texts)

    def embed_query(self, text: str) -> list[float]:
        return self._encode([text])[0]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.embed_docs(texts)


def make_embedder(model_name: str | None = None):
    """Backend pick: OE_EMBED_BACKEND=mlx|st forces, default auto-tries mlx
    (native memory behaviour) and falls back to SentenceTransformer."""
    backend = os.environ.get("OE_EMBED_BACKEND", "auto")
    if backend == "st":
        return Embedder(model_name)
    if backend == "mlx":
        return MlxEmbedder(model_name)
    try:
        return MlxEmbedder(model_name)
    except Exception as e:
        import sys

        print(f"[embed] mlx backend unavailable ({e}); using torch/ST",
              file=sys.stderr)
        return Embedder(model_name)
