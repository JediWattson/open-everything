"""Build embedding documents and run a local SentenceTransformer model.

Each function is embedded as a structured document: signature, call-graph
context (callees + callers), referenced strings, then the decompiled body.
The call context up front is what makes 'function calls as embeddings' work —
retrieval matches on both what a function does and who it talks to.
"""

from __future__ import annotations

import os

import tabulate  # noqa: F401  pre-imported so torch's atexit handler doesn't hit jpype's dead import hook

from . import config
from .models import FunctionRecord

_MAX_BODY_CHARS = 8000
_MAX_STRINGS = 20


def build_embed_text(rec: FunctionRecord) -> str:
    parts = [
        f"function: {rec.name}",
        f"signature: {rec.signature}",
    ]
    if rec.callees:
        parts.append("calls: " + ", ".join(rec.callees))
    if rec.callers:
        parts.append("called by: " + ", ".join(rec.callers))
    if rec.strings:
        shown = rec.strings[:_MAX_STRINGS]
        parts.append("strings: " + " | ".join(s.replace("\n", " ") for s in shown))
    parts.append("---")
    parts.append(rec.decompiled[:_MAX_BODY_CHARS] or "(no decompiled body)")
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


class MlxEmbedder:
    """mlx-lm-backed embedder — same interface as Embedder, Apple-silicon
    native memory behaviour (lazy weights, cache limits) instead of MPS.

    Qodo-Embed is Qwen2-arch with is_causal=false: bidirectional attention.
    mlx's scaled_dot_product_attention with mask=None is already full
    attention, so the only patch needed is suppressing the causal mask
    Qwen2Model builds internally — plus a padding mask when batching.
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
        self._model = qwen2.Qwen2Model(args)  # backbone only, no lm_head
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
        self._pad_lens: mx.array | None = None
        self._patch_bidirectional()
        self.dim = int(args.hidden_size)

    def _bf16(self) -> None:
        from mlx.utils import tree_map

        mx = self._mx
        params = tree_map(
            lambda p: p.astype(mx.bfloat16), self._model.parameters()
        )
        self._model.update(params)

    def _patch_bidirectional(self) -> None:
        """Qwen2Model.__call__ hardcodes create_attention_mask(h, cache) —
        swap it for a padding-only mask (or None when unpadded)."""
        import mlx.core as mx

        mod = __import__(self._model.__module__, fromlist=["x"])
        orig = getattr(mod, "create_attention_mask", None)
        if orig is None or getattr(orig, "_oe_patched", False):
            return
        embedder = self

        def mask_fn(h, cache=None, *args, **kwargs):
            lens = embedder._pad_lens
            if lens is None:
                return None  # full bidirectional, no padding
            L = h.shape[1]
            keep = mx.arange(L)[None, :] < lens[:, None]
            return mx.where(keep, 0.0, -mx.inf)[:, None, None, :].astype(
                h.dtype
            )

        mask_fn._oe_patched = True
        mod.create_attention_mask = mask_fn

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
        self._pad_lens = lens
        try:
            h = self._model(batch)  # [B, L, D] post-norm hidden states
        finally:
            self._pad_lens = None
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
