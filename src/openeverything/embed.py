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
