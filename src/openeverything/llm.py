"""Local LLM backend for `oe ask`.

Prefers in-process mlx-lm (Metal-native, no daemon). Falls back to a running
Ollama server at localhost:11434. Override with OE_LLM_MODEL / OE_LLM_BACKEND.
"""

from __future__ import annotations

import json
import os
import urllib.request

from . import config

_DEFAULT_MLX_MODEL = "mlx-community/Qwen2.5-Coder-7B-Instruct-4bit"
_OLLAMA_URL = "http://localhost:11434/api/chat"

_mlx_cache: tuple = ()


def _ollama_reachable() -> bool:
    try:
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=1)
        return True
    except OSError:
        return False


def _mlx_chat(messages: list[dict], model_name: str, max_tokens: int):
    global _mlx_cache
    from mlx_lm import generate, load, stream_generate

    if not _mlx_cache or _mlx_cache[0] != model_name:
        _mlx_cache = (model_name, *load(model_name))
    _, model, tokenizer = _mlx_cache
    prompt = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    for chunk in stream_generate(model, tokenizer, prompt, max_tokens=max_tokens):
        yield chunk.text


def _ollama_chat(messages: list[dict], model_name: str, max_tokens: int):
    body = json.dumps(
        {
            "model": model_name,
            "messages": messages,
            "stream": True,
            "options": {"num_predict": max_tokens},
        }
    ).encode()
    req = urllib.request.Request(
        _OLLAMA_URL, body, {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            chunk = json.loads(line)
            if text := chunk.get("message", {}).get("content"):
                yield text


def chat(
    messages: list[dict],
    model: str | None = None,
    max_tokens: int = 1024,
    backend: str | None = None,
):
    """Yield response text chunks. Backend: 'mlx' | 'ollama' | auto."""
    backend = backend or os.environ.get("OE_LLM_BACKEND", "auto")
    model = model or os.environ.get("OE_LLM_MODEL") or (
        _DEFAULT_MLX_MODEL if backend != "ollama" else "qwen2.5-coder:7b"
    )
    if backend in ("auto", "mlx"):
        try:
            yield from _mlx_chat(messages, model, max_tokens)
            return
        except ImportError:
            if backend == "mlx":
                raise
    if backend in ("auto", "ollama") and _ollama_reachable():
        yield from _ollama_chat(messages, model, max_tokens)
        return
    raise RuntimeError(
        "no local LLM backend — `pip install mlx-lm` or run `ollama serve`"
    )
