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


def _mlx_chat(
    messages: list[dict], model_name: str, max_tokens: int,
    tools: list[dict] | None = None, temp: float | None = None,
):
    global _mlx_cache
    from mlx_lm import generate, load, stream_generate

    if not _mlx_cache or _mlx_cache[0] != model_name:
        _mlx_cache = (model_name, *load(model_name))
    _, model, tokenizer = _mlx_cache
    prompt = tokenizer.apply_chat_template(
        messages, tools=tools, tokenize=False, add_generation_prompt=True
    )
    kw = {}
    if temp is not None:
        from mlx_lm.sample_utils import make_sampler

        kw["sampler"] = make_sampler(temp=temp)
    for chunk in stream_generate(
        model, tokenizer, prompt, max_tokens=max_tokens, **kw
    ):
        yield chunk.text


def _api_chat(
    messages: list[dict], model_name: str, max_tokens: int,
    tools: list[dict] | None = None, temp: float | None = None,
):
    """OpenAI-compatible /v1/chat/completions (LM Studio, llama.cpp,
    OpenRouter, OpenAI, …). Base+key from OE_API_BASE / OE_API_KEY.

    Tool calls come back as tool_calls deltas; re-emitted as our internal
    <tool_call> text so the agent parser is backend-agnostic."""
    base = os.environ.get("OE_API_BASE", "http://localhost:1234")
    key = os.environ.get("OE_API_KEY", "none")
    body: dict = {
        "model": model_name,
        "messages": messages,
        "stream": True,
        "max_tokens": max_tokens,
    }
    if tools:
        body["tools"] = tools
    if temp is not None:
        body["temperature"] = temp
    body = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base.rstrip('/')}/v1/chat/completions",
        body,
        {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    pending_calls: dict[int, dict] = {}
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            if not line.startswith(b"data: "):
                continue
            data = line[6:].strip()
            if data == b"[DONE]":
                break
            chunk = json.loads(data)
            delta = chunk["choices"][0].get("delta", {})
            for tc in delta.get("tool_calls") or []:
                slot = pending_calls.setdefault(
                    tc["index"], {"name": "", "arguments": ""}
                )
                fn = tc.get("function") or {}
                slot["name"] += fn.get("name") or ""
                slot["arguments"] += fn.get("arguments") or ""
            if text := delta.get("content"):
                yield text
    for tc in pending_calls.values():
        yield (
            "<tool_call>\n"
            + json.dumps({"name": tc["name"], "arguments": json.loads(tc["arguments"] or "{}")})
            + "\n</tool_call>"
        )


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
    tools: list[dict] | None = None,
    temp: float | None = None,
):
    """Yield response text chunks. Backend: 'mlx' | 'ollama' | auto.

    `tools` is an OpenAI-style function-schema list and `temp` a sampling
    temperature; only the mlx backend honors them.
    """
    backend = backend or os.environ.get("OE_LLM_BACKEND", "auto")
    model = model or os.environ.get("OE_LLM_MODEL") or {
        "ollama": "qwen2.5-coder:7b",
        "api": "local-model",
    }.get(backend, _DEFAULT_MLX_MODEL)
    if backend in ("auto", "mlx"):
        try:
            yield from _mlx_chat(
                messages, model, max_tokens, tools=tools, temp=temp
            )
            return
        except ImportError:
            if backend == "mlx":
                raise
    if backend in ("auto", "ollama") and _ollama_reachable():
        yield from _ollama_chat(messages, model, max_tokens)
        return
    if backend == "api":
        yield from _api_chat(
            messages, model, max_tokens, tools=tools, temp=temp
        )
        return
    raise RuntimeError(
        "no local LLM backend — `pip install mlx-lm`, run `ollama serve`, "
        "or set OE_LLM_BACKEND=api + OE_API_BASE/OE_API_KEY"
    )
