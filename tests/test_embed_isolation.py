"""Attention isolation checks without Metal, model weights, or network access."""

from concurrent.futures import ThreadPoolExecutor
import sys
import threading
import types

import numpy as np
import pytest

from openeverything.embed import MlxEmbedder, _make_bidirectional_qwen2


@pytest.fixture
def fake_mlx(monkeypatch):
    mx = types.ModuleType("mlx.core")
    for name in ("array", "arange", "where", "inf", "int32", "linalg"):
        setattr(mx, name, getattr(np, name))
    mx.eval = lambda *args: None
    mlx = types.ModuleType("mlx")
    mlx.core = mx
    qwen2 = types.ModuleType("mlx_lm.models.qwen2")
    qwen2.create_attention_mask = lambda h, cache=None: "causal"

    class Layer:
        def __init__(self):
            self.masks = []
            self.on_call = None

        def __call__(self, h, mask, cache):
            self.masks.append(mask if isinstance(mask, str) else mask.copy())
            if self.on_call:
                self.on_call()
            # A small attention-like operation: each token receives the mean
            # of the tokens its mask permits, making padding leaks observable.
            if isinstance(mask, str):
                keep = np.tril(np.ones((h.shape[1], h.shape[1]), dtype=bool))
                keep = np.broadcast_to(keep, (h.shape[0], *keep.shape))
            else:
                keep = np.broadcast_to(
                    np.isfinite(mask[:, 0]),
                    (h.shape[0], h.shape[1], h.shape[1]),
                )
            return np.einsum("bqk,bkd->bqd", keep, h) / keep.sum(
                axis=-1, keepdims=True
            )

    class Qwen2Model:
        def __init__(self, args):
            self.layers = [Layer()]
            self.norm = lambda h: h

        def embed_tokens(self, inputs):
            return np.stack((inputs, inputs ** 2 + 1), axis=-1).astype(np.float32)

        def __call__(self, inputs):
            h = self.embed_tokens(inputs)
            mask = qwen2.create_attention_mask(h, None)
            for layer in self.layers:
                h = layer(h, mask, None)
            return self.norm(h)

    qwen2.Qwen2Model = Qwen2Model
    models = types.ModuleType("mlx_lm.models")
    models.qwen2 = qwen2
    mlx_lm = types.ModuleType("mlx_lm")
    mlx_lm.models = models
    for name, module in {
        "mlx": mlx,
        "mlx.core": mx,
        "mlx_lm": mlx_lm,
        "mlx_lm.models": models,
        "mlx_lm.models.qwen2": qwen2,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    return mx, qwen2


def _embedder(mx):
    embedder = object.__new__(MlxEmbedder)
    embedder._mx = mx
    embedder._model = _make_bidirectional_qwen2(None)
    embedder._tokenizer = types.SimpleNamespace(
        encode=lambda text: [int(token) for token in text.split()],
        pad_token_id=0,
    )
    embedder._max_len = 2048
    return embedder


def test_embedding_leaves_normal_decoder_causal_during_forward(fake_mlx):
    mx, qwen2 = fake_mlx
    original_mask = qwen2.create_attention_mask
    decoder = qwen2.Qwen2Model(None)
    first = mx.array([[1, 2]])
    second = mx.array([[1, 9]])
    expected_prefix = decoder(first)[:, 0]
    embedder = _embedder(mx)
    during = []
    embedder._model.layers[0].on_call = lambda: during.append(
        decoder(second)[:, 0]
    )

    hidden = embedder._model(first, lengths=mx.array([2]))

    np.testing.assert_allclose(hidden[0, 0], [1.5, 3.5])
    np.testing.assert_allclose(during[0], expected_prefix)
    np.testing.assert_allclose(decoder(second)[:, 0], expected_prefix)
    assert qwen2.create_attention_mask is original_mask
    assert all(mask == "causal" for mask in decoder.layers[0].masks)


def test_two_embedders_keep_their_own_padding_masks(fake_mlx):
    mx, _ = fake_mlx
    first, second = _embedder(mx), _embedder(mx)

    first_batch = first.embed_docs(["1", "2 3 4"])
    second_batch = second.embed_docs(["5 6", "7"])

    np.testing.assert_allclose(first_batch[0], first.embed_query("1"))
    np.testing.assert_allclose(second_batch[1], second.embed_query("7"))
    np.testing.assert_array_equal(
        first._model.layers[0].masks[0][:, 0, 0],
        [[0.0, -np.inf, -np.inf], [0.0, 0.0, 0.0]],
    )
    np.testing.assert_array_equal(
        second._model.layers[0].masks[0][:, 0, 0],
        [[0.0, 0.0], [0.0, -np.inf]],
    )


def test_failed_embedding_leaves_decoder_and_next_batch_unchanged(fake_mlx):
    mx, qwen2 = fake_mlx
    original_mask = qwen2.create_attention_mask
    embedder = _embedder(mx)

    def fail():
        raise RuntimeError("layer failed")

    embedder._model.layers[0].on_call = fail
    with pytest.raises(RuntimeError, match="layer failed"):
        embedder.embed_docs(["1", "2 3 4"])

    assert qwen2.create_attention_mask is original_mask
    decoder = qwen2.Qwen2Model(None)
    decoder(mx.array([[1, 2]]))
    assert decoder.layers[0].masks == ["causal"]
    embedder._model.layers[0].on_call = None
    np.testing.assert_allclose(embedder.embed_query("5"), _embedder(mx).embed_query("5"))


def test_concurrent_embedding_batches_do_not_share_padding(fake_mlx):
    mx, qwen2 = fake_mlx
    original_mask = qwen2.create_attention_mask
    first, second = _embedder(mx), _embedder(mx)
    barrier = threading.Barrier(2)
    first._model.layers[0].on_call = lambda: barrier.wait(timeout=5)
    second._model.layers[0].on_call = lambda: barrier.wait(timeout=5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result = pool.submit(first.embed_docs, ["1", "2 3 4"])
        second_result = pool.submit(second.embed_docs, ["5 6", "7"])
        first_vectors, second_vectors = first_result.result(), second_result.result()

    np.testing.assert_allclose(first_vectors[0], _embedder(mx).embed_query("1"))
    np.testing.assert_allclose(second_vectors[1], _embedder(mx).embed_query("7"))
    assert qwen2.create_attention_mask is original_mask
