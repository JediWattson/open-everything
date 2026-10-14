"""Storage schema and ingest recovery regressions, without models or Ghidra."""

from pathlib import Path

import pyarrow as pa
import pytest

from openeverything import config, pipeline
from openeverything.graph import GraphStore
from openeverything.models import FunctionRecord
from openeverything.store import Store


def _record(sha, name="leaf", callees=(), vector=None, **kwargs):
    return FunctionRecord(
        binary_sha256=sha, binary_name="bin", address=f"0x{len(name):x}",
        name=name, signature=f"void {name}()", decompiled=f"void {name}() {{}}",
        callees=list(callees), model="test-model", vector=vector, **kwargs,
    )


class _Embedder:
    model_name = "test-model"

    def embed_docs(self, texts):
        return [[1.0, 0.0] for _ in texts]


@pytest.mark.parametrize("deferred", [True, False])
def test_empty_context_lists_allow_later_context_and_backfill(tmp_path, monkeypatch, deferred):
    monkeypatch.setitem(config.MODEL_DIMS, "test-model", 2)
    store = Store(tmp_path / "db")
    vector = None if deferred else [1.0, 0.0]
    store.add_functions([_record("one", vector=vector)])
    store.add_functions([_record(
        "two", "caller", callees=["leaf"], callers=["main"],
        strings=["hello"], vector=vector,
    )])
    row = store.get_function("caller", "two")
    assert row["callees"] == ["leaf"]
    assert row["callers"] == ["main"]
    assert row["strings"] == ["hello"]
    if deferred:
        assert len(store.missing_vectors()) == 2
        store.set_vector("caller", "two", [0.0, 1.0])
        assert store.get_function("caller", "two")["vector"] == [0.0, 1.0]


def test_legacy_empty_list_schema_is_upgraded_without_losing_rows(tmp_path):
    store = Store(tmp_path / "db")
    old = _record("one", vector=[1.0, 0.0]).to_row()
    store._db.create_table(config.TABLE_NAME, [old])
    assert pa.types.is_null(store._table().schema.field("callees").type.value_type)
    store.add_functions([_record(
        "two", "caller", callees=["leaf"], callers=["main"],
        strings=["hello"], vector=[0.0, 1.0],
    )])
    assert store.get_function("leaf", "one")["vector"] == [1.0, 0.0]
    assert store.get_function("caller", "two")["callees"] == ["leaf"]
    assert store.get_function("caller", "two")["strings"] == ["hello"]


@pytest.fixture
def indexed(tmp_path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"same binary, replacement extraction")
    sha = pipeline.sha256_file(binary)
    store = Store(tmp_path / "db")
    graph = GraphStore(tmp_path / "graph.db")
    old = _record(sha, "old", ["previous"], [1.0, 0.0])
    other = _record("unrelated", "other", ["untouched"], [0.0, 1.0])
    store.add_functions([old, other])
    store.register_binary(sha, "bin", str(binary), 1)
    store.register_binary("unrelated", "other", "/tmp/other", 1)
    graph.add_edges(sha, [("old", "previous")])
    graph.add_edges("unrelated", [("other", "untouched")])
    before = store.list_functions(limit=100)
    registry = store.list_binaries()
    yield binary, sha, store, graph, before, registry
    graph.close()


@pytest.mark.parametrize("stage", [
    "extract", "empty", "embed", "vector_count", "dimension", "functions", "graph", "registry",
])
def test_failed_forced_ingest_preserves_both_indexes(indexed, monkeypatch, stage):
    binary, sha, store, graph, before, registry = indexed

    def extract(*args, **kwargs):
        if stage == "empty":
            return
        yield _record(sha, "replacement", ["new_callee"])
        if stage == "extract":
            raise RuntimeError("failed extraction")

    monkeypatch.setattr(pipeline, "extract_functions", extract)
    embedder = _Embedder()
    if stage == "embed":
        def fail_embedding(texts):
            raise RuntimeError("failed embedding")
        monkeypatch.setattr(embedder, "embed_docs", fail_embedding)
    elif stage == "vector_count":
        monkeypatch.setattr(embedder, "embed_docs", lambda texts: [])
    elif stage == "dimension":
        monkeypatch.setattr(embedder, "embed_docs", lambda texts: [[1.0, 0.0, 0.0]])
    elif stage in ("functions", "graph", "registry"):
        target, method = {
            "functions": (store, "add_functions"),
            "graph": (graph, "add_edges"),
            "registry": (store, "register_binary"),
        }[stage]
        original = getattr(target, method)

        def fail_after_write(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError(f"failed {stage} write")

        monkeypatch.setattr(target, method, fail_after_write)

    with pytest.raises((RuntimeError, ValueError)):
        pipeline.ingest(binary, store, embedder, force=True, graph=graph)

    by_name = lambda row: row["name"]
    assert sorted(store.list_functions(limit=100), key=by_name) == sorted(before, key=by_name)
    assert sorted(store.list_binaries(), key=lambda row: row["binary_sha256"]) == sorted(
        registry, key=lambda row: row["binary_sha256"],
    )
    assert graph.callees(sha, "old") == ["previous"]
    assert graph.callees(sha, "replacement") == []
    assert graph.callees("unrelated", "other") == ["untouched"]
    # Check that nested graph writes were not committed behind the outer scope.
    observer = GraphStore(Path(graph._conn.execute("PRAGMA database_list").fetchone()[2]))
    try:
        assert observer.callees(sha, "old") == ["previous"]
        assert observer.callees(sha, "replacement") == []
    finally:
        observer.close()


def test_successful_forced_ingest_replaces_only_target_binary(indexed, monkeypatch):
    binary, sha, store, graph, _, _ = indexed
    monkeypatch.setattr(pipeline, "extract_functions", lambda *args, **kwargs: iter([
        _record(sha, "replacement", ["new_callee"]),
    ]))
    assert pipeline.ingest(binary, store, _Embedder(), force=True, graph=graph) == (sha, 1)
    assert [r["name"] for r in store.list_functions(sha)] == ["replacement"]
    assert store.get_function("other", "unrelated")["callees"] == ["untouched"]
    assert graph.callees(sha, "old") == []
    assert graph.callees(sha, "replacement") == ["new_callee"]
    assert graph.callees("unrelated", "other") == ["untouched"]
    assert len(store.list_binaries()) == 2


def test_failed_initial_ingest_leaves_no_orphans_and_can_be_retried(tmp_path, monkeypatch):
    binary = tmp_path / "bin"
    binary.write_bytes(b"new binary")
    sha = pipeline.sha256_file(binary)
    store = Store(tmp_path / "db")
    graph = GraphStore(tmp_path / "graph.db")
    monkeypatch.setattr(pipeline, "extract_functions", lambda *args, **kwargs: iter([
        _record(sha, "main", ["callee"]),
    ]))
    original = store.register_binary

    def fail_registry(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("failed registry write")

    monkeypatch.setattr(store, "register_binary", fail_registry)
    try:
        with pytest.raises(RuntimeError, match="failed registry"):
            pipeline.ingest(binary, store, _Embedder(), graph=graph)
        assert store._db.list_tables().tables == []
        assert graph.callees(sha, "main") == []
        monkeypatch.setattr(store, "register_binary", original)
        assert pipeline.ingest(binary, store, _Embedder(), graph=graph) == (sha, 1)
        assert len(store.list_functions(sha)) == 1
        assert graph.callees(sha, "main") == ["callee"]
    finally:
        graph.close()
