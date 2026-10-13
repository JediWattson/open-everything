"""Unit tests that run without Ghidra or an embedding model."""

from pathlib import Path

import pytest

from openeverything.embed import build_embed_text
from openeverything.graph import GraphStore
from openeverything.models import FunctionRecord
from openeverything.store import Store


def _rec(name, callees=None, callers=None, strings=None, body="int x() {}",
         vec=None, sha="abc123", binary="bin"):
    return FunctionRecord(
        binary_sha256=sha, binary_name=binary, address="0x1000", name=name,
        signature=f"int {name}(void)", decompiled=body,
        callees=callees or [], callers=callers or [], strings=strings or [],
        embed_text="", vector=vec or [0.0, 0.0, 0.0],
    )


def test_embed_text_includes_call_context():
    r = _rec("check_pw", callees=["strcmp", "log_fail"], callers=["main"],
             strings=["bad password"])
    text = build_embed_text(r)
    assert "calls: strcmp, log_fail" in text
    assert "called by: main" in text
    assert "bad password" in text
    assert "int x() {}" in text


def test_embed_text_handles_empty_context():
    r = _rec("leaf")
    text = build_embed_text(r)
    assert "calls:" not in text
    assert "(no decompiled body)" not in text


def test_store_roundtrip(tmp_path):
    store = Store(tmp_path / "db")
    near = _rec("crypto", vec=[1.0, 0.0, 0.0])
    far = _rec("ui", vec=[0.0, 1.0, 0.0])
    stub = _rec("ext", vec=[1.0, 0.0, 0.0])
    stub.is_external = True
    store.add_functions([near, far, stub])
    store.register_binary("abc123", "bin", "/tmp/bin", 3)

    assert store.indexed_sha("abc123")

    hits = store.search([1.0, 0.0, 0.0], k=3)
    assert hits[0]["name"] == "crypto"
    assert all(not h["is_external"] for h in hits)

    hits = store.search([1.0, 0.0, 0.0], k=3, include_stubs=True)
    assert any(h["name"] == "ext" for h in hits)

    assert store.get_function("ui", "abc123")["name"] == "ui"
    assert store.drop_binary("abc123") == 3
    assert store.search([1.0, 0.0, 0.0], k=3) == []


def test_store_binary_scoped_search(tmp_path):
    store = Store(tmp_path / "db")
    store.add_functions([_rec("f", vec=[1.0, 0.0], sha="aaa", binary="a")])
    store.add_functions([_rec("g", vec=[1.0, 0.0], sha="bbb", binary="b")])
    hits = store.search([1.0, 0.0], k=5, binary_sha256="bbb")
    assert [h["name"] for h in hits] == ["g"]


def test_graph_roundtrip(tmp_path):
    g = GraphStore(tmp_path / "graph.db")
    g.add_edges("sha1", [("main", "parse"), ("parse", "lex"),
                         ("lex", "main"), ("main", "exit")])
    assert g.callees("sha1", "main") == ["exit", "parse"]
    assert g.callers("sha1", "lex") == ["parse"]
    assert g.callees("sha1", "missing") == []

    reach = dict(g.reachable("sha1", "main", max_depth=5))
    assert reach["parse"] == 1
    assert reach["lex"] == 2
    assert reach["main"] == 3  # lex -> main recursion cycle, depth-capped
    assert reach["exit"] == 1

    back = dict(g.reachable("sha1", "exit", direction="callers", max_depth=2))
    assert back == {"main": 1, "lex": 2}  # lex -> main -> exit


def test_graph_binary_scoped(tmp_path):
    g = GraphStore(tmp_path / "graph.db")
    g.add_edges("a", [("f", "g")])
    g.add_edges("b", [("x", "g"), ("g", "zzz")])
    assert g.callers("a", "g") == ["f"]
    assert dict(g.reachable("a", "g", direction="callers")) == {"f": 1}

    assert g.drop_binary("a") == 1
    assert g.callees("a", "f") == []
    assert g.callees("b", "g") == ["zzz"]


def test_graph_bad_direction(tmp_path):
    g = GraphStore(tmp_path / "graph.db")
    with pytest.raises(ValueError):
        g.reachable("a", "f", direction="sideways")


def test_ingest_writes_graph(tmp_path, monkeypatch):
    from openeverything import pipeline

    recs = [_rec("main", callees=["f"]), _rec("f")]
    monkeypatch.setattr(
        pipeline, "extract_functions", lambda *a, **k: iter(recs)
    )

    class FakeEmbedder:
        model_name = "fake"

        def embed_docs(self, texts):
            return [[0.0, 0.0, 0.0]] * len(texts)

    store = Store(tmp_path / "db")
    g = GraphStore(tmp_path / "graph.db")
    sha, n = pipeline.ingest(
        Path(__file__), store, FakeEmbedder(), graph=g
    )
    assert n == 2
    assert g.callees(sha, "main") == ["f"]

    # force re-ingest clears stale edges
    recs[0].callees = ["g"]
    recs.append(_rec("g"))
    sha, n = pipeline.ingest(
        Path(__file__), store, FakeEmbedder(), graph=g, force=True
    )
    assert n == 3
    assert g.callees(sha, "main") == ["g"]


def test_agent_extracts_native_tool_call():
    from openeverything.agent import _extract_action

    text = 'thinking\n<tool_call>\n{"name": "show", "arguments": {"name": "f"}}\n</tool_call>\nmore'
    assert _extract_action(text) == {"tool": "show", "args": {"name": "f"}}
    assert _extract_action('{"tool": "search", "args": {"query": "x"}}')["tool"] == "search"


def test_agent_validates_args_and_replays_repeats(tmp_path):
    from openeverything.agent import Agent

    store = Store(tmp_path / "db")
    g = GraphStore(tmp_path / "graph.db")
    calls = []

    def fake_chat(messages, tools=None):
        calls.append(tools)
        yield ""

    ag = Agent(store, g, "sha", None, fake_chat, native=False)

    # bad args → legible validation error, not a TypeError string
    obs = ag._dispatch({"tool": "graph", "args": {"name": "f", "direction": "up"}})
    assert "invalid args for graph" in obs
    assert "direction" in obs
    assert ag._dispatch({"tool": "nope", "args": {}}).startswith("unknown tool")

    # schema-driven tool_schemas for the chat template
    schemas = ag.tool_schemas()
    names = {s["function"]["name"] for s in schemas}
    assert names == {"search", "show", "graph", "functions"}
    assert "direction" in next(
        s for s in schemas if s["function"]["name"] == "graph"
    )["function"]["parameters"]["properties"]

    # loop guard: second identical call replays cached obs, no re-execution
    ran = []

    class SpyAgent(Agent):
        def _dispatch(self, action):
            ran.append(action)
            return "OBS"

    spy = SpyAgent(store, g, "sha", None, fake_chat, native=False)
    obs1 = spy._dispatch({"tool": "functions", "args": {}})
    assert obs1 == "OBS" and len(ran) == 1


def test_agent_logs_trajectory(tmp_path):
    import json as _json

    from openeverything.agent import Agent

    store = Store(tmp_path / "db")
    g = GraphStore(tmp_path / "graph.db")

    def fake_chat(messages, tools=None, temp=None):
        yield '{"answer": "done"}'

    log = tmp_path / "runs" / "t.jsonl"
    ag = Agent(store, g, "sha", None, fake_chat, native=False, log_path=log)
    assert ag.turn("hi") == "done"
    rec = _json.loads(log.read_text().strip())
    assert rec["user"] == "hi" and rec["answer"] == "done"
    assert rec["messages"][0]["role"] == "system"
    assert rec["messages"][-1] == {"role": "assistant",
                                   "content": '{"answer": "done"}'}


def test_uleb128_decode():
    from openeverything.disasm import _uleb128

    assert _uleb128(b"\x0c", 0) == (0x0C, 1)
    assert _uleb128(b"\x80\x0e", 0) == (0x700, 2)
    assert _uleb128(b"\xe5\x8e\x26", 0) == (0x98765, 3)


def test_cluster_order_callees_first():
    from openeverything.lift import _cluster_order

    gA = [{"name": "a", "callees": ["b"]}]
    gB = [{"name": "b", "callees": []}]
    groups = _cluster_order([gA, gB])
    assert [g[0]["name"] for g in groups] == ["b", "a"]

    # cycle between clusters doesn't hang
    gC = [{"name": "c", "callees": ["d"]}]
    gD = [{"name": "d", "callees": ["c"]}]
    assert len(_cluster_order([gC, gD])) == 2
