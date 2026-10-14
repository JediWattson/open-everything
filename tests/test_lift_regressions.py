"""Lift regressions with scripted model replies and no model downloads."""

import json

import pytest

from openeverything import lift


class _Store:
    def __init__(self, record):
        self.record = record

    def list_functions(self, *args, **kwargs):
        return [dict(self.record)]

    def _table(self):
        return self

    def search(self):
        return self

    def where(self, *args):
        return self

    def to_list(self):
        return [dict(self.record)]


def _record():
    return {
        "name": "original", "signature": "void original(void)",
        "decompiled": "void original(void) {}", "callees": [],
        "strings": [], "address": "0x1000", "is_external": False,
        "is_thunk": False, "vector": [1.0, 0.0],
    }


def _large_record():
    ops = {a: "nop" for a in range(0x1000, 0x1140, 4)}
    ops.update({
        0x1000: "cbz x0, 0x1080", 0x1004: "bl _read",
        0x1008: "bl _write", 0x100C: "bl _close",
        0x107C: "b 0x10f0", 0x10F0: "cbz x1, 0x113c",
        0x113C: "ret",
    })
    return _record() | {
        "decompiled": "\n".join(f"0x{a:x}: {op}" for a, op in ops.items()),
        "callees": ["_read", "_write", "_close"],
    }


def _response(code):
    return {
        "name": "original", "signature": "void original(void)",
        "code": code,
    }


def _is_module_prompt(msgs):
    return msgs[0]["content"].startswith("You are analyzing a cluster")


@pytest.mark.parametrize(
    "runner", [lift.lift_binary, lift.lift_binary_clustered],
    ids=["flat", "clustered"],
)
def test_perfect_agent_repair_skips_regional_lift(runner, tmp_path):
    rec = _large_record()
    good_code = "void original(void) { _read(); _write(); _close(); }"
    calls = {"flat": 0, "agent": 0}

    def chat(msgs, tools=None, **kwargs):
        if _is_module_prompt(msgs):
            yield json.dumps({"label": "io_helpers"})
        elif tools is not None:
            calls["agent"] += 1
            yield "<tool_call>" + json.dumps({
                "name": "emit", "arguments": _response(good_code),
            }) + "</tool_call>"
        elif msgs[0]["content"].startswith("You rewrite decompiled"):
            calls["flat"] += 1
            yield json.dumps(_response(
                "void original(void) { invented1(); invented2(); }"
            ))
        else:
            pytest.fail("a perfect agent repair must not reach tier 4")

    _, symbols = runner(_Store(rec), "sha", "binary", chat, tmp_path)

    assert calls == {"flat": 2, "agent": 1}
    assert symbols["original"]["code"] == good_code
    assert not symbols["original"]["failed"]
    assert symbols["original"]["unresolved"] == []
    assert lift._dropped(rec, symbols["original"]["code"], symbols) == []


@pytest.mark.parametrize(
    "runner", [lift.lift_binary, lift.lift_binary_clustered],
    ids=["flat", "clustered"],
)
def test_regional_lift_must_improve_on_latest_agent_repair(runner, tmp_path):
    rec = _large_record()
    repaired_code = "void original(void) { _read(); }"
    region_calls = []

    def chat(msgs, tools=None, **kwargs):
        if _is_module_prompt(msgs):
            yield json.dumps({"label": "io_helpers"})
        elif tools is not None:
            yield "<tool_call>" + json.dumps({
                "name": "emit", "arguments": _response(repaired_code),
            }) + "</tool_call>"
        elif msgs[0]["content"].startswith("Lift one asm region"):
            region_calls.append(msgs)
            yield ";"
        elif msgs[0]["content"].startswith("A function was lifted"):
            yield json.dumps({"name": "regional", "doc": "Regional output"})
        else:
            yield json.dumps(_response(
                "void original(void) { invented1(); invented2(); }"
            ))

    _, symbols = runner(_Store(rec), "sha", "binary", chat, tmp_path)

    assert region_calls
    assert symbols["original"]["code"] == repaired_code
    assert lift._dropped(rec, repaired_code, symbols) == ["_write", "_close"]


def test_cluster_metadata_reaches_lift_prompt_and_module_header(tmp_path):
    module = {
        "label": "io_helpers", "summary": "File I/O",
        "types": "struct Reader { int fd; };",
    }
    function_prompts = []

    def chat(msgs, **kwargs):
        if _is_module_prompt(msgs):
            yield json.dumps(module)
        else:
            function_prompts.append(msgs[1]["content"])
            yield json.dumps(_response("void original(void) {}"))

    lift.lift_binary_clustered(
        _Store(_record()), "sha", "binary", chat, tmp_path,
    )

    assert len(function_prompts) == 1
    assert "module: io_helpers — File I/O" in function_prompts[0]
    assert module["types"] in function_prompts[0]
    header = (tmp_path / "modules" / "00_io_helpers.h").read_text()
    assert module["types"] in header
    report = json.loads((tmp_path / "lift_report.json").read_text())
    assert all(report["modules"][0][key] == value
               for key, value in module.items())


def test_regional_metadata_reaches_prompts_and_final_function():
    region_prompts = []
    embedded = []

    def embed(texts):
        embedded.extend(texts)
        return [[1.0, 0.0] for _ in texts]

    def chat(msgs, **kwargs):
        prompt = msgs[0]["content"]
        if prompt.startswith("These asm regions share a role"):
            yield json.dumps({"label": "read loop"})
        elif prompt.startswith("Lift one asm region"):
            region_prompts.append(msgs[1]["content"])
            yield ";"
        else:
            assert prompt.startswith("A function was lifted")
            assert "read loop" in prompt
            yield json.dumps({"name": "read_file", "doc": "Reads a file"})

    result = lift._lift_regions(_large_record(), {}, set(), chat, embed)

    assert len(embedded) == len(region_prompts) >= 2
    assert all("Region role: read loop." in p for p in region_prompts)
    assert result["name"] == "read_file"
    assert result["doc"] == "Reads a file"
    assert result["signature"] == "void read_file(void)"
    assert result["code"].startswith("void read_file(void) {")


@pytest.mark.parametrize("payload", [
    {"label": "io_helpers"}, {"name": "read_file", "doc": "Reads a file"},
    {"code": None}, {"code": ["invalid"]},
])
def test_wrong_response_shape_still_escalates_to_agent(payload, tmp_path):
    agent_calls = []

    def chat(msgs, tools=None, **kwargs):
        if tools is None:
            yield json.dumps(payload)
        else:
            agent_calls.append(msgs)
            yield "<tool_call>" + json.dumps({
                "name": "emit",
                "arguments": _response("void original(void) {}"),
            }) + "</tool_call>"

    _, symbols = lift.lift_binary(
        _Store(_record()), "sha", "binary", chat, tmp_path,
    )

    assert len(agent_calls) == 1
    assert not symbols["original"]["failed"]
    assert symbols["original"]["code"] == "void original(void) {}"
