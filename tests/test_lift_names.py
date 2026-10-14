"""Qualified source names remain distinct from indexed overload identities."""

import json

import pytest

from openeverything import lift


def test_guards_accept_exact_qualified_calls_and_reject_other_namespaces():
    known = {"A::foo", "B::bar"}
    assert lift._unresolved("A::foo(); ::B::bar();", known, "caller") == []
    assert lift._unresolved(
        "B::foo(); C::bar(); foo(); invented();", known, "caller",
    ) == ["B::foo", "C::bar", "foo", "invented"]
    rec = {"callees": ["A::foo", "B::bar"]}
    assert lift._dropped(rec, "A::foo(); B::bar();", {}) == []
    assert lift._dropped(rec, "C::foo(); D::bar();", {}) == rec["callees"]


def test_guards_accept_overload_source_names_and_lifted_aliases():
    originals = ["A::helper__0x1000", "A::helper__0x1010_2"]
    rec = {"callees": originals}
    symbols = {
        originals[0]: {"name": "read_integer"},
        originals[1]: {"name": "read_float"},
    }
    assert lift._unresolved("A::helper(1);", set(originals), "caller") == []
    assert lift._dropped(rec, "A::helper(1); A::helper(1.5);", {}) == []
    assert lift._dropped(rec, "read_integer(); read_float();", symbols) == []
    assert lift._dropped(rec, "B::helper();", symbols) == originals
    assert lift._unresolved("helper();", set(originals), "caller") == ["helper"]
    assert lift._unresolved("void A::helper(int x) {}", {"void"}, originals[0]) == []


def test_rename_respects_namespace_boundaries_and_ambiguous_overloads():
    identities = {"A::helper__0x1000", "A::helper__0x1010", "B::helper"}
    renamed = lift._rewrite_names(
        "A::helper(1); A::helper__0x1000(1); B::helper(1); "
        "Outer::B::helper(1); helper(1);",
        {"A::helper__0x1000": "read_int", "B::helper": "read_other"},
        identities,
    )
    assert renamed == (
        "A::helper(1); read_int(1); read_other(1); "
        "Outer::B::helper(1); helper(1);"
    )
    assert lift._rewrite_names(
        "A::helper(1);", {"A::helper__0x1000": "read_int"},
        {"A::helper__0x1000"},
    ) == "read_int(1);"


def test_regional_signature_renames_source_name_without_touching_return_type():
    assert lift._rename_signature(
        "helper_result helper(int value)", "A::helper__0x1000", "read_int",
    ) == "helper_result read_int(int value)"
    assert lift._rename_signature(
        "int A::helper(int value)", "A::helper__0x1000", "read_int",
    ) == "int read_int(int value)"


class _Store:
    def __init__(self, rows):
        self.rows = rows

    def list_functions(self, *args, **kwargs):
        return [dict(row) for row in self.rows]

    def _table(self):
        return self

    def search(self):
        return self

    def where(self, *args):
        return self

    def to_list(self):
        return self.list_functions()


def _record(name="caller"):
    return {
        "name": name, "signature": f"void {name}(void)",
        "decompiled": f"void {name}(void) {{ A::helper(1); A::helper(1.5); }}",
        "callees": ["A::helper__0x1000", "A::helper__0x1010"],
        "strings": [], "address": "0x1020", "is_external": False,
        "is_thunk": False, "vector": [1.0, 0.0],
    }


@pytest.mark.parametrize("runner", [lift.lift_binary, lift.lift_binary_clustered])
def test_lift_retains_original_overload_identities_in_report(runner, tmp_path):
    rec = _record() | {
        "name": "Owner::caller__0x1020", "signature": "void caller(void)",
        "decompiled": "void Owner::caller(void) { A::helper(1); A::helper(1.5); }",
    }

    def chat(messages, **kwargs):
        if messages[0]["content"].startswith("You are analyzing a cluster"):
            yield json.dumps({"label": "helpers"})
        else:
            assert kwargs.get("tools") is None
            yield json.dumps({
                "name": rec["name"], "signature": rec["signature"],
                "code": rec["decompiled"],
            })

    _, symbols = runner(_Store([rec]), "sha", "binary", chat, tmp_path)

    assert symbols[rec["name"]]["unresolved"] == []
    report = json.loads((tmp_path / "lift_report.json").read_text())
    assert rec["name"] in report["functions"]
    declarations = (tmp_path / "decls.h").read_text()
    assert all(identity in declarations for identity in rec["callees"])


@pytest.mark.parametrize("invalid_types", [["bad type"], 123])
def test_cluster_metadata_wrong_optional_type_does_not_crash(tmp_path, invalid_types):
    rec = _record()

    def chat(messages, **kwargs):
        if messages[0]["content"].startswith("You are analyzing a cluster"):
            yield json.dumps({"label": "helpers", "types": invalid_types})
        else:
            yield json.dumps({
                "name": rec["name"], "signature": rec["signature"],
                "code": rec["decompiled"],
            })

    lift.lift_binary_clustered(_Store([rec]), "sha", "binary", chat, tmp_path)

    report = json.loads((tmp_path / "lift_report.json").read_text())
    assert report["modules"][0]["types"] == ""
    assert (tmp_path / "modules" / "00_module_0.h").exists()


def test_regional_metadata_rejects_invalid_optional_doc():
    assert lift._extract_json(
        '{"name":"read_file","doc":[]}',
        required_fields=("name",), optional_fields=("doc",),
    ) is None
