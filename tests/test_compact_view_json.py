"""idx_search's compact view cuts an object or a list over 500 characters from
its JSON, never from a Python repr.

Before, a non-string field over the cap became `str(value)[:500] + "..."`, so
an evtx `event_data` read `{'SubjectUserName': …`, with single quotes, True and
None. Now it is the JSON text's first 500 characters plus "...", and the field
is named in `_truncated` as before. Strings, short values and the full view are
unchanged. The client is a mock; idx_search runs as the MCP tool does.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.server as srv

INDEX = "case-0123abcdef01-evtx-0"
CAP = srv._MAX_FIELD_CHARS


@pytest.fixture
def search(monkeypatch):
    c = MagicMock()
    c.cat.indices.return_value = [{"index": INDEX, "status": "open"}]
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: "aid-1")
    monkeypatch.setattr(srv, "_add_field_hint", lambda *a, **k: None)
    monkeypatch.setattr(srv, "_annotate_hosts", lambda *a, **k: None)

    def run(source, compact=True):
        hit = {"_id": "d1", "_index": INDEX, "_source": source}
        c.search.return_value = {"hits": {"total": {"value": 1}, "hits": [hit]}}
        resp = srv.idx_search(query="*", index=INDEX, compact=compact)
        (doc,) = resp["results"]
        return doc

    return run


def _cut(value):
    return json.dumps(value, ensure_ascii=False)[:CAP] + "..."


EVENT_DATA = {
    "SubjectUserName": "tdungan",
    "CommandLine": "powershell.exe -enc " + "A" * 600,
    "ProcessId": "0x1a2c",
    "Elevated": True,
    "ParentImage": None,
}
SEEDS = {
    "non-ascii": "日本語 é ü",
    "quotes": 'it\'s "quoted"',
    "backslash": "C:\\Windows\\System32\\cmd.exe",
    "control": "tab\there nul\x00 esc\x1b[31m cr\r lf\n c1\x85\x9b",
    "rlo": "invoice\u202egpj.exe",
    "html": "<script>alert(1)</script>&amp;",
    "nested": {"a": [1, 2.5, False, None], "b": {"c": "d"}},
    "pad": "x" * 600,
}


# --- the measured RED shape (p121_compact_repr) ---------------------------------


def test_an_object_over_the_cap_is_cut_from_its_json(search):
    doc = search({"event_data": EVENT_DATA})
    got = doc["event_data"]
    assert got == _cut(EVENT_DATA)
    assert got.startswith('{"SubjectUserName": "tdungan"')
    assert "{'" not in got and "True" not in got
    assert doc["_truncated"] == ["event_data"]


def test_a_list_over_the_cap_is_cut_from_its_json(search):
    val = [{"Name": f"proc{i}", "Signed": i % 2 == 0} for i in range(40)]
    doc = search({"processes": val})
    assert doc["processes"] == _cut(val)
    assert doc["processes"].startswith('[{"Name": "proc0", "Signed": true}')
    assert doc["_truncated"] == ["processes"]


@pytest.mark.parametrize("seed", SEEDS)
def test_seed_shapes_inside_an_object_cut_as_json(search, seed):
    val = {"seed": SEEDS[seed], "pad": "y" * 600}
    doc = search({"event_data": val})
    assert doc["event_data"] == _cut(val)
    assert doc["event_data"].startswith('{"seed": ')
    assert doc["_truncated"] == ["event_data"]


def test_non_ascii_stays_as_written_not_escaped(search):
    val = {"User": "日本語", "pad": "z" * 600}
    assert search({"x": val})["x"].startswith('{"User": "日本語"')


# --- the boundary: the JSON length decides ------------------------------------


def _sized(n):
    """A dict whose JSON text is exactly n characters."""
    base = len(json.dumps({"k": ""}))
    return {"k": "v" * (n - base)}


@pytest.mark.parametrize("n,cut", [(CAP - 1, False), (CAP, False), (CAP + 1, True)])
def test_the_cap_is_measured_on_the_json(search, n, cut):
    val = _sized(n)
    assert len(json.dumps(val)) == n
    doc = search({"event_data": val})
    if cut:
        assert doc["event_data"] == _cut(val) and len(doc["event_data"]) == CAP + 3
        assert doc["_truncated"] == ["event_data"]
    else:
        assert doc["event_data"] == val and "_truncated" not in doc


# --- twins: what was right stays as it was ------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {"SubjectUserName": "tdungan", "ProcessId": "0x1a2c"},
        ["a", "b", {"c": None}],
        "short string",
        4624,
        2.5,
        True,
        None,
        [],
        {},
        "",
    ],
    ids=["small dict", "small list", "str", "int", "float", "bool", "none",
         "empty list", "empty dict", "empty str"],
)  # fmt: skip
def test_twin_a_value_under_the_cap_is_returned_as_it_is(search, value):
    doc = search({"f": value})
    assert doc["f"] == value and type(doc["f"]) is type(value)
    assert "_truncated" not in doc


def test_twin_a_string_over_the_cap_is_cut_as_before(search):
    s = "'" + "S" * 700
    doc = search({"CommandLine": s})
    assert doc["CommandLine"] == s[:CAP] + "..."
    assert doc["_truncated"] == ["CommandLine"]


def test_twin_the_full_view_returns_an_object_whole(search):
    doc = search({"event_data": EVENT_DATA}, compact=False)
    assert doc["event_data"] == EVENT_DATA
    assert "_truncated" not in doc


def test_twin_excluded_fields_stay_out_and_others_keep_their_order(search):
    excluded = sorted(srv._SEARCH_EXCLUDE_FIELDS)[0]
    doc = search({excluded: "x", "a": EVENT_DATA, "b": "s" * 700, "c": 1})
    assert excluded not in doc
    assert list(doc) == ["_id", "_index", "a", "b", "c", "_truncated"]
    assert doc["_truncated"] == ["a", "b"]
