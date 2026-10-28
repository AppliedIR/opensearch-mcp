"""idx_search's compact view keeps every object and list as it is stored, and
cuts only the long text inside them.

Before, a non-string field over 500 characters was cut from its JSON text, so
an evtx `winlog.event_data` came back as a string and lost every key past its
500th character. Now the walk keeps objects and lists in their shape: a string
over 500 characters becomes its first 500 plus "...", a list over 100 elements
keeps its first 100, and `_truncated` names each cut by its path (`a.b`,
`a[0]`, `a[100:]`). The full view cuts nothing. The client is a mock;
idx_search runs as the MCP tool does.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.server as srv

INDEX = "case-0123abcdef01-evtx-0"
CAP = srv._MAX_FIELD_CHARS
ITEMS = srv._MAX_LIST_ITEMS


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


def _cut(s):
    return s[:CAP] + "..."


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


# --- the measured RED shape: an object stays an object ---------------------


def test_an_object_over_the_cap_keeps_every_key_and_cuts_only_its_long_text(search):
    doc = search({"winlog.event_data": EVENT_DATA})
    got = doc["winlog.event_data"]
    assert isinstance(got, dict) and list(got) == list(EVENT_DATA)
    assert got == {**EVENT_DATA, "CommandLine": _cut(EVENT_DATA["CommandLine"])}
    assert doc["_truncated"] == ["winlog.event_data.CommandLine"]


def test_a_list_of_short_objects_over_the_cap_comes_back_whole(search):
    val = [{"Name": f"proc{i}", "Signed": i % 2 == 0} for i in range(40)]
    doc = search({"processes": val})
    assert doc["processes"] == val
    assert "_truncated" not in doc


@pytest.mark.parametrize("seed", SEEDS)
def test_seed_shapes_inside_an_object_come_back_as_stored(search, seed):
    val = {"seed": SEEDS[seed], "pad": "y" * 600}
    doc = search({"event_data": val})
    want = SEEDS[seed] if seed != "pad" else _cut(SEEDS[seed])
    assert doc["event_data"] == {"seed": want, "pad": _cut("y" * 600)}
    assert type(doc["event_data"]["seed"]) is type(SEEDS[seed])
    assert doc["_truncated"] == ["event_data.seed"] * (seed == "pad") + ["event_data.pad"]


def test_non_ascii_stays_as_written(search):
    val = {"User": "日本語", "pad": "z" * 600}
    assert search({"x": val})["x"]["User"] == "日本語"


# --- the boundary: each string's own length decides ------------------------


@pytest.mark.parametrize("n,cut", [(CAP - 1, False), (CAP, False), (CAP + 1, True)])
def test_the_cap_is_measured_on_each_string(search, n, cut):
    s = "v" * n
    doc = search({"o": {"s": s, "t": "short"}})
    if cut:
        assert doc["o"] == {"s": _cut(s), "t": "short"} and len(doc["o"]["s"]) == CAP + 3
        assert doc["_truncated"] == ["o.s"]
    else:
        assert doc["o"] == {"s": s, "t": "short"} and "_truncated" not in doc


# --- lists: element paths at any depth, and the element cap ----------------


def test_a_string_in_a_nested_list_is_cut_by_its_element_path(search):
    doc = search({"winlog": {"event_data": {"Data": {"#text": ["x" * 600, "short"]}}}})
    assert doc["winlog"]["event_data"]["Data"]["#text"] == [_cut("x" * 600), "short"]
    assert doc["_truncated"] == ["winlog.event_data.Data.#text[0]"]


def test_a_list_of_objects_names_the_key_under_its_element(search):
    doc = search({"a": [{"b": "x" * 600}, {"b": "short"}]})
    assert doc["a"] == [{"b": _cut("x" * 600)}, {"b": "short"}]
    assert doc["_truncated"] == ["a[0].b"]


@pytest.mark.parametrize("n,cut", [(ITEMS, False), (ITEMS + 1, True)])
def test_a_list_keeps_its_first_hundred_elements(search, n, cut):
    items = [f"i{k}" for k in range(n)]
    doc = search({"items": items})
    assert doc["items"] == items[:ITEMS]
    assert doc.get("_truncated") == (["items[100:]"] if cut else None)


def test_cuts_are_listed_in_walk_order_one_entry_each(search):
    doc = search({"a": {"b": "x" * 600}, "a.b": "y" * 600, "c": [["z" * 600] * 2] * 101})
    assert doc["_truncated"] == ["a.b", "a.b"] + ["c[%d][%d]" % (i, j) for i in range(ITEMS)
                                                   for j in range(2)] + ["c[100:]"]  # fmt: skip


# --- twins: what was right stays as it was ---------------------------------


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
    assert doc["CommandLine"] == _cut(s)
    assert doc["_truncated"] == ["CommandLine"]


def test_twin_the_full_view_cuts_nothing(search):
    src = {"event_data": EVENT_DATA, "items": list(range(ITEMS + 1)), "s": "q" * 5000}
    doc = search(src, compact=False)
    assert {k: doc[k] for k in src} == src
    assert "_truncated" not in doc


def test_twin_excluded_fields_stay_out_and_others_keep_their_order(search):
    excluded = sorted(srv._SEARCH_EXCLUDE_FIELDS)[0]
    doc = search({excluded: "x", "a": EVENT_DATA, "b": "s" * 700, "c": 1})
    assert excluded not in doc
    assert list(doc) == ["_id", "_index", "a", "b", "c", "_truncated"]
    assert doc["_truncated"] == ["a.CommandLine", "b"]


# Deep values, through the MCP tool call: the reply's serializer refuses nesting
# past about 255 levels, so the walk stops at _MAX_NESTING and a deeper object or
# list comes back as its JSON text, cut as a long string is. `_truncated` lists
# it with the depth as its reason whatever its length, so a JSON string never
# stands silently where an object or list was.

DEPTH = srv._MAX_NESTING


@pytest.fixture
def tool(search, monkeypatch):
    c = srv._get_os()

    def run(source, compact=True):
        hit = {"_id": "d1", "_index": INDEX, "_source": source}
        c.search.return_value = {"hits": {"total": {"value": 1}, "hits": [hit]}}
        args = {"query": "*", "index": INDEX, "compact": compact}
        out = asyncio.run(srv.server.call_tool("idx_search", args))
        content = out[0] if isinstance(out, tuple) else out
        return json.loads(content[0].text)

    return run


def _lists(n):
    v = "x"
    for _ in range(n):
        v = [v]
    return v


def _dicts(n):
    v = "x"
    for _ in range(n):
        v = {"a": v}
    return v


def _mixed(n):
    v = "x"
    for i in range(n):
        v = [v] if i % 2 else {"a": v}
    return v


def _down(v, n, path):
    for _ in range(n):
        v, path = (v[0], path + "[0]") if isinstance(v, list) else (v["a"], path + ".a")
    return v, path


def _head(v):
    """The first CAP characters of the JSON text of a list or object nested
    more than CAP deep: its opening brackets and keys."""
    text = ""
    while len(text) < CAP:
        text += "[" if isinstance(v, list) else '{"a": '
        v, _ = _down(v, 1, "")
    return text[:CAP]


def _at(v, n, key):
    for _ in range(n):
        v = v[key]
    return v


def _why(path, long):
    reason = f" (as JSON text: nested {DEPTH} levels deep"
    return path + reason + (f"; cut at {CAP} characters)" if long else ")")


@pytest.mark.parametrize("n", [260, 600])
def test_a_list_nested_past_the_serializer_limit_comes_back_as_listed_text(tool, n):
    resp = tool({"deep": _lists(n), "ok": 1})
    (doc,) = resp["results"]
    text = json.dumps(_lists(n - DEPTH), ensure_ascii=False)
    long = len(text) > CAP  # 260 deep is 395 characters of text, 600 deep is 1075
    assert _at(doc["deep"], DEPTH, 0) == (_cut(text) if long else text)
    assert doc["ok"] == 1
    assert doc["_truncated"] == [_why("deep" + "[0]" * DEPTH, long)]


def test_an_object_nested_past_the_serializer_limit_comes_back_as_listed_text(tool):
    resp = tool({"deep": _dicts(260)})
    (doc,) = resp["results"]
    text = json.dumps(_dicts(260 - DEPTH), ensure_ascii=False)
    assert _at(doc["deep"], DEPTH, "a") == _cut(text)
    assert doc["_truncated"] == [_why("deep" + ".a" * DEPTH, True)]


@pytest.mark.parametrize(
    "make, key, step", [(_lists, 0, "[0]"), (_dicts, "a", ".a")], ids=["lists", "objects"]
)
def test_twin_nesting_up_to_the_bound_keeps_its_shape_and_one_more_level_is_listed_text(
    tool, make, key, step
):
    (doc,) = tool({"deep": make(DEPTH)})["results"]
    assert doc["deep"] == make(DEPTH)
    assert "_truncated" not in doc
    (doc,) = tool({"deep": make(DEPTH + 1)})["results"]
    assert _at(doc["deep"], DEPTH, key) == json.dumps(make(1))
    assert doc["_truncated"] == [_why("deep" + step * DEPTH, False)]


def test_the_compact_hints_name_idx_get_events_event_id_parameter(tool):
    hint = "idx_get_event(event_id, index)"
    assert list(inspect.signature(srv.idx_get_event).parameters)[:2] == ["event_id", "index"]
    assert hint in tool({"a": 1})["note"]
    (info,) = [t for t in asyncio.run(srv.server.list_tools()) if t.name == "idx_search"]
    assert hint in info.description


# Past the bound the JSON text is built without recursion, so a value nested
# deeper than Python's stack (near 1000 frames on 3.10) still comes back as text.


@pytest.mark.parametrize("n", [925, 975, 999, 1000, 3000])
@pytest.mark.parametrize("make", [_lists, _dicts, _mixed], ids=["lists", "objects", "mixed"])
def test_a_value_nested_past_the_stack_limit_comes_back_as_listed_text(tool, make, n):
    src = make(n)
    (doc,) = tool({"deep": src})["results"]
    kept, path = _down(doc["deep"], DEPTH, "deep")
    rest, _ = _down(src, DEPTH, "deep")
    assert kept == _head(rest) + "..."
    assert doc["_truncated"] == [_why(path, True)]


@pytest.mark.parametrize("n", [DEPTH + 1, 100])
@pytest.mark.parametrize("make", [_lists, _dicts], ids=["lists", "objects"])
def test_twin_the_full_view_keeps_nesting_past_the_bound_in_its_shape(tool, make, n):
    (doc,) = tool({"deep": make(n)}, compact=False)["results"]
    assert doc["deep"] == make(n)
    assert "_truncated" not in doc


ZOO = {
    "s": 'a "quoted" \\ line\n',
    "n": -3,
    "f": 1.5,
    "big": 10**30,
    "inf": float("inf"),
    "t": True,
    "no": False,
    "z": None,
    "e": [],
    "o": {},
    "l": [1, [2, {"k": "v"}], "x"],
}


@pytest.mark.parametrize("member", [ZOO, list(range(300))], ids=["every-type", "wide"])
def test_twin_text_past_the_bound_is_the_values_json_text(tool, member):
    deep = ["x", member]
    for _ in range(DEPTH):
        deep = [deep]
    (doc,) = tool({"deep": deep})["results"]
    text = json.dumps(["x", member], ensure_ascii=False)
    long = len(text) > CAP
    assert _at(doc["deep"], DEPTH, 0) == (_cut(text) if long else text)
    assert doc["_truncated"] == [_why("deep" + "[0]" * DEPTH, long)]


def test_non_ascii_text_past_the_bound_stays_as_written(tool):
    cafe = "café"
    for _ in range(DEPTH + 2):
        cafe = [cafe]
    name = {"名前": "Привет"}
    for _ in range(DEPTH):
        name = {"a": name}
    (doc,) = tool({"cafe": cafe, "name": name})["results"]
    assert _at(doc["cafe"], DEPTH, 0) == '[["café"]]'
    assert _at(doc["name"], DEPTH, "a") == '{"名前": "Привет"}'
    assert doc["_truncated"] == [
        _why("cafe" + "[0]" * DEPTH, False),
        _why("name" + ".a" * DEPTH, False),
    ]
