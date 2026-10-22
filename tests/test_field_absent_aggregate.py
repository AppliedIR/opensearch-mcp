"""Which searched indices hold the field idx_aggregate and idx_field_values name.

One get_mapping, filtered to the field's top-level name, says how each index
maps it, a red index too; cat.indices with expand_wildcards=open names the
indices a search reads, so closed and hidden ones aren't counted. A field in
none of them, an object, a wildcard or list, a name with an empty part, and
an ip/keyword mix are refused before the search. A field in only some
answers, with a field_note naming the indices without it. A metadata field
(_id, _index, ...) is in every index and is searched as before.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _mapping_shapes import cat_indices, get_mapping
from opensearchpy.exceptions import ConnectionTimeout, RequestError

from opensearch_mcp import server as srv

EVTX, SHIM = "case-acme-evtx-a", "case-acme-shimcache-a"
BOTH = f"{EVTX},{SHIM}"
MAPPED = {
    EVTX: {"host.name": "keyword", "host.id": "keyword", "event.code": "long",
           "source.ip": "ip", "hn": {"type": "alias", "path": "host.name"},
           "_event_values_hash": "keyword"},
    SHIM: {"host.name": "keyword", "host.id": "keyword", "Path": "text",
           "Path.keyword": "keyword", "source.ip": "keyword",
           "hn": {"type": "alias", "path": "host.name"}},
}  # fmt: skip
TOOLS = {"idx_aggregate": ("buckets", "key"), "idx_field_values": ("values", "value")}


class Cluster:
    """get_mapping and cat.indices answer from `mapped` as OpenSearch 3.5.0
    does, leaving the `closed` indices out of an open-only call; every search
    answers one bucket."""

    def __init__(self, mapped=MAPPED, closed=(), fail=None, search_fails=None):
        self.calls: list[tuple[str, dict]] = []
        self.searches: list[str] = []
        self.search_fails = search_fails
        shapes = {"get_mapping": get_mapping(mapped), "cat": cat_indices(mapped)}

        def call(name):
            def answer(**kw):
                self.calls.append((name, kw))
                if fail:
                    raise fail
                got = shapes[name](**kw)
                if kw.get("expand_wildcards") != "open":
                    return got
                if name == "cat":
                    return [r for r in got if r["index"] not in closed]
                return {i: m for i, m in got.items() if i not in closed}

            return answer

        self.indices = SimpleNamespace(get_mapping=call("get_mapping"))
        self.cat = SimpleNamespace(indices=call("cat"))

    def search(self, index=None, body=None, **kw):
        self.searches.append(index)
        if self.search_fails:
            raise self.search_fails
        buckets = [{"key": "WKSTN05", "doc_count": 2}]
        aggs = {name: {"buckets": buckets} for name in ("agg", "values")}
        aggs["result_ingests"] = {"buckets": []}
        return {"_shards": {"total": 1, "successful": 1, "failed": 0}, "timed_out": False,
                "hits": {"total": {"value": 2, "relation": "eq"}, "hits": []},
                "aggregations": aggs}  # fmt: skip


@pytest.fixture
def run(monkeypatch):
    monkeypatch.setattr(srv.audit, "log", lambda **kw: "aid-1")
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    logged: list[dict] = []  # what each answer is audited as

    def log_query(resp, **kw):
        logged.append(kw)
        return resp

    monkeypatch.setattr(srv, "_logged_query", log_query)

    def go(cluster, tool, field, index=BOTH):
        monkeypatch.setattr(srv, "_get_os", lambda: cluster)
        return getattr(srv, tool)(field=field, index=index)

    go.logged = logged
    return go


def answered(reply, tool):
    out, key = TOOLS[tool]
    assert "error" not in reply
    return [b[key] for b in reply[out]]


# OpenSearch 3.5.0's metadata fields, as its field_caps lists them
METADATA = ["_id", "_index", "_routing", "_ignored", "_doc_count", "_field_names",
            "_source", "_seq_no", "_version", "_nested_path", "_data_stream_timestamp",
            "_feature"]  # fmt: skip
HOSTS = "Hosts are host.id (the machine) and host.name (the raw name)"
NONE = "{} is in none of the 2 searched indices ({}): 0 buckets would not mean no values."
REFUSED = [
    ("host.*", "'host.*' is not one field name"),
    ("host.id,host.name", "'host.id,host.name' is not one field name"),
    *[(f, f"{f!r} is not one field name: a part of it is empty")
      for f in ("", " ", ".id", "a.", "a..b")],
    ("host", "host is an object, not a field: aggregate one of its fields "
             "(host.id, host.name)."),
    ("no.such.field", NONE.format("no.such.field", BOTH)),
    ("host.name.keyword", NONE.format("host.name.keyword", BOTH) + " " + HOSTS),
    ("source.ip", f"source.ip is mapped as ip in ['{EVTX}'] and as keyword in ['{SHIM}']"),
    # guards: names that start with _ but aren't OpenSearch metadata fields
    *[(f, NONE.format(f, BOTH)) for f in ("_primary_term", "__type__", "_index.keyword", "_id.x")],
]  # fmt: skip


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(("field", "error"), REFUSED)
def test_a_field_no_search_can_answer_is_refused_before_the_search(run, tool, field, error):
    cluster = Cluster()
    reply = run(cluster, tool, field)
    assert reply["error"].startswith(error)
    assert (HOSTS in reply["error"]) == (field == "host.name.keyword")
    assert cluster.searches == []
    if "not one field name" in error:
        assert cluster.calls == []


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(("field", "index"), [
    ("host.name", BOTH), ("host.id", BOTH), ("hn", BOTH), ("Path.keyword", SHIM),
    ("host.name", EVTX), ("event.code", EVTX), ("_event_values_hash", EVTX),
])  # fmt: skip
def test_a_field_every_searched_index_holds_answers_with_no_note(run, tool, field, index):
    cluster = Cluster()
    reply = run(cluster, tool, field, index=index)
    assert answered(reply, tool) == ["WKSTN05"] and "field_note" not in reply
    assert cluster.searches == [index]


@pytest.mark.parametrize("tool", TOOLS)
def test_one_mapping_and_one_open_listing_decide_it(run, tool):
    cluster = Cluster()
    run(cluster, tool, "Path.keyword")
    assert cluster.calls == [
        ("cat", {"index": BOTH, "format": "json", "h": "index", "expand_wildcards": "open"}),
        ("get_mapping", {"index": BOTH, "expand_wildcards": "open", "allow_no_indices": True,
                         "ignore_unavailable": True, "filter_path": "*.mappings.properties.Path"}),
    ]  # fmt: skip


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("field", ["event.code", "_event_values_hash"])
def test_a_field_in_some_searched_indices_names_the_others(run, tool, field):
    reply = run(Cluster(), tool, field)
    assert answered(reply, tool) == ["WKSTN05"]
    assert reply["field_note"] == (
        f"{field} is in 1 of the 2 searched indices; not in {SHIM}: 0 there is not 'no values'."
    )


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("field", METADATA)
def test_a_metadata_field_is_in_every_searched_index(run, tool, field):
    cluster = Cluster()
    reply = run(cluster, tool, field)
    assert answered(reply, tool) == ["WKSTN05"] and "field_note" not in reply
    assert [name for name, _ in cluster.calls] == ["cat"] and cluster.searches == [BOTH]
    (entry,) = run.logged  # audited as any field that answers
    run.logged.clear()
    run(Cluster(), tool, "host.id")
    assert entry == {**run.logged[0], "params": {**run.logged[0]["params"], "field": field}}


@pytest.mark.parametrize("tool", TOOLS)
def test_a_metadata_field_opensearch_refuses_raises_its_error_unaudited(run, tool):
    why = "Fielddata is not supported on field [_routing] of type [_routing]"
    info = {"error": {"reason": "all shards failed", "root_cause": [{"reason": why}]}}
    fails = RequestError(400, "search_phase_execution_exception", info)
    with pytest.raises(ValueError, match="Fielddata is not supported on field"):
        run(Cluster(search_fails=fails), tool, "_routing")
    assert run.logged == []


def test_metadata_fields_are_the_ones_opensearch_lists():
    assert srv._METADATA_FIELDS == set(METADATA)


@pytest.mark.parametrize("tool", TOOLS)
def test_the_note_names_five_indices_then_a_count(run, tool):
    many = {f"case-acme-x-{n}": {"host.id": "keyword"} for n in range(8)}
    many["case-acme-x-0"]["event.code"] = "long"
    reply = run(Cluster(many), tool, "event.code", index="case-acme-x-*")
    lack = ", ".join(f"case-acme-x-{n}" for n in range(1, 6))
    assert reply["field_note"] == (
        f"event.code is in 1 of the 8 searched indices; not in {lack}, and 2 more: "
        "0 there is not 'no values'."
    )


@pytest.mark.parametrize("tool", TOOLS)
def test_a_closed_index_is_not_counted(run, tool):
    mapped = {**MAPPED, "case-acme-old-a": {"event.code": "long"}}
    reply = run(Cluster(mapped, closed={"case-acme-old-a"}), tool, "no.such.field",
                index="case-acme-*")  # fmt: skip
    assert reply["error"].startswith("no.such.field is in none of the 2 searched indices")
    reply = run(Cluster(mapped, closed={"case-acme-old-a"}), tool, "event.code",
                index="case-acme-*")  # fmt: skip
    assert "1 of the 2 searched" in reply["field_note"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_pattern_matching_no_index_is_left_to_the_search(run, tool):
    cluster = Cluster()
    reply = run(cluster, tool, "host.name.keyword", index="case-acme-nothing-*")
    assert answered(reply, tool) == ["WKSTN05"]
    assert cluster.searches == ["case-acme-nothing-*"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_mapping_call_that_fails_raises_as_before(run, tool):
    with pytest.raises(RuntimeError, match="connection temporarily lost"):
        run(Cluster(fail=ConnectionTimeout("TIMEOUT", "timed out", None)), tool, "host.name")
