"""A field in none of the searched indices is refused, not answered with 0 buckets.

host.name and host.id are keyword in every template, with no .keyword
sub-field: idx_aggregate(field="host.name.keyword") used to answer
buckets [] over millions of documents, with no warning. field_caps already
runs before the aggregation; when it finds the field in none of the searched
indices, both terms tools say so and name the host fields.

A real sub-field (Path.keyword), a field in only some indices, a field_caps
call that fails or reports failures, and a pattern matching no index answer
as before.
"""

from __future__ import annotations

import pytest
from opensearchpy.exceptions import ConnectionTimeout

from opensearch_mcp import server as srv

EVTX, SHIM = "case-acme-evtx-a", "case-acme-shimcache-a"
MAPPED = {
    EVTX: {"host.name": "keyword", "host.id": "keyword", "event.code": "long"},
    SHIM: {
        "host.name": "keyword",
        "host.id": "keyword",
        "Path": "text",
        "Path.keyword": "keyword",
    },
}
TOOLS = {"idx_aggregate": ("buckets", "key"), "idx_field_values": ("values", "value")}


class Cluster:
    """field_caps answers per index from MAPPED, the way OpenSearch 3.5.0 lists
    a field's types; every search answers one bucket."""

    def __init__(self, caps=None):
        self.caps, self.searches = caps, []

    def field_caps(self, index, fields, **kw):
        if isinstance(self.caps, Exception):
            raise self.caps
        if self.caps is not None:
            return self.caps
        names = [i for i in MAPPED if i in index.split(",")]
        types: dict = {}
        for name in names:
            if t := MAPPED[name].get(fields):
                types.setdefault(t, {"type": t, "aggregatable": True, "indices": []})
                types[t]["indices"].append(name)
        return {"indices": names, "fields": {fields: types} if types else {}}

    def search(self, index=None, body=None, **kw):
        self.searches.append(index)
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

    def go(cluster, tool, field, index=f"{EVTX},{SHIM}"):
        monkeypatch.setattr(srv, "_get_os", lambda: cluster)
        return getattr(srv, tool)(field=field, index=index)

    return go


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("field", ["host.name.keyword", "no.such.field"])
def test_a_field_in_no_searched_index_is_refused(run, tool, field):
    cluster = Cluster()
    reply = run(cluster, tool, field)
    assert field in reply["error"]
    assert "none of the searched indices" in reply["error"]
    assert f"{EVTX},{SHIM}" in reply["error"]
    assert "host.id" in reply["error"] and "host.name" in reply["error"]
    assert cluster.searches == []


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("field", ["Path.keyword", "host.name", "host.id"])
def test_a_mapped_field_or_sub_field_still_answers(run, tool, field):
    out, key = TOOLS[tool]
    reply = run(Cluster(), tool, field)
    assert "error" not in reply
    assert [b[key] for b in reply[out]] == ["WKSTN05"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_field_in_only_some_indices_answers_as_before(run, tool):
    out, key = TOOLS[tool]
    reply = run(Cluster(), tool, "event.code")
    assert "error" not in reply and "note" not in reply
    assert [b[key] for b in reply[out]] == ["WKSTN05"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_field_caps_call_that_fails_raises_as_before(run, tool):
    with pytest.raises(RuntimeError, match="connection temporarily lost"):
        run(Cluster(ConnectionTimeout("TIMEOUT", "timed out", None)), tool, "host.name.keyword")


@pytest.mark.parametrize("tool", TOOLS)
def test_field_caps_failures_are_not_read_as_absence(run, tool):
    caps = {"indices": [EVTX], "fields": {}, "failures": [{"indices": [SHIM]}]}
    out, key = TOOLS[tool]
    reply = run(Cluster(caps), tool, "host.name.keyword")
    assert "error" not in reply
    assert [b[key] for b in reply[out]] == ["WKSTN05"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_pattern_matching_no_index_answers_as_before(run, tool):
    cluster = Cluster({"indices": [], "fields": {}})
    reply = run(cluster, tool, "host.name.keyword", index="case-acme-nothing-*")
    assert "error" not in reply
    assert cluster.searches == ["case-acme-nothing-*"]
