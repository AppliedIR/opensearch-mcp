"""A zero FILETIME (1601) neither leads the case time range nor the default timeline."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from _mapping_shapes import serve
from sift_common import host_identity

import opensearch_mcp.server as srv
from opensearch_mcp import write_context as wc

ZERO = {"value_as_string": "1601-01-01T00:00:00.000Z"}
FIRST = {"value_as_string": "2023-01-20T08:00:00.000Z"}
LAST = {"value_as_string": "2023-01-28T17:00:00.000Z"}
RANGE = {"earliest": FIRST["value_as_string"], "latest": LAST["value_as_string"]}
NOTE = (
    "3 record(s) have @timestamp before 1990-01-01 (a zero FILETIME reads as 1601-01-01) "
    "and {}; idx_search query='@timestamp:<1990-01-01' finds them"
)


def _summary(monkeypatch, aggs):
    evtx = f"case-{host_identity.ensure_case_uuid(wc.case_dir_for('acme'), 2)[0]}-evtx-0"
    c = MagicMock()
    c.cat.indices.return_value = [{"index": evtx, "docs.count": "12"}]
    c.search.return_value = {
        "aggregations": {**aggs, "hosts": {"buckets": []}, "by_index": {"buckets": []}}
    }
    c.count.return_value = {"count": 0}
    serve(c, {evtx: {"@timestamp": "date"}}, cat=False)
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    return srv.idx_case_summary(case_id="acme"), c


def _range_body(c):
    return next(
        k["body"] for _, k in c.search.call_args_list if "min_ts" in k["body"].get("aggs", {})
    )


def test_summary_takes_earliest_at_or_after_1990_and_counts_the_rest(monkeypatch):
    r, c = _summary(monkeypatch, {
        "min_ts": ZERO, "max_ts": LAST, "early": {"doc_count": 3},
        "timed": {"doc_count": 9, "min_ts": FIRST}})  # fmt: skip
    assert r["time_range"] == RANGE
    assert [w for w in r["warnings"] if "1601" in w] == [
        "Time range: " + NOTE.format("aren't in time_range")
    ]
    aggs = _range_body(c)["aggs"]
    assert aggs["timed"]["filter"] == {"range": {"@timestamp": {"gte": "1990-01-01"}}}
    assert aggs["early"] == {"filter": {"range": {"@timestamp": {"lt": "1990-01-01"}}}}


def test_summary_with_nothing_before_1990_reads_as_before(monkeypatch):
    r, _ = _summary(monkeypatch, {
        "min_ts": FIRST, "max_ts": LAST, "early": {"doc_count": 0},
        "timed": {"doc_count": 12, "min_ts": FIRST}})  # fmt: skip
    assert r["time_range"] == RANGE
    assert not [w for w in r.get("warnings", []) if "1990" in w or "Time range" in w]


def test_summary_of_only_1601_records_names_them_and_keeps_the_rest(monkeypatch):
    r, _ = _summary(monkeypatch, {
        "min_ts": ZERO, "max_ts": ZERO, "early": {"doc_count": 3},
        "timed": {"doc_count": 0, "min_ts": {}}})  # fmt: skip
    assert r["time_range"] == {}
    assert "Time range: " + NOTE.format("aren't in time_range") in r["warnings"]
    assert r["case_id"] == "acme" and r["total_docs"] == 12 and "evtx" in r["artifacts"]


@pytest.fixture
def client(monkeypatch):
    c = MagicMock()
    c.cluster.health.return_value = {"status": "green"}
    serve(c, {})
    monkeypatch.setattr(srv, "_client", None)
    monkeypatch.setattr(srv, "_client_verified", False)
    with (patch("opensearch_mcp.server.get_client", return_value=c),
          patch("opensearch_mcp.server._get_active_case", return_value="test-case")):  # fmt: skip
        yield c


def _timeline(client, early, **kw):
    buckets = [{"key_as_string": "2023-01-20T00:00:00.000Z", "doc_count": 9}]
    aggs = {"timeline": {"buckets": buckets}}
    if early is not None:
        aggs["early"] = {"doc_count": early}
    client.search.return_value = {"hits": {"total": {"value": 12}}, "aggregations": aggs}
    r = srv.idx_timeline(interval="1d", **kw)
    return r, next(
        k["body"]
        for _, k in client.search.call_args_list
        if "timeline" in k["body"].get("aggs", {})
    )


def test_default_timeline_starts_at_1990_and_says_what_it_left_out(client):
    r, body = _timeline(client, 3)
    assert body["aggs"]["timeline"]["date_histogram"]["hard_bounds"] == {
        "min": "1990-01-01",
        "max": 2**63 - 1,
    }
    assert body["aggs"]["early"] == {"filter": {"range": {"@timestamp": {"lt": "1990-01-01"}}}}
    assert r["hint"].startswith(NOTE.format("aren't in this timeline"))
    assert r["total_docs"] == 12


def test_default_timeline_with_nothing_before_1990_reads_as_before(client):
    r, _ = _timeline(client, 0)
    assert "hint" not in r and r["buckets"] == [{"time": "2023-01-20T00:00:00.000Z", "count": 9}]


@pytest.mark.parametrize("kw", [
    {"time_from": "1601-01-01T00:00:00Z"},
    {"time_field": "Created0x10"},
])  # fmt: skip
def test_a_time_from_or_another_time_field_takes_no_floor(client, kw):
    r, body = _timeline(client, None, **kw)
    assert "early" not in body["aggs"] and "hard_bounds" not in str(body)
    assert "hint" not in r
    if "time_from" in kw:
        rng = body["query"]["bool"]["must"][1]["range"]["@timestamp"]
        assert rng == {"gte": "1601-01-01T00:00:00Z"}
