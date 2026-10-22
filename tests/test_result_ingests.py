"""A search's audit entry records which ingests its results came from.

Every indexed record carries `vhir.ingest_audit_id`, the audit id of the
parser entry that wrote it. idx_search and idx_get_event add the distinct ids
of the records they returned to their audit entry, as
`params.result_ingests` (sorted), so a finding citing those results traces to
the files and tools behind them. idx_count, idx_aggregate, idx_timeline and
idx_field_values summarise records, so the same request carries a sibling
terms aggregation on the id; the records with no id and any past the cap are
logged too, never dropped silently. The reply is unchanged. The client is a
mock; the audit log is captured.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from _mapping_shapes import serve

import opensearch_mcp.server as srv

INDEX = "case-0123abcdef01-evtx-0"


def _hit(n, aid, nested=False):
    src = {"event.code": "4624", "host.name": "RD01"}
    if aid is not None:
        if nested:
            src["vhir"] = {"ingest_audit_id": aid}
        else:
            src["vhir.ingest_audit_id"] = aid
    return {"_id": f"d{n}", "_index": INDEX, "_source": src}


@pytest.fixture
def os_(monkeypatch):
    c = MagicMock()
    c.cat.indices.return_value = [{"index": INDEX, "status": "open"}]
    serve(c, {INDEX: {"@timestamp": "date", "host.name": "keyword"}}, cat=False)
    logged = []
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: (logged.append(kw), "aid-9")[1])
    monkeypatch.setattr(srv, "_add_field_hint", lambda *a, **k: None)
    monkeypatch.setattr(srv, "_annotate_hosts", lambda *a, **k: None)
    return c, logged


def _search(c, hits):
    c.search.return_value = {"hits": {"total": {"value": len(hits)}, "hits": hits}}
    return srv.idx_search(query="event.code:4624", index=INDEX, compact=True)


def test_a_search_records_the_distinct_ingests_of_its_results_sorted(os_):
    c, logged = os_
    hits = [_hit(1, "opensearch-ex-20261008-007"), _hit(2, "opensearch-ex-20261008-003"),
            _hit(3, "opensearch-ex-20261008-007"), _hit(4, "opensearch-ex-20261008-005",
                                                         nested=True)]  # fmt: skip
    resp = _search(c, hits)
    (entry,) = logged
    assert entry["tool"] == "idx_search"
    assert entry["params"]["result_ingests"] == [
        "opensearch-ex-20261008-003", "opensearch-ex-20261008-005",
        "opensearch-ex-20261008-007",
    ]  # fmt: skip
    assert "result_ingests" not in resp  # the reply is unchanged


def test_records_without_an_ingest_id_record_none(os_):
    c, logged = os_
    _search(c, [_hit(1, None), _hit(2, "")])
    assert logged[0]["params"]["result_ingests"] == []


def test_compact_results_still_record_the_ingests(os_):
    """Compact mode trims what the reply shows, not what is recorded."""
    c, logged = os_
    _search(c, [_hit(1, "opensearch-ex-20261008-001")])
    assert logged[0]["params"]["result_ingests"] == ["opensearch-ex-20261008-001"]


def test_a_fetched_event_records_its_ingest(os_, monkeypatch):
    c, logged = os_
    c.get.return_value = _hit(1, "opensearch-ex-20261008-004")
    monkeypatch.setattr(srv, "_resolve_index", lambda *a, **k: (INDEX, None))
    doc = srv.idx_get_event(event_id="d1", index=INDEX)
    (entry,) = logged
    assert entry["tool"] == "idx_get_event"
    assert entry["params"]["result_ingests"] == ["opensearch-ex-20261008-004"]
    assert "result_ingests" not in doc


def _stamped(n, aid):
    hit = _hit(n, aid)
    hit["_source"].update({"vhir.content_hash": f"{n:064x}", "vhir.original.sha256": "ab" * 32})
    return hit


def test_a_search_records_each_record_it_returned_and_how_many_carry_no_ingest(os_):
    c, logged = os_
    _search(c, [_stamped(1, "opensearch-ex-20261009-001"), _stamped(2, None)])
    params = logged[0]["params"]
    assert params["result_ingests"] == ["opensearch-ex-20261009-001"]
    assert params["result_ingests_missing"] == 1  # never dropped silently
    assert params["result_docs"] == [
        {"_index": INDEX, "_id": "d1", "ingest_audit_id": "opensearch-ex-20261009-001",
         "content_hash": f"{1:064x}", "original_sha256": "ab" * 32},
        {"_index": INDEX, "_id": "d2", "ingest_audit_id": "",
         "content_hash": f"{2:064x}", "original_sha256": "ab" * 32},
    ]  # fmt: skip


def test_a_fetched_event_records_its_record(os_, monkeypatch):
    c, logged = os_
    c.get.return_value = _stamped(1, "opensearch-ex-20261009-004")
    monkeypatch.setattr(srv, "_resolve_index", lambda *a, **k: (INDEX, None))
    srv.idx_get_event(event_id="d1", index=INDEX)
    (doc,) = logged[0]["params"]["result_docs"]
    assert doc["_id"] == "d1" and doc["content_hash"] == f"{1:064x}"
    assert doc["ingest_audit_id"] == "opensearch-ex-20261009-004"
    assert "result_ingests_missing" not in logged[0]["params"]


def _summary(ids=(), missing=0, other=0, **own):
    return {
        "hits": {"total": {"value": 9}, "hits": []},
        "aggregations": {
            **own,
            "result_ingests": {
                "buckets": [{"key": k, "doc_count": 1} for k in ids],
                "sum_other_doc_count": other,
            },
            "result_ingests_missing": {"doc_count": missing},
        },
    }


SUMMARIES = {
    "idx_count": (lambda: srv.idx_count(query="*", index=INDEX), {}),
    "idx_aggregate": (
        lambda: srv.idx_aggregate(field="host.name", index=INDEX),
        {"agg": {"buckets": [{"key": "RD01", "doc_count": 9}]}},
    ),
    "idx_timeline": (
        lambda: srv.idx_timeline(index=INDEX),
        {
            "timeline": {"buckets": [{"key_as_string": "2026-10-08T00:00:00Z", "doc_count": 9}]},
            "early": {"doc_count": 0},  # the default timeline also counts records before 1990
        },
    ),
    "idx_field_values": (
        lambda: srv.idx_field_values(field="host.name", index=INDEX),
        {"values": {"buckets": [{"key": "RD01", "doc_count": 9}]}},
    ),
}


@pytest.mark.parametrize("tool", sorted(SUMMARIES))
def test_a_summary_records_the_ingests_of_the_records_it_counted(os_, tool):
    c, logged = os_
    call, own = SUMMARIES[tool]
    ids = ["opensearch-ex-20261008-007", "opensearch-ex-20261008-003"]
    c.search.return_value = _summary(ids, **own)
    resp = call()
    (entry,) = logged
    assert entry["tool"] == tool
    assert entry["params"]["result_ingests"] == sorted(ids)
    assert "result_ingests_missing" not in entry["params"]
    assert "result_ingests_overflow" not in entry["params"]
    assert "result_ingests" not in json.dumps(resp)  # the reply is unchanged
    aggs = c.search.call_args.kwargs["body"]["aggs"]  # top-level siblings
    assert aggs["result_ingests"] == {
        "terms": {"field": "vhir.ingest_audit_id", "size": srv._INGEST_AGG_CAP}
    }
    assert aggs["result_ingests_missing"] == {"missing": {"field": "vhir.ingest_audit_id"}}
    assert set(aggs) == {"result_ingests", "result_ingests_missing", *own}


@pytest.mark.parametrize("tool", sorted(SUMMARIES))
def test_records_with_no_id_and_ids_past_the_cap_are_logged(os_, tool):
    c, logged = os_
    call, own = SUMMARIES[tool]
    c.search.return_value = _summary(["opensearch-ex-20261008-001"], missing=4, other=12, **own)
    call()
    params = logged[0]["params"]
    assert params["result_ingests"] == ["opensearch-ex-20261008-001"]
    assert params["result_ingests_missing"] == 4
    assert params["result_ingests_overflow"] == 12
    assert params["result_ingests_cap"] == srv._INGEST_AGG_CAP


def test_a_count_is_a_search_of_no_records_counting_every_match(os_):
    c, _ = os_
    c.search.return_value = {**_summary(), "hits": {"total": {"value": 12345}, "hits": []}}
    assert srv.idx_count(query="*", index=INDEX)["count"] == 12345
    body = c.search.call_args.kwargs["body"]
    assert body["size"] == 0 and body["track_total_hits"] is True
    c.count.assert_not_called()


QUERIES = {
    "idx_search": lambda c: (_search_reply(c), srv.idx_search(query="*", index=INDEX))[1],
    "idx_get_event": lambda c: srv.idx_get_event(event_id="d1", index=INDEX),
    **{name: (lambda c, run=run: run()) for name, (run, _own) in SUMMARIES.items()},
}


def _search_reply(c):
    c.search.return_value = {"hits": {"total": {"value": 1}, "hits": [_hit(1, "x-001")]}}


@pytest.mark.parametrize("tool", sorted(QUERIES))
def test_a_query_saves_its_response_as_returned_and_its_entry_holds_the_hash(
    os_, tool, tmp_path, monkeypatch
):
    import hashlib

    from sift_common.audit import AuditWriter

    c, _ = os_
    case = tmp_path / "case"
    (case / "audit").mkdir(parents=True)
    monkeypatch.setattr(srv, "audit", AuditWriter("opensearch-mcp", audit_dir=str(case / "audit")))
    monkeypatch.setattr(srv, "_resolve_index", lambda *a, **k: (INDEX, None))
    c.get.return_value = _hit(1, "x-001")
    if tool in SUMMARIES:
        c.search.return_value = _summary(["x-001"], **SUMMARIES[tool][1])
    resp = QUERIES[tool](c)
    lines = (case / "audit" / "opensearch-mcp.jsonl").read_text().splitlines()
    (entry,) = [json.loads(line) for line in lines]
    saved = case / "extractions" / entry["audit_id"] / "response.json"
    assert entry["tool"] == tool and resp["audit_id"] == entry["audit_id"]
    assert json.loads(saved.read_text()) == json.loads(json.dumps(resp, default=str))
    assert entry["response"] == {
        "path": str(saved),
        "sha256": hashlib.sha256(saved.read_bytes()).hexdigest(),
    }


def test_a_query_s_entry_stays_in_the_case_its_id_was_minted_for(os_, tmp_path, monkeypatch):
    from sift_common.audit import AuditWriter

    c, _ = os_
    a, b = tmp_path / "case-a", tmp_path / "case-b"
    for d in (a, b):
        (d / "audit").mkdir(parents=True)
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "active_case").write_text(str(b))  # b is active by the time it logs
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("VHIR_ACTIVE_CASE", raising=False)
    writer = AuditWriter("opensearch-mcp")
    dirs = iter([a / "audit", b / "audit", b / "audit"])  # switched after the first
    monkeypatch.setattr(writer, "_get_audit_dir", lambda *x, **k: next(dirs))
    monkeypatch.setattr(srv, "audit", writer)
    monkeypatch.setattr(srv, "_resolve_index", lambda *a, **k: (INDEX, None))
    c.get.return_value = _hit(1, "x-001")
    resp = srv.idx_get_event(event_id="d1", index=INDEX)
    (entry,) = [
        json.loads(x) for x in (a / "audit" / "opensearch-mcp.jsonl").read_text().splitlines()
    ]
    assert entry["audit_id"] == resp["audit_id"] and entry["case_id"] == "case-a"
    assert (a / "extractions" / resp["audit_id"] / "response.json").exists()
    assert not (b / "audit" / "opensearch-mcp.jsonl").exists()
