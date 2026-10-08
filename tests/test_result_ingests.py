"""A search's audit entry records which ingests its results came from.

Every indexed record carries `vhir.ingest_audit_id`, the audit id of the
parser entry that wrote it. idx_search and idx_get_event add the distinct ids
of the records they returned to their audit entry, as
`params.result_ingests` (sorted), so a finding citing those results traces to
the files and tools behind them. The reply is unchanged. The client is a mock;
the audit log is captured.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

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
