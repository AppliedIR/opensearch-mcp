"""Against a cluster, with the tree's templates: each summary tool's request
is accepted and logs the ingests of the records it counted, and the records
with no ingest id. Values are synthetic."""

from __future__ import annotations

import pytest
from test_host_keys_cluster import cases, client, write  # noqa: F401

from opensearch_mcp import server as srv

pytestmark = pytest.mark.integration

A, B = "opensearch-ex-20261008-001", "opensearch-ex-20261008-002"


def test_each_summary_tool_logs_the_ingests_it_counted(client, cases, monkeypatch):  # noqa: F811
    case, _ = cases("ri")
    docs = {}
    for n, aid in enumerate([A, A, A, B, B, None]):
        docs[str(n)] = {"@timestamp": "2026-10-08T00:00:00Z", "event.code": "4624",
                        **({"vhir.ingest_audit_id": aid} if aid else {})}  # fmt: skip
    write(client, case, "hosts/RD01", "RD01", docs)
    monkeypatch.setattr(srv, "_get_active_case", lambda: case.name)
    logged = []
    monkeypatch.setattr(srv.audit, "log", lambda **kw: logged.append(kw))
    assert srv.idx_count(query="*")["count"] == 6
    assert srv.idx_aggregate(field="event.code")["total_docs"] == 6
    assert srv.idx_timeline(interval="1d")["total_docs"] == 6
    assert srv.idx_field_values(field="event.code")["values"][0]["count"] == 6
    assert [e["tool"] for e in logged] == [
        "idx_count", "idx_aggregate", "idx_timeline", "idx_field_values"
    ]  # fmt: skip
    for e in logged:
        assert e["params"]["result_ingests"] == [A, B], e
        assert e["params"]["result_ingests_missing"] == 1, e
        assert "result_ingests_overflow" not in e["params"]
