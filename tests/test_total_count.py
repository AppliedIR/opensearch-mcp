"""idx_aggregate and idx_timeline report the true number of matching documents.

Without track_total_hits a search counts hits only up to 10,000 and says
"gte", so total_docs read 10,000 for any larger match. The stand-in cluster
answers like that.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import server as srv

TRUE_TOTAL = 25_000


def _search(index=None, body=None, **kw):
    total = (
        {"value": TRUE_TOTAL, "relation": "eq"}
        if body.get("track_total_hits") is True
        else {"value": 10_000, "relation": "gte"}
    )
    return {
        "hits": {"total": total, "hits": []},
        "aggregations": {
            "agg": {"buckets": []},
            "timeline": {"buckets": []},
            "values": {"buckets": []},
        },
    }


@pytest.fixture
def cluster(monkeypatch):
    client = MagicMock()
    client.search.side_effect = _search
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    with patch.object(srv, "_get_os", return_value=client):
        yield client


def test_aggregate(cluster):
    assert srv.idx_aggregate(field="host.name", index="case-x-*")["total_docs"] == TRUE_TOTAL


def test_timeline(cluster):
    assert srv.idx_timeline(index="case-x-*")["total_docs"] == TRUE_TOTAL
