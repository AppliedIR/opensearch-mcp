"""An update_by_query over 150,000 documents runs once and reports its own counts.

At the default scroll size that's 150 batches, so 150 response headers.
The script increments a counter, so a request sent again shows in the data.
"""

from __future__ import annotations

import uuid

import pytest
from opensearchpy import helpers

pytestmark = pytest.mark.integration

DOCS = 150_000


@pytest.fixture(scope="module")
def client():
    try:
        from opensearch_mcp.client import get_client

        c = get_client()
        if c.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    return c


@pytest.fixture
def index(client):
    name = f"case-{uuid.uuid4().hex[:12]}-ubq-0"
    client.indices.create(index=name, body={"settings": {"number_of_shards": 1}})
    helpers.bulk(
        client,
        ({"_index": name, "_id": str(i), "_source": {"n": 0}} for i in range(DOCS)),
        chunk_size=10_000,
        request_timeout=120,
    )
    client.indices.refresh(index=name)
    yield name
    client.indices.delete(index=name, ignore=[404])


def test_a_by_query_update_over_many_batches_runs_once_with_its_counts(client, index):
    r = client.update_by_query(
        index=index,
        body={"script": {"source": "ctx._source.n += 1", "lang": "painless"}},
        refresh=True,
        conflicts="proceed",
        request_timeout=300,
    )
    assert r["updated"] == DOCS and r["batches"] >= 150
    counts = client.search(
        index=index, body={"size": 0, "aggs": {"n": {"terms": {"field": "n"}}}}
    )["aggregations"]["n"]["buckets"]
    assert counts == [{"key": 1, "doc_count": DOCS}]  # each document changed once
