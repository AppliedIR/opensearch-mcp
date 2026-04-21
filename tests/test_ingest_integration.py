"""Integration tests requiring OpenSearch Docker container.

All tests are marked with @pytest.mark.integration and will be skipped
when OpenSearch is not running.

To run: pytest tests/test_ingest_integration.py -m integration
"""

from __future__ import annotations

import csv
import time
import uuid

import pytest

# Skip entire module if opensearchpy is not installed
opensearchpy = pytest.importorskip("opensearchpy")


pytestmark = pytest.mark.integration


@pytest.fixture
def os_client():
    """Get an OpenSearch client or skip if not available.

    Also ensures case-* templates are installed on the cluster — post
    2026-04-22 setup-opensearch.sh no longer installs templates at
    deployment time (that duty moved to ensure_winlog_pipeline, called
    on MCP startup + ingest pre-flight). Integration tests create
    indices directly without going through MCP, so they need to
    trigger the installer themselves or new indices land with dynamic
    mappings and fail assertions like host.name:keyword.
    """
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        health = client.cluster.health()
        if health.get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception:
        pytest.skip("OpenSearch not available")
    # Idempotent template install — guarantees templates are present
    # before integration tests create case-* indices.
    try:
        from opensearch_mcp.mappings import ensure_winlog_pipeline

        ensure_winlog_pipeline(client)
    except Exception:
        pass  # non-fatal — if install fails, tests fail with their own errors
    return client


@pytest.fixture
def test_index(os_client):
    """Create a unique test index and clean up after test."""
    index_name = f"case-pytest-{uuid.uuid4().hex[:8]}-evtx-testhost"
    yield index_name
    # Cleanup
    try:
        os_client.indices.delete(index=index_name, ignore=[404])
    except Exception:
        pass


@pytest.fixture
def test_csv_index(os_client):
    """Create a unique test index for CSV and clean up after."""
    index_name = f"case-pytest-{uuid.uuid4().hex[:8]}-amcache-testhost"
    yield index_name
    try:
        os_client.indices.delete(index=index_name, ignore=[404])
    except Exception:
        pass


def _write_csv(path, rows, encoding="utf-8"):
    """Write rows as CSV."""
    with open(path, "w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def _wait_for_count(client, index, expected, timeout=10):
    """Wait for document count to reach expected value."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client.indices.refresh(index=index)
            r = client.count(index=index)
            if r["count"] >= expected:
                return r["count"]
        except Exception:
            pass
        time.sleep(0.5)
    client.indices.refresh(index=index)
    return client.count(index=index)["count"]


# ---------------------------------------------------------------------------
# Evtx integration tests
# ---------------------------------------------------------------------------


class TestEvtxIntegration:
    def test_search_returns_correct_results(self, os_client, test_index):
        """Documents indexed via bulk are searchable."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": f"doc-{i}",
                "_source": {
                    "event.code": 4624,
                    "host.name": "testhost",
                    "@timestamp": f"2024-01-15T10:0{i}:00Z",
                    "user.name": f"user{i}",
                    "pipeline_version": "test",
                },
            }
            for i in range(5)
        ]
        flushed, failed = flush_bulk(os_client, actions)
        assert flushed == 5
        assert failed == 0

        count = _wait_for_count(os_client, test_index, 5)
        assert count == 5

        # Search for specific event code
        result = os_client.search(
            index=test_index,
            body={"query": {"term": {"event.code": 4624}}},
        )
        assert result["hits"]["total"]["value"] == 5

    def test_count_matches_expected(self, os_client, test_index):
        """Count API returns correct document count."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": f"cnt-{i}",
                "_source": {"event.code": 1000 + i, "host.name": "testhost"},
            }
            for i in range(10)
        ]
        flush_bulk(os_client, actions)
        count = _wait_for_count(os_client, test_index, 10)
        assert count == 10

    def test_reingest_produces_same_count_dedup(self, os_client, test_index):
        """Re-ingest with same IDs produces same doc count (dedup works)."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": f"dedup-{i}",
                "_source": {"event.code": 4624, "host.name": "testhost"},
            }
            for i in range(5)
        ]

        # First ingest
        flush_bulk(os_client, actions)
        count1 = _wait_for_count(os_client, test_index, 5)
        assert count1 == 5

        # Second ingest (same IDs)
        flush_bulk(os_client, actions)
        os_client.indices.refresh(index=test_index)
        count2 = os_client.count(index=test_index)["count"]
        assert count2 == 5  # same count, dedup worked

    def test_provenance_fields_present(self, os_client, test_index):
        """Every document has provenance fields present and searchable."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "prov-1",
                "_source": {
                    "event.code": 4624,
                    "host.name": "testhost",
                    "vhir.source_file": "/evidence/Security.evtx",
                    "vhir.ingest_audit_id": "audit-001",
                    "pipeline_version": "opensearch-mcp-0.1.0",
                },
            }
        ]
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 1)

        doc = os_client.get(index=test_index, id="prov-1")
        src = doc["_source"]
        assert src["pipeline_version"] == "opensearch-mcp-0.1.0"
        assert src["vhir.source_file"] == "/evidence/Security.evtx"
        assert src["vhir.ingest_audit_id"] == "audit-001"

    def test_vhir_source_file_searchable(self, os_client, test_index):
        """vhir.source_file is searchable via term query."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "sf-1",
                "_source": {
                    "event.code": 4624,
                    "vhir.source_file": "/evidence/Security.evtx",
                },
            }
        ]
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 1)

        # vhir.source_file is keyword type — use term (exact) or wildcard
        result = os_client.search(
            index=test_index,
            body={"query": {"term": {"vhir.source_file": "/evidence/Security.evtx"}}},
        )
        assert result["hits"]["total"]["value"] >= 1

    def test_aggregation_on_host_name(self, os_client, test_index):
        """Aggregation on host.name works correctly."""
        from opensearch_mcp.bulk import flush_bulk

        actions = []
        for i in range(10):
            host = "host-a" if i < 6 else "host-b"
            actions.append(
                {
                    "_index": test_index,
                    "_id": f"agg-{i}",
                    "_source": {"event.code": 4624, "host.name": host},
                }
            )
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 10)

        result = os_client.search(
            index=test_index,
            body={
                "aggs": {"hosts": {"terms": {"field": "host.name"}}},
                "size": 0,
            },
        )
        buckets = result["aggregations"]["hosts"]["buckets"]
        bucket_dict = {b["key"]: b["doc_count"] for b in buckets}
        assert bucket_dict.get("host-a") == 6
        assert bucket_dict.get("host-b") == 4

    def test_time_range_filtering(self, os_client, test_index):
        """Time range query excludes events outside the range."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "tr-1",
                "_source": {
                    "event.code": 4624,
                    "@timestamp": "2024-01-10T00:00:00Z",
                },
            },
            {
                "_index": test_index,
                "_id": "tr-2",
                "_source": {
                    "event.code": 4624,
                    "@timestamp": "2024-01-15T12:00:00Z",
                },
            },
            {
                "_index": test_index,
                "_id": "tr-3",
                "_source": {
                    "event.code": 4624,
                    "@timestamp": "2024-01-20T00:00:00Z",
                },
            },
        ]
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 3)

        result = os_client.search(
            index=test_index,
            body={
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "2024-01-14",
                            "lte": "2024-01-16",
                        }
                    }
                }
            },
        )
        assert result["hits"]["total"]["value"] == 1

    def test_source_ip_accepts_valid_ip(self, os_client, test_index):
        """source.ip field accepts valid IP addresses."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "ip-1",
                "_source": {
                    "event.code": 4624,
                    "source.ip": "192.168.1.100",
                },
            }
        ]
        flushed, failed = flush_bulk(os_client, actions)
        # If source.ip is mapped as 'ip' type, valid IPs should index fine
        assert flushed == 1 or failed == 0


# ---------------------------------------------------------------------------
# CSV integration tests
# ---------------------------------------------------------------------------


class TestCsvIntegration:
    def test_utf16le_csv_ingest(self, os_client, test_csv_index, tmp_path):
        """UTF-16LE CSV (PowerShell 5.1 format) ingests correctly."""
        from opensearch_mcp.parse_csv import ingest_csv

        csv_file = tmp_path / "test.csv"
        content = "Path,LastModified\nC:\\evil.exe,2024-01-15\nC:\\good.exe,2024-01-16\n"
        csv_file.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))

        count, sk, bf = ingest_csv(
            csv_path=csv_file,
            client=os_client,
            index_name=test_csv_index,
            hostname="testhost",
        )
        assert count == 2

        actual_count = _wait_for_count(os_client, test_csv_index, 2)
        assert actual_count == 2

    def test_mft_natural_key_dedup(self, os_client, tmp_path):
        """MFT natural key dedup: same E:S:F:P = same doc."""
        from opensearch_mcp.parse_csv import ingest_csv

        index_name = f"case-pytest-{uuid.uuid4().hex[:8]}-mft-testhost"
        try:
            csv_file = tmp_path / "mft.csv"
            rows = [
                {
                    "EntryNumber": "100",
                    "SequenceNumber": "5",
                    "FileName": "test.txt",
                    "ParentEntryNumber": "50",
                    "Created0x10": "2024-01-15",
                },
                {
                    "EntryNumber": "100",
                    "SequenceNumber": "5",
                    "FileName": "test.txt",
                    "ParentEntryNumber": "50",
                    "Created0x10": "2024-01-15",
                },
            ]
            _write_csv(csv_file, rows)

            natural_key = "EntryNumber:SequenceNumber:FileName:ParentEntryNumber"
            count, _, _ = ingest_csv(
                csv_path=csv_file,
                client=os_client,
                index_name=index_name,
                hostname="testhost",
                natural_key=natural_key,
            )

            actual = _wait_for_count(os_client, index_name, 1, timeout=5)
            # Both rows have same natural key -> should dedup to 1 doc
            assert actual == 1
        finally:
            try:
                os_client.indices.delete(index=index_name, ignore=[404])
            except Exception:
                pass


# ---------------------------------------------------------------------------
# idx_status integration
# ---------------------------------------------------------------------------


class TestIdxStatusIntegration:
    def test_idx_status_shows_case_indices(self, os_client, test_index):
        """idx_status returns case-* indices."""
        from opensearch_mcp.bulk import flush_bulk

        # Create a doc to make the index exist
        flush_bulk(os_client, [{"_index": test_index, "_id": "st-1", "_source": {"test": True}}])
        _wait_for_count(os_client, test_index, 1)

        indices = os_client.cat.indices(format="json")
        case_indices = [i for i in indices if i["index"].startswith("case-")]
        assert any(i["index"] == test_index for i in case_indices)
