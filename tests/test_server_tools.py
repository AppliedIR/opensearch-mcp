"""Tests for server.py MCP tool functions with mocked OpenSearch."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import opensearch_mcp.server as srv
from opensearch_mcp.server import (
    _get_os,
    _os_call,
    _strip_hits,
    idx_aggregate,
    idx_count,
    idx_field_values,
    idx_get_event,
    idx_ingest,
    idx_ingest_status,
    idx_search,
    idx_status,
    idx_timeline,
)


@pytest.fixture(autouse=True)
def _reset_server_state():
    """Reset the module-level client cache before each test."""
    old_client = srv._client
    old_verified = srv._client_verified
    srv._client = None
    srv._client_verified = False
    yield
    srv._client = old_client
    srv._client_verified = old_verified


@pytest.fixture
def mock_client():
    """Provide a mock OpenSearch client and inject it into server module."""
    client = MagicMock()
    client.cluster.health.return_value = {"status": "green"}
    with patch("opensearch_mcp.server.get_client", return_value=client):
        yield client


# ---------------------------------------------------------------------------
# _get_os
# ---------------------------------------------------------------------------


class TestGetOs:
    def test_raises_runtime_error_when_config_missing(self):
        """_get_os raises RuntimeError when config file not found."""
        with patch(
            "opensearch_mcp.server.get_client",
            side_effect=FileNotFoundError("OpenSearch config not found"),
        ):
            with pytest.raises(RuntimeError, match="config not found"):
                _get_os()

    def test_raises_runtime_error_on_connection_failure(self):
        """_get_os raises RuntimeError when health check fails."""
        mock_client = MagicMock()
        mock_client.cluster.health.side_effect = Exception("Connection refused")
        with patch("opensearch_mcp.server.get_client", return_value=mock_client):
            with pytest.raises(RuntimeError, match="not running"):
                _get_os()

    def test_caches_client_on_second_call(self):
        """_get_os returns cached client on second call (no second get_client)."""
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {"status": "green"}
        with patch("opensearch_mcp.server.get_client", return_value=mock_client) as mock_gc:
            c1 = _get_os()
            c2 = _get_os()
        assert c1 is c2
        # get_client called only once
        mock_gc.assert_called_once()


# ---------------------------------------------------------------------------
# _os_call
# ---------------------------------------------------------------------------


class TestOsCall:
    def test_resets_cache_on_connection_error(self, mock_client):
        """_os_call resets client cache on ConnectionError."""
        from opensearchpy.exceptions import ConnectionError as OSConnectionError

        # First call succeeds to populate the cache
        _get_os()
        assert srv._client is not None
        assert srv._client_verified is True

        # Now simulate a connection error
        def failing_fn():
            raise OSConnectionError("connection lost")

        with pytest.raises(RuntimeError, match="temporarily lost"):
            _os_call(failing_fn)
        assert srv._client is None
        assert srv._client_verified is False

    def test_passes_through_successful_call(self, mock_client):
        """_os_call passes through the return value on success."""
        _get_os()
        result = _os_call(lambda x: x * 2, 21)
        assert result == 42


# ---------------------------------------------------------------------------
# _strip_hits
# ---------------------------------------------------------------------------


class TestStripHits:
    def test_extracts_source_adds_id_and_index(self):
        hits = [
            {
                "_id": "doc1",
                "_index": "case-test-evtx-host1",
                "_source": {"event.code": 4624, "user.name": "admin"},
            }
        ]
        result = _strip_hits(hits)
        assert len(result) == 1
        assert result[0]["_id"] == "doc1"
        assert result[0]["_index"] == "case-test-evtx-host1"
        assert result[0]["event.code"] == 4624

    def test_empty_hits_returns_empty(self):
        assert _strip_hits([]) == []

    def test_missing_source_returns_id_and_index(self):
        hits = [{"_id": "x", "_index": "idx"}]
        result = _strip_hits(hits)
        assert result[0]["_id"] == "x"
        assert result[0]["_index"] == "idx"


# ---------------------------------------------------------------------------
# idx_search
# ---------------------------------------------------------------------------


class TestIdxSearch:
    def test_returns_total_returned_results(self, mock_client):
        mock_client.search.return_value = {
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_id": "1", "_index": "idx", "_source": {"event.code": 4624}},
                    {"_id": "2", "_index": "idx", "_source": {"event.code": 4625}},
                ],
            }
        }
        resp = idx_search(query="event.code:4624")
        assert resp["total"] == 2
        assert resp["returned"] == 2
        assert len(resp["results"]) == 2

    def test_caps_limit_at_200(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        idx_search(query="*", limit=999)
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["size"] == 200

    def test_validates_sort_order_invalid_becomes_desc(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        idx_search(query="*", sort="@timestamp:INVALID")
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["sort"][0]["@timestamp"]["order"] == "desc"

    def test_audit_id_in_response(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
        }
        with patch.object(srv.audit, "log", return_value="audit-123"):
            resp = idx_search(query="*")
        assert resp["audit_id"] == "audit-123"


# ---------------------------------------------------------------------------
# idx_count
# ---------------------------------------------------------------------------


class TestIdxCount:
    def test_returns_count(self, mock_client):
        mock_client.count.return_value = {"count": 42}
        resp = idx_count(query="*")
        assert resp["count"] == 42

    def test_audit_id_in_response(self, mock_client):
        mock_client.count.return_value = {"count": 0}
        with patch.object(srv.audit, "log", return_value="audit-456"):
            resp = idx_count()
        assert resp["audit_id"] == "audit-456"


# ---------------------------------------------------------------------------
# idx_aggregate
# ---------------------------------------------------------------------------


class TestIdxAggregate:
    def test_returns_field_total_docs_buckets(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 100}},
            "aggregations": {
                "agg": {
                    "buckets": [
                        {"key": "host-a", "doc_count": 60},
                        {"key": "host-b", "doc_count": 40},
                    ]
                }
            },
        }
        resp = idx_aggregate(field="host.name")
        assert resp["field"] == "host.name"
        assert resp["total_docs"] == 100
        assert len(resp["buckets"]) == 2
        assert resp["buckets"][0] == {"key": "host-a", "count": 60, "doc_count": 60}

    def test_caps_limit_at_500(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 0}},
            "aggregations": {"agg": {"buckets": []}},
        }
        idx_aggregate(field="host.name", limit=9999)
        call_body = mock_client.search.call_args[1]["body"]
        assert call_body["aggs"]["agg"]["terms"]["size"] == 500


# ---------------------------------------------------------------------------
# idx_get_event
# ---------------------------------------------------------------------------


class TestIdxGetEvent:
    def test_returns_document_with_id_and_index(self, mock_client):
        mock_client.get.return_value = {
            "_id": "doc123",
            "_index": "case-test-evtx-host1",
            "_source": {"event.code": 4624, "user.name": "admin"},
        }
        resp = idx_get_event(doc_id="doc123", index="case-test-evtx-host1")
        assert resp["_id"] == "doc123"
        assert resp["_index"] == "case-test-evtx-host1"
        assert resp["event.code"] == 4624


# ---------------------------------------------------------------------------
# idx_timeline
# ---------------------------------------------------------------------------


class TestIdxTimeline:
    def test_returns_total_docs_interval_buckets(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 500}},
            "aggregations": {
                "timeline": {
                    "buckets": [
                        {"key_as_string": "2024-01-15T10:00:00Z", "doc_count": 100},
                        {"key_as_string": "2024-01-15T11:00:00Z", "doc_count": 200},
                    ]
                }
            },
        }
        resp = idx_timeline(query="*", interval="1h")
        assert resp["total_docs"] == 500
        assert resp["interval"] == "1h"
        assert len(resp["buckets"]) == 2
        assert resp["buckets"][0] == {"time": "2024-01-15T10:00:00Z", "count": 100}


# ---------------------------------------------------------------------------
# idx_field_values
# ---------------------------------------------------------------------------


class TestIdxFieldValues:
    def test_returns_field_and_values(self, mock_client):
        mock_client.search.return_value = {
            "hits": {"total": {"value": 100}},
            "aggregations": {
                "values": {
                    "buckets": [
                        {"key": "Sysmon", "doc_count": 50},
                        {"key": "Security", "doc_count": 30},
                    ]
                }
            },
        }
        resp = idx_field_values(field="winlog.provider_name")
        assert resp["field"] == "winlog.provider_name"
        assert len(resp["values"]) == 2
        assert resp["values"][0] == {"value": "Sysmon", "count": 50, "doc_count": 50}


# ---------------------------------------------------------------------------
# idx_status
# ---------------------------------------------------------------------------


class TestIdxStatus:
    def test_filters_to_case_indices_only(self, mock_client):
        mock_client.cat.indices.return_value = [
            {
                "index": "case-test-evtx-host1",
                "docs.count": "1000",
                "store.size": "5mb",
                "status": "open",
            },
            {"index": ".kibana_1", "docs.count": "10", "store.size": "1mb", "status": "open"},
            {
                "index": "case-inc2-amcache-host2",
                "docs.count": "50",
                "store.size": "100kb",
                "status": "open",
            },
        ]
        mock_client.cluster.health.return_value = {"status": "green"}
        resp = idx_status()
        assert resp["total_indices"] == 2
        index_names = [i["index"] for i in resp["indices"]]
        assert ".kibana_1" not in index_names
        assert "case-test-evtx-host1" in index_names

    def test_includes_cluster_status(self, mock_client):
        mock_client.cat.indices.return_value = []
        mock_client.cluster.health.return_value = {
            "status": "yellow",
            "number_of_nodes": 1,
        }
        resp = idx_status()
        assert "yellow" in resp["cluster_status"]
        assert "single-node" in resp["cluster_status"]

    def test_cluster_status_green_not_annotated(self, mock_client):
        mock_client.cat.indices.return_value = []
        mock_client.cluster.health.return_value = {
            "status": "green",
            "number_of_nodes": 3,
        }
        resp = idx_status()
        assert resp["cluster_status"] == "green"


# ---------------------------------------------------------------------------
# idx_ingest
# ---------------------------------------------------------------------------


class TestIdxIngest:
    def test_rejects_paths_outside_allowed_locations(self, mock_client):
        """Paths outside ~, /mnt, /evidence, /tmp are rejected."""
        # Use /etc which is a directory but not in allowed locations
        resp = idx_ingest(path="/etc")
        assert "error" in resp
        assert "not in allowed locations" in resp["error"]

    def test_dry_run_returns_preview(self, mock_client, tmp_path, monkeypatch):
        """dry_run=True returns preview with host/artifact discovery."""
        from _helpers import make_windows_tree

        make_windows_tree(tmp_path)

        # Create the active_case file under the fake home
        vhir_dir = tmp_path / ".vhir"
        vhir_dir.mkdir()
        active_case = vhir_dir / "active_case"
        active_case.write_text("TEST-CASE\n")

        # Patch Path.home to return tmp_path so idx_ingest finds active_case
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        mock_client.count.side_effect = Exception("no index")

        resp = idx_ingest(path=str(tmp_path), dry_run=True)
        assert resp.get("status") == "preview"
        assert len(resp.get("hosts", [])) >= 1

    def test_not_a_directory_returns_error(self, mock_client, tmp_path, monkeypatch):
        """Non-directory, non-container path returns error."""
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        vhir_dir = tmp_path / ".vhir"
        vhir_dir.mkdir()
        (vhir_dir / "active_case").write_text("TEST-CASE\n")
        f = tmp_path / "not_a_dir.txt"
        f.write_text("test")
        resp = idx_ingest(path=str(f))
        assert "error" in resp
        assert "Not a directory or supported container" in resp["error"]

    def test_ingest_status_returns_empty_when_no_status(self, mock_client):
        """idx_ingest_status returns empty when no status files exist."""
        with patch(
            "opensearch_mcp.ingest_status.read_active_ingests",
            return_value=[],
        ):
            resp = idx_ingest_status()
        assert resp["ingests"] == []
        assert "No active" in resp["message"]
