"""Exhaustive tests for idx_list_detections tool (Phase 4)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import opensearch_mcp.server as srv
from opensearch_mcp.server import idx_list_detections


@pytest.fixture(autouse=True)
def _reset_server_state():
    old_client = srv._client
    old_verified = srv._client_verified
    srv._client = None
    srv._client_verified = False
    yield
    srv._client = old_client
    srv._client_verified = old_verified


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.cluster.health.return_value = {"status": "green"}
    with patch("opensearch_mcp.server.get_client", return_value=client):
        yield client


def _empty_response():
    return {"total_findings": 0, "findings": []}


def _make_finding(
    id="f-1", ts=1708647166500, index="case-inc001-evtx-host1", doc_ids=None, queries=None
):
    return {
        "id": id,
        "timestamp": ts,
        "index": index,
        "related_doc_ids": ["doc-1"] if doc_ids is None else doc_ids,
        "queries": [{"name": "Test Rule", "tags": ["high"]}] if queries is None else queries,
    }


# ---------------------------------------------------------------------------
# Basic functionality
# ---------------------------------------------------------------------------


class TestIdxListDetections:
    def test_returns_findings(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 2,
            "findings": [
                _make_finding(
                    "finding-1",
                    doc_ids=["doc-1"],
                    queries=[
                        {
                            "name": "Suspicious Service Install",
                            "tags": ["high", "attack.persistence"],
                        }
                    ],
                ),
                _make_finding(
                    "finding-2",
                    doc_ids=["doc-2", "doc-3"],
                    queries=[{"name": "Mimikatz Detection", "tags": ["critical"]}],
                ),
            ],
        }

        resp = idx_list_detections()
        assert resp["total"] == 2
        assert resp["returned"] == 2
        assert len(resp["findings"]) == 2
        assert resp["findings"][0]["id"] == "finding-1"
        assert resp["findings"][0]["rules"][0]["name"] == "Suspicious Service Install"
        assert resp["findings"][0]["matched_docs"] == 1
        assert resp["findings"][1]["matched_docs"] == 2

    def test_empty_findings(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()

        resp = idx_list_detections()
        assert resp["total"] == 0
        assert resp["returned"] == 0
        assert resp["findings"] == []

    def test_multiple_rules_per_finding(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                _make_finding(
                    queries=[
                        {"name": "Rule A", "tags": ["high"]},
                        {"name": "Rule B", "tags": ["medium"]},
                    ]
                )
            ],
        }

        resp = idx_list_detections()
        assert len(resp["findings"][0]["rules"]) == 2
        assert resp["findings"][0]["rules"][0]["name"] == "Rule A"
        assert resp["findings"][0]["rules"][1]["name"] == "Rule B"

    def test_finding_without_queries(self, mock_client):
        """Finding with empty queries list handled gracefully."""
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(doc_ids=[], queries=[])],
        }

        resp = idx_list_detections()
        assert resp["findings"][0]["rules"] == []
        assert resp["findings"][0]["matched_docs"] == 0


# ---------------------------------------------------------------------------
# API parameters
# ---------------------------------------------------------------------------


class TestDetectionsAPIParams:
    def test_default_params(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections()
        call_kwargs = mock_client.transport.perform_request.call_args
        assert call_kwargs[0][0] == "GET"
        assert "/_plugins/_security_analytics/findings/_search" in call_kwargs[0][1]

    def test_default_shows_all_detector_types(self, mock_client):
        """Default (no detector_type) queries all detectors."""
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections()
        call_args = mock_client.transport.perform_request.call_args
        params = call_args[1].get("params", {})
        assert "detectorType" not in params

    def test_explicit_detector_type_filters(self, mock_client):
        """Explicit detector_type filters to that type."""
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections(detector_type="linux")
        call_args = mock_client.transport.perform_request.call_args
        params = call_args[1].get("params", {})
        assert params["detectorType"] == "linux"

    def test_severity_filter_python_side(self, mock_client):
        """Severity filtering is done in Python (API doesn't support it)."""
        mock_client.transport.perform_request.return_value = {
            "total_findings": 2,
            "findings": [
                _make_finding("f1", queries=[{"name": "R1", "tags": ["high"]}]),
                _make_finding("f2", queries=[{"name": "R2", "tags": ["low"]}]),
            ],
        }
        resp = idx_list_detections(severity="high")
        assert resp["returned"] == 1
        assert resp["findings"][0]["id"] == "f1"

    def test_severity_filter_case_insensitive(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                _make_finding("f1", queries=[{"name": "R1", "tags": ["HIGH"]}]),
            ],
        }
        # Sigma tags are typically lowercase, but test case-insensitive matching
        resp = idx_list_detections(severity="high")
        assert resp["returned"] == 1

    def test_severity_not_in_api_params(self, mock_client):
        """Severity is NOT passed to the API — filtered in Python."""
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections(severity="critical")
        params = mock_client.transport.perform_request.call_args[1].get("params", {})
        assert "severity" not in params

    def test_no_severity_returns_all(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 2,
            "findings": [
                _make_finding("f1", queries=[{"name": "R1", "tags": ["high"]}]),
                _make_finding("f2", queries=[{"name": "R2", "tags": ["low"]}]),
            ],
        }
        resp = idx_list_detections(severity="")
        assert resp["returned"] == 2

    def test_limit_passed_as_size(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections(limit=25)
        params = mock_client.transport.perform_request.call_args[1].get("params", {})
        assert params["size"] == 25

    def test_offset_passed_as_start_index(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections(offset=100)
        params = mock_client.transport.perform_request.call_args[1].get("params", {})
        assert params["startIndex"] == 100

    def test_sort_order_desc(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        idx_list_detections()
        params = mock_client.transport.perform_request.call_args[1].get("params", {})
        assert params["sortOrder"] == "desc"


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------


class TestDetectionsResponseSchema:
    def test_response_has_total(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 42,
            "findings": [],
        }
        resp = idx_list_detections()
        assert resp["total"] == 42

    def test_response_has_returned(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 100,
            "findings": [_make_finding()],
        }
        resp = idx_list_detections()
        assert resp["returned"] == 1

    def test_response_has_offset(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        resp = idx_list_detections(offset=50)
        assert resp["offset"] == 50

    def test_offset_zero_by_default(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        resp = idx_list_detections()
        assert resp["offset"] == 0

    def test_finding_has_id(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(id="abc-123")],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["id"] == "abc-123"

    def test_finding_has_timestamp(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(ts=1708647166500)],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["timestamp"] == 1708647166500

    def test_finding_has_index(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(index="case-inc001-evtx-ws05")],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["index"] == "case-inc001-evtx-ws05"

    def test_finding_has_matched_docs_count(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(doc_ids=["d1", "d2", "d3"])],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["matched_docs"] == 3

    def test_rule_has_name(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                _make_finding(queries=[{"name": "Suspicious Process", "tags": ["high"]}])
            ],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["rules"][0]["name"] == "Suspicious Process"

    def test_rule_has_tags(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                _make_finding(
                    queries=[{"name": "R", "tags": ["high", "attack.persistence", "T1543"]}]
                )
            ],
        }
        resp = idx_list_detections()
        tags = resp["findings"][0]["rules"][0]["tags"]
        assert "high" in tags
        assert "attack.persistence" in tags
        assert "T1543" in tags


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class TestDetectionsAudit:
    def test_audit_id_in_response(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        with patch.object(srv.audit, "log", return_value="audit-789"):
            resp = idx_list_detections()
        assert resp["audit_id"] == "audit-789"

    def test_no_audit_id_when_none(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        with patch.object(srv.audit, "log", return_value=None):
            resp = idx_list_detections()
        assert "audit_id" not in resp

    def test_audit_params_recorded(self, mock_client):
        mock_client.transport.perform_request.return_value = _empty_response()
        with patch.object(srv.audit, "log", return_value="a1") as mock_log:
            idx_list_detections(severity="critical", limit=10, offset=20)
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["tool"] == "idx_list_detections"
        assert call_kwargs["params"]["severity"] == "critical"
        assert call_kwargs["params"]["limit"] == 10
        assert call_kwargs["params"]["offset"] == 20

    def test_audit_summary_count(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 3,
            "findings": [_make_finding(), _make_finding(id="f2"), _make_finding(id="f3")],
        }
        with patch.object(srv.audit, "log", return_value="a1") as mock_log:
            idx_list_detections()
        assert mock_log.call_args[1]["result_summary"] == "3 findings"


# ---------------------------------------------------------------------------
# Edge cases & robustness
# ---------------------------------------------------------------------------


class TestDetectionsEdgeCases:
    def test_missing_related_doc_ids(self, mock_client):
        """Finding without related_doc_ids key."""
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                {
                    "id": "f1",
                    "timestamp": 123,
                    "index": "idx",
                    "queries": [],
                    # no related_doc_ids
                }
            ],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["matched_docs"] == 0

    def test_missing_queries_key(self, mock_client):
        """Finding without queries key."""
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                {
                    "id": "f1",
                    "timestamp": 123,
                    "index": "idx",
                    "related_doc_ids": ["d1"],
                    # no queries
                }
            ],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["rules"] == []

    def test_missing_total_findings(self, mock_client):
        """Response without total_findings key."""
        mock_client.transport.perform_request.return_value = {
            "findings": [_make_finding()],
        }
        resp = idx_list_detections()
        assert resp["total"] == 0
        assert resp["returned"] == 1

    def test_query_missing_tags(self, mock_client):
        """Query without tags key gets empty list."""
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(queries=[{"name": "Rule"}])],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["rules"][0]["tags"] == []

    def test_query_missing_name(self, mock_client):
        """Query without name key gets None."""
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [_make_finding(queries=[{"tags": ["high"]}])],
        }
        resp = idx_list_detections()
        assert resp["findings"][0]["rules"][0]["name"] is None

    def test_connection_error_propagates(self, mock_client):
        """RuntimeError from _os_call propagates to caller."""
        mock_client.transport.perform_request.side_effect = RuntimeError("connection lost")
        # _os_call wraps connection errors as RuntimeError
        with patch("opensearch_mcp.server._os_call", side_effect=RuntimeError("Lost connection")):
            with pytest.raises(RuntimeError, match="Lost connection"):
                idx_list_detections()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestDetectionsToolRegistration:
    def test_tool_exists_in_server(self):
        """idx_list_detections is registered as an MCP tool."""
        assert hasattr(srv, "idx_list_detections")

    def test_tool_count(self):
        """All idx_* tools registered."""
        import inspect

        tool_names = [
            name
            for name, obj in inspect.getmembers(srv)
            if callable(obj) and name.startswith("idx_") and not name.startswith("_")
        ]
        # 17 original + idx_shard_status (shard-capacity) + idx_install_pipelines (Fix G)
        assert len(tool_names) == 19
