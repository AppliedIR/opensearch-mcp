"""Tests for idx_list_detections tool."""

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


class TestIdxListDetections:
    def test_returns_findings(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 2,
            "findings": [
                {
                    "id": "finding-1",
                    "timestamp": 1708647166500,
                    "index": "case-inc001-evtx-wkstn05",
                    "related_doc_ids": ["doc-1"],
                    "queries": [
                        {
                            "name": "Suspicious Service Install",
                            "tags": ["high", "attack.persistence"],
                        }
                    ],
                },
                {
                    "id": "finding-2",
                    "timestamp": 1708647200000,
                    "index": "case-inc001-evtx-wkstn05",
                    "related_doc_ids": ["doc-2", "doc-3"],
                    "queries": [
                        {
                            "name": "Mimikatz Detection",
                            "tags": ["critical", "attack.credential_access"],
                        }
                    ],
                },
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
        mock_client.transport.perform_request.return_value = {
            "total_findings": 0,
            "findings": [],
        }

        resp = idx_list_detections()
        assert resp["total"] == 0
        assert resp["returned"] == 0
        assert resp["findings"] == []

    def test_severity_filter_passed(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 0,
            "findings": [],
        }

        idx_list_detections(severity="high")
        call_args = mock_client.transport.perform_request.call_args
        assert "high" in str(call_args)

    def test_pagination_offset(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 100,
            "findings": [],
        }

        resp = idx_list_detections(limit=10, offset=50)
        assert resp["offset"] == 50

    def test_audit_id_in_response(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 0,
            "findings": [],
        }

        with patch.object(srv.audit, "log", return_value="audit-789"):
            resp = idx_list_detections()
        assert resp["audit_id"] == "audit-789"

    def test_multiple_rules_per_finding(self, mock_client):
        mock_client.transport.perform_request.return_value = {
            "total_findings": 1,
            "findings": [
                {
                    "id": "finding-1",
                    "timestamp": 1708647166500,
                    "index": "case-test-evtx-host1",
                    "related_doc_ids": ["doc-1"],
                    "queries": [
                        {"name": "Rule A", "tags": ["high"]},
                        {"name": "Rule B", "tags": ["medium"]},
                    ],
                }
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
            "findings": [
                {
                    "id": "finding-1",
                    "timestamp": 1708647166500,
                    "index": "case-test-evtx-host1",
                    "related_doc_ids": [],
                    "queries": [],
                }
            ],
        }

        resp = idx_list_detections()
        assert resp["findings"][0]["rules"] == []
        assert resp["findings"][0]["matched_docs"] == 0
