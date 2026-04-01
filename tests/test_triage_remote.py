"""Tests for triage_remote.py — the only triage enrichment path."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Response field mapping
# ---------------------------------------------------------------------------


class TestResponseFieldMapping:
    """check_file response fields correctly mapped to triage.* fields."""

    def test_reasons_list_joined_to_string(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\cmd.exe": {
                "verdict": "EXPECTED_LOLBIN",
                "reasons": ["LOLBin", "Known admin tool"],
                "confidence": "high",
                "is_lolbin": True,
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        call_args = client.update_by_query.call_args
        params = call_args.kwargs["body"]["script"]["params"]
        assert params["verdict"] == "EXPECTED_LOLBIN"
        assert params["confidence"] == "high"

    def test_is_lolbin_mapped(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\cmd.exe": {
                "verdict": "EXPECTED_LOLBIN",
                "reasons": [],
                "confidence": "high",
                "is_lolbin": True,
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        script_source = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
        assert "triage.lolbin" in script_source

    def test_confidence_stamped(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\svchost.exe": {
                "verdict": "EXPECTED",
                "reasons": [],
                "confidence": "high",
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        script_source = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
        assert "triage.confidence" in script_source
        params = client.update_by_query.call_args.kwargs["body"]["script"]["params"]
        assert params["confidence"] == "high"

    def test_no_lolbin_when_false(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\Windows\\notepad.exe": {
                "verdict": "EXPECTED",
                "reasons": [],
                "confidence": "medium",
            }
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        script_source = client.update_by_query.call_args.kwargs["body"]["script"]["source"]
        assert "triage.lolbin" not in script_source


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_stops_after_3_failures(self):
        from opensearch_mcp.triage_remote import _enrich_file_artifact

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "aggregations": {
                "paths": {"buckets": [{"key": f"C:\\path{i}.exe"} for i in range(10)]}
            }
        }

        with patch("opensearch_mcp.triage_remote.call_tool", side_effect=Exception("down")):
            result = _enrich_file_artifact(
                mock_client, "test", "case-test-shimcache-*", "Path.keyword", "shimcache"
            )
        assert result["enriched"] == 0
        # Should stop after 3, not try all 10
        assert result["checked"] == 10  # checked = total buckets


# ---------------------------------------------------------------------------
# case_id sanitization
# ---------------------------------------------------------------------------


class TestSanitization:
    def test_case_id_sanitized(self):
        from opensearch_mcp.triage_remote import enrich_remote

        mock_client = MagicMock()
        mock_client.indices.refresh.return_value = {}
        # Registry persistence will try to query — mock to return no results
        mock_client.search.return_value = {"hits": {"hits": []}}
        mock_client.update_by_query.return_value = {"updated": 0}

        with patch("opensearch_mcp.triage_remote.gateway_available", return_value=False):
            enrich_remote(mock_client, "Test Case!@#")

        # Should have called refresh with sanitized case_id
        refresh_call = mock_client.indices.refresh.call_args
        index_arg = refresh_call.kwargs.get("index", "")
        assert "!" not in index_arg
        assert "@" not in index_arg


# ---------------------------------------------------------------------------
# Gateway-unavailable path
# ---------------------------------------------------------------------------


class TestGatewayUnavailable:
    def test_registry_rules_run_without_gateway(self):
        from opensearch_mcp.triage_remote import enrich_remote

        mock_client = MagicMock()
        mock_client.indices.refresh.return_value = {}
        mock_client.update_by_query.return_value = {"updated": 0}

        with patch("opensearch_mcp.triage_remote.gateway_available", return_value=False):
            result = enrich_remote(mock_client, "test-case")

        assert "registry_persistence" in result
        assert "_gateway" in result
        assert "not configured" in result["_gateway"]
        # File/service enrichment should NOT be in results
        assert "shimcache" not in result


# ---------------------------------------------------------------------------
# Batch stamp grouping
# ---------------------------------------------------------------------------


class TestBatchStamp:
    def test_groups_by_verdict(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            "C:\\a.exe": {"verdict": "EXPECTED", "confidence": "high"},
            "C:\\b.exe": {"verdict": "EXPECTED", "confidence": "high"},
            "C:\\c.exe": {"verdict": "SUSPICIOUS", "reasons": ["bad"], "confidence": "low"},
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 1}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        # Should be 2 calls: one for EXPECTED group, one for SUSPICIOUS
        assert client.update_by_query.call_count == 2

    def test_chunks_large_batches(self):
        from opensearch_mcp.triage_remote import _batch_stamp_verdicts

        verdicts = {
            f"C:\\path{i}.exe": {"verdict": "EXPECTED", "confidence": "high"} for i in range(1200)
        }
        client = MagicMock()
        client.update_by_query.return_value = {"updated": 500}
        _batch_stamp_verdicts(client, "case-test-*", "Path.keyword", verdicts)
        # 1200 paths / 500 chunk = 3 calls
        assert client.update_by_query.call_count == 3


# ---------------------------------------------------------------------------
# Non-path filter
# ---------------------------------------------------------------------------


class TestNonPathFilter:
    def test_appx_metadata_skipped(self):
        from opensearch_mcp.triage_remote import _enrich_file_artifact

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "aggregations": {
                "paths": {
                    "buckets": [
                        {"key": "00000009\t00010000a4d00000"},  # AppX metadata
                        {"key": "C:\\Windows\\cmd.exe"},  # real path
                    ]
                }
            }
        }

        call_count = 0

        def mock_call_tool(name, args, timeout=15):
            nonlocal call_count
            call_count += 1
            return {"verdict": "EXPECTED", "confidence": "high"}

        with patch("opensearch_mcp.triage_remote.call_tool", side_effect=mock_call_tool):
            mock_client.update_by_query.return_value = {"updated": 1}
            _enrich_file_artifact(
                mock_client, "test", "case-test-shimcache-*", "Path.keyword", "shimcache"
            )

        # Only the real path should have been checked
        assert call_count == 1
