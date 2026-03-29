"""Tests for parse_evtx module (unit tests, no OpenSearch required)."""

import json
from unittest.mock import MagicMock, patch

from opensearch_mcp.parse_evtx import parse_and_index


def _mock_bulk(client, actions, **kwargs):
    """Mock helpers.bulk that returns (success_count, [])."""
    return (len(actions), [])


def _make_record(
    event_id, channel="Security", computer="TEST01", timestamp="2024-01-15T10:00:00Z"
):
    """Create a mock pyevtx-rs record."""
    return {
        "data": json.dumps(
            {
                "Event": {
                    "System": {
                        "EventID": event_id,
                        "Channel": channel,
                        "Computer": computer,
                        "TimeCreated": {"#attributes": {"SystemTime": timestamp}},
                        "Provider": {"#attributes": {"Name": "TestProvider"}},
                    },
                    "EventData": {"TargetUserName": "testuser"},
                }
            }
        )
    }


class TestParseAndIndex:
    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_basic_indexing(self, mock_helpers, mock_parser_cls):
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [
            _make_record(4624),
            _make_record(4625),
        ]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, skipped, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="case-test-evtx-host1",
        )

        assert count == 2
        assert skipped == 0
        mock_helpers.bulk.assert_called_once()
        actions = mock_helpers.bulk.call_args[0][1]
        assert len(actions) == 2
        assert actions[0]["_index"] == "case-test-evtx-host1"
        assert actions[0]["_source"]["event.code"] == 4624

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_missing_data_key_skipped(self, mock_helpers, mock_parser_cls):
        """Record missing 'data' key entirely should be skipped, not abort."""
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [
            {"event_record_id": 1, "timestamp": "2024-01-01T00:00:00Z"},  # no "data" key
            _make_record(4624),
        ]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, skipped, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="case-test-evtx-host1",
        )

        assert count == 1
        assert skipped == 1

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_corrupt_record_skipped(self, mock_helpers, mock_parser_cls):
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [
            {"data": "not valid json"},
            _make_record(4624),
        ]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, skipped, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="case-test-evtx-host1",
        )

        assert count == 1
        assert skipped == 1

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_time_range_filter(self, mock_helpers, mock_parser_cls):
        from datetime import datetime, timezone

        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [
            _make_record(4624, timestamp="2024-01-10T00:00:00Z"),  # before range
            _make_record(4624, timestamp="2024-01-15T12:00:00Z"),  # in range
            _make_record(4624, timestamp="2024-01-20T00:00:00Z"),  # after range
        ]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, _, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="test",
            time_from=datetime(2024, 1, 14, tzinfo=timezone.utc),
            time_to=datetime(2024, 1, 16, tzinfo=timezone.utc),
        )

        assert count == 1

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_reduced_ids_filter(self, mock_helpers, mock_parser_cls):
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [
            _make_record(4624),  # in reduced set
            _make_record(4688),  # in reduced set
            _make_record(1000),  # not in reduced set
        ]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, _, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="test",
            reduced_ids={4624, 4688},
        )

        assert count == 2

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_bulk_batching(self, mock_helpers, mock_parser_cls):
        """Bulk is called every 1000 records."""
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [_make_record(4624) for _ in range(2500)]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, _, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="test",
        )

        assert count == 2500
        # 2 full batches of 1000 + 1 final batch of 500
        assert mock_helpers.bulk.call_count == 3

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_provenance_fields_injected(self, mock_helpers, mock_parser_cls):
        """Every doc should have pipeline_version, source_file, ingest_audit_id."""
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [_make_record(4624)]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, _, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="test",
            source_file="/evidence/Security.evtx",
            ingest_audit_id="opensearch-steve-20260329-001",
        )

        assert count == 1
        actions = mock_helpers.bulk.call_args[0][1]
        doc = actions[0]["_source"]
        assert doc["vhir.source_file"] == "/evidence/Security.evtx"
        assert doc["vhir.ingest_audit_id"] == "opensearch-steve-20260329-001"
        assert "pipeline_version" in doc
        assert doc["pipeline_version"].startswith("opensearch-mcp-")

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_provenance_fields_optional(self, mock_helpers, mock_parser_cls):
        """Without source_file/audit_id, docs still index (backward compat)."""
        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [_make_record(4624)]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk

        client = MagicMock()
        count, _, _bf = parse_and_index(
            evtx_path="test.evtx",
            client=client,
            index_name="test",
        )

        assert count == 1
        actions = mock_helpers.bulk.call_args[0][1]
        doc = actions[0]["_source"]
        assert "pipeline_version" in doc
        assert "vhir.source_file" not in doc
        assert "vhir.ingest_audit_id" not in doc
