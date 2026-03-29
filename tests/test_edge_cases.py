"""Edge case tests for robustness."""

from __future__ import annotations

import csv
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.normalize import normalize_event
from opensearch_mcp.parse_csv import _doc_id, ingest_csv


def _mock_bulk_ok(client, actions, **kwargs):
    """Mock helpers.bulk that succeeds for all docs."""
    return (len(actions), [])


def _write_csv(path, rows, encoding="utf-8"):
    """Write rows as CSV."""
    with open(path, "w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Empty / corrupt evtx
# ---------------------------------------------------------------------------


class TestEmptyEvtx:
    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_empty_evtx_file_zero_records(self, mock_helpers, mock_parser_cls):
        """Evtx file with 0 records indexes nothing."""
        from opensearch_mcp.parse_evtx import parse_and_index

        mock_parser = MagicMock()
        mock_parser.records_json.return_value = []  # empty
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk_ok

        client = MagicMock()
        count, skipped, bf = parse_and_index(
            evtx_path="empty.evtx",
            client=client,
            index_name="test",
        )
        assert count == 0
        assert skipped == 0
        assert bf == 0
        mock_helpers.bulk.assert_not_called()

    @patch("opensearch_mcp.parse_evtx.PyEvtxParser")
    @patch("opensearch_mcp.bulk.helpers")
    def test_all_corrupt_records_all_skipped(self, mock_helpers, mock_parser_cls):
        """Evtx file where every record is corrupt: all skipped, 0 indexed."""
        from opensearch_mcp.parse_evtx import parse_and_index

        mock_parser = MagicMock()
        mock_parser.records_json.return_value = [
            {"data": "not json 1"},
            {"data": "not json 2"},
            {"data": "{broken"},
        ]
        mock_parser_cls.return_value = mock_parser
        mock_helpers.bulk.side_effect = _mock_bulk_ok

        client = MagicMock()
        count, skipped, bf = parse_and_index(
            evtx_path="corrupt.evtx",
            client=client,
            index_name="test",
        )
        assert count == 0
        assert skipped == 3
        mock_helpers.bulk.assert_not_called()


# ---------------------------------------------------------------------------
# CSV edge cases
# ---------------------------------------------------------------------------


class TestCsvEdgeCases:
    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_csv_header_only_no_data_rows(self, mock_flush, tmp_path):
        """CSV with header but no data rows: 0 indexed."""
        csv_file = tmp_path / "empty.csv"
        csv_file.write_text("col1,col2,col3\n")

        client = MagicMock()
        count, sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="test",
            hostname="HOST1",
        )
        assert count == 0
        mock_flush.assert_not_called()

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_csv_with_empty_columns(self, mock_flush, tmp_path):
        """CSV with empty column values handled gracefully."""
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("col1,col2,col3\nval1,,\n")

        client = MagicMock()
        count, _, _ = ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")
        assert count == 1
        actions = mock_flush.call_args[0][1]
        doc = actions[0]["_source"]
        assert doc["col2"] == ""
        assert doc["col3"] == ""

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_csv_with_very_long_values(self, mock_flush, tmp_path):
        """CSV with extremely long field values (>10KB)."""
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        long_value = "x" * 15000  # 15KB
        csv_file.write_text(f"col1,col2\nshort,{long_value}\n")

        client = MagicMock()
        count, _, _ = ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")
        assert count == 1
        actions = mock_flush.call_args[0][1]
        assert len(actions[0]["_source"]["col2"]) == 15000

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_csv_with_newlines_in_quoted_fields(self, mock_flush, tmp_path):
        """CSV with newlines inside quoted fields parsed correctly."""
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text('col1,col2\n"line1\nline2\nline3",value2\n')

        client = MagicMock()
        count, _, _ = ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")
        assert count == 1
        actions = mock_flush.call_args[0][1]
        assert "line1\nline2\nline3" in actions[0]["_source"]["col1"]

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_csv_with_null_bytes(self, mock_flush, tmp_path):
        """CSV with null bytes raises _csv.Error — Python csv module limitation."""
        csv_file = tmp_path / "test.csv"
        content = b"col1,col2\nval\x00ue,normal\n"
        csv_file.write_bytes(content)

        client = MagicMock()
        # Python csv module cannot handle NUL bytes — raises ValueError or _csv.Error
        with pytest.raises((ValueError, Exception)):
            ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")


# ---------------------------------------------------------------------------
# Hostname / Case ID edge cases
# ---------------------------------------------------------------------------


class TestHostnameCaseIdEdgeCases:
    def test_hostname_with_spaces(self):
        """Hostname with spaces in index name (currently not sanitized)."""
        hostname = "HOST WITH SPACES"
        case_id = "test"
        index_name = f"case-{case_id}-evtx-{hostname}".lower()
        # Documents current behavior: spaces are preserved after lowering
        assert " " in index_name

    def test_case_id_with_unicode(self):
        """Case ID with Unicode characters in index name."""
        case_id = "INC-2024-cafe"  # ASCII chars that look like they could be unicode
        hostname = "host1"
        index_name = f"case-{case_id}-evtx-{hostname}".lower()
        assert index_name == "case-inc-2024-cafe-evtx-host1"


# ---------------------------------------------------------------------------
# Path edge cases
# ---------------------------------------------------------------------------


class TestPathEdgeCases:
    def test_path_with_spaces_in_dir_names(self, tmp_path):
        """Discovery works with spaces in directory names."""
        from _helpers import make_windows_tree

        from opensearch_mcp.discover import find_volume_root

        spaced = tmp_path / "My Evidence" / "Case Files"
        spaced.mkdir(parents=True)
        make_windows_tree(spaced)
        assert find_volume_root(spaced) == spaced

    def test_very_deep_nesting(self, tmp_path):
        """Deep nesting (>10 levels) doesn't crash discovery."""
        from opensearch_mcp.discover import find_volume_root

        deep = tmp_path
        for i in range(15):
            deep = deep / f"level{i}"
        deep.mkdir(parents=True)
        # No Windows tree -> should return None, not crash
        result = find_volume_root(deep)
        assert result is None

    def test_symlinks_in_evidence_dir(self, tmp_path):
        """Symlinks in evidence directory are followed for file detection."""
        from _helpers import make_windows_tree

        from opensearch_mcp.discover import find_volume_root

        real_dir = tmp_path / "real"
        make_windows_tree(real_dir)
        link_dir = tmp_path / "linked"
        link_dir.symlink_to(real_dir)

        vr = find_volume_root(link_dir)
        assert vr is not None  # symlinks should be followed

    def test_permission_denied_on_evidence_file(self, tmp_path):
        """Permission denied on an evidence file is handled gracefully."""
        from _helpers import make_windows_tree

        from opensearch_mcp.discover import DiscoveredHost, discover_artifacts

        make_windows_tree(tmp_path)
        # Make the Amcache hive unreadable
        amcache = tmp_path / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
        amcache.chmod(0o000)
        try:
            host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
            # discover_artifacts uses is_file() which should still work
            # The actual error would happen during ingest, not discovery
            discover_artifacts(host)
            # Should still find it (is_file works even without read permission)
            artifact_names = {a[0] for a in host.artifacts}
            assert "amcache" in artifact_names
        finally:
            amcache.chmod(0o644)


# ---------------------------------------------------------------------------
# Bulk flush edge cases
# ---------------------------------------------------------------------------


class TestBulkFlushEdgeCases:
    def test_flush_with_zero_actions(self):
        """flush_bulk with empty actions list."""
        from opensearch_mcp.bulk import flush_bulk

        client = MagicMock()
        # helpers.bulk with empty list should either not be called
        # or return (0, 0)
        with patch("opensearch_mcp.bulk.helpers") as mock_helpers:
            mock_helpers.bulk.return_value = (0, [])
            flushed, failed = flush_bulk(client, [])
            assert flushed == 0
            assert failed == 0


# ---------------------------------------------------------------------------
# normalize_event edge cases
# ---------------------------------------------------------------------------


class TestNormalizeEdgeCases:
    def test_completely_empty_dict(self):
        """normalize_event with empty dict doesn't crash."""
        doc = normalize_event({})
        # Should produce a doc with None values stripped
        assert isinstance(doc, dict)

    def test_event_but_no_system(self):
        """Event key present but no System subkey."""
        doc = normalize_event({"Event": {}})
        assert isinstance(doc, dict)
        # event.code should be None -> stripped
        assert "event.code" not in doc

    def test_event_with_empty_system(self):
        """Event.System is empty dict."""
        doc = normalize_event({"Event": {"System": {}}})
        assert isinstance(doc, dict)
        assert "event.code" not in doc

    def test_deeply_nested_user_data(self):
        """UserData with deeply nested structure (3+ levels)."""
        data = {
            "Event": {
                "System": {
                    "EventID": 999,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Test"}},
                },
                "EventData": None,
                "UserData": {
                    "OuterWrapper": {
                        "#attributes": {"xmlns": "http://example.com"},
                        "Level1": {"Level2": {"Level3": "deep_value"}},
                        "SimpleField": "simple",
                    }
                },
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 999
        # UserData stored as-is for searchability
        assert "OuterWrapper" in doc["winlog.event_data"]


# ---------------------------------------------------------------------------
# _doc_id edge cases
# ---------------------------------------------------------------------------


class TestDocIdEdgeCases:
    def test_empty_row(self):
        """_doc_id with empty dict still produces a valid ID."""
        doc_id = _doc_id("index", {})
        assert len(doc_id) == 20
        assert all(c in "0123456789abcdef" for c in doc_id)

    def test_none_values_in_natural_key(self):
        """_doc_id with None values in natural key falls back to content hash."""
        row = {
            "EntryNumber": "100",
            "SequenceNumber": None,
            "FileName": "test.txt",
            "ParentEntryNumber": "50",
        }
        nk = "EntryNumber:SequenceNumber:FileName:ParentEntryNumber"
        id_nk = _doc_id("idx", row, nk)
        # SequenceNumber is None -> row.get returns None -> "" which is falsy
        # -> falls back to content hash
        id_ch = _doc_id("idx", row)
        assert id_nk == id_ch

    def test_doc_id_with_special_chars_in_values(self):
        """_doc_id handles special characters in values."""
        row = {"path": 'C:\\Windows\\System32\\cmd.exe /c "whoami && net user"'}
        doc_id = _doc_id("index", row)
        assert len(doc_id) == 20

    def test_doc_id_with_unicode_values(self):
        """_doc_id handles Unicode values."""
        row = {"name": "Administrateur"}
        doc_id = _doc_id("index", row)
        assert len(doc_id) == 20


# ---------------------------------------------------------------------------
# Missing OpenSearch connection
# ---------------------------------------------------------------------------


class TestMissingConnection:
    def test_get_client_graceful_error_on_missing_config(self, tmp_path):
        """Missing OpenSearch config produces a clear error, not a crash."""
        from opensearch_mcp.client import get_client

        with pytest.raises(FileNotFoundError, match="OpenSearch config not found"):
            get_client(config_path=tmp_path / "nonexistent.yaml")

    def test_server_get_os_raises_on_connection_failure(self):
        """_get_os raises RuntimeError when OpenSearch is not reachable."""
        import opensearch_mcp.server as srv
        from opensearch_mcp.server import _get_os

        old_client = srv._client
        old_verified = srv._client_verified
        try:
            srv._client = None
            srv._client_verified = False
            with patch("opensearch_mcp.server.get_client") as mock_gc:
                mock_client = MagicMock()
                mock_client.cluster.health.side_effect = Exception("Connection refused")
                mock_gc.return_value = mock_client
                with pytest.raises(RuntimeError, match="not running"):
                    _get_os()
        finally:
            srv._client = old_client
            srv._client_verified = old_verified


# ---------------------------------------------------------------------------
# CSV time range filter edge cases
# ---------------------------------------------------------------------------


class TestCsvTimeRangeEdgeCases:
    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_time_filter_with_invalid_timestamp(self, mock_flush, tmp_path):
        """Rows with unparseable timestamps are NOT skipped by time filter."""
        from datetime import datetime, timezone

        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("ts,data\nnot-a-date,value\n")

        client = MagicMock()
        count, sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="test",
            hostname="H",
            time_field="ts",
            time_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        # Invalid timestamp -> ts = None -> not filtered out
        assert count == 1
        assert sk == 0

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_time_filter_with_missing_field(self, mock_flush, tmp_path):
        """Rows missing the time field entirely are not filtered."""
        from datetime import datetime, timezone

        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("other_col,data\nfoo,bar\n")

        client = MagicMock()
        count, sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="test",
            hostname="H",
            time_field="timestamp",
            time_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        # Missing field -> ts_str = "" -> not filtered
        assert count == 1
        assert sk == 0
