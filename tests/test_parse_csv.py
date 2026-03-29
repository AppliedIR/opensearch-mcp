"""Tests for CSV ingest module."""

import csv
from unittest.mock import MagicMock, patch

from opensearch_mcp.parse_csv import _detect_encoding, _doc_id, ingest_csv


class TestDetectEncoding:
    def test_utf8_bom(self, tmp_path):
        f = tmp_path / "test.csv"
        f.write_bytes(b"\xef\xbb\xbfcol1,col2\nval1,val2\n")
        assert _detect_encoding(f) == "utf-8-sig"

    def test_utf16le_bom(self, tmp_path):
        f = tmp_path / "test.csv"
        content = "col1,col2\nval1,val2\n"
        f.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))
        assert _detect_encoding(f) == "utf-16"

    def test_utf16be_bom(self, tmp_path):
        f = tmp_path / "test.csv"
        content = "col1,col2\nval1,val2\n"
        f.write_bytes(b"\xfe\xff" + content.encode("utf-16-be"))
        assert _detect_encoding(f) == "utf-16"

    def test_plain_utf8(self, tmp_path):
        f = tmp_path / "test.csv"
        f.write_text("col1,col2\nval1,val2\n")
        assert _detect_encoding(f) == "utf-8-sig"


class TestDocId:
    def test_content_hash_deterministic(self):
        row = {"a": "1", "b": "2"}
        id1 = _doc_id("idx", row)
        id2 = _doc_id("idx", row)
        assert id1 == id2
        assert len(id1) == 20

    def test_different_content_different_id(self):
        assert _doc_id("idx", {"a": "1"}) != _doc_id("idx", {"a": "2"})

    def test_natural_key(self):
        row = {
            "EntryNumber": "100",
            "SequenceNumber": "5",
            "FileName": "test.txt",
            "ParentEntryNumber": "50",
        }
        id1 = _doc_id("idx", row, "EntryNumber:SequenceNumber:FileName:ParentEntryNumber")
        id2 = _doc_id("idx", row, "EntryNumber:SequenceNumber:FileName:ParentEntryNumber")
        assert id1 == id2

    def test_natural_key_fallback_on_missing(self):
        row = {"EntryNumber": "100", "SequenceNumber": "", "other": "data"}
        # SequenceNumber is empty → falls back to content hash
        id_nk = _doc_id("idx", row, "EntryNumber:SequenceNumber")
        id_ch = _doc_id("idx", row)
        assert id_nk == id_ch  # fell back to content hash

    def test_volatile_keys_excluded_from_hash(self):
        """Rows differing only in volatile keys produce the same doc ID."""
        row1 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-abc/out.csv"}
        row2 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-xyz/out.csv"}
        vk = {"PluginDetailFile"}
        assert _doc_id("idx", row1, volatile_keys=vk) == _doc_id("idx", row2, volatile_keys=vk)

    def test_without_volatile_keys_different_hash(self):
        """Without volatile_keys param, differing PluginDetailFile produces different IDs."""
        row1 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-abc/out.csv"}
        row2 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-xyz/out.csv"}
        assert _doc_id("idx", row1) != _doc_id("idx", row2)

    def test_volatile_keys_multiple_fields(self):
        """Multiple volatile keys all excluded."""
        row1 = {"Path": "C:\\a.exe", "PluginDetailFile": "/tmp/a", "SourceFile": "/tmp/x"}
        row2 = {"Path": "C:\\a.exe", "PluginDetailFile": "/tmp/b", "SourceFile": "/tmp/y"}
        vk = {"PluginDetailFile", "SourceFile"}
        assert _doc_id("idx", row1, volatile_keys=vk) == _doc_id("idx", row2, volatile_keys=vk)


class TestIngestCsv:
    def _write_csv(self, path, rows):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_basic_ingest(self, mock_flush, tmp_path):
        mock_flush.return_value = (2, 0)
        csv_file = tmp_path / "test.csv"
        self._write_csv(
            csv_file,
            [
                {"Path": "C:\\evil.exe", "LastModifiedTimeUTC": "2024-01-15"},
                {"Path": "C:\\good.exe", "LastModifiedTimeUTC": "2024-01-16"},
            ],
        )

        client = MagicMock()
        count, sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="case-test-shimcache-host1",
            hostname="HOST1",
        )
        assert count == 2
        assert sk == 0
        assert bf == 0

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_provenance_fields_injected(self, mock_flush, tmp_path):
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        self._write_csv(csv_file, [{"col1": "val1"}])

        client = MagicMock()
        ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="test",
            hostname="HOST1",
            source_file="/evidence/test.csv",
            ingest_audit_id="opensearch-steve-001",
            pipeline_version="opensearch-mcp-0.1.0",
            table_name="AssociatedFileEntries",
        )

        actions = mock_flush.call_args[0][1]
        doc = actions[0]["_source"]
        assert doc["host.name"] == "HOST1"
        assert doc["vhir.source_file"] == "/evidence/test.csv"
        assert doc["vhir.ingest_audit_id"] == "opensearch-steve-001"
        assert doc["pipeline_version"] == "opensearch-mcp-0.1.0"
        assert doc["vhir.table"] == "AssociatedFileEntries"

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_dedup_id_in_action(self, mock_flush, tmp_path):
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        self._write_csv(csv_file, [{"col1": "val1"}])

        client = MagicMock()
        ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")

        actions = mock_flush.call_args[0][1]
        assert "_id" in actions[0]
        assert len(actions[0]["_id"]) == 20

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_utf16le_csv(self, mock_flush, tmp_path):
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        content = "ControlSet,Path\n1,C:\\Windows\n"
        csv_file.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))

        client = MagicMock()
        count, _, _ = ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")
        assert count == 1
        actions = mock_flush.call_args[0][1]
        assert actions[0]["_source"]["ControlSet"] == "1"


# ---------------------------------------------------------------------------
# _VOLATILE_KEYS behavior
# ---------------------------------------------------------------------------


class TestVolatileKeysIngest:
    """Test that _VOLATILE_KEYS strips PluginDetailFile and SourceFile from hash."""

    def _write_csv(self, path, rows):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    def test_volatile_keys_strips_plugin_detail_file(self):
        """_VOLATILE_KEYS includes PluginDetailFile."""
        from opensearch_mcp.parse_csv import _VOLATILE_KEYS

        assert "PluginDetailFile" in _VOLATILE_KEYS

    def test_volatile_keys_strips_source_file(self):
        """_VOLATILE_KEYS includes SourceFile."""
        from opensearch_mcp.parse_csv import _VOLATILE_KEYS

        assert "SourceFile" in _VOLATILE_KEYS

    def test_same_row_different_plugin_detail_file_same_doc_id(self):
        """Same row with different PluginDetailFile produces same _doc_id
        when volatile_keys is applied (as ingest_csv does)."""
        from opensearch_mcp.parse_csv import _VOLATILE_KEYS

        row1 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-aaa/out.csv"}
        row2 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-bbb/out.csv"}
        id1 = _doc_id("idx", row1, volatile_keys=_VOLATILE_KEYS)
        id2 = _doc_id("idx", row2, volatile_keys=_VOLATILE_KEYS)
        assert id1 == id2

    def test_same_row_different_actual_content_different_doc_id(self):
        """Rows with different actual content produce different _doc_id."""
        from opensearch_mcp.parse_csv import _VOLATILE_KEYS

        row1 = {"Path": "C:\\evil.exe", "PluginDetailFile": "/tmp/vhir-aaa/out.csv"}
        row2 = {"Path": "C:\\good.exe", "PluginDetailFile": "/tmp/vhir-aaa/out.csv"}
        id1 = _doc_id("idx", row1, volatile_keys=_VOLATILE_KEYS)
        id2 = _doc_id("idx", row2, volatile_keys=_VOLATILE_KEYS)
        assert id1 != id2

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_ingest_csv_with_table_name(self, mock_flush, tmp_path):
        """ingest_csv with table_name sets vhir.table on every row."""
        mock_flush.return_value = (2, 0)
        csv_file = tmp_path / "test.csv"
        self._write_csv(
            csv_file,
            [
                {"Path": "C:\\a.exe"},
                {"Path": "C:\\b.exe"},
            ],
        )

        client = MagicMock()
        ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="test",
            hostname="HOST1",
            table_name="AssociatedFileEntries",
        )
        actions = mock_flush.call_args[0][1]
        for action in actions:
            assert action["_source"]["vhir.table"] == "AssociatedFileEntries"

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_replacement_char_warning_on_binary_data(self, mock_flush, tmp_path):
        """Binary data decoded with errors='replace' triggers warning."""
        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        # Write a CSV with bytes that decode to replacement character
        # \x80 is invalid UTF-8 start byte, will become \ufffd with errors='replace'
        csv_file.write_bytes(b"col1,col2\nval\x80ue,normal\n")

        client = MagicMock()
        import io

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            ingest_csv(
                csv_path=csv_file,
                client=client,
                index_name="test",
                hostname="H",
            )

        output = stderr_capture.getvalue()
        assert "Replacement chars" in output or "replacement" in output.lower()
