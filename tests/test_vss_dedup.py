"""Tests for VSS dedup behavior across parse_csv and parse_evtx."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opensearch_mcp.parse_csv import _VOLATILE_KEYS, _doc_id


class TestVssVolatileKeys:
    def test_vss_id_in_volatile_keys(self):
        assert "vhir.vss_id" in _VOLATILE_KEYS

    def test_same_content_different_vss_id_same_hash(self):
        """Content-hash tools: identical rows across VSS collapse to one doc."""
        row1 = {"Path": "C:\\evil.exe", "vhir.vss_id": "live"}
        row2 = {"Path": "C:\\evil.exe", "vhir.vss_id": "vss1"}
        id1 = _doc_id("idx", row1, volatile_keys=_VOLATILE_KEYS)
        id2 = _doc_id("idx", row2, volatile_keys=_VOLATILE_KEYS)
        assert id1 == id2

    def test_different_content_different_vss_id_different_hash(self):
        """Modified content across VSS versions produces different doc IDs."""
        row1 = {"Path": "C:\\evil.exe", "vhir.vss_id": "live"}
        row2 = {"Path": "C:\\good.exe", "vhir.vss_id": "vss1"}
        id1 = _doc_id("idx", row1, volatile_keys=_VOLATILE_KEYS)
        id2 = _doc_id("idx", row2, volatile_keys=_VOLATILE_KEYS)
        assert id1 != id2


class TestMftVssNaturalKey:
    def test_mft_natural_key_with_vss_preserves_different_versions(self):
        """MFT entries from different VSS versions with same E:S:F:P but different
        vss_id get different natural key IDs when vss_id is in the key."""
        nk = "EntryNumber:SequenceNumber:FileName:ParentEntryNumber:vhir.vss_id"
        row1 = {
            "EntryNumber": "100",
            "SequenceNumber": "5",
            "FileName": "evil.exe",
            "ParentEntryNumber": "50",
            "vhir.vss_id": "live",
        }
        row2 = {
            "EntryNumber": "100",
            "SequenceNumber": "5",
            "FileName": "evil.exe",
            "ParentEntryNumber": "50",
            "vhir.vss_id": "vss1",
        }
        id1 = _doc_id("idx", row1, natural_key=nk, volatile_keys=_VOLATILE_KEYS)
        id2 = _doc_id("idx", row2, natural_key=nk, volatile_keys=_VOLATILE_KEYS)
        assert id1 != id2

    def test_mft_natural_key_without_vss_same_id(self):
        """MFT entries without VSS use 4-field key and produce same ID."""
        nk = "EntryNumber:SequenceNumber:FileName:ParentEntryNumber"
        row1 = {
            "EntryNumber": "100",
            "SequenceNumber": "5",
            "FileName": "test.exe",
            "ParentEntryNumber": "50",
        }
        row2 = {
            "EntryNumber": "100",
            "SequenceNumber": "5",
            "FileName": "test.exe",
            "ParentEntryNumber": "50",
        }
        assert _doc_id("idx", row1, natural_key=nk) == _doc_id("idx", row2, natural_key=nk)

    def test_ordering_natural_key_before_volatile_stripping(self):
        """Natural key check happens before volatile key stripping.
        vhir.vss_id is in _VOLATILE_KEYS but used as natural key component.
        The natural key path returns early, so volatile stripping never runs."""
        nk = "EntryNumber:vhir.vss_id"
        row = {"EntryNumber": "100", "vhir.vss_id": "vss1", "other": "data"}
        # This should use the natural key path (not content hash)
        id_nk = _doc_id("idx", row, natural_key=nk, volatile_keys=_VOLATILE_KEYS)
        # The natural key should include vss_id
        id_no_nk = _doc_id("idx", row, volatile_keys=_VOLATILE_KEYS)
        # They should be different because one uses natural key, other uses content hash
        assert id_nk != id_no_nk


class TestIngestCsvVssId:
    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_vss_id_injected_into_rows(self, mock_flush, tmp_path):
        """ingest_csv with vss_id sets vhir.vss_id on every row."""
        from opensearch_mcp.parse_csv import ingest_csv

        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("col1,col2\nval1,val2\n")

        client = MagicMock()
        ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name="test",
            hostname="HOST1",
            vss_id="vss2",
        )
        actions = mock_flush.call_args[0][1]
        assert actions[0]["_source"]["vhir.vss_id"] == "vss2"

    @patch("opensearch_mcp.parse_csv.flush_bulk")
    def test_no_vss_id_when_empty(self, mock_flush, tmp_path):
        """ingest_csv without vss_id does not set vhir.vss_id."""
        from opensearch_mcp.parse_csv import ingest_csv

        mock_flush.return_value = (1, 0)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("col1,col2\nval1,val2\n")

        client = MagicMock()
        ingest_csv(csv_path=csv_file, client=client, index_name="test", hostname="H")
        actions = mock_flush.call_args[0][1]
        assert "vhir.vss_id" not in actions[0]["_source"]
