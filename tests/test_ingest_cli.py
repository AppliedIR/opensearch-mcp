"""Tests for CLI argument parsing and command dispatch (ingest_cli.py)."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.ingest_cli import (
    _parse_date,
    _parse_set,
    _resolve_case_id,
    main,
)


# ---------------------------------------------------------------------------
# _resolve_case_id
# ---------------------------------------------------------------------------


class TestResolveCaseId:
    def test_from_case_flag(self):
        """--case flag value returned directly."""
        assert _resolve_case_id("INC-2024-001") == "INC-2024-001"

    def test_from_active_case_file(self, tmp_path, monkeypatch):
        """Reads case ID from active_case file."""
        active_case = tmp_path / "active_case"
        active_case.write_text("INC-FROM-FILE\n")
        monkeypatch.setattr("opensearch_mcp.ingest_cli._ACTIVE_CASE_FILE", active_case)
        assert _resolve_case_id(None) == "INC-FROM-FILE"

    def test_absolute_path_in_active_case_extracts_dir_name(self, tmp_path, monkeypatch):
        """Absolute path in active_case → extracts the directory name."""
        active_case = tmp_path / "active_case"
        active_case.write_text("/home/user/cases/INC-2024-003\n")
        monkeypatch.setattr("opensearch_mcp.ingest_cli._ACTIVE_CASE_FILE", active_case)
        assert _resolve_case_id(None) == "INC-2024-003"

    def test_missing_both_exits(self, tmp_path, monkeypatch):
        """No --case flag and no active_case file → sys.exit(1)."""
        monkeypatch.setattr(
            "opensearch_mcp.ingest_cli._ACTIVE_CASE_FILE",
            tmp_path / "nonexistent",
        )
        with pytest.raises(SystemExit) as exc:
            _resolve_case_id(None)
        assert exc.value.code == 1

    def test_empty_active_case_file_exits(self, tmp_path, monkeypatch):
        """active_case file exists but is empty → sys.exit(1)."""
        active_case = tmp_path / "active_case"
        active_case.write_text("   \n")
        monkeypatch.setattr("opensearch_mcp.ingest_cli._ACTIVE_CASE_FILE", active_case)
        with pytest.raises(SystemExit) as exc:
            _resolve_case_id(None)
        assert exc.value.code == 1

    def test_case_flag_takes_precedence_over_file(self, tmp_path, monkeypatch):
        """--case flag takes precedence even when active_case file exists."""
        active_case = tmp_path / "active_case"
        active_case.write_text("FROM-FILE\n")
        monkeypatch.setattr("opensearch_mcp.ingest_cli._ACTIVE_CASE_FILE", active_case)
        assert _resolve_case_id("FROM-FLAG") == "FROM-FLAG"


# ---------------------------------------------------------------------------
# _parse_date
# ---------------------------------------------------------------------------


class TestParseDate:
    def test_iso_date_string(self):
        """Full ISO datetime string parsed correctly."""
        dt = _parse_date("2024-01-15T10:30:00+00:00")
        assert dt == datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

    def test_date_only_string_adds_utc(self):
        """Date-only string (no time/tz) gets UTC added."""
        dt = _parse_date("2024-01-15")
        assert dt.tzinfo == timezone.utc
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15

    def test_datetime_without_tz_gets_utc(self):
        """Datetime without timezone gets UTC assigned."""
        dt = _parse_date("2024-06-15T14:30:00")
        assert dt.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# _parse_set
# ---------------------------------------------------------------------------


class TestParseSet:
    def test_comma_separated(self):
        result = _parse_set("mft,usn,timeline")
        assert result == {"mft", "usn", "timeline"}

    def test_strips_whitespace(self):
        result = _parse_set(" mft , usn ")
        assert result == {"mft", "usn"}

    def test_lowercases(self):
        result = _parse_set("MFT,USN")
        assert result == {"mft", "usn"}

    def test_none_returns_none(self):
        assert _parse_set(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_set("") is None


# ---------------------------------------------------------------------------
# CLI argument parsing via main()
# ---------------------------------------------------------------------------


class TestCliParsing:
    def test_scan_subcommand_requires_path(self):
        """scan subcommand fails without path argument."""
        with patch("sys.argv", ["opensearch-ingest", "scan"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 2  # argparse error

    def test_csv_subcommand_requires_tool_and_path(self):
        """csv subcommand fails without tool_name and csv_path."""
        with patch("sys.argv", ["opensearch-ingest", "csv"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 2

    def test_csv_subcommand_requires_hostname(self):
        """csv subcommand fails without --hostname."""
        with patch("sys.argv", ["opensearch-ingest", "csv", "amcache", "/tmp/test.csv"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 2

    def test_no_subcommand_exits(self):
        """No subcommand prints help and exits with code 1."""
        with patch("sys.argv", ["opensearch-ingest"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    @patch("opensearch_mcp.ingest_cli.cmd_csv")
    def test_csv_with_unknown_tool_name_calls_cmd_csv(self, mock_cmd):
        """CSV subcommand dispatches to cmd_csv even with unknown tool."""
        # cmd_csv itself validates the tool name and exits
        with patch("sys.argv", [
            "opensearch-ingest", "csv", "bogus_tool", "/tmp/test.csv",
            "--hostname", "HOST1",
        ]):
            main()
        mock_cmd.assert_called_once()

    @patch("opensearch_mcp.ingest_cli.cmd_scan")
    def test_scan_with_include_exclude_flags(self, mock_cmd):
        """--include and --exclude flags are parsed correctly."""
        with patch("sys.argv", [
            "opensearch-ingest", "scan", "/tmp/evidence",
            "--include", "mft,usn",
            "--exclude", "jumplists",
        ]):
            main()
        mock_cmd.assert_called_once()
        args = mock_cmd.call_args[0][0]
        assert args.include == "mft,usn"
        assert args.exclude == "jumplists"

    @patch("opensearch_mcp.ingest_cli.cmd_scan")
    def test_scan_with_yes_flag(self, mock_cmd):
        """--yes flag parsed correctly."""
        with patch("sys.argv", [
            "opensearch-ingest", "scan", "/tmp/evidence", "--yes",
        ]):
            main()
        args = mock_cmd.call_args[0][0]
        assert args.yes is True

    @patch("opensearch_mcp.ingest_cli.cmd_scan")
    def test_scan_with_hostname_flag(self, mock_cmd):
        """--hostname flag parsed correctly."""
        with patch("sys.argv", [
            "opensearch-ingest", "scan", "/tmp/evidence", "--hostname", "MYHOST",
        ]):
            main()
        args = mock_cmd.call_args[0][0]
        assert args.hostname == "MYHOST"


# ---------------------------------------------------------------------------
# cmd_csv tool name validation
# ---------------------------------------------------------------------------


class TestCmdCsvValidation:
    def test_unknown_tool_name_exits(self, tmp_path, monkeypatch):
        """Unknown tool name in csv subcommand exits with error."""
        from opensearch_mcp.ingest_cli import cmd_csv

        csv_file = tmp_path / "test.csv"
        csv_file.write_text("col1\nval1\n")

        args = argparse.Namespace(
            tool_name="bogus_tool",
            csv_path=str(csv_file),
            hostname="HOST1",
            case=None,
            examiner=None,
        )

        with pytest.raises(SystemExit) as exc:
            cmd_csv(args)
        assert exc.value.code == 1

    def test_missing_csv_file_exits(self, tmp_path, monkeypatch):
        """Non-existent CSV path exits with error."""
        from opensearch_mcp.ingest_cli import cmd_csv

        args = argparse.Namespace(
            tool_name="amcache",
            csv_path=str(tmp_path / "nonexistent.csv"),
            hostname="HOST1",
            case=None,
            examiner=None,
        )

        with pytest.raises(SystemExit) as exc:
            cmd_csv(args)
        assert exc.value.code == 1
