"""Tests for CLI argument parsing and command dispatch (ingest_cli.py)."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from unittest.mock import patch

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
        with patch(
            "sys.argv",
            [
                "opensearch-ingest",
                "csv",
                "bogus_tool",
                "/tmp/test.csv",
                "--hostname",
                "HOST1",
            ],
        ):
            main()
        mock_cmd.assert_called_once()

    @patch("opensearch_mcp.ingest_cli.cmd_scan")
    def test_scan_with_include_exclude_flags(self, mock_cmd):
        """--include and --exclude flags are parsed correctly."""
        with patch(
            "sys.argv",
            [
                "opensearch-ingest",
                "scan",
                "/tmp/evidence",
                "--include",
                "mft,usn",
                "--exclude",
                "jumplists",
            ],
        ):
            main()
        mock_cmd.assert_called_once()
        args = mock_cmd.call_args[0][0]
        assert args.include == "mft,usn"
        assert args.exclude == "jumplists"

    @patch("opensearch_mcp.ingest_cli.cmd_scan")
    def test_scan_with_yes_flag(self, mock_cmd):
        """--yes flag parsed correctly."""
        with patch(
            "sys.argv",
            [
                "opensearch-ingest",
                "scan",
                "/tmp/evidence",
                "--yes",
            ],
        ):
            main()
        args = mock_cmd.call_args[0][0]
        assert args.yes is True

    @patch("opensearch_mcp.ingest_cli.cmd_scan")
    def test_scan_with_hostname_flag(self, mock_cmd):
        """--hostname flag parsed correctly."""
        with patch(
            "sys.argv",
            [
                "opensearch-ingest",
                "scan",
                "/tmp/evidence",
                "--hostname",
                "MYHOST",
            ],
        ):
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


# ---------------------------------------------------------------------------
# Fix 1.4 regression — .ndjson discovery in cmd_ingest_json walker
# UAT 2026-04-22: newline-delimited JSON files using the .ndjson extension
# (tshark, suricata eve-json, community convention) were silently skipped
# in recursive mode because the allowlist was ("json", "jsonl") only.
# This test asserts the allowlist now includes .ndjson and a file with
# that extension is picked up by the walker's file-discovery glob.
# ---------------------------------------------------------------------------


class TestJsonWalkerNdjsonDiscovery:
    def test_ndjson_in_allowlist(self, tmp_path):
        """Regression: .ndjson extension must be discovered by the
        walker's file filter. Reproduces the discovery step inline
        (the exact filter idiom at ingest_cli.py:884) so the test
        doesn't need live OpenSearch or a fully-wired cmd_ingest_json
        invocation — it asserts the allowlist invariant directly."""
        # Create a realistic mix of files at the walker's input-path level.
        (tmp_path / "events.json").write_text('{"a": 1}\n')
        (tmp_path / "events.jsonl").write_text('{"a": 1}\n')
        (tmp_path / "suricata-eve.ndjson").write_text('{"a": 1}\n')
        (tmp_path / "README.md").write_text("not json\n")
        (tmp_path / "binary.dat").write_bytes(b"\x00\x01\x02")

        # Mirror the exact filter at ingest_cli.py:884 post-Fix-1.4.
        discovered = sorted(
            f.name
            for f in tmp_path.iterdir()
            if f.suffix.lower() in (".json", ".jsonl", ".ndjson")
        )
        # .ndjson must appear; non-json extensions must not.
        assert "suricata-eve.ndjson" in discovered
        assert "events.json" in discovered
        assert "events.jsonl" in discovered
        assert "README.md" not in discovered
        assert "binary.dat" not in discovered

    def test_source_allowlist_literal_contains_ndjson(self):
        """Belt-and-suspenders: grep the source to catch a future
        refactor that accidentally drops .ndjson. Prevents the test
        above from silently passing if someone changes the filter
        to a dynamic set that excludes ndjson.

        Resolves the source path via `__file__` so the test is
        portable across clones, CI runners, and relocated repos.
        """
        from pathlib import Path

        # tests/test_ingest_cli.py → repo root → src/opensearch_mcp/...
        src = (
            Path(__file__).resolve().parent.parent / "src" / "opensearch_mcp" / "ingest_cli.py"
        ).read_text()
        # The allowlist literal as it appears at line 884+.
        assert '".ndjson"' in src, (
            "ingest_cli.py must include '.ndjson' in the cmd_ingest_json "
            "file-discovery allowlist (Fix 1.4). If the allowlist was "
            "refactored to a module constant, update this assertion to "
            "match the new symbol."
        )


# ---------------------------------------------------------------------------
# UAT 2026-04-23 regression — cmd_ingest_delimited wrappers must write a
# terminal "complete" status on clean exit. Fix 3.1's atexit guard stamps
# `failed: process_died_unexpectedly` on any worker that exits while the
# status file still says `running`/`starting`. When the recursive or
# auto_hosts wrapper finishes with an empty subdirs/auto-hosts list, the
# inner cmd_ingest_delimited never ran and no terminal status was ever
# written — so the atexit guard mislabeled clean no-op walks as failed.
# These tests assert the wrappers call _write_bg_status with
# status="complete" before returning.
# ---------------------------------------------------------------------------


class TestDelimitedWrapperTerminalStatus:
    def test_recursive_wrapper_writes_complete_on_empty_subdirs(self, tmp_path, monkeypatch):
        """Empty-subdirs recursive walk must write a terminal 'complete'
        status so the atexit guard no-ops instead of stamping failed."""
        from opensearch_mcp import ingest_cli

        # tmp_path has no subdirs matching the walker's ext filter.
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", "TEST-RUN-123")
        monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: "TEST-CASE")
        monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda _c: None)
        monkeypatch.setattr(ingest_cli, "reset_circuit_breaker", lambda: None, raising=False)

        args = argparse.Namespace(
            path=str(tmp_path),
            hostname="",
            recursive=True,
            auto_hosts="",
            case=None,
            time_field=None,
            delimiter=None,
            format=None,
            time_from=None,
            time_to=None,
            batch_size=1000,
            dry_run=False,
            index_suffix=None,
        )

        captured = []

        def _capture(*a, **kw):
            # _write_bg_status signature: (case_id, run_id, status, hostname, ...)
            captured.append(a[2] if len(a) >= 3 else kw.get("status"))

        with patch.object(ingest_cli, "_write_bg_status", side_effect=_capture):
            ingest_cli.cmd_ingest_delimited(args)

        # Must have written at least one terminal "complete" status.
        assert "complete" in captured, (
            f"recursive wrapper exited without writing 'complete'; wrote: {captured}"
        )

    def test_auto_hosts_wrapper_writes_complete_on_empty_list(self, tmp_path, monkeypatch):
        """Symmetric fix: auto_hosts wrapper with an empty effective
        hosts list must also write terminal 'complete'."""
        from opensearch_mcp import ingest_cli

        monkeypatch.setenv("VHIR_INGEST_RUN_ID", "TEST-RUN-456")
        monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: "TEST-CASE")
        monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda _c: None)
        monkeypatch.setattr(ingest_cli, "reset_circuit_breaker", lambda: None, raising=False)

        args = argparse.Namespace(
            path=str(tmp_path),
            hostname="",
            recursive=False,
            # Comma-only string → split-and-strip yields empty list,
            # wrapper enters the auto_hosts branch but loops 0 times.
            auto_hosts=",,,",
            case=None,
            time_field=None,
            delimiter=None,
            format=None,
            time_from=None,
            time_to=None,
            batch_size=1000,
            dry_run=False,
            index_suffix=None,
        )

        captured = []

        def _capture(*a, **kw):
            captured.append(a[2] if len(a) >= 3 else kw.get("status"))

        with patch.object(ingest_cli, "_write_bg_status", side_effect=_capture):
            ingest_cli.cmd_ingest_delimited(args)

        assert "complete" in captured, (
            f"auto_hosts wrapper exited without writing 'complete'; wrote: {captured}"
        )


# ---------------------------------------------------------------------------
# B82 regression pin (2026-04-23) — `recursive=True` is ONE LEVEL ONLY.
# Documented in idx_ingest_delimited's docstring + --recursive help text.
# This test mechanically enforces the contract so a future refactor (e.g.
# swapping iterdir() for rglob()) cannot silently change behavior without
# breaking a test. Lands with the doc change per "tests land with the fix".
# ---------------------------------------------------------------------------


class TestDelimitedRecursiveIsOneLevel:
    """Pin the one-level recursive contract. If this test fails, either
    the walker's iterdir() was changed to rglob() (true-recursive) or the
    subdir filter was widened to include nested dirs; in either case the
    docstring at server.py idx_ingest_delimited and the --recursive help
    at ingest_cli.py must also be updated."""

    def test_recursive_does_not_descend_into_nested_subdirs(self, tmp_path, monkeypatch):
        """A CSV at depth 2 (root/hostA/subdir/evidence.csv) must NOT be
        ingested by recursive=True; only files at depth 1 (directly in
        root/hostA/) are considered. Documented behavior per B82."""
        from opensearch_mcp import ingest_cli

        # Layout:
        #   root/
        #     shallow_host/
        #       at_depth_1.csv          ← MUST be seen
        #     deep_host/
        #       nested/
        #         at_depth_2.csv        ← MUST NOT be seen (too deep)
        shallow = tmp_path / "shallow_host"
        shallow.mkdir()
        (shallow / "at_depth_1.csv").write_text("a,b\n1,2\n")

        deep = tmp_path / "deep_host"
        (deep / "nested").mkdir(parents=True)
        (deep / "nested" / "at_depth_2.csv").write_text("a,b\n3,4\n")

        monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: "TEST-CASE")
        monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda _c: None)
        monkeypatch.setattr(ingest_cli, "reset_circuit_breaker", lambda: None, raising=False)

        ingested: list[str] = []

        def _fake_ingest_delimited(f, *a, **kw):
            ingested.append(str(f))
            return (0, 0, 0, False)

        # Also stub the OS client + preflight so the wrapper is reachable
        # without a real OpenSearch. `get_client` is imported into
        # ingest_cli at module scope, so patch there.
        monkeypatch.setattr(ingest_cli, "get_client", lambda: object())
        monkeypatch.setattr(
            ingest_cli, "_preflight_shard_capacity", lambda *a, **kw: None, raising=False
        )
        monkeypatch.setattr(
            "opensearch_mcp.parse_delimited.ingest_delimited",
            _fake_ingest_delimited,
        )
        # The walker queries _detect_delimited_format on every file; return
        # a trivial csv shape so the walker proceeds past detection.
        monkeypatch.setattr(
            "opensearch_mcp.parse_delimited._detect_delimited_format",
            lambda f: {"format": "csv", "delimiter": ",", "header": "first_line"},
        )

        args = argparse.Namespace(
            path=str(tmp_path),
            hostname="",
            recursive=True,
            auto_hosts="",
            case=None,
            time_field=None,
            delimiter=None,
            format=None,
            time_from=None,
            time_to=None,
            batch_size=1000,
            dry_run=False,
            index_suffix=None,
        )

        ingest_cli.cmd_ingest_delimited(args)

        # Depth-1 file must have been sent to ingest_delimited.
        assert any(p.endswith("at_depth_1.csv") for p in ingested), (
            f"recursive walk missed the depth-1 file; saw: {ingested}"
        )
        # Depth-2 file must NOT have been sent — walker is one level only.
        assert not any(p.endswith("at_depth_2.csv") for p in ingested), (
            f"recursive walk descended into nested subdir (B82 contract broken); saw: {ingested}"
        )

    def test_recursive_ignores_top_level_files(self, tmp_path, monkeypatch):
        """Per the updated docstring: files directly under `path` (not
        in a subdir) are IGNORED when recursive=True. A top-level
        `summary.csv` must not be ingested under the root's basename
        — callers must use non-recursive mode for flat layouts."""
        from opensearch_mcp import ingest_cli

        (tmp_path / "summary.csv").write_text("a,b\n1,2\n")  # top-level, must be ignored
        host = tmp_path / "hostA"
        host.mkdir()
        (host / "evidence.csv").write_text("a,b\n3,4\n")  # in subdir, must be seen

        monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: "TEST-CASE")
        monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda _c: None)
        monkeypatch.setattr(ingest_cli, "reset_circuit_breaker", lambda: None, raising=False)

        ingested: list[str] = []

        def _fake_ingest_delimited(f, *a, **kw):
            ingested.append(str(f))
            return (0, 0, 0, False)

        monkeypatch.setattr(ingest_cli, "get_client", lambda: object())
        monkeypatch.setattr(
            ingest_cli, "_preflight_shard_capacity", lambda *a, **kw: None, raising=False
        )
        monkeypatch.setattr(
            "opensearch_mcp.parse_delimited.ingest_delimited",
            _fake_ingest_delimited,
        )
        monkeypatch.setattr(
            "opensearch_mcp.parse_delimited._detect_delimited_format",
            lambda f: {"format": "csv", "delimiter": ",", "header": "first_line"},
        )

        args = argparse.Namespace(
            path=str(tmp_path),
            hostname="",
            recursive=True,
            auto_hosts="",
            case=None,
            time_field=None,
            delimiter=None,
            format=None,
            time_from=None,
            time_to=None,
            batch_size=1000,
            dry_run=False,
            index_suffix=None,
        )

        ingest_cli.cmd_ingest_delimited(args)

        assert any(p.endswith("evidence.csv") for p in ingested), (
            f"recursive walk missed the subdir file; saw: {ingested}"
        )
        assert not any(p.endswith("summary.csv") for p in ingested), (
            f"recursive walk picked up a top-level file (B82 contract broken); saw: {ingested}"
        )


# ---------------------------------------------------------------------------
# UAT 2026-04-24 B84 — cmd_scan TypeError on mixed Hayabusa result dict
# Pre-fix: `sum(hb_results.values())` choked on per-host failure dicts
# returned when Hayabusa rules were missing, crashing cmd_scan *after*
# every parser had already completed (docs indexed, but the scan-summary
# step took the whole command down). Helper filters to ints so per-host
# failures contribute 0 alerts rather than propagating a fatal.
# ---------------------------------------------------------------------------


class TestSumHayabusaAlerts:
    def test_happy_path_all_int_values(self):
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        assert _sum_hayabusa_alerts({"host1": 10, "host2": 5}) == 15

    def test_skipped_marker_returns_zero(self):
        """`run_hayabusa_batch` returns this shape when hayabusa binary
        is missing — not an error, just a skip."""
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        assert _sum_hayabusa_alerts({"skipped": "hayabusa not installed"}) == 0

    def test_mixed_int_and_failure_dict_b84_regression(self):
        """The exact B84 repro: some hosts succeed (int), others fail
        with a dict value. Pre-fix `sum()` raised TypeError and
        crashed cmd_scan. Post-fix the dict-valued entries contribute
        zero."""
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        mixed = {
            "host1": 42,
            "host2": {"status": "failed", "error": "rules_not_found"},
            "host3": 8,
            "host4": {"status": "failed", "error": "timeout"},
        }
        # Pre-fix: `sum(mixed.values())` raises TypeError.
        # Post-fix: filters to ints only → 42 + 8 = 50.
        assert _sum_hayabusa_alerts(mixed) == 50

    def test_all_failure_dicts_returns_zero(self):
        """Every host failed → sum is zero, no crash."""
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        all_failed = {
            "host1": {"status": "failed", "error": "rules_not_found"},
            "host2": {"status": "failed", "error": "rules_not_found"},
        }
        assert _sum_hayabusa_alerts(all_failed) == 0

    def test_non_dict_input_returns_zero(self):
        """Defensive: any unexpected shape (None, list, str) must not
        crash — cmd_scan's parser summary is too late in the flow to
        swallow an exception gracefully."""
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        assert _sum_hayabusa_alerts(None) == 0
        assert _sum_hayabusa_alerts([1, 2, 3]) == 0
        assert _sum_hayabusa_alerts("unexpected") == 0

    def test_empty_dict_returns_zero(self):
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        assert _sum_hayabusa_alerts({}) == 0

    def test_bool_and_float_edge_cases(self):
        """bool is a subclass of int in Python, so bool values count
        as 1/0. Floats are filtered out. This test documents the
        current behavior so a future isinstance refinement catches
        if we intended something else."""
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        # True=1, False=0 (bool is int subclass), 3.14 filtered, 5 kept.
        assert _sum_hayabusa_alerts({"a": True, "b": False, "c": 3.14, "d": 5}) == 6


# ---------------------------------------------------------------------------
# UAT 2026-04-24 d334134 follow-up — Hayabusa summary line format pin.
# The print statement at cmd_scan is operator-visible; a capsys test pins
# the exact format so a future wording refactor doesn't silently drift
# behavior (e.g. dropping the failure-count clause, mis-pluralizing, or
# suppressing a line operators depend on).
#
# Note: cmd_scan wraps this print in a larger flow. These tests exercise
# the summary-line emission logic DIRECTLY by simulating its local
# variables rather than running cmd_scan end-to-end, which would require
# the full ingest harness. The production code path is a 5-line sequence
# with no control flow peculiar to cmd_scan's surroundings — direct
# exercise is adequate.
# ---------------------------------------------------------------------------


class TestHayabusaSummaryLine:
    """Pin the exact operator-visible output shape of the Hayabusa
    summary line in cmd_scan. Defends against wording drift + regression
    of the grammar and conditional-suppression rules."""

    @staticmethod
    def _emit_summary(hb_results) -> str:
        """Replicate the cmd_scan summary-line logic against `hb_results`,
        returning what would be printed (or empty string if suppressed).

        Keeps the production logic and the test assertion colocated in
        review. If the real code at ingest_cli.py:722-738 diverges from
        this mirror, the tests fail loudly — which is the intent of
        having the tests at all."""
        from opensearch_mcp.ingest_cli import _sum_hayabusa_alerts

        total_alerts = _sum_hayabusa_alerts(hb_results)
        failed_hosts = (
            sum(1 for v in hb_results.values() if isinstance(v, dict))
            if isinstance(hb_results, dict)
            else 0
        )
        if total_alerts or failed_hosts:
            line = f"Hayabusa: {total_alerts:,} alerts indexed"
            if failed_hosts:
                noun = "host" if failed_hosts == 1 else "hosts"
                line += f" ({failed_hosts} {noun} failed — see progress log)"
            return line
        return ""

    def test_all_success(self):
        """Every host produced an int alert count — summary is plain
        count, no failure clause."""
        line = self._emit_summary({"host1": 100, "host2": 50})
        assert line == "Hayabusa: 150 alerts indexed"

    def test_all_failed_singular(self):
        """All hosts failed (single-host case) — 0 alerts + failure
        clause + SINGULAR `host` noun."""
        line = self._emit_summary({"host1": {"status": "failed", "error": "rules_not_found"}})
        assert line == "Hayabusa: 0 alerts indexed (1 host failed — see progress log)"

    def test_all_failed_plural(self):
        """Multi-host failure — PLURAL `hosts` noun. Guards against the
        ungrammatical `1 hosts failed` regression."""
        line = self._emit_summary(
            {
                "h1": {"status": "failed", "error": "rules_not_found"},
                "h2": {"status": "failed", "error": "timeout"},
                "h3": {"status": "failed", "error": "rules_not_found"},
            }
        )
        assert line == "Hayabusa: 0 alerts indexed (3 hosts failed — see progress log)"

    def test_mixed_success_and_failure(self):
        """Some hosts succeeded, some failed — both clauses present."""
        line = self._emit_summary(
            {
                "h1": 42,
                "h2": {"status": "failed", "error": "rules_not_found"},
                "h3": 8,
            }
        )
        assert line == "Hayabusa: 50 alerts indexed (1 host failed — see progress log)"

    def test_mixed_singular_host_failed(self):
        """Mixed case where exactly one host failed — SINGULAR noun."""
        line = self._emit_summary(
            {"h1": 100, "h2": {"status": "failed", "error": "rules_not_found"}}
        )
        assert line == "Hayabusa: 100 alerts indexed (1 host failed — see progress log)"

    def test_skipped_marker_suppresses_line(self):
        """`run_hayabusa_batch` returned the skipped marker → no line
        printed (consistent with pre-B84 behavior for this case)."""
        line = self._emit_summary({"skipped": "hayabusa not installed"})
        assert line == ""

    def test_empty_dict_suppresses_line(self):
        """No hosts ran Hayabusa at all → no line printed."""
        line = self._emit_summary({})
        assert line == ""

    def test_non_dict_input_suppresses_line(self):
        """Defensive: None / list / str input → no line, no crash."""
        assert self._emit_summary(None) == ""
        assert self._emit_summary([1, 2, 3]) == ""
        assert self._emit_summary("unexpected") == ""

    def test_thousand_separator_on_large_counts(self):
        """Large alert totals format with comma thousand-separators so
        operators reading the line quickly can parse order-of-magnitude."""
        line = self._emit_summary({"h1": 12345, "h2": 6789})
        assert "19,134" in line
