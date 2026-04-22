"""Tests for ingest status file management."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from opensearch_mcp.ingest_status import (
    _is_process_alive,
    _status_path_safe,
    cleanup_old,
    read_active_ingests,
    write_status,
)


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    """Redirect _STATUS_DIR to a temp directory."""
    sd = tmp_path / ".vhir" / "ingest-status"
    monkeypatch.setattr("opensearch_mcp.ingest_status._STATUS_DIR", sd)
    return sd


# ---------------------------------------------------------------------------
# write_status
# ---------------------------------------------------------------------------


class TestWriteStatus:
    def test_creates_file_in_correct_location(self, status_dir):
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="abc-123",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        assert len(files) == 1
        assert "INC001" in files[0].name
        assert "12345" in files[0].name

    def test_atomic_write_no_tmp_files_left(self, status_dir):
        """After write, no .tmp files should remain."""
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="abc",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        tmp_files = list(status_dir.glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_contains_all_required_fields(self, status_dir):
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="run-xyz",
            status="running",
            hosts=[{"hostname": "HOST1"}],
            totals={"indexed": 100},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["run_id"] == "run-xyz"
        assert data["pid"] == 12345
        assert data["status"] == "running"
        assert data["case_id"] == "INC001"
        assert data["started"] == "2024-01-15T10:00:00Z"
        assert "updated" in data
        assert data["hosts"] == [{"hostname": "HOST1"}]
        assert data["totals"] == {"indexed": 100}

    def test_with_error_field(self, status_dir):
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="run-err",
            status="failed",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
            error="Connection refused",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["error"] == "Connection refused"

    # -------------------------------------------------------------------
    # UAT 2026-04-23: monotonic transitions. Terminal states (complete,
    # failed) must not be overwritten by a later running/starting write.
    # Race: fast-worker writes "complete" before MCP's post-spawn
    # write_status(status="running", ...) at server.py:2336 lands; the
    # later "running" clobbered the terminal so the sweep mislabeled the
    # worker failed: process_died_unexpectedly.
    # -------------------------------------------------------------------

    def test_monotonic_running_does_not_downgrade_complete(self, status_dir):
        """Worker's terminal complete must survive MCP's post-spawn running write."""
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="race-1",
            status="complete",
            hosts=[],
            totals={"indexed": 42},
            started="2024-01-15T10:00:00Z",
        )
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="race-1",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["status"] == "complete"
        assert data["totals"]["indexed"] == 42  # Terminal payload preserved

    def test_monotonic_running_does_not_downgrade_failed(self, status_dir):
        """Worker's terminal failed must survive a later running write."""
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="race-2",
            status="failed",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
            error="shard_capacity_exhausted: cluster full",
        )
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="race-2",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["status"] == "failed"
        assert "shard_capacity_exhausted" in data["error"]

    def test_monotonic_starting_does_not_downgrade_complete(self, status_dir):
        """Same guard applies to a late 'starting' write (belt-and-suspenders)."""
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="race-3",
            status="complete",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="race-3",
            status="starting",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["status"] == "complete"

    def test_monotonic_complete_overwrites_running(self, status_dir):
        """Normal forward transition: running → complete must still work."""
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="normal-1",
            status="running",
            hosts=[],
            totals={"indexed": 10},
            started="2024-01-15T10:00:00Z",
        )
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="normal-1",
            status="complete",
            hosts=[],
            totals={"indexed": 100},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["status"] == "complete"
        assert data["totals"]["indexed"] == 100

    def test_monotonic_running_updates_allowed_when_no_terminal(self, status_dir):
        """Running → running progress updates must still work (no terminal in file)."""
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="progress-1",
            status="running",
            hosts=[],
            totals={"indexed": 10},
            started="2024-01-15T10:00:00Z",
        )
        write_status(
            case_id="INC001",
            pid=12345,
            run_id="progress-1",
            status="running",
            hosts=[],
            totals={"indexed": 50},
            started="2024-01-15T10:00:00Z",
        )
        files = list(status_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert data["status"] == "running"
        assert data["totals"]["indexed"] == 50

    def test_sanitizes_case_id_path_traversal(self, status_dir):
        """case_id with ../ should not escape the status directory."""
        write_status(
            case_id="../../../etc/passwd",
            pid=1,
            run_id="x",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        # File must be within status_dir, not above it
        files = list(status_dir.glob("*.json"))
        assert len(files) == 1
        assert files[0].parent == status_dir

    def test_multiple_concurrent_status_files(self, status_dir):
        """Multiple PIDs can each have their own status file."""
        for pid in (100, 200, 300):
            write_status(
                case_id="INC001",
                pid=pid,
                run_id=f"run-{pid}",
                status="running",
                hosts=[],
                totals={},
                started="2024-01-15T10:00:00Z",
            )
        files = list(status_dir.glob("*.json"))
        assert len(files) == 3


# ---------------------------------------------------------------------------
# _status_path_safe
# ---------------------------------------------------------------------------


class TestStatusPathSafe:
    def test_path_traversal_slash(self, status_dir):
        """Forward slashes in case_id are replaced with underscores."""
        path = _status_path_safe("../../evil", 1)
        assert ".." not in path.name
        assert "/" not in path.name

    def test_path_traversal_backslash(self, status_dir):
        """Backslashes in case_id are replaced with underscores."""
        path = _status_path_safe("..\\..\\evil", 1)
        assert "\\" not in path.name

    def test_double_dot_replaced(self, status_dir):
        """Double dots (..) are replaced."""
        path = _status_path_safe("a..b", 1)
        assert ".." not in path.name


# ---------------------------------------------------------------------------
# read_active_ingests
# ---------------------------------------------------------------------------


class TestReadActiveIngests:
    def test_returns_empty_when_no_status_dir(self, status_dir):
        """No status directory returns empty list."""
        result = read_active_ingests()
        assert result == []

    def test_returns_running_status_when_pid_alive(self, status_dir):
        """Running process shows as 'running'."""
        write_status(
            case_id="INC001",
            pid=os.getpid(),  # current process is alive
            run_id="test-run",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        # Mock _is_process_alive to return True
        with patch("opensearch_mcp.ingest_status._is_process_alive", return_value=True):
            results = read_active_ingests()
        assert len(results) == 1
        assert results[0]["status"] == "running"

    def test_marks_failed_when_pid_dead(self, status_dir):
        """Dead process PID gets status changed to 'failed' with
        `process_died_unexpectedly:` error prefix (UAT 2026-04-22
        consolidation: 'killed' merged into 'failed', diagnostic
        preserved via prefix so portal/CLI don't juggle a third
        terminal state)."""
        write_status(
            case_id="INC001",
            pid=99999999,  # almost certainly not a real PID
            run_id="dead-run",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        # Mock _is_process_alive to return False (zombie / dead / missing).
        with patch("opensearch_mcp.ingest_status._is_process_alive", return_value=False):
            results = read_active_ingests()
        assert len(results) == 1
        assert results[0]["status"] == "failed"
        assert results[0]["error"].startswith("process_died_unexpectedly:")

    def test_handles_corrupt_json_files(self, status_dir):
        """Corrupt JSON files are skipped, not crashed on."""
        status_dir.mkdir(parents=True, exist_ok=True)
        corrupt = status_dir / "corrupt-1.json"
        corrupt.write_text("{invalid json")
        # Also add a valid one
        write_status(
            case_id="INC001",
            pid=os.getpid(),
            run_id="valid",
            status="complete",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )
        results = read_active_ingests()
        # Only the valid file should be returned
        assert len(results) == 1
        assert results[0]["status"] == "complete"


# ---------------------------------------------------------------------------
# _is_process_alive
# ---------------------------------------------------------------------------


class TestIsProcessAlive:
    def test_returns_false_for_dead_pid(self):
        """Dead PID (ProcessLookupError) returns False."""
        with patch("os.kill", side_effect=ProcessLookupError):
            assert _is_process_alive(99999999, "some-run-id") is False

    def test_returns_true_for_alive_pid_with_matching_run_id(self):
        """Alive PID with matching run_id returns True."""
        with patch("os.kill"):  # no exception = PID exists
            # Mock /proc reading to return matching environ
            environ_bytes = b"VHIR_INGEST_RUN_ID=test-run\x00OTHER=val\x00"
            with patch.object(Path, "read_bytes", return_value=environ_bytes):
                assert _is_process_alive(1234, "test-run") is True

    def test_returns_false_for_alive_pid_with_wrong_run_id(self):
        """Alive PID but different run_id (PID reuse) returns False."""
        with patch("os.kill"):  # no exception = PID exists
            environ_bytes = b"VHIR_INGEST_RUN_ID=different-run\x00"
            with patch.object(Path, "read_bytes", return_value=environ_bytes):
                assert _is_process_alive(1234, "test-run") is False

    def test_falls_back_to_pid_only_when_proc_not_readable(self):
        """When /proc is not readable, falls back to PID-only check (returns True)."""
        with patch("os.kill"):  # no exception = PID exists
            with patch.object(Path, "read_bytes", side_effect=OSError("permission denied")):
                assert _is_process_alive(1234, "test-run") is True

    def test_permission_error_treated_as_alive(self):
        """PermissionError from os.kill means process exists (another user's)."""
        with patch("os.kill", side_effect=PermissionError):
            assert _is_process_alive(1234, "test-run") is True


# ---------------------------------------------------------------------------
# cleanup_old
# ---------------------------------------------------------------------------


class TestCleanupOld:
    def test_removes_old_files(self, status_dir):
        """Files older than 24 hours are removed."""
        status_dir.mkdir(parents=True, exist_ok=True)
        old_file = status_dir / "old-case-1.json"
        old_file.write_text('{"status":"complete"}')
        # Set mtime to 25 hours ago
        old_mtime = time.time() - (25 * 3600)
        os.utime(old_file, (old_mtime, old_mtime))

        cleanup_old()
        assert not old_file.exists()

    def test_preserves_recent_files(self, status_dir):
        """Files newer than 24 hours are preserved."""
        status_dir.mkdir(parents=True, exist_ok=True)
        recent_file = status_dir / "recent-case-1.json"
        recent_file.write_text('{"status":"running"}')
        # mtime is now (default), so it's recent

        cleanup_old()
        assert recent_file.exists()

    def test_no_status_dir_is_safe(self, status_dir):
        """cleanup_old does not error when status dir doesn't exist."""
        cleanup_old()  # should not raise
