"""An access-log ingest's status names what it didn't index: a file it
couldn't read, a file none of whose lines it indexed, and records OpenSearch
rejected. The ingest and the status are real; the bulk write is a stand-in.
Values are synthetic."""

from __future__ import annotations

import argparse
import os
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import bulk, ingest_status, parse_accesslog
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import server as srv

LINE = '192.0.2.{i} - - [10/Oct/2026:13:55:{i:02d} +0000] "GET /p{i} HTTP/1.1" 200 2326 "-" "UA"\n'
GOOD = "".join(LINE.format(i=i) for i in range(1, 6))


@pytest.fixture
def run(tmp_path, monkeypatch):
    """`run(files, rejected=False, **args)` ingests a folder of logs; returns
    the status (and keeps the exit code in `run.exit`)."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-al")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    for name in ("_ensure_case_active", "_preflight_shard_capacity", "AuditWriter",
                 "get_client"):  # fmt: skip
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)

    def go(files: dict, rejected=False, time_from=None):
        folder = tmp_path / "logs"
        folder.mkdir(exist_ok=True)
        for name, text in files.items():
            (folder / name).write_text(text)

        def flush(client, actions, **k):
            if rejected:
                bulk._tls.last_bulk_reason = "failed to parse field [url.path] of type [long]"
                return 0, len(actions)
            return len(actions), 0

        monkeypatch.setattr(parse_accesslog, "flush_bulk", flush)
        bulk.reset_circuit_breaker()
        go.exit = 0
        try:
            cli.cmd_ingest_accesslog(argparse.Namespace(
                path=str(folder), case="c1", hostname="web01", time_from=time_from, time_to=None,
                dry_run=False, index_suffix=None))  # fmt: skip
        except SystemExit as e:  # a `failed` run exits 1
            go.exit = e.code
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status, folder

    return go


def _warned(status, text):
    return [w for w in status.get("warnings", []) if text in w]


def test_a_log_of_which_no_line_was_indexed_is_named(run):
    status, folder = run({"garbage.log": "not\nan\naccess\nlog\n"})
    assert _warned(status, "garbage.log (no line indexed: 4 line(s) unrecognised)"), status


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_a_log_that_cant_be_read_is_named_beside_the_one_that_was(run, tmp_path):
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "b-locked.log").write_text(GOOD)
    (folder / "b-locked.log").chmod(0)
    try:
        status, _ = run({"a-good.log": GOOD})
    finally:
        (folder / "b-locked.log").chmod(0o644)
    (row,) = status["checklist"]
    assert row["status"] == "done" and row["detail"].startswith("5 ")
    assert _warned(status, "b-locked.log") and _warned(status, "Permission denied"), status


def test_records_all_rejected_fail_the_run_with_the_reason(run):
    status, _ = run({"good.log": GOOD}, rejected=True)
    assert status["status"] == "failed" and run.exit == 1  # was exit 0
    assert status["bulk_failed"] == 5
    (row,) = status["checklist"]
    assert row["status"] == "failed"
    assert "all_records_rejected" in str(status) and "url.path" in str(status)


def test_anchor_a_good_log_is_done_without_a_warning(run):
    status, _ = run({"good.log": GOOD})
    (row,) = status["checklist"]
    assert row["status"] == "done" and row["detail"].startswith("5 ")
    assert not status.get("warnings")


def test_a_log_outside_the_time_window_says_so(run):
    status, _ = run({"good.log": GOOD}, time_from="2027-01-01")
    assert _warned(status, "no line indexed: 5 line(s) unrecognised or outside the time window")


def test_a_log_inside_the_time_window_has_no_warning(run):
    status, _ = run({"good.log": GOOD}, time_from="2026-01-01")
    assert not status.get("warnings")


def test_an_empty_log_is_not_named_as_unindexed(run):
    status, _ = run({"good.log": GOOD, "empty.log": ""})
    assert not _warned(status, "empty.log"), status
    assert not _warned(status, "no line indexed")
