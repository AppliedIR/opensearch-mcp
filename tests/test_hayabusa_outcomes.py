"""Every host Hayabusa runs for leaves an outcome the status shows.

A Hayabusa that can't run, writes an [ERROR], has its alerts rejected or its
CSV fail to ingest fails the hayabusa row with the reason. One that writes
nothing is neither a failure nor "0 alerts": a note names both causes. The
scan, the hayabusa phase and the status are real; Hayabusa is a stand-in
script, and the evtx parse and the CSV ingest are stubbed.
"""

from __future__ import annotations

import argparse
import shutil
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import bulk, ingest_status, parse_delimited
from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost

CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID\n"
    "2026-02-01 00:00:00,Log cleared,high,DEV01,Security,1102\n"
)

# writes the CSV at -o according to HB_MODE
STUB = """#!/bin/sh
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
case "$1" in --help|dfir-timeline) [ "$2" = "--help" ] && exit 1 ;; esac
case "$HB_MODE" in
  empty) : > "$out" ;;
  none) ;;
  error) echo "[ERROR] Failed to load rules: no rule file found" >&2 ;;
  *) printf '%s' "$HB_CSV" > "$out" ;;
esac
exit 0
"""


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """`run(mode, ingest=None)`: a scan of DEV01 with the hayabusa phase on;
    returns (status, console)."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-hb")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    evtx = tmp_path / "ev" / "evtx"
    evtx.mkdir(parents=True)
    (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="DEV01", volume_root=tmp_path / "ev")
    host.evtx_dir = evtx
    monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])
    monkeypatch.setattr(
        cli, "_preflight_host_discovery", lambda *a, **k: ({"decisions_applied": []}, None)
    )
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ing, "parse_and_index", MagicMock(return_value=(500, 0, 0)))
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    # Hayabusa itself: a script on PATH, its rules, its output folder
    hb = tmp_path / "bin" / "hayabusa"
    hb.parent.mkdir()
    hb.write_text(STUB)
    hb.chmod(0o755)
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda n, *a, **k: str(hb) if n == "hayabusa" else real_which(n)
    )
    rules = tmp_path / "rules"
    (rules / "config").mkdir(parents=True)
    monkeypatch.setattr(ing, "_resolve_hayabusa_rules_dir", lambda: rules)
    monkeypatch.setattr(ing, "vhir_dir", lambda: tmp_path / "vhir")
    monkeypatch.setenv("HB_CSV", CSV)

    def run(mode="ok", ingest=None, hayabusa_text=None, triage=False, client=None):
        monkeypatch.setenv("HB_MODE", mode)
        if hayabusa_text is not None:
            hb.write_text(hayabusa_text)
            hb.chmod(0o755)
        monkeypatch.setattr(
            parse_delimited, "ingest_delimited", ingest or (lambda *a, **k: (1, 0, 0, 0))
        )
        if client is not None:
            monkeypatch.setattr(cli, "get_client", lambda: client)
        bulk.reset_circuit_breaker()
        cli.cmd_scan(argparse.Namespace(path=str(tmp_path / "ev"), case="c1", yes=True,
                                        hostname="DEV01", all_logs=False, no_hayabusa=False,
                                        skip_triage=not triage))  # fmt: skip
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status

    return run


def _row(status):
    (row,) = [c for c in status["checklist"] if c["artifact"] == "hayabusa-detection"]
    return row


def test_a_hayabusa_that_cant_run_fails_the_row_naming_the_host(scan, capsys):
    status = scan(hayabusa_text="this is not a program\n")  # no #!: Exec format error
    row = _row(status)
    assert row["status"] == "failed", row
    assert "DEV01" in row["detail"] and "Exec format error" in row["detail"]
    assert status["message"].startswith("Ingest complete with 1 error(s)")


def test_a_hayabusa_that_writes_nothing_leaves_a_note_not_a_failure(scan, capsys):
    status = scan("empty")
    out = capsys.readouterr().out
    assert _row(status)["status"] == "done"
    note = "DEV01: Hayabusa wrote no detections: no rule matched, or no event could be read"
    assert any(note in w for w in status.get("warnings", [])), status
    hb_line = [ln for ln in out.splitlines() if "hayabusa: DEV01" in ln]
    assert hb_line and "failed" not in hb_line[0]


def test_rejected_alerts_fail_the_row_and_count_in_the_runs_rejections(scan):
    def rejected(*a, **k):
        bulk._tls.last_bulk_reason = "failed to parse field [Level] of type [long]"
        return 0, 0, 6254, 0

    status = scan(ingest=rejected)
    row = _row(status)
    assert row["status"] == "failed"
    assert "6,254 of 6,254 alerts rejected by OpenSearch" in row["detail"]
    assert "Level" in row["detail"]
    assert status["bulk_failed"] >= 6254
    assert any("rejected by OpenSearch" in w for w in status.get("warnings", []))


def test_a_csv_that_fails_to_ingest_fails_the_host(scan):
    def boom(*a, **k):
        raise RuntimeError("mapping exploded")

    row = _row(scan(ingest=boom))
    assert row["status"] == "failed" and "ingest failed: mapping exploded" in row["detail"]


def test_an_error_hayabusa_writes_with_exit_0_fails_the_row(scan):
    row = _row(scan("error"))
    assert row["status"] == "failed" and "[ERROR] Failed to load rules" in row["detail"]


def test_anchor_a_healthy_run_is_done_without_a_note(scan):
    status = scan()
    assert _row(status)["status"] == "done" and _row(status)["detail"].startswith("1 ")
    assert not any("Hayabusa" in w for w in status.get("warnings", []))
