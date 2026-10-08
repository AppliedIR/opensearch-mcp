"""A SRUM or prefetch artifact whose records OpenSearch rejected is failed,
with how many and why, and stays failed when the detection phase rebuilds the
status. The scan and the status are real; the SRUM parse and Hayabusa are
stand-ins. Values are synthetic.
"""

from __future__ import annotations

import argparse
import shutil
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import bulk, ingest_status, parse_delimited, parse_srum
from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.results import PARSER_COMPLETED

REASON = "failed to parse field [user_identifier] of type [long]"
HAYABUSA = (
    '#!/bin/sh\ncase "$1" in --help|dfir-timeline) [ "$2" = "--help" ] && exit 1 ;; esac\nexit 0\n'
)


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """`run(rejected, hayabusa)`: a scan of dev01's SRUM (and evtx, for the
    detection phase); returns its status."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-a6")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    root = tmp_path / "ev"
    srum = root / "Windows/System32/sru/SRUDB.dat"
    srum.parent.mkdir(parents=True)
    srum.write_bytes(b"x" * 64)
    evtx = root / "evtx"
    evtx.mkdir()
    (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="dev01", volume_root=root)
    host.evtx_dir = evtx
    host.artifacts.append(("srum", srum))
    monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ing, "parse_and_index", MagicMock(return_value=(500, 0, 0)))
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    hb = tmp_path / "bin" / "hayabusa"  # writes no CSV: a note, never a failure
    hb.parent.mkdir()
    hb.write_text(HAYABUSA)
    hb.chmod(0o755)
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda n, *a, **k: str(hb) if n == "hayabusa" else real_which(n)
    )
    (tmp_path / "rules" / "config").mkdir(parents=True)
    monkeypatch.setattr(ing, "_resolve_hayabusa_rules_dir", lambda: tmp_path / "rules")
    monkeypatch.setattr(ing, "vhir_dir", lambda: tmp_path / "vhir")
    monkeypatch.setattr(parse_delimited, "ingest_delimited", lambda *a, **k: (0, 0, 0, 0))

    def run(rejected: int, hayabusa: bool):
        def srum_parse(**kw):
            if rejected:
                bulk._tls.last_bulk_reason = REASON
            return 66505 - rejected, rejected, "", PARSER_COMPLETED, 66505

        monkeypatch.setattr(parse_srum, "parse_srum", srum_parse)
        bulk.reset_circuit_breaker()
        cli.cmd_scan(argparse.Namespace(path=str(root), case="c1", yes=True, hostname="dev01",
                                        all_logs=False, no_hayabusa=not hayabusa,
                                        skip_triage=True))  # fmt: skip
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status

    return run


def _srum(status):
    (row,) = [c for c in status["checklist"] if c["artifact"] == "srum"]
    return row


@pytest.mark.parametrize("hayabusa", [True, False], ids=["hayabusa", "no hayabusa"])
def test_rejected_records_fail_the_srum_row_with_the_count_and_reason(scan, hayabusa):
    status = scan(63659, hayabusa)
    row = _srum(status)
    assert row["status"] == "failed", row
    assert "63,659 of 66,505 records rejected by OpenSearch" in row["detail"], row
    assert "user_identifier" in row["detail"]
    assert "with 1 error(s)" in status["message"], status["message"]


def test_anchor_srum_with_nothing_rejected_is_done(scan):
    row = _srum(scan(0, True))
    assert row["status"] == "done" and row["detail"].startswith("66,505 "), row
