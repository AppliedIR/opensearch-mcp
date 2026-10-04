"""A failed evtx artifact's status names the file and the error.

The evtx loop kept each file's failure in the host's result and marked the
status `failed`, but never copied the reason into the status, so
idx_ingest_status read "unknown error" unless a hayabusa phase rebuilt the
status afterwards. The files here are synthetic: no evtx signature, so the
real parser rejects them.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from test_evtx_truncation import CHUNK, _evtx

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

_NO_SIGNATURE = b"\0" * 8


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _host(tmp_path, name):
    evtx = tmp_path / name / "evtx"
    evtx.mkdir(parents=True)
    h = DiscoveredHost(hostname=name, volume_root=tmp_path / name)
    h.evtx_dir = evtx
    return h


def _bad(host, name):
    return _evtx(host.evtx_dir / name, 1, 4096 + CHUNK, signature=_NO_SIGNATURE)


def _ingest(hosts, parse=None):
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    stubs = [patch("opensearch_mcp.ingest.sha256_file", return_value="h")]
    if parse is not None:
        stubs.append(patch("opensearch_mcp.ingest.parse_and_index", side_effect=parse))
    for s in stubs:
        s.start()
    try:
        ingest(
            hosts=hosts,
            client=client,
            audit=audit,
            case_id="c1",
            reduced_log_names=None,
            status_pid=os.getpid(),
            status_run_id="run-failed",
        )
    finally:
        for s in stubs:
            s.stop()
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status


def _evtx_rows(status):
    return {c["host"]: c for c in status["checklist"] if c["artifact"] == "evtx"}


def test_a_file_the_parser_rejects_is_named(tmp_path, status_dir):
    host = _host(tmp_path, "HOST1")
    _bad(host, "Security.evtx")
    row = _evtx_rows(_ingest([host]))["HOST1"]
    assert row["status"] == "failed"
    assert row["detail"].startswith("Security.evtx: "), row
    assert row["detail"] != "unknown error"


def test_every_failed_file_is_named(tmp_path, status_dir):
    host = _host(tmp_path, "HOST1")
    _bad(host, "Security.evtx")
    _bad(host, "System.evtx")
    detail = _evtx_rows(_ingest([host]))["HOST1"]["detail"]
    assert detail.startswith("Security.evtx: ") and "; System.evtx: " in detail, detail


def test_a_failure_after_an_indexed_file_is_named(tmp_path, status_dir):
    host = _host(tmp_path, "HOST1")
    _evtx(host.evtx_dir / "Application.evtx", 1, 4096 + CHUNK)
    _evtx(host.evtx_dir / "System.evtx", 1, 4096 + CHUNK)

    def parse(evtx_path, **kw):
        if evtx_path.name == "System.evtx":
            raise RuntimeError("synthetic parse failure")
        return 500, 0, 0

    status = _ingest([host], parse)
    assert _evtx_rows(status)["HOST1"]["detail"] == "System.evtx: synthetic parse failure"
    assert status["total_indexed"] == 500


def test_the_status_names_it_while_later_hosts_run(tmp_path, status_dir):
    first, second = _host(tmp_path, "host-a"), _host(tmp_path, "host-b")
    _bad(first, "Security.evtx")
    _evtx(second.evtx_dir / "Security.evtx", 1, 4096 + CHUNK)
    seen = {}

    def parse(evtx_path, **kw):
        if "host-b" in str(evtx_path):
            (live,) = srv.idx_ingest_status(case_id="c1")["ingests"]
            seen.update(_evtx_rows(live))
            return 500, 0, 0
        raise RuntimeError("synthetic parse failure")

    _ingest([first, second], parse)
    assert seen["host-a"]["detail"] == "Security.evtx: synthetic parse failure", seen


def test_anchor_a_clean_run_writes_no_error(tmp_path, status_dir):
    host = _host(tmp_path, "HOST1")
    _evtx(host.evtx_dir / "Security.evtx", 1, 4096 + CHUNK)
    status = _ingest([host], lambda evtx_path, **kw: (500, 0, 0))
    assert _evtx_rows(status)["HOST1"]["detail"] == "500 docs submitted"
    (path,) = status_dir.glob("*.json")
    (art,) = json.loads(path.read_text())["hosts"][0]["artifacts"]
    assert "error" not in art, art


@pytest.mark.parametrize("hayabusa", [False, True], ids=["no hayabusa", "hayabusa"])
def test_the_final_status_through_the_worker_names_it(tmp_path, status_dir, monkeypatch, hayabusa):
    import argparse
    import shutil

    from opensearch_mcp import ingest as ing
    from opensearch_mcp import ingest_cli as cli

    host = _host(tmp_path, "HOST1")
    _bad(host, "Security.evtx")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-scan")
    monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])
    monkeypatch.setattr(
        cli, "_preflight_host_discovery", lambda *a, **k: ({"decisions_applied": []}, None)
    )
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    batch = MagicMock(return_value={})
    monkeypatch.setattr(ing, "run_hayabusa_batch", batch)
    monkeypatch.setattr(shutil, "which", lambda n: "/x/hayabusa" if hayabusa else None)
    cli.cmd_scan(
        argparse.Namespace(
            path=str(host.volume_root),
            case="c1",
            yes=True,
            hostname="HOST1",
            all_logs=True,
            no_hayabusa=not hayabusa,
            skip_triage=True,
        )
    )
    assert batch.called == hayabusa
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert status["status"] == "complete", status
    assert _evtx_rows(status)["HOST1"]["detail"].startswith("Security.evtx: "), status
