"""`--exclude evtx` skips the event logs and the Hayabusa phase that reads them.

The excluded host still had its evtx folder, so the event logs were indexed
and Hayabusa ran anyway. Discovery, preflight, the client and evtx parsing are
stubbed; the Hayabusa batch is a stand-in that records whether it ran.
"""

from __future__ import annotations

import argparse
import shutil
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost


@pytest.fixture
def scan(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-x")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    evtx = tmp_path / "ev" / "evtx"
    evtx.mkdir(parents=True)
    (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path / "ev")
    host.evtx_dir = evtx
    monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])
    monkeypatch.setattr(cli, "discover_artifacts", lambda *a, **k: [], raising=False)
    monkeypatch.setattr(
        cli, "_preflight_host_discovery", lambda *a, **k: ({"decisions_applied": []}, None)
    )
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    parse = MagicMock(return_value=(500, 0, 0))
    monkeypatch.setattr(ing, "parse_and_index", parse)
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    monkeypatch.setattr(shutil, "which", lambda n: "/x/hayabusa")
    batch = MagicMock(return_value={})
    monkeypatch.setattr(ing, "run_hayabusa_batch", batch)

    def run(exclude=None):
        args = argparse.Namespace(
            path=str(tmp_path / "ev"),
            case="c1",
            yes=True,
            hostname="HOST1",
            all_logs=False,
            no_hayabusa=False,
            skip_triage=True,
            exclude=exclude,
        )
        cli.cmd_scan(args)
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status, parse, batch

    return run


def _rows(status):
    return [c["artifact"] for c in status.get("checklist", [])]


def test_exclude_evtx_skips_the_event_logs_and_hayabusa(scan):
    status, parse, batch = scan(exclude="evtx")
    assert not parse.called
    assert not batch.called
    assert "evtx" not in _rows(status) and "hayabusa-detection" not in _rows(status)


def test_without_exclude_the_event_logs_and_hayabusa_run(scan):
    status, parse, batch = scan()
    assert parse.called and batch.called
    assert "evtx" in _rows(status) and "hayabusa-detection" in _rows(status)


def test_excluding_another_type_keeps_the_event_logs(scan):
    status, parse, batch = scan(exclude="amcache,shimcache")
    assert parse.called and batch.called
    assert "evtx" in _rows(status)
