"""An ingest's final status names its log file.

The launcher writes each worker's output to ingest-logs/<run_id>.log, but no
worker passed that path to write_status, so once a run ended the status had
no `log_file` and the examiner couldn't find the log. Workers run in-process
here with the cluster and the parsers stubbed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest import mock

import pytest
from _helpers import make_windows_tree

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import parse_memory as pm


@pytest.fixture
def run(tmp_path, monkeypatch):
    """A run id, the status dir, and the launcher's log file for that run."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "vhir" / "ingest-status")
    run_id = "run-log-path"
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", run_id)
    log = tmp_path / "vhir" / "ingest-logs" / f"{run_id}.log"
    log.parent.mkdir(parents=True)
    log.write_text("")
    for name in (
        "get_client",
        "_preflight_shard_capacity",
        "_ensure_case_active",
        "_warn_if_mapping_upgrade_required",
        "AuditWriter",
    ):
        monkeypatch.setattr(cli, name, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    return log


def _final_status() -> dict:
    (path,) = ingest_status._STATUS_DIR.glob("*.json")
    return json.loads(path.read_text())


def test_memory(run, tmp_path, monkeypatch):
    def fake(**kw):
        for p in pm.TIER_1:
            kw["on_progress"]("plugin_start", plugin=p)
            kw["on_progress"]("plugin_done", plugin=p, indexed=0)
        return {p: {"indexed": 0, "status": "done"} for p in pm.TIER_1}

    monkeypatch.setattr(pm, "ingest_memory", fake)
    img = tmp_path / "m.raw"
    img.write_bytes(b"\0" * 64)
    cli.cmd_ingest_memory(
        argparse.Namespace(
            path=str(img), case="c1", hostname="H", tier=1, plugins=None, yes=True, timeout=10
        )
    )
    status = _final_status()
    assert (status["status"], status.get("log_file")) == ("complete", str(run))


def test_delimited(run, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "opensearch_mcp.parse_delimited.ingest_delimited", lambda *a, **k: (2, 0, 0, 0)
    )
    csv = tmp_path / "a.csv"
    csv.write_text("x,y\n1,2\n")
    cli.cmd_ingest_delimited(
        argparse.Namespace(path=str(csv), case="c1", hostname="H", dry_run=False)
    )
    status = _final_status()
    assert (status["status"], status.get("log_file")) == ("complete", str(run))


def test_triage(run, tmp_path, monkeypatch):
    root = tmp_path / "evidence"
    make_windows_tree(root / "host-a")
    cli.cmd_ingest(
        argparse.Namespace(
            path=str(root / "host-a"),
            case="c1",
            hostname="host-a",
            include="evtx",
            yes=True,
            no_hayabusa=True,
        )
    )
    status = _final_status()
    assert (status["status"], status.get("log_file")) == ("complete", str(run))


def test_no_log_file_no_key(tmp_path, monkeypatch):
    """A run with no launcher log (a CLI run) gets no `log_file`."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "vhir" / "ingest-status")
    ingest_status.write_status(
        "c1", 7, "run-without-log", "complete", [], {}, "2026-10-01T00:00:00Z"
    )
    assert "log_file" not in _final_status()


def test_an_explicit_log_file_is_kept(run):
    ingest_status.write_status(
        "c1", 7, "run-log-path", "running", [], {}, "2026-10-01T00:00:00Z", log_file="/given.log"
    )
    assert _final_status()["log_file"] == "/given.log"


@pytest.fixture
def launch(tmp_path, monkeypatch):
    """The MCP tools up to the spawn, stubbed below it."""
    from opensearch_mcp import mappings, paths, shard_capacity
    from opensearch_mcp import server as srv

    vhir = tmp_path / "vhir"
    case = tmp_path / "cases" / "CASE-T"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-T\n")
    vhir.mkdir(exist_ok=True)
    (vhir / "active_case").write_text(str(case))
    monkeypatch.setattr(paths, "vhir_dir", lambda: vhir)
    monkeypatch.setattr(srv, "_get_active_case", lambda: "CASE-T")
    monkeypatch.setattr(srv, "get_client", lambda: mock.MagicMock())
    monkeypatch.setattr(srv, "_spawn_ingest", lambda *a, **k: mock.MagicMock(pid=4242))
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    monkeypatch.setattr(mappings, "ensure_winlog_pipeline", lambda c: {"status": "ok"})
    monkeypatch.setattr(ingest_status, "write_status", lambda *a, **k: None)
    monkeypatch.setattr(ingest_status, "read_active_ingests", lambda *a, **k: [])
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "mem.img").write_bytes(b"\0" * 16)
    make_windows_tree(evidence / "host-a")
    return srv, evidence, vhir


@pytest.mark.parametrize("tool", ["idx_ingest", "idx_ingest_memory"])
def test_the_start_response_names_the_log(launch, tool):
    srv, evidence, vhir = launch
    if tool == "idx_ingest":
        resp = srv.idx_ingest(path=str(evidence / "host-a"), hostname="h", dry_run=False)
    else:
        resp = srv.idx_ingest_memory(path=str(evidence / "mem.img"), hostname="h", dry_run=False)
    assert resp["status"] == "started", resp
    log = Path(resp["log_file"])
    assert (log.parent, log.suffix) == (vhir / "ingest-logs", ".log")
