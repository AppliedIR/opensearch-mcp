"""An evtx scan says `running` until its hayabusa phase ends.

ingest() wrote the run's terminal `complete` before cmd_scan's hayabusa
phase, whose `running` write the status's monotonic guard then refused: for
the whole phase the status read `complete` with no hayabusa row, and a poll
that waits for `complete` stopped before any detection existed. Discovery,
preflight, the client and evtx parsing are stubbed; the hayabusa batch is a
stand-in that reads the status while it "runs".
"""

from __future__ import annotations

import argparse
import shutil
import sys
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost


def _status() -> dict:
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """Runs cmd_scan on one host with an in-set evtx file; `batch` is what
    the hayabusa phase calls."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-hb")
    # A real worker is spawned with the run id in its environ, which is how
    # the status sweep knows it's alive; this process got it too late.
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
    monkeypatch.setattr(ing, "parse_and_index", MagicMock(return_value=(500, 0, 0)))
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    monkeypatch.setattr(shutil, "which", lambda n: "/x/hayabusa")

    def run(batch, no_hayabusa=False, enrich=None):
        """`enrich`, when given, is the triage enrichment phase."""
        monkeypatch.setattr(ing, "run_hayabusa_batch", batch)
        if enrich is not None:
            from opensearch_mcp import triage_remote

            monkeypatch.setattr(triage_remote, "enrich_remote", enrich)
        args = argparse.Namespace(
            path=str(tmp_path / "ev"),
            case="c1",
            yes=True,
            hostname="HOST1",
            all_logs=False,
            no_hayabusa=no_hayabusa,
            skip_triage=enrich is None,
        )
        cli.cmd_scan(args)
        return _status()

    return run


def _hayabusa_row(status):
    return [c for c in status.get("checklist", []) if c["artifact"] == "hayabusa-detection"]


def test_the_status_says_running_until_hayabusa_ends(scan):
    seen = []

    def batch(*a, **k):
        seen.append(_status()["status"])  # read while detection "runs"
        return {}

    final = scan(batch)
    assert seen == ["running"]
    assert final["status"] == "complete"
    assert [c["status"] for c in _hayabusa_row(final)] == ["done"]


def test_without_a_hayabusa_phase_ingest_ends_complete(scan):
    batch = MagicMock()
    final = scan(batch, no_hayabusa=True)
    assert not batch.called
    assert final["status"] == "complete" and not _hayabusa_row(final)


def test_a_hayabusa_phase_that_raises_ends_failed(scan, monkeypatch):
    """The worker's excepthook turns a status still `running` into `failed`;
    one that already says `complete` it leaves."""
    import atexit

    monkeypatch.setattr(atexit, "register", lambda f: f)  # not this test process's exit
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    cli._install_terminal_status_guards()

    def batch(*a, **k):
        raise RuntimeError("hayabusa crashed")

    with pytest.raises(RuntimeError) as err:
        scan(batch)
    sys.excepthook(err.type, err.value, err.tb)
    final = _status()
    assert final["status"] == "failed", final
    assert "hayabusa crashed" in final["message"], final


# --- Triage enrichment runs after hayabusa, and last --------------------


@pytest.mark.parametrize("no_hayabusa", [False, True], ids=["hayabusa", "no hayabusa"])
def test_the_status_says_running_until_triage_ends(scan, no_hayabusa):
    seen = []

    def batch(*a, **k):
        seen.append(("hayabusa", _status()["status"]))
        return {}

    def enrich(**kw):
        seen.append(("triage", _status()["status"]))
        return {}

    final = scan(batch, no_hayabusa=no_hayabusa, enrich=enrich)
    phases = (
        [("triage", "running")]
        if no_hayabusa
        else [
            ("hayabusa", "running"),
            ("triage", "running"),
        ]
    )
    assert seen == phases
    assert final["status"] == "complete"
    assert bool(_hayabusa_row(final)) is not no_hayabusa


def test_a_triage_phase_that_fails_still_ends_complete(scan):
    """Enrichment failures are reported and the scan goes on, as before."""

    def enrich(**kw):
        raise RuntimeError("gateway down")

    assert scan(lambda *a, **k: {}, enrich=enrich)["status"] == "complete"


def test_finishing_leaves_a_failed_run_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    ingest_status.write_status("c1", 7, "r", "failed", [], {}, "2026-10-02T00:00:00Z", error="x")
    ingest_status.finish_status("c1", 7)
    (path,) = (tmp_path / "status").glob("*.json")
    assert '"status": "failed"' in path.read_text()
