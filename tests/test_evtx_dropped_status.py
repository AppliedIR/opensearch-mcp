"""The ingest status names the evtx files dropped before parsing, and why.

Forensic-logs mode (on by default) keeps only the logs in its set, and files
under one chunk are skipped as empty. Neither left a trace in the status an
examiner reads over MCP. parse_and_index is a stand-in; the log set is the
real one.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest
from opensearch_mcp.reduced import load_reduced_logs

OUT_OF_SET = "Microsoft-Windows-Example%4Operational.evtx"


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
    (evtx / OUT_OF_SET).write_bytes(b"\0" * 70000)
    (evtx / "System.evtx").write_bytes(b"\0" * 50000)  # in the set, under one chunk
    h = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    h.evtx_dir = evtx
    return h


def _run(host, log_names):
    assert {"security", "system"} <= load_reduced_logs()
    assert OUT_OF_SET[:-5].lower() not in load_reduced_logs()
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.parse_and_index", return_value=(500, 0, 0)) as parse,
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
    ):
        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            reduced_log_names=log_names,
            status_pid=os.getpid(),
            status_run_id="run-evtx",
        )
    parsed = sorted(c.kwargs["evtx_path"].name for c in parse.call_args_list)
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return result, parsed, status.get("warnings", [])


def test_both_drops_are_named_with_their_reasons(host):
    result, parsed, warnings = _run(host, load_reduced_logs())
    assert parsed == ["Security.evtx"] and result.hosts[0].artifacts[0].indexed == 500
    (not_in_set,) = [w for w in warnings if "forensic-logs set" in w]
    assert OUT_OF_SET in not_in_set and "all_logs=True" in not_in_set
    assert not_in_set.startswith("HOST1: 1 evtx file(s)")
    (small,) = [w for w in warnings if "under one chunk" in w]
    assert "System.evtx" in small and "Security.evtx" not in small


def test_all_logs_has_no_log_set_warning(host):
    _, parsed, warnings = _run(host, None)
    assert parsed == sorted(["Security.evtx", OUT_OF_SET])
    assert not [w for w in warnings if "forensic-logs set" in w]
    assert [w for w in warnings if "under one chunk" in w]


# --- Through cmd_scan, where a hayabusa phase rewrites the status ---------


def _scan(host, monkeypatch, hayabusa: bool):
    """The worker's cmd_scan with discovery, the client and hayabusa stubbed;
    returns the final status's dropped-evtx warnings."""
    import argparse
    import shutil

    from opensearch_mcp import ingest as ing
    from opensearch_mcp import ingest_cli as cli

    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-scan")
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
    batch = MagicMock(return_value={})
    monkeypatch.setattr(ing, "run_hayabusa_batch", batch)
    monkeypatch.setattr(shutil, "which", lambda n: "/x/hayabusa" if hayabusa else None)
    args = argparse.Namespace(
        path=str(host.volume_root),
        case="c1",
        yes=True,
        hostname="HOST1",
        all_logs=False,
        no_hayabusa=not hayabusa,
    )
    cli.cmd_scan(args)
    assert batch.called == hayabusa
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert status["status"] == "complete", status
    return [w for w in status.get("warnings", []) if "evtx file(s)" in w]


@pytest.mark.parametrize("hayabusa", [True, False])
def test_the_final_status_names_both_drops(host, monkeypatch, hayabusa):
    warnings = _scan(host, monkeypatch, hayabusa)
    assert len(warnings) == 2 and OUT_OF_SET in warnings[0] and "System.evtx" in warnings[1]


def test_a_host_whose_every_evtx_file_was_dropped_still_names_them(host, monkeypatch):
    (host.evtx_dir / "Security.evtx").unlink()
    warnings = _scan(host, monkeypatch, hayabusa=True)
    assert len(warnings) == 2, warnings
