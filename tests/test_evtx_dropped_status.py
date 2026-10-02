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
