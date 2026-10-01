"""idx_ingest_status warns when a memory ingest's pslist came back empty.

A running Windows image always has processes. The worker records an empty
plugin as `complete` with 0 indexed, so the status read "0 docs submitted"
and nothing more, which tells the examiner there is nothing to find.
"""

from __future__ import annotations

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp.server import idx_ingest_status

TIER_1 = ["windows.info", "windows.pslist", "windows.cmdline", "windows.modules"]


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    return tmp_path / "status"


def _memory_run(status_dir, pslist: int, run_id: str = "run-mem") -> dict:
    counts = {
        "windows.info": 1,
        "windows.pslist": pslist,
        "windows.cmdline": 0,
        "windows.modules": 0,
    }
    artifacts = [{"name": p, "status": "complete", "indexed": counts[p]} for p in TIER_1]
    ingest_status.write_status(
        case_id="CASE-1",
        pid=1,
        run_id=run_id,
        status="complete",
        hosts=[{"hostname": "host-a", "artifacts": artifacts}],
        totals={"indexed": sum(counts.values()), "artifacts_total": 4, "artifacts_complete": 4},
        started="2026-10-01T00:00:00Z",
    )
    (run,) = idx_ingest_status(case_id="CASE-1")["ingests"]
    return run


def test_an_empty_pslist_carries_the_warning(status_dir):
    run = _memory_run(status_dir, pslist=0)
    (warning,) = [w for w in run.get("warnings", []) if "windows.pslist" in w]
    assert warning.startswith("host-a: windows.pslist indexed no processes")
    assert "windows.psscan" in warning and "check the ingest log" in warning


def test_a_pslist_with_processes_does_not(status_dir):
    """Other plugins at 0 (cmdline, modules) are not warned about."""
    run = _memory_run(status_dir, pslist=170)
    assert not [w for w in run.get("warnings", []) if "pslist" in w]
