"""An evtx file that fails flags its host's evtx index in the case summary.

The ingest loop, the audit writer and the summary are real; the evtx parse is
a stand-in that reads the file, so an unreadable one fails as it would.
Values are synthetic.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sift_common.audit import AuditWriter

from opensearch_mcp import ingest_status, server
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")

CID = "case-ev"
INDEX = f"case-{CID}-evtx-dev01"
DOCS = {INDEX: 26275}


class _Client:
    class cat:  # noqa: N801
        @staticmethod
        def indices(index, format="json", **kw):
            return [{"index": n, "docs.count": str(d)} for n, d in DOCS.items()]

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            return {"aggregations": {"hosts": {"buckets": [{"key": "dev01"}]}}}
        return {"aggregations": {"min_ts": {}, "max_ts": {}}}

    def count(self, index, body):
        return {"count": 0}


@pytest.fixture
def case(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / CID
    (case_dir / "audit").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {CID}\n")
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("VHIR_ACTIVE_CASE", CID)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(server, "_get_os", lambda: _Client())
    return tmp_path


def scan(root: Path, run_id: str, unreadable: str = ""):
    """dev01's evtx: Application, Security and System, `unreadable` mode 000."""
    evtx = root / run_id / "evtx"
    evtx.mkdir(parents=True)
    for name in ("Application.evtx", "Security.evtx", "System.evtx"):
        (evtx / name).write_bytes(b"\0" * 70000)
    if unreadable:
        (evtx / unreadable).chmod(0)
    host = DiscoveredHost(hostname="dev01", volume_root=root / run_id)
    host.evtx_dir = evtx

    def parse(**kw):
        Path(kw["evtx_path"]).read_bytes()  # PermissionError on a mode-000 file
        return 9795, 0, 0

    client = MagicMock()
    client.count.side_effect = Exception("no index")
    try:
        with patch("opensearch_mcp.ingest.parse_and_index", side_effect=parse):
            audit = AuditWriter(mcp_name=f"opensearch-ingest-{run_id}")
            ingest(hosts=[host], client=client, audit=audit, case_id=CID, reduced_log_names=None,
                   status_pid=os.getpid(), status_run_id=run_id)  # fmt: skip
    finally:
        if unreadable:
            (evtx / unreadable).chmod(0o644)


def incomplete():
    resp = server.idx_case_summary(case_id=CID)
    return [w for w in resp.get("warnings", []) if "may be incomplete" in w]


def test_an_unreadable_evtx_file_flags_the_hosts_evtx_index(case):
    scan(case, "r1", unreadable="System.evtx")
    (warning,) = incomplete()
    assert warning.startswith(
        f"{INDEX} (26,275 docs) may be incomplete: the most recent ingest of evtx on dev01"
        " failed (FAILED: "
    ), warning
    assert "Permission denied" in warning


def test_a_failed_first_file_flags_it_though_later_files_succeed(case):
    scan(case, "r1", unreadable="Application.evtx")
    (warning,) = incomplete()
    assert warning.startswith(f"{INDEX} (26,275 docs) may be incomplete") and (
        "Permission denied" in warning
    )


def test_anchor_a_healthy_case_has_none(case):
    scan(case, "r1")
    assert incomplete() == []


def test_anchor_a_clean_rerun_clears_it(case):
    scan(case, "r1", unreadable="System.evtx")
    scan(case, "r2")
    assert incomplete() == []
