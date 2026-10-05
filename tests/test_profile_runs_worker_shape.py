"""The warning, read from entries the real ingest loop writes for two profiles.

The tool runs are stubs; the ingest loop, the audit writer and the summary are real.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sift_common.audit import AuditWriter

from opensearch_mcp import server
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

CID = "case-w"
INDEX = f"case-{CID}-jumplists-host1"


class _Client:
    class cat:  # noqa: N801
        @staticmethod
        def indices(index, format="json", **kw):
            return [{"index": INDEX, "docs.count": "7"}]

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            return {"aggregations": {"hosts": {"buckets": [{"key": "host1"}]}}}
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
    monkeypatch.setattr(server, "_get_os", lambda: _Client())
    return tmp_path


def scan(root, run_id, results):
    host = DiscoveredHost(hostname="HOST1", volume_root=root / "HOST1")
    for user in results:
        recent = root / "HOST1" / "Users" / user / "AppData/Roaming/Microsoft/Windows/Recent"
        recent.mkdir(parents=True, exist_ok=True)
        host.artifacts.append(("jumplists", recent))

    def run(*args, **kwargs):
        r = results[next(p for p in Path(kwargs["artifact_path"]).parts if p in results)]
        if isinstance(r, Exception):
            raise r
        return r

    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with patch("opensearch_mcp.ingest.run_and_ingest", side_effect=run):
        ingest(
            hosts=[host],
            client=client,
            audit=AuditWriter(mcp_name=f"opensearch-ingest-{run_id}"),
            case_id=CID,
            status_run_id=run_id,
        )


def flagged():
    resp = server.idx_case_summary(case_id=CID)
    return [w.split(" ")[0] for w in resp.get("warnings", []) if "may be incomplete" in w]


def test_a_failed_profile_then_a_good_one_then_a_fixed_reingest(case):
    bad = RuntimeError("JLECmd failed (exit 3): bad file")
    scan(case / "x1", "r1", {"alice": bad, "bob": (7, 0, 0)})
    assert flagged() == [INDEX]
    scan(case / "x2", "r2", {"alice": (2, 0, 0), "bob": (7, 0, 0)})  # a new extraction dir
    assert flagged() == []
