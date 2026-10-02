"""Hayabusa counts and query hints cover the active case, not every case.

idx_list_detections counted `case-*-hayabusa-*` and pointed the AI at it, so
with an active case of 124 alerts it reported every case's 744 and handed
back a query over all of them. The cluster is a stand-in that counts by
pattern over a fixed set of indices.
"""

from __future__ import annotations

import fnmatch
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv

INDICES = {
    "case-case-a-hayabusa-host1": 124,
    "case-case-b-hayabusa-host9": 620,
    "case-case-a-evtx-host1": 5000,
}


def _count(index, **kw):
    return {
        "count": sum(
            n
            for name, n in INDICES.items()
            for pattern in index.split(",")
            if fnmatch.fnmatchcase(name, pattern.strip())
        )
    }


@pytest.fixture
def cluster(monkeypatch):
    client = MagicMock()
    client.count.side_effect = _count
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    monkeypatch.setattr(srv, "_get_active_case", lambda: "case-a")
    return client


@pytest.mark.parametrize("branch", ["no sigma plugin", "no sigma findings"])
def test_the_active_cases_alerts_only(cluster, branch):
    if branch == "no sigma plugin":
        cluster.transport.perform_request.side_effect = RuntimeError("404 No detectors found")
    else:
        cluster.transport.perform_request.return_value = {"total_findings": 0, "findings": []}
    suggestion = srv.idx_list_detections()["suggestion"]
    assert "124 Hayabusa alerts" in suggestion, suggestion
    assert "index='case-case-a-hayabusa-*'" in suggestion, suggestion
    assert "744" not in suggestion and "case-*-hayabusa-*" not in suggestion


def test_the_ingest_next_step_names_its_own_case(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(srv, "invalidate_index_cache", lambda: None, raising=False)
    hosts = [
        {"hostname": "host1", "artifacts": [{"name": "evtx", "status": "complete", "indexed": 9}]},
        {"hostname": "hayabusa", "artifacts": [{"name": "hayabusa", "status": "complete"}]},
    ]
    ingest_status.write_status("case-b", 99999999, "r", "complete", hosts, {"indexed": 9}, "t0")
    (status,) = srv.idx_ingest_status(case_id="case-b")["ingests"]
    hint = [s for s in status["next_steps"] if "Hayabusa" in s]
    assert hint == [
        "Query Hayabusa alerts: idx_search(query='Level:critical OR Level:high', "
        "index='case-case-b-hayabusa-*')"
    ], status["next_steps"]


def test_a_named_case_and_no_case(monkeypatch):
    monkeypatch.setattr(srv, "_get_active_case", lambda: "A")
    assert srv._hayabusa_index("Inc 9") == "case-inc-9-hayabusa-*"
    assert srv._hayabusa_index() == "case-a-hayabusa-*"
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    assert srv._hayabusa_index() == "case-*-hayabusa-*"
