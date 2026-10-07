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
from sift_common import host_identity

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc


def c12(case: str) -> str:
    return host_identity.ensure_case_uuid(wc.case_dir_for(case), 2)[0]


def _indices():
    return {
        f"case-{c12('case-a')}-hayabusa-0": 124,
        f"case-{c12('case-b')}-hayabusa-0": 620,
        f"case-{c12('case-a')}-evtx-0": 5000,
    }


def _count(index, **kw):
    return {
        "count": sum(
            n
            for name, n in _indices().items()
            for pattern in index.split(",")
            if fnmatch.fnmatchcase(name, pattern.strip())
        )
    }


@pytest.fixture
def cluster(monkeypatch):
    c12("case-a"), c12("case-b")  # both cases have their identities before any read
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
    assert f"index='case-{c12('case-a')}-hayabusa-*'" in suggestion, suggestion
    assert "744" not in suggestion and "case-*-hayabusa-*" not in suggestion


def test_the_ingest_next_step_names_its_own_case(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(srv, "invalidate_index_cache", lambda: None, raising=False)
    hosts = [
        {"hostname": "host1", "artifacts": [{"name": "evtx", "status": "complete", "indexed": 9}]},
        {"hostname": "hayabusa", "artifacts": [{"name": "hayabusa", "status": "complete"}]},
    ]
    own = c12("case-b")
    ingest_status.write_status("case-b", 99999999, "r", "complete", hosts, {"indexed": 9}, "t0")
    (status,) = srv.idx_ingest_status(case_id="case-b")["ingests"]
    hint = [s for s in status["next_steps"] if "Hayabusa" in s]
    assert hint == [
        "Query Hayabusa alerts: idx_search(query='Level:(emer OR crit OR critical OR high)', "
        f"index='case-{own}-hayabusa-*')"
    ], status["next_steps"]


def test_a_named_case_and_no_case(monkeypatch):
    monkeypatch.setattr(srv, "_get_active_case", lambda: "A")
    named, active = c12("Inc 9"), c12("A")
    assert srv._hayabusa_index("Inc 9") == f"case-{named}-hayabusa-*"
    assert srv._hayabusa_index() == f"case-{active}-hayabusa-*"
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    assert srv._hayabusa_index() == ""  # no case: nothing, never every case's
