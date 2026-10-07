"""Hayabusa counts and query hints cover the active case, not every case.

idx_list_detections counted `case-*-hayabusa-*` and pointed the AI at it, so
with an active case of 124 alerts it reported every case's 744 and handed
back a query over all of them. The cluster is a stand-in that counts by
pattern over a fixed set of indices.
"""

from __future__ import annotations

import fnmatch
import uuid
from unittest.mock import MagicMock

import pytest
import yaml
from sift_common import host_identity

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc


def c12(case: str) -> str:
    """The case's identity, as a case made by 0.7: another row may have
    made the same case id first, without a naming version."""
    d = wc.case_dir_for(case)
    meta = yaml.safe_load((d / "CASE.yaml").read_text()) or {}
    if meta.get("naming_version") != 2:
        meta["naming_version"] = 2
        (d / "CASE.yaml").write_text(yaml.safe_dump(meta))
    return host_identity.ensure_case_uuid(d, 2)[0]


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
    assert "744 Hayabusa" not in suggestion and "case-*-hayabusa-*" not in suggestion


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


def _resolve(pattern: str, names) -> dict:
    """What the cluster resolves an expression with exclusions to."""
    parts = [p.strip() for p in pattern.split(",")]
    keep = {n for n in names for p in parts if not p.startswith("-") and fnmatch.fnmatchcase(n, p)}
    drop = {n for n in names for p in parts if p.startswith("-") and fnmatch.fnmatchcase(n, p[1:])}
    return {n: {} for n in sorted(keep - drop)}


@pytest.fixture
def old_case_beside_a_longer_one(monkeypatch, tmp_path):
    """A case from before 0.7 beside a case whose id is its id plus
    "-hayabusa…": that case's indices fall under its alert expression, which
    then carries an exclusion."""
    old = f"old{uuid.uuid4().hex[:6]}"
    wc.case_dir_for(old), wc.case_dir_for(f"{old}-hayabusa-review")  # pre-0.7: no case_uuid
    names = {f"case-{old}-hayabusa-wks10": 7, f"case-{old}-hayabusa-review-evtx-wks90": 50}
    client = MagicMock()
    client.indices.get.side_effect = lambda index, **kw: _resolve(index, names)
    client.count.side_effect = lambda index, **kw: {
        "count": sum(names[n] for n in _resolve(index, names))
    }
    client.transport.perform_request.return_value = {"total_findings": 0, "findings": []}
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    monkeypatch.setattr(srv, "_get_active_case", lambda: old)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(srv, "invalidate_index_cache", lambda: None, raising=False)
    return old


def _hinted_index(text: str) -> str:
    return text.split("index='", 1)[1].split("'", 1)[0]


def test_a_hint_with_an_exclusion_names_indices_idx_search_accepts(old_case_beside_a_longer_one):
    old = old_case_beside_a_longer_one
    assert "-case-" in srv._hayabusa_index()  # the expression does exclude
    suggestion = srv.idx_list_detections()["suggestion"]
    assert "7 Hayabusa alerts" in suggestion, suggestion
    index = _hinted_index(suggestion)
    assert srv._validate_index(index) is None
    assert index == f"case-{old}-hayabusa-wks10"

    hosts = [{"hostname": "hayabusa", "artifacts": [{"name": "hayabusa", "status": "complete"}]}]
    ingest_status.write_status(old, 99999998, "r", "complete", hosts, {"indexed": 7}, "t0")
    (status,) = srv.idx_ingest_status(case_id=old)["ingests"]
    (hint,) = [s for s in status["next_steps"] if "Hayabusa" in s]
    assert srv._validate_index(_hinted_index(hint)) is None
    assert _hinted_index(hint) == f"case-{old}-hayabusa-wks10"


def test_a_hint_for_a_case_beside_a_0_7_case_with_a_longer_id_works(monkeypatch, tmp_path):
    from opensearch_mcp.case_scope import confine

    old = f"old{uuid.uuid4().hex[:6]}"
    wc.case_dir_for(old)  # pre-0.7: no case_uuid
    # made by 0.7, so no pre-0.7 indices, but its id reaches under the alert prefix
    newer = wc.case_dir_for(f"{old}-hayabusa-review")
    (newer / "CASE.yaml").write_text(
        f"case_id: {old}-hayabusa-review\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    names = {f"case-{old}-hayabusa-wks10": 7}
    client = MagicMock()
    client.indices.get.side_effect = lambda index, **kw: _resolve(index, names)
    client.count.side_effect = lambda index, **kw: {
        "count": sum(names[n] for n in _resolve(index, names))
    }
    client.transport.perform_request.return_value = {"total_findings": 0, "findings": []}
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    monkeypatch.setattr(srv, "_get_active_case", lambda: old)
    assert "-case-" not in srv._hayabusa_index()  # the exclusion was dropped
    index = _hinted_index(srv.idx_list_detections()["suggestion"])
    assert srv._validate_index(index) is None
    assert confine(index, old, client) == index  # idx_search accepts it
