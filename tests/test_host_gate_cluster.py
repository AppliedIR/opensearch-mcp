"""Start now against a cluster: records stored under the proposed machine are
marked in results until the examiner confirms it, and that confirmation
changes no stored document. Templates are the tree's, under this run's names.
Values are synthetic."""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest
from registry_rows import register
from sift_common import host_gate
from sift_common import host_identity as hi

from opensearch_mcp import bulk
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc

pytestmark = [pytest.mark.integration, pytest.mark.host_gate]


@pytest.fixture(scope="module")
def client():
    try:
        from opensearch_mcp.client import get_client

        c = get_client()
        if c.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    return c


@pytest.fixture
def case(client, monkeypatch):
    cid = f"gate-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    c12 = wc.case_identity(d)[0]
    created = _scratch_templates.install(client, f"gt-{c12}", c12=c12)
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv, "_get_active_case", lambda: cid)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    yield d
    client.indices.delete(index=f"case-{c12}-*", ignore=[404])
    _scratch_templates.remove(client, created)


def _seq_nos(client, case_dir) -> dict:
    c12 = wc.case_identity(case_dir)[0]
    res = client.search(
        index=f"case-{c12}-*", body={"query": {"match_all": {}}, "size": 100,
                                    "seq_no_primary_term": True},
    )  # fmt: skip
    return {h["_id"]: (h["_seq_no"], h["_primary_term"]) for h in res["hits"]["hits"]}


def test_start_now_then_an_unchanged_confirm_marks_then_unmarks_and_rewrites_nothing(client, case):
    u = hi.unit_key("evidence/WKS80")
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": "evidence/WKS80"},
        {"kind": "name", "unit": u, "raw": "WKS80", "evidence": "SYSTEM", "origin": "artifact"},
    ])  # fmt: skip
    host_gate.record_wait(case, "run-g3", [u])
    (m,) = host_gate.start_now(case, "run-g3", "ex1")["machines"]

    ctx = wc.open_unit(case, "evidence/WKS80", "WKS80", source="test", origin="artifact")
    with wc.writing(ctx):
        index = wc.index_name("evtx")
        docs = [{"_index": index, "_id": str(i),
                 "_source": {"@timestamp": "2024-01-01T00:00:00Z", "event.code": "4624"}}
                for i in range(3)]  # fmt: skip
        bulk.flush_bulk(client, docs)
    client.indices.refresh(index=index)

    hits = srv.idx_search(query="*", limit=10)["results"]
    assert len(hits) == 3 and all(h.get("host_unconfirmed") for h in hits)
    assert {h["host.id"] for h in hits} == {m["canonical"]}
    assert srv.idx_count(query="*")["host_unconfirmed"] == 3
    before = _seq_nos(client, case)

    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": m["key"], "canonical": m["canonical"], "pairs": m["pairs"]}]}},
        hi.load(case).obs_offset)  # fmt: skip

    assert _seq_nos(client, case) == before  # no stored document changed
    hits = srv.idx_search(query="*", limit=10)["results"]
    assert not any(h.get("host_unconfirmed") for h in hits)
    assert "host_unconfirmed" not in srv.idx_count(query="*")


def test_a_run_whose_hosts_are_confirmed_answers_started_at_once(client, tmp_path, monkeypatch):
    """A real worker: the launch waits for it to pass the gate, then says so,
    and the worker stores the row. It writes under vhir's own templates, which
    it installs at its first write: template copies for this case would
    outrank them, and the worker, a process of its own, refuses an index
    whose vhir template is outranked."""
    import os
    import shutil
    import time
    from pathlib import Path

    from _helpers import confirm_unit

    from opensearch_mcp import ingest_status, shard_capacity

    real_home = Path(os.environ["HOME"])
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    shutil.copy(real_home / ".vhir" / "opensearch.yaml", home / ".vhir")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", home / ".vhir" / "ingest-status")
    cid = f"gate-run-{uuid.uuid4().hex[:8]}"
    case_dir = home / "cases" / cid
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    (home / ".vhir" / "active_case").write_text(str(case_dir))
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    rows = case_dir / "evidence" / "events.csv"
    rows.write_text("when,what\n2026-01-01T00:00:00Z,a\n")
    confirm_unit(case_dir, rows, "h1")  # the examiner confirmed it already
    register(case_dir, rows)
    c12 = wc.case_identity(case_dir)[0]

    def settled():  # the worker has ended
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            runs = [r for r in ingest_status.read_active_ingests() if r.get("case_id") == cid]
            if not any(r.get("status") in ("running", "starting") for r in runs):
                return
            time.sleep(0.5)

    try:
        t0 = time.monotonic()
        resp = srv.idx_ingest_delimited(
            path=str(rows), hostname="h1", time_field="when", dry_run=False
        )
        assert resp["status"] == "started", resp
        assert time.monotonic() - t0 < srv._GATE_ANSWER_SECONDS
        assert "hosts_note" not in resp
        settled()
        client.indices.refresh(index=f"case-{c12}-*")
        assert client.count(index=f"case-{c12}-delim-*")["count"] == 1  # the row is stored
    finally:
        settled()  # before the cleanup
        client.indices.delete(index=f"case-{c12}-*", ignore=[404])
