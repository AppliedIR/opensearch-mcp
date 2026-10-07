"""Start now against a cluster: records stored under the proposed machine are
marked in results until the examiner confirms it, and that confirmation
changes no stored document. Templates are the tree's, under this run's names.
Values are synthetic."""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest
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


def test_start_now_then_an_unchanged_confirm_marks_then_unmarks_and_rewrites_nothing(
    client, case
):
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
