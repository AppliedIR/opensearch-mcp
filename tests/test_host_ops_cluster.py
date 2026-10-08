"""The examiner's host operations against a cluster: rename, merge and split
relabel host.id on exactly the machine keys they move, never change a doc id
or a count, and are recorded only once the docs carry the new names. One runs
at a time, with no ingest writing; one left incomplete is resumed, never
replaced. Templates are the tree's, under this run's names. Values are
synthetic."""

from __future__ import annotations

import json
import uuid

import _scratch_templates
import pytest
from sift_common import host_identity as hi

from opensearch_mcp import bulk, host_ops
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.integration


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
def case(client):
    cid = f"hops-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    c12 = wc.case_identity(d)[0]
    created = _scratch_templates.install(client, f"ho-{c12}", c12=c12)
    yield d
    client.indices.delete(index=f"case-{c12}-*", ignore=[404])
    client.indices.delete(index=f"v1-{c12}-*", ignore=[404])
    _scratch_templates.remove(client, created)


def machine(client, case, name: str, n: int, artifact: str = "evtx") -> str:
    """A confirmed machine `name` whose unit wrote `n` docs; its key."""
    ctx = wc.open_unit(case, f"evidence/{name}", name, source="test", origin="artifact")
    with wc.writing(ctx):
        index = wc.index_name(artifact)
        bulk.flush_bulk(client, [
            {"_index": index, "_id": f"{name}-{i}",
             "_source": {"@timestamp": "2024-01-01T00:00:00Z", "event.code": str(i)}}
            for i in range(n)
        ])  # fmt: skip
    client.indices.refresh(index=f"case-{wc.case_identity(case)[0]}-*")
    _, key, _ = ctx.resolve(name)
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": name, "pairs": [[ctx.unit, name]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return key


def docs(client, case) -> dict:
    """_id -> (host.id, vhir.host_key) of every doc in the case."""
    c12 = wc.case_identity(case)[0]
    client.indices.refresh(index=f"case-{c12}-*")
    res = client.search(index=f"case-{c12}-*", body={"size": 1000, "query": {"match_all": {}}})
    return {
        h["_id"]: (h["_source"]["host.id"], h["_source"]["vhir.host_key"])
        for h in res["hits"]["hits"]
    }


def canon(case, key) -> str:
    return hi.load(case).machine_of_key(key).canonical


def decisions(case) -> list[str]:
    lines = (case / hi.DECISIONS).read_text().splitlines()
    return [json.loads(line).get("action") for line in lines if line.strip()]


# -- the three operations


def test_a_rename_relabels_its_machine_only_and_keeps_every_id(client, case):
    a, b = machine(client, case, "WKS01", 4), machine(client, case, "WKS02", 3)
    before = docs(client, case)
    result = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-WKS01"},
                          "ex1", client=client)  # fmt: skip
    assert result["state"] == "done" and result["relabelled"] == 4
    after = docs(client, case)
    assert set(after) == set(before)
    assert {i for i, (h, k) in after.items() if h == "FIN-WKS01"} == {
        i for i, (h, k) in before.items() if k == a
    }
    assert all(after[i] == before[i] for i, (_, k) in before.items() if k == b)
    assert canon(case, a) == "FIN-WKS01" and decisions(case)[-1] == "rename"
    assert hi.read_ops(case)["ops"][result["id"]]["before"]["keys"] == {a: 4}


def test_a_merge_relabels_the_merged_machine_and_deletes_nothing(client, case):
    a, b = machine(client, case, "WKS01", 4), machine(client, case, "WKS01-OLD", 3)
    before = docs(client, case)
    result = host_ops.run(case, {"kind": "merge", "into": a, "from": [b]}, "ex1", client=client)
    assert result["state"] == "done" and result["relabelled"] == 3
    after = docs(client, case)
    assert set(after) == set(before) and {h for h, _ in after.values()} == {"WKS01"}
    assert {k for _, k in after.values()} == {a, b}  # ids keep their own machine key
    m = hi.load(case).machine_of_key(b)
    assert m.id == hi.load(case).machine_of_key(a).id


def test_a_split_relabels_the_moved_key_back_exactly(client, case):
    a, b = machine(client, case, "WKS01", 4), machine(client, case, "WKS09", 3)
    original = docs(client, case)
    host_ops.run(case, {"kind": "merge", "into": a, "from": [b]}, "ex1", client=client)
    result = host_ops.run(case, {"kind": "split", "machine": a, "keys": [b],
                                 "canonical": "WKS09"}, "ex1", client=client)  # fmt: skip
    assert result["state"] == "done"
    assert docs(client, case) == original
    assert canon(case, b) == "WKS09" and canon(case, a) == "WKS01"


def test_pre_0_7_docs_are_relabelled_by_their_index_and_host_name(client, case):
    a = machine(client, case, "WKS01", 2)
    c12 = wc.case_identity(case)[0]
    index = f"v1-{c12}-evtx-wks01"
    client.indices.create(
        index=index,
        body={
            "mappings": {
                "properties": {
                    "host": {
                        "properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}
                    }
                }
            }
        },
    )
    client.index(index=index, id="old1", body={"host": {"name": "wks01", "id": "WKS01"}})
    client.index(index=index, id="other", body={"host": {"name": "srv9", "id": "SRV9"}},
                 refresh=True)  # fmt: skip
    u = hi.unit_key(f"pre-0.7 index {index}")
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": f"pre-0.7 index {index}"},
        {"kind": "name", "unit": u, "raw": "wks01", "evidence": "host.name", "origin": "artifact"},
        {"kind": "bind", "unit": u, "raw": "wks01", "key": a, "state": hi.CONFIRMED},
    ])  # fmt: skip
    result = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-WKS01"},
                          "ex1", client=client)  # fmt: skip
    assert result["state"] == "done" and result["relabelled"] == 3
    assert client.get(index=index, id="old1")["_source"]["host"]["id"] == "FIN-WKS01"
    assert client.get(index=index, id="other")["_source"]["host"]["id"] == "SRV9"


# -- one at a time, checks first, recorded last


def test_a_running_ingest_refuses_the_operation_and_nothing_is_written(client, case):
    a = machine(client, case, "WKS01", 2)
    before = docs(client, case)
    with hi.case_lock(case, shared=True):
        with pytest.raises(host_ops.HostOpRefused, match="case lock|runs are writing"):
            host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "X1"}, "ex1",
                         client=client)  # fmt: skip
    assert docs(client, case) == before and hi.read_ops(case)["ops"] == {}
    assert "rename" not in decisions(case)


def test_an_index_without_keyword_identity_fields_is_refused_before_any_write(client, case):
    a = machine(client, case, "WKS01", 2)
    c12 = wc.case_identity(case)[0]
    client.indices.create(index=f"case-{c12}-odd-x", body={"mappings": {"properties": {
        "host.name": {"type": "text"}, "vhir": {"properties": {
            "host_key": {"type": "keyword"}, "unit": {"type": "keyword"}}}}}})  # fmt: skip
    before = docs(client, case)
    with pytest.raises(host_ops.HostOpRefused, match="host.name as keyword"):
        host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "X1"}, "ex1",
                     client=client)  # fmt: skip
    assert docs(client, case) == before and hi.read_ops(case)["ops"] == {}


def test_an_incomplete_operation_is_resumed_and_recorded_once(client, case, monkeypatch):
    a = machine(client, case, "WKS01", 3)
    real = host_ops.verify
    monkeypatch.setattr(host_ops, "verify", lambda *a, **k: "a node went away")
    first = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                         client=client)  # fmt: skip
    assert first["state"] == "incomplete" and first["reason"] == "a node went away"
    assert canon(case, a) == "WKS01" and "rename" not in decisions(case)
    with pytest.raises(host_ops.HostOpRefused, match="resume it first"):
        host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-2"}, "ex1",
                     client=client)  # fmt: skip
    monkeypatch.setattr(host_ops, "verify", real)
    done = host_ops.run(case, None, "ex1", resume=first["id"], client=client)
    assert done["id"] == first["id"] and done["state"] == "done"
    assert canon(case, a) == "FIN-1" and decisions(case).count("rename") == 1
    assert {h for h, _ in docs(client, case).values()} == {"FIN-1"}


def test_an_operation_cut_off_partway_through_the_relabel_is_resumed_to_the_same_ids(
    client, case, monkeypatch
):
    """The relabel's task stops after one doc: the op is incomplete, a resume
    relabels the rest, and every doc keeps its id."""
    a = machine(client, case, "WKS01", 5)
    ids = set(docs(client, case))
    real = host_ops._update

    def cut_off(client_, index, query, canonical):
        client_.update_by_query(index=index, body={"query": query, "script": {
            "source": host_ops._SET_HOST_ID, "params": {"c": canonical}}},
            max_docs=1, conflicts="abort", refresh=True)  # fmt: skip
        raise RuntimeError("the worker was stopped")

    monkeypatch.setattr(host_ops, "_update", cut_off)
    first = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                         client=client)  # fmt: skip
    assert first["state"] == "incomplete" and "stopped" in first["reason"]
    assert sorted(h for h, _ in docs(client, case).values()).count("FIN-1") == 1
    monkeypatch.setattr(host_ops, "_update", real)
    done = host_ops.run(case, None, "ex1", resume=first["id"], client=client)
    assert done["state"] == "done" and done["relabelled"] == 4
    after = docs(client, case)
    assert set(after) == ids and {h for h, _ in after.values()} == {"FIN-1"}
    assert decisions(case).count("rename") == 1


def test_a_stale_doc_left_by_the_relabel_leaves_the_operation_incomplete(
    client, case, monkeypatch
):
    a = machine(client, case, "WKS01", 3)
    monkeypatch.setattr(host_ops, "relabel", lambda *a, **k: 0)  # wrote nothing
    result = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                          client=client)  # fmt: skip
    assert result["state"] == "incomplete" and "3 doc(s) still without" in result["reason"]
    assert canon(case, a) == "WKS01"


def test_failures_the_update_reports_leave_the_operation_incomplete(client, case, monkeypatch):
    a = machine(client, case, "WKS01", 2)
    monkeypatch.setattr(host_ops, "_update", lambda *a, **k: {
        "updated": 1, "failures": [{"cause": {"type": "x"}}]})  # fmt: skip
    result = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                          client=client)  # fmt: skip
    assert result["state"] == "incomplete" and "1 failure(s)" in result["reason"]
    assert canon(case, a) == "WKS01" and "rename" not in decisions(case)


def test_a_count_that_changes_during_the_operation_leaves_it_incomplete(client, case, monkeypatch):
    """Something wrote a doc of the machine meanwhile."""
    a = machine(client, case, "WKS01", 2)
    real = host_ops.relabel

    def and_one_more(client_, c12, p, forms):
        n = real(client_, c12, p, forms)
        hit = client_.search(index=f"case-{c12}-*", body={"size": 1})["hits"]["hits"][0]
        late = {**hit["_source"], "event.code": "99999"}
        client_.index(index=hit["_index"], id="late", body=late, refresh=True)
        return n

    monkeypatch.setattr(host_ops, "relabel", and_one_more)
    result = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                          client=client)  # fmt: skip
    assert result["state"] == "incomplete" and "doc counts changed" in result["reason"]
    assert "rename" not in decisions(case)


def test_the_ais_host_fix_changes_no_doc_and_no_binding(client, case, monkeypatch):
    from opensearch_mcp import case_scope
    from opensearch_mcp import server as srv

    a = machine(client, case, "WKS01", 2)
    monkeypatch.setattr(case_scope, "_active_case_id", lambda: case.name)
    before, bindings = docs(client, case), dict(hi.load(case).bindings)
    srv.case_host_fix("WKS01", "FIN-WKS01")
    assert docs(client, case) == before and hi.load(case).bindings == bindings
    assert canon(case, a) == "WKS01"
