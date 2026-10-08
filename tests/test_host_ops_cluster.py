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


@pytest.mark.parametrize("kind", ["rename", "merge", "split"])
def test_a_worker_stopped_after_the_decision_is_resumed_to_done(client, case, monkeypatch, kind):
    """The decision line is written, then the worker dies before the journal
    says done: a resume finishes it, and the case takes new work again."""
    a, b = machine(client, case, "WKS01", 2), machine(client, case, "WKS02", 2)
    if kind == "split":
        host_ops.run(case, {"kind": "merge", "into": a, "from": [b]}, "ex1", client=client)
    op = {
        "rename": {"kind": "rename", "machine": a, "canonical": "FIN-1"},
        "merge": {"kind": "merge", "into": a, "from": [b]},
        "split": {"kind": "split", "machine": a, "keys": [b], "canonical": "FIN-2"},
    }[kind]
    real = hi.record_op

    def dies_on_done(root, op_id, fields, check=None):
        if fields.get("state") == "done":
            raise SystemExit("killed")
        return real(root, op_id, fields, check=check)

    monkeypatch.setattr(hi, "record_op", dies_on_done)
    with pytest.raises(SystemExit):
        host_ops.run(case, op, "ex1", client=client)
    monkeypatch.setattr(hi, "record_op", real)
    pending = hi.unfinished_op(case)
    assert pending is not None and pending["state"] == "running"
    done = host_ops.run(case, None, "ex1", resume=pending["id"], client=client)
    assert done["state"] == "done" and hi.unfinished_op(case) is None
    assert decisions(case).count(kind) == 1
    nxt = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "NEXT-1"}, "ex1",
                       client=client)  # fmt: skip
    assert nxt["state"] == "done"


def test_docs_not_yet_visible_are_in_the_baseline(client, case):
    """A doc written without a refresh just before the operation."""
    a = machine(client, case, "WKS01", 2)
    hit = client.search(index=f"case-{wc.case_identity(case)[0]}-*",
                        body={"size": 1})["hits"]["hits"][0]  # fmt: skip
    client.index(index=hit["_index"], id="unrefreshed", refresh=False,
                 body={**hit["_source"], "event.code": "99998"})  # fmt: skip
    result = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                          client=client)  # fmt: skip
    assert result["state"] == "done", result
    assert result["relabelled"] == 3


def test_an_operation_from_a_page_that_has_gone_stale_is_refused(client, case):
    """Two tabs: one renamed the machine since the other was opened."""
    a = machine(client, case, "WKS01", 2)
    mid = hi.load(case).machine_of_key(a).id
    host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                 client=client, expect={mid: "WKS01"})  # fmt: skip
    before, ops = docs(client, case), dict(hi.read_ops(case)["ops"])
    with pytest.raises(host_ops.HostOpRefused, match="refused: changed since you opened it"):
        host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-2"}, "ex1",
                     client=client, expect={mid: "WKS01"})  # fmt: skip
    assert docs(client, case) == before and hi.read_ops(case)["ops"] == ops
    assert canon(case, a) == "FIN-1"


def _scan_only_unit(case):
    """A unit the scan named OTHER, with no docs yet."""
    u = hi.unit_key("evidence/scan-only")
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": "evidence/scan-only"}] + [
        {"kind": "name", "unit": u, "raw": "OTHER", "evidence": ev, "origin": "artifact"}
        for ev in ("SYSTEM ComputerName", "Security.evtx Computer")])  # fmt: skip
    return u


def _take_the_name(case, u, name):
    return hi.append_decision_items(case, {"action": "confirm", "examiner": "ex2", "args": {
        "machines": [{"key": hi.new_machine_key(), "canonical": name, "pairs": [[u, "OTHER"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip


def test_a_name_taken_before_the_operation_starts_refuses_it_and_writes_nothing(
    client, case, monkeypatch
):
    """Another machine is confirmed under the operation's new name after the
    operation was planned, before its journal entry: it plans again under the
    lock and refuses, so it never relabels into a name it can't record."""
    a = machine(client, case, "WKS01", 2)
    mid = hi.load(case).machine_of_key(a).id
    u = _scan_only_unit(case)
    real = host_ops.check_headroom

    def then_another_takes_the_name(*args, **kw):
        real(*args, **kw)
        _take_the_name(case, u, "FIN-1")

    monkeypatch.setattr(host_ops, "check_headroom", then_another_takes_the_name)
    before = docs(client, case)
    with pytest.raises(host_ops.HostOpRefused, match="already used by another machine"):
        host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                     client=client, expect={mid: "WKS01"})  # fmt: skip
    assert docs(client, case) == before and hi.read_ops(case)["ops"] == {}
    assert canon(case, a) == "WKS01" and hi.unfinished_op(case) is None


def test_a_name_taken_once_the_operation_is_running_is_refused_instead(client, case, monkeypatch):
    a = machine(client, case, "WKS01", 2)
    u = _scan_only_unit(case)
    real, tried = host_ops.relabel, []

    def while_relabelling(*args, **kw):
        try:
            _take_the_name(case, u, "FIN-1")
        except hi.HostOpRunning as e:
            tried.append(str(e))
        return real(*args, **kw)

    monkeypatch.setattr(host_ops, "relabel", while_relabelling)
    done = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                        client=client)  # fmt: skip
    assert done["state"] == "done" and canon(case, a) == "FIN-1"
    assert tried and "a host rename/merge is running" in tried[0]


def test_a_list_upload_during_the_operation_is_refused_and_the_operation_finishes(
    client, case, monkeypatch
):
    """The list would confirm a doc-less unit under the operation's new name."""
    from sift_common import host_proposal as hp

    a = machine(client, case, "WKS01", 2)
    _scan_only_unit(case)
    real, tried = host_ops.relabel, []

    def while_relabelling(*args, **kw):
        try:
            hp.upload_host_list(case, "OTHER,FIN-1\n", "ex2")
        except hi.HostOpRunning as e:
            tried.append(str(e))
        return real(*args, **kw)

    monkeypatch.setattr(host_ops, "relabel", while_relabelling)
    done = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                        client=client)  # fmt: skip
    assert done["state"] == "done" and canon(case, a) == "FIN-1"
    assert tried and "a host rename/merge is running" in tried[0]
    assert hi.unfinished_op(case) is None


def test_a_resume_ignores_what_the_page_saw(client, case, monkeypatch):
    a = machine(client, case, "WKS01", 2)
    mid = hi.load(case).machine_of_key(a).id
    real = host_ops.verify
    monkeypatch.setattr(host_ops, "verify", lambda *a, **k: "a node went away")
    first = host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "FIN-1"}, "ex1",
                         client=client, expect={mid: "WKS01"})  # fmt: skip
    monkeypatch.setattr(host_ops, "verify", real)
    done = host_ops.run(case, None, "ex1", resume=first["id"], client=client,
                        expect={mid: "SOMETHING-ELSE"})  # fmt: skip
    assert done["state"] == "done" and canon(case, a) == "FIN-1"


def test_the_ais_host_fix_changes_no_doc_and_no_binding(client, case, monkeypatch):
    from opensearch_mcp import case_scope
    from opensearch_mcp import server as srv

    a = machine(client, case, "WKS01", 2)
    monkeypatch.setattr(case_scope, "_active_case_id", lambda: case.name)
    before, bindings = docs(client, case), dict(hi.load(case).bindings)
    srv.case_host_fix("WKS01", "FIN-WKS01")
    assert docs(client, case) == before and hi.load(case).bindings == bindings
    assert canon(case, a) == "WKS01"
