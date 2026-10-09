"""The AI reads the case's machines and never decides them: idx_host_inventory
returns machines, states, names with evidence, units, document counts, flags,
suggestions and the runs awaiting host confirmation, paged, and changes no
file; no tool confirms, starts now, uploads a list or runs a host operation.
The host logs are real; the cluster is a stand-in. Values are synthetic.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import inspect
import uuid

import pytest
from sift_common import host_gate
from sift_common import host_identity as hi

from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.host_gate  # the real gate: what runs wait on is the point


@pytest.fixture
def case(monkeypatch):
    cid = f"hinv-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    hi.ensure_host_files(d)
    monkeypatch.setattr(srv, "_get_active_case", lambda: cid)
    return d


def unit(case, locator, *names):
    u = hi.unit_key(locator)
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": locator}] + [
        {"kind": "name", "unit": u, "raw": n, "evidence": ev, "origin": "artifact"}
        for n in names for ev in ("SYSTEM ComputerName", "Security.evtx Computer")
    ])  # fmt: skip
    return u


def confirm(case, u, name):
    key = hi.new_machine_key()
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": name, "pairs": [[u, name]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    return key


class Cluster:
    def __init__(self, docs: dict):
        self.docs, self.calls = docs, []

    def search(self, index, body, **k):
        self.calls.append(index)
        keys = body["query"]["terms"]["vhir.host_key"]
        buckets = [{"key": k_, "doc_count": n} for k_, n in self.docs.items() if k_ in keys]
        return {"aggregations": {"k": {"buckets": buckets}}}


def _hashes(case) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(case.rglob("*")) if p.is_file()}  # fmt: skip


def test_the_inventory_names_every_machine_and_what_waits(case, monkeypatch):
    a = unit(case, "evidence/a", "WKS01")
    b = unit(case, "evidence/b", "SRV9")
    unit(case, "evidence/c", "DC01")  # proposed only
    ka = confirm(case, a, "WKS01")
    host_gate.record_wait(case, "run-1", [hi.unit_key("evidence/c")])
    cluster = Cluster({ka: 1234})
    monkeypatch.setattr(srv, "_get_os", lambda: cluster)
    before = _hashes(case)
    inv = srv.idx_host_inventory()
    assert _hashes(case) == before  # writes nothing
    assert inv["machines_total"] == 1 and inv["machines_by_state"] == {hi.CONFIRMED: 1}
    (m,) = inv["machines"]
    assert m["host.id"] == "WKS01" and m["state"] == hi.CONFIRMED and m["docs"] == 1234
    assert m["units"] == [a] and inv["units"][a]["locator"] == "evidence/a"
    (name,) = m["names"]
    assert name["raw"] == "WKS01" and set(name["evidence"]) == {
        "SYSTEM ComputerName", "Security.evtx Computer"}  # fmt: skip
    waiting = {n["raw"] for n in inv["names_without_machine"]}
    assert waiting == {"SRV9", "DC01"} and inv["names_without_machine_total"] == 2
    (run,) = inv["awaiting_host_confirmation"]
    assert run["run_id"] == "run-1" and run["unresolved"][0]["raw"] == "DC01"
    assert b not in inv["units"]


def test_the_inventory_pages_by_name(case, monkeypatch):
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster({}))
    for n in ("WKS03", "WKS01", "WKS02"):
        confirm(case, unit(case, f"evidence/{n}", n), n)
    first = srv.idx_host_inventory(offset=0, limit=2)
    rest = srv.idx_host_inventory(offset=2, limit=2)
    assert [m["host.id"] for m in first["machines"]] == ["WKS01", "WKS02"]
    assert [m["host.id"] for m in rest["machines"]] == ["WKS03"]
    assert first["machines_total"] == rest["machines_total"] == 3


def test_the_inventory_shows_the_ais_suggestions_and_a_silent_cluster(case, monkeypatch):
    confirm(case, unit(case, "evidence/a", "WKS01"), "WKS01")
    srv.case_host_fix("WKS01", "WKS01-NEW")

    def down():
        raise ConnectionError("refused")

    monkeypatch.setattr(srv, "_get_os", down)
    inv = srv.idx_host_inventory()
    assert inv["suggestions"] and inv["suggestions"][-1]["raw"] == "WKS01"
    assert inv["machines"][0]["docs"] is None and "unavailable" in inv["docs_note"]


def test_only_runs_still_waiting_are_listed(case, monkeypatch):
    """One run's host was confirmed since, one was cancelled, one still waits."""
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster({}))
    done, gone, wait = (unit(case, f"evidence/{n}", n) for n in ("WKS01", "WKS02", "WKS03"))
    confirm(case, done, "WKS01")
    for run, u in (("run-done", done), ("run-cancelled", gone), ("run-waits", wait)):
        host_gate.record_wait(case, run, [u])
    hi.append_decision(case, {"action": "cancel_run", "examiner": "ex1",
                              "args": {"run_id": "run-cancelled"}},
                       hi.load(case).obs_offset)  # fmt: skip
    runs = [r["run_id"] for r in srv.idx_host_inventory()["awaiting_host_confirmation"]]
    assert runs == ["run-waits"]


def test_a_page_is_at_most_200_machines(case, monkeypatch):
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster({}))
    inv = srv.idx_host_inventory(limit=5000)
    assert inv["limit"] == 200


def test_names_without_a_machine_page_with_the_offset(case, monkeypatch):
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster({}))
    unit(case, "evidence/x", "A1", "A2", "A3")
    first = srv.idx_host_inventory(offset=0, limit=2)["names_without_machine"]
    rest = srv.idx_host_inventory(offset=2, limit=2)["names_without_machine"]
    assert len(first) == 2 and len(rest) == 1
    assert {n["raw"] for n in first + rest} == {"A1", "A2", "A3"}


@pytest.mark.parametrize("answer", [{"timed_out": True}, {"_shards": {"total": 4, "failed": 1}}],
                         ids=["timed out", "a shard failed"])  # fmt: skip
def test_an_incomplete_count_says_so(case, monkeypatch, answer):
    key = confirm(case, unit(case, "evidence/a", "WKS01"), "WKS01")

    class Partial(Cluster):
        def search(self, index, body, **k):
            return {**super().search(index, body, **k), **answer}

    monkeypatch.setattr(srv, "_get_os", lambda: Partial({key: 7}))
    inv = srv.idx_host_inventory()
    assert inv["machines"][0]["docs"] == 7 and "incomplete" in inv["docs_note"]


def test_a_case_without_a_readable_identity_has_no_counts_and_says_why(case, monkeypatch):
    confirm(case, unit(case, "evidence/a", "WKS01"), "WKS01")
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster({}))

    def broken(case_dir):
        raise ValueError("case_uuid is not hex")

    monkeypatch.setattr(wc, "case_identity", broken)
    inv = srv.idx_host_inventory()
    assert inv["machines"][0]["docs"] is None and "case_uuid is not hex" in inv["docs_note"]


def test_the_result_names_the_case_by_its_own_id(case, monkeypatch):
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster({}))
    meta = (case / "CASE.yaml").read_text().replace(f"case_id: {case.name}", "case_id: INC-2431")
    (case / "CASE.yaml").write_text(meta)
    assert srv.idx_host_inventory()["case_id"] == "INC-2431"


def test_with_no_case_it_says_so(monkeypatch):
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    assert "error" in srv.idx_host_inventory()


# -- no tool decides


def test_no_tool_confirms_starts_now_uploads_a_list_or_runs_a_host_operation():
    names = {t.name for t in asyncio.run(srv.server.list_tools())}
    assert "idx_host_inventory" in names and "case_host_fix" in names
    deciding = ("confirm", "start_now", "upload", "host_list", "host_op", "rename",
                "merge", "split", "approve")  # fmt: skip
    assert not [n for n in names if any(w in n for w in deciding)], names
    source = inspect.getsource(srv)
    for writer in ("append_decision(", "append_decision_items(", "start_now(",
                   "upload_host_list("):  # fmt: skip
        assert writer not in source, writer
    # host operations: a tool may report one or wait for it, never run one
    used = {a.name for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ImportFrom)
            and (node.module or "").endswith("host_ops") for a in node.names}  # fmt: skip
    assert used <= {"unfinished_note", "case_writes", "HostOpRefused"}, used
    assert "host_ops." not in source


# -- what the tool descriptions say


def test_the_query_tools_say_to_filter_by_host_id_and_that_index_names_carry_no_host():
    tools = {t.name: t.description for t in asyncio.run(srv.server.list_tools())}
    for name in ("idx_search", "idx_count", "idx_aggregate", "idx_timeline"):
        text = " ".join(tools[name].split())
        assert "filter and group by host.id" in text, name
        assert "Index names carry no host" in text, name
    status = " ".join(tools["idx_ingest_status"].split())
    assert '"awaiting host confirmation": the run has read' in status
    assert "writes nothing until the examiner confirms them" in status


def test_the_inventory_records_the_ingests_of_the_records_it_counted(case, monkeypatch):
    key = confirm(case, unit(case, "evidence/a", "WKS01"), "WKS01")

    class Counted(Cluster):
        def search(self, index, body, **k):
            resp = super().search(index, body, **k)
            assert body["aggs"]["result_ingests"]["terms"]["field"] == "vhir.ingest_audit_id"
            resp["aggregations"]["result_ingests"] = {
                "buckets": [{"key": "opensearch-ingest-1-001", "doc_count": 6}],
                "sum_other_doc_count": 0,
            }
            resp["aggregations"]["result_ingests_missing"] = {"doc_count": 1}
            return resp

    logged = []
    monkeypatch.setattr(srv, "_get_os", lambda: Counted({key: 7}))
    monkeypatch.setattr(srv.audit, "log", lambda **kw: logged.append(kw) or "aid-1")
    inv = srv.idx_host_inventory()
    (entry,) = logged
    assert entry["tool"] == "idx_host_inventory" and inv["audit_id"] == "aid-1"
    assert entry["params"]["result_ingests"] == ["opensearch-ingest-1-001"]
    assert entry["params"]["result_ingests_missing"] == 1
