"""The examiner's host operations, without a cluster: what each may do to the
case as it is, the index checks before any write, who is named when the case
is busy, and the worker's command line. Values are synthetic."""

from __future__ import annotations

import json
import os
import uuid

import pytest
from sift_common import host_identity as hi

from opensearch_mcp import host_ops, ingest_status
from opensearch_mcp import write_context as wc


@pytest.fixture
def case():
    cid = f"hops-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    hi.ensure_host_files(d)
    return d


def machine(case, name, locator=None):
    """A confirmed machine `name` holding one unit's name; its key."""
    locator = locator or f"evidence/{name}"
    u = hi.unit_key(locator)
    key = hi.new_machine_key()
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": locator},
        {"kind": "name", "unit": u, "raw": name, "evidence": "SYSTEM", "origin": "artifact"},
        {"kind": "bind", "unit": u, "raw": name, "key": key, "canonical": name,
         "state": hi.CONFIRMED},
    ])  # fmt: skip
    return key


# -- what each operation may do


@pytest.mark.parametrize(
    "op, why",
    [
        ({"kind": "delete"}, "unknown host operation"),
        ({"kind": "rename", "machine": "nope", "canonical": "X"}, "no machine"),
        ({"kind": "rename", "machine": "A", "canonical": "WKS01"}, "already named"),
        ({"kind": "rename", "machine": "A", "canonical": "wks02"}, "merge the two machines"),
        ({"kind": "rename", "machine": "A", "canonical": "X\n[evil]"}, "control characters"),
        ({"kind": "rename", "machine": "A", "canonical": "  "}, "must be given"),
        ({"kind": "merge", "into": "A", "from": []}, "one or more other machines"),
        ({"kind": "merge", "into": "A", "from": ["A"]}, "one or more other machines"),
        ({"kind": "split", "machine": "A", "keys": [], "canonical": "X"}, "never none"),
        ({"kind": "split", "machine": "A", "keys": ["A"], "canonical": "X"}, "never all"),
        ({"kind": "split", "machine": "A", "keys": ["B"], "canonical": "X"}, "never none"),
    ],
)
def test_an_operation_that_doesnt_fit_the_case_is_refused(case, op, why):
    keys = {"A": machine(case, "WKS01"), "B": machine(case, "WKS02")}
    op = {k: (keys.get(v, v) if isinstance(v, str) else [keys.get(x, x) for x in v])
          for k, v in op.items()}  # fmt: skip
    with pytest.raises(host_ops.HostOpRefused, match=why):
        host_ops.plan(hi.load(case), op)


def test_a_split_takes_its_moved_keys_names_and_a_unique_name(case):
    a, b = machine(case, "WKS01"), machine(case, "WKS09")
    hi.append_decision(case, {"action": "merge", "examiner": "ex1",
                              "args": {"into": a, "from": [b]}},
                       hi.load(case).obs_offset, door="R")  # fmt: skip
    with pytest.raises(host_ops.HostOpRefused, match="already used"):
        host_ops.plan(hi.load(case), {"kind": "split", "machine": a, "keys": [b],
                                      "canonical": "WKS01"})  # fmt: skip
    p = host_ops.plan(hi.load(case), {"kind": "split", "machine": a, "keys": [b],
                                      "canonical": "WKS09"})  # fmt: skip
    assert p["keys"] == [b] and p["canonical"] == "WKS09" and p["v1"] == []


def test_a_merge_moves_the_other_machines_keys_under_the_kept_name(case):
    a, b = machine(case, "WKS01"), machine(case, "WKS01-OLD")
    p = host_ops.plan(hi.load(case), {"kind": "merge", "into": a, "from": [b]})
    assert p["keys"] == [b] and p["canonical"] == "WKS01"
    assert p["args"] == {"into": a, "from": [b]}


def test_pre_0_7_names_go_with_their_machine_by_index_and_host_name(case):
    a = machine(case, "WKS01")
    u = hi.unit_key("pre-0.7 index case-old-evtx-wks01")
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": "pre-0.7 index case-old-evtx-wks01"},
        {"kind": "name", "unit": u, "raw": "wks01", "evidence": "host.name", "origin": "artifact"},
        {"kind": "bind", "unit": u, "raw": "wks01", "key": a, "state": hi.CONFIRMED},
    ])  # fmt: skip
    p = host_ops.plan(hi.load(case), {"kind": "rename", "machine": a, "canonical": "FIN"})
    assert p["v1"] == [("case-old-evtx-wks01", "wks01")]


# -- the indices, before any write


class Indices:
    def __init__(self, own, v1=None):
        self.own, self.v1 = own, v1 or {}

    def get_mapping(self, index, **k):
        if index.endswith("-*"):
            return {n: {"mappings": {"properties": p}} for n, p in self.own.items()}
        return {index: {"mappings": {"properties": self.v1[index]}}}


def client(own, v1=None):
    c = type("C", (), {})()
    c.indices = Indices(own, v1)
    return c


KW = {"type": "keyword"}
GOOD = {"host.name": KW, "host.id": KW, "vhir": {"properties": {"host_key": KW, "unit": KW}}}


def test_own_indices_with_keyword_identity_fields_pass():
    forms = host_ops.check_indices(client({"case-x-evtx-1": GOOD}), "x", [])
    assert forms == {"case-x-evtx-1": {f: f for f in host_ops._KEYWORD_FIELDS}}


@pytest.mark.parametrize(
    "props, field",
    [
        ({**GOOD, "host.name": {"type": "text"}}, "host.name"),
        ({**GOOD, "host.id": {"type": "text", "fields": {"keyword": KW}}}, "host.id"),
        ({"host.name": KW, "vhir": {"properties": {"host_key": KW}}}, "vhir.unit"),
    ],
)
def test_an_own_index_without_keyword_identity_fields_is_refused(props, field):
    with pytest.raises(host_ops.HostOpRefused, match=f"{field}.*as keyword"):
        host_ops.check_indices(client({"case-x-evtx-1": GOOD, "case-x-odd-1": props}), "x", [])


def test_a_pre_0_7_index_is_read_with_its_own_field_forms():
    text_kw = {"type": "text", "fields": {"keyword": KW}}
    old = {"host": {"properties": {"name": text_kw, "id": KW}}}
    forms = host_ops.check_indices(client({}, {"case-old-1": old}), "x", ["case-old-1"])
    assert forms["case-old-1"] == {"host.name": "host.name.keyword", "host.id": "host.id"}
    with pytest.raises(host_ops.HostOpRefused, match="no keyword host.name or host.id"):
        host_ops.check_indices(
            client({}, {"case-old-2": {"host": {"properties": {"name": {"type": "text"}}}}}),
            "x",
            ["case-old-2"],
        )


def test_an_index_near_its_shard_limit_is_refused_before_the_journal(case):
    """The updates leave deleted copies: 100 more on a shard 50 short of the
    limit don't fit."""
    c12 = wc.case_identity(case)[0]
    key = machine(case, "WKS01")
    index = f"case-{c12}-evtx-1"
    c = client({index: GOOD})
    shard = {"routing": {"primary": True}, "docs": {"count": wc.SHARD_DOC_LIMIT - 150,
                                                     "deleted": 100}}  # fmt: skip
    c.indices.stats = lambda **k: {"indices": {index: {"shards": {"0": [shard]}}}}
    c.count = lambda **k: {"count": 100}
    c.update_by_query = lambda **k: pytest.fail("nothing may be written")
    with pytest.raises(
        host_ops.HostOpRefused, match="shard 0 holds .* past .*nothing was changed"
    ):
        host_ops.run(case, {"kind": "rename", "machine": key, "canonical": "WKS02"}, "ex1",
                     client=c)  # fmt: skip
    assert hi.read_ops(case)["ops"] == {}


def test_a_pre_0_7_text_field_without_a_keyword_form_is_refused():
    old = {"host": {"properties": {"name": {"type": "text"}, "id": KW}}}
    with pytest.raises(host_ops.HostOpRefused, match="no keyword host.name or host.id"):
        host_ops.check_indices(client({}, {"case-old-3": old}), "x", ["case-old-3"])


@pytest.mark.parametrize("wanted", [None, "accesslog", "weblogs", "evtx", "web-01"])
def test_an_access_log_index_always_takes_the_access_log_template(wanted):
    import fnmatch

    from opensearch_mcp.ingest_cli import accesslog_suffix
    from opensearch_mcp.mappings import template_type_tokens
    from opensearch_mcp.paths import build_index_name

    index = build_index_name("0123456789ab", accesslog_suffix(wanted))
    assert fnmatch.fnmatch(index, "case-*-accesslog-*"), index
    others = [t for t in template_type_tokens() if t != "accesslog"]
    assert not [t for t in others if fnmatch.fnmatch(index, f"case-*-{t}-*")], index


def test_an_index_without_keyword_identity_fields_names_the_way_out():
    bad = {**GOOD, "host.name": {"type": "text"}}
    with pytest.raises(host_ops.HostOpRefused, match="Delete and re-ingest that index"):
        host_ops.check_indices(client({"case-x-odd-1": bad}), "x", [])


def test_a_count_with_failed_shards_refuses_before_the_journal(case):
    c12 = wc.case_identity(case)[0]
    key = machine(case, "WKS01")
    c = client({f"case-{c12}-evtx-1": GOOD})
    c.count = lambda **k: {"count": 3, "_shards": {"total": 4, "failed": 1}}
    c.update_by_query = lambda **k: pytest.fail("nothing may be written")
    with pytest.raises(host_ops.HostOpRefused, match="1 shard.s. failed"):
        host_ops.run(case, {"kind": "rename", "machine": key, "canonical": "WKS02"}, "ex1",
                     client=c)  # fmt: skip
    assert hi.read_ops(case)["ops"] == {}


# -- one at a time


def test_a_busy_case_names_the_runs_writing_into_it(case, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    ingest_status.write_status(case.name, os.getpid(), "run-77", "running", [], {}, "t0")
    a = machine(case, "WKS01")
    with hi.case_lock(case, shared=True):
        with pytest.raises(host_ops.HostOpRefused, match=r"run-77 \(running\)"):
            host_ops.run(case, {"kind": "rename", "machine": a, "canonical": "X"}, "ex1",
                         client=object())  # fmt: skip
    assert hi.read_ops(case)["ops"] == {}


def test_a_killed_lock_holder_lets_the_operation_take_the_case(case):
    """A writer holding the case shared, SIGKILLed with no cleanup."""
    import signal
    import subprocess
    import sys
    import time

    holder = subprocess.Popen([sys.executable, "-c", (
        "import sys, time; from sift_common import host_identity as hi\n"
        f"with hi.case_lock({str(case)!r}, shared=True):\n"
        "    print('held', flush=True); time.sleep(60)")], stdout=subprocess.PIPE)  # fmt: skip
    try:
        assert holder.stdout.readline().strip() == b"held"
        with pytest.raises(host_ops.HostOpRefused, match="case lock|runs are writing"):
            host_ops.run(case, {"kind": "rename", "machine": "nope"}, "ex1", client=object())
        holder.send_signal(signal.SIGKILL)
        holder.wait(10)
    finally:
        if holder.poll() is None:
            holder.kill()
        holder.wait(10)
    time.sleep(0.1)
    with pytest.raises(host_ops.HostOpRefused, match="no machine"):  # past the lock
        host_ops.run(case, {"kind": "rename", "machine": "nope"}, "ex1", client=object())


def test_resuming_names_the_incomplete_operation_itself(case):
    hi.record_op(case, "op-1", {"state": "incomplete", "op": {"kind": "rename"}})
    with pytest.raises(host_ops.HostOpRefused, match="no incomplete host operation 'op-2'"):
        host_ops.run(case, None, "ex1", resume="op-2", client=object())


def test_an_operation_needs_its_examiner(case):
    with pytest.raises(host_ops.HostOpRefused, match="examiner"):
        host_ops.run(case, {"kind": "rename"}, "", client=object())


def test_only_the_incomplete_operation_can_be_resumed(case):
    with pytest.raises(host_ops.HostOpRefused, match="no incomplete host operation"):
        host_ops.run(case, None, "ex1", resume="op-x", client=object())
    hi.record_op(case, "op-done", {"state": "done"})
    with pytest.raises(host_ops.HostOpRefused, match="no incomplete host operation"):
        host_ops.run(case, None, "ex1", resume="op-done", client=object())


# -- the worker's command line


def test_the_worker_prints_a_refusal_as_json_and_exits_2(case, capsys):
    code = host_ops.main(["--case-dir", str(case), "--examiner", "ex1", "--op", '"rename"'])
    assert code == 2
    assert json.loads(capsys.readouterr().out) == {
        "state": "refused", "reason": "--op must be a JSON object"}  # fmt: skip


def test_the_worker_refuses_an_expect_that_isnt_an_object(case, capsys):
    code = host_ops.main(["--case-dir", str(case), "--examiner", "ex1",
                          "--op", '{"kind": "rename"}', "--expect", "[1]"])  # fmt: skip
    assert code == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "--expect must be a JSON object"


# -- the journal


def test_the_journal_keeps_each_operation_by_id_and_replaces_whole(case):
    hi.record_op(case, "op-1", {"state": "running", "kind": "rename"})
    hi.record_op(case, "op-2", {"state": "done"})
    hi.record_op(case, "op-1", {"state": "incomplete", "reason": "x"})
    ops = hi.read_ops(case)["ops"]
    assert ops["op-1"]["kind"] == "rename" and ops["op-1"]["state"] == "incomplete"
    assert ops["op-2"]["state"] == "done"
    assert hi.unfinished_op(case)["id"] == "op-1"
    assert not [p for p in case.iterdir() if p.name.endswith(".tmp")]


# -- other writers while an operation is running or unfinished


def test_results_say_an_operation_is_unfinished(case):
    from opensearch_mcp import server as srv

    hi.record_op(case, "op-7", {"state": "incomplete", "kind": "merge", "canonical": "WKS01"})
    _, note = srv._host_review(case.name)
    assert note == (
        "host operation op-7 (merge to 'WKS01') is incomplete: "
        "the examiner resumes it in the Hosts tab"
    )


def test_triage_waits_for_an_unfinished_operation(case, monkeypatch):
    from opensearch_mcp import server as srv
    from opensearch_mcp import triage_remote

    ran = []
    monkeypatch.setattr(triage_remote, "enrich_remote", lambda *a, **k: ran.append(1) or {})
    monkeypatch.setattr(srv, "_get_os", lambda: object())
    hi.record_op(case, "op-7", {"state": "incomplete", "kind": "rename", "canonical": "X"})
    resp = srv.idx_enrich_triage(case_id=case.name)
    assert ran == [] and "op-7 (rename to 'X') is incomplete" in resp["error"]


def test_triage_never_runs_beside_a_running_operation(case, monkeypatch):
    from opensearch_mcp import server as srv
    from opensearch_mcp import triage_remote

    ran = []
    monkeypatch.setattr(triage_remote, "enrich_remote", lambda *a, **k: ran.append(1) or {})
    monkeypatch.setattr(srv, "_get_os", lambda: object())
    with hi.case_lock(case, shared=False):
        resp = srv.idx_enrich_triage(case_id=case.name)
    assert ran == [] and "host operation is running" in resp["error"]


def test_triage_holds_the_case_while_it_writes(case, monkeypatch):
    from opensearch_mcp import server as srv
    from opensearch_mcp import triage_remote

    def enrich(*a, **k):  # a host operation can't start meanwhile
        with pytest.raises(hi.CaseLockBusy):
            with hi.case_lock(case, shared=False):
                pass
        return {}

    monkeypatch.setattr(triage_remote, "enrich_remote", enrich)
    monkeypatch.setattr(srv, "_get_os", lambda: object())
    assert "error" not in srv.idx_enrich_triage(case_id=case.name)


def test_intel_waits_for_an_unfinished_operation(case, monkeypatch, tmp_path):
    import argparse

    from opensearch_mcp import ingest_cli as cli
    from opensearch_mcp import threat_intel

    ran = []
    monkeypatch.setattr(threat_intel, "enrich_case", lambda *a, **k: ran.append(1) or {})
    monkeypatch.setattr(cli, "get_client", lambda: object())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: case.name)
    hi.record_op(case, "op-7", {"state": "running", "kind": "rename", "canonical": "X"})
    with pytest.raises(host_ops.HostOpRefused, match="op-7"):
        cli.cmd_enrich_intel(argparse.Namespace(case=case.name))
    assert ran == []


def test_the_access_log_command_puts_back_the_callers_write_context(tmp_path, monkeypatch):
    """What the command opens and holds (a unit's context, the case lock) ends
    with it, even when it stops partway."""
    import argparse
    import contextlib
    from unittest.mock import MagicMock

    from opensearch_mcp import ingest_cli as cli

    log = tmp_path / "access.log"
    log.write_text("")
    for name in ("_ensure_case_active", "get_client", "_preflight_shard_capacity",
                 "AuditWriter", "_load_case_host_dict"):  # fmt: skip
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    released = []

    @contextlib.contextmanager
    def lock():
        yield
        released.append(True)

    def open_unit(*a, **k):
        wc._tls.ctx = "the unit's context"
        wc.hold(lock())
        raise RuntimeError("stopped partway")

    monkeypatch.setattr(cli, "_open_unit", open_unit)
    callers = object()
    monkeypatch.setattr(wc._tls, "ctx", callers, raising=False)
    with pytest.raises(RuntimeError, match="stopped partway"):
        cli.cmd_ingest_accesslog(argparse.Namespace(
            path=str(log), case="c1", hostname="web01", time_from=None, time_to=None,
            dry_run=False, index_suffix="weblogs"))  # fmt: skip
    assert wc.current() is callers and released == [True]
