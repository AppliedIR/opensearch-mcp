"""An ingest writes nothing until the examiner confirms its hosts.

Every entry point (the folder or image scan, memory, delimited, JSON, access
log and the EZ-tool CSV) stops at the gate before its first write, says it
waits and why, and goes on once the examiner confirms, chooses Start now or
uploads a host list that names its hosts; a cancel ends it. It then holds
the case lock shared, and an unfinished host rename refuses it. The workers
run in-process with a stub client; every write is recorded. Values are
synthetic.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import subprocess
import threading
import time
import uuid
from unittest import mock

import pytest
from _helpers import make_windows_tree
from sift_common import host_gate, host_proposal
from sift_common import host_identity as hi

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import parse_memory as pm
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.host_gate

RUN = "run-gate"
SLOT_WAIT = "Its hosts are confirmed. It starts when one of the 3 running ingests ends."


@pytest.fixture
def gate(tmp_path, monkeypatch):
    """A fresh case; commands run in-process against a stub client. Returns
    an object with the case, its id, the writes made and a runner."""
    case_id = f"gate-{uuid.uuid4().hex[:8]}"
    case_dir = wc.case_dir_for(case_id)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    (tmp_path / "audit").mkdir()
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", RUN)
    monkeypatch.setattr(cli, "get_client", lambda: mock.MagicMock())
    for n in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter"):
        monkeypatch.setattr(cli, n, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: case_id)
    monkeypatch.setattr(cli, "stored_counts", lambda *a, **k: {})
    monkeypatch.setattr(
        host_gate, "wait_for_hosts", functools.partial(host_gate.wait_for_hosts, poll=0.05)
    )
    writes: list[dict] = []
    locked: list[bool] = []

    def stamp_or_refuse(actions, client=None):
        ctx = wc.current()
        wc.stamp(ctx, actions)
        writes.extend(a["_source"] for a in actions)
        try:  # a host rename (exclusive) can't start while the run writes
            with hi.case_lock(case_dir, shared=False):
                locked.append(False)
        except hi.CaseLockBusy:
            locked.append(True)

    monkeypatch.setattr(wc, "stamp_or_refuse", stamp_or_refuse)
    from opensearch_mcp import bulk

    monkeypatch.setattr(bulk, "_flush_with_retry", lambda client, actions, **k: (len(actions), 0))

    class Gate:
        pass

    g = Gate()
    g.case_id, g.case_dir, g.writes, g.locked, g.tmp = case_id, case_dir, writes, locked, tmp_path

    def start(command, args):
        """Run `command(args)` on a thread; returns (thread, outcome)."""
        out: dict = {}

        def body():
            try:
                command(args)
                out["ok"] = True
            except SystemExit as e:
                out["exit"] = e.code
            except BaseException as e:  # noqa: BLE001 - reported to the row
                out["error"] = e

        t = threading.Thread(target=body, daemon=True)
        t.start()
        return t, out

    def waiting(timeout=15.0) -> dict:
        """The run's status once it waits at the gate."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if RUN in hi.load(case_dir).waits:
                for f in (tmp_path / "status").glob("*.json"):
                    data = json.loads(f.read_text())
                    if data.get("run_id") == RUN and data["status"] == host_gate.AWAITING:
                        return data
            time.sleep(0.05)
        raise AssertionError("the run never waited at the gate")

    def status() -> dict:
        (data,) = [
            json.loads(f.read_text())
            for f in (tmp_path / "status").glob("*.json")
            if json.loads(f.read_text()).get("run_id") == RUN
        ]
        return data

    g.start, g.waiting, g.status = start, waiting, status
    return g


# -- each entry point waits, writing nothing


def _delimited(g):
    f = g.tmp / "events.csv"
    f.write_text("when,what\n2026-01-01T00:00:00Z,a\n2026-01-01T00:00:01Z,b\n")
    return cli.cmd_ingest_delimited, argparse.Namespace(
        path=str(f), case=None, hostname="h1", time_field="when"
    )


def _listed(g):
    """A CSV the examiner put in the case, whose host column names a machine
    on the host list: artifact evidence, so the list confirms it."""
    host_proposal.upload_host_list(g.case_dir, "WKS71\n", "ex1")
    f = g.case_dir / "evidence" / "events.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_text("when,Computer,what\n2026-01-01T00:00:00Z,WKS71,a\n")
    return cli.cmd_ingest_delimited, argparse.Namespace(
        path=str(f), case=None, hostname="WKS71", time_field="when"
    )


def _json(g):
    f = g.tmp / "events.jsonl"
    f.write_text('{"ts": "2026-01-01T00:00:00Z", "n": 1}\n')
    return cli.cmd_ingest_json, argparse.Namespace(path=str(f), case=None, hostname="h1")


def _accesslog(g):
    f = g.tmp / "access.log"
    f.write_text('192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl"\n')
    return cli.cmd_ingest_accesslog, argparse.Namespace(
        path=str(f), hostname="web01", case=None, time_from=None, time_to=None,
        index_suffix=None, batch_size=1000,
    )  # fmt: skip


def _csv(g):
    f = g.tmp / "20260101000000_AutomaticDestinations.csv"
    f.write_text("SourceFile,Path\nC:\\x.automaticDestinations-ms,C:\\a.txt\n")
    return cli.cmd_csv, argparse.Namespace(
        tool_name="jumplists", csv_path=str(f), hostname="wkstn", case=None
    )


def _memory(g, hostname="h1"):
    import pytest as _pytest

    mp = _pytest.MonkeyPatch()
    mp.setattr(pm, "_find_vol3", lambda: "true")
    mp.setattr(pm, "run_vol3_plugin", lambda *a, **k: [{"PID": 4, "Name": "svc-a"}])
    g.undo = mp.undo
    image = g.tmp / "mem.raw"
    image.write_bytes(b"\0" * 64)
    return cli.cmd_ingest_memory, argparse.Namespace(
        path=str(image), case=None, hostname=hostname, tier=1,
        plugins="windows.svcscan", yes=True, timeout=10,
    )  # fmt: skip


def _scan(g):
    folder = g.tmp / "evidence" / "WKS70"
    make_windows_tree(folder)
    return cli.cmd_scan, argparse.Namespace(
        path=str(folder), case=None, yes=True, hostname=None, all_logs=False,
        no_hayabusa=True, skip_triage=True, vss=False,
    )  # fmt: skip


ENTRY_POINTS = {
    "scan": _scan,
    "memory": _memory,
    "delimited": _delimited,
    "json": _json,
    "accesslog": _accesslog,
    "csv": _csv,
}


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_every_entry_point_waits_writing_nothing_until_cancelled(gate, entry):
    command, args = ENTRY_POINTS[entry](gate)
    try:
        t, out = gate.start(command, args)
        data = gate.waiting()
        assert data["message"] == host_gate.WAIT_MESSAGE
        assert data["totals"]["unresolved"] >= 1
        assert gate.writes == []
        host_gate.cancel(gate.case_dir, RUN, "ex1")
        t.join(15)
    finally:
        getattr(gate, "undo", lambda: None)()
    assert out == {"exit": 1}
    assert gate.status()["status"] == "cancelled"
    assert gate.writes == []


# -- confirmed, started now, or named by the list: the run goes on


def _pending_pairs(gate):
    state = hi.load(gate.case_dir)
    units = state.waits[RUN]
    return [(e["unit"], e["raw"]) for e in host_gate.unresolved(state, units) if e["raw"]]


def test_the_run_goes_on_once_the_examiner_confirms_and_its_records_carry_that_machine(gate):
    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    gate.waiting()
    key = hi.new_machine_key()
    pairs = _pending_pairs(gate)
    hi.append_decision(gate.case_dir, {"action": "confirm", "examiner": "ex1", "args": {
        "machines": [{"key": key, "canonical": "WKS-C1", "pairs": [list(p) for p in pairs]}]}},
        hi.load(gate.case_dir).obs_offset)  # fmt: skip
    t.join(15)
    assert out == {"ok": True}
    assert gate.writes and {(w["host.id"], w["vhir.host_key"]) for w in gate.writes} == {
        ("WKS-C1", key)
    }
    assert all(gate.locked)  # the case lock was held shared while it wrote


def test_start_now_lets_the_run_go_on_under_the_proposed_machine(gate):
    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    gate.waiting()
    (m,) = host_gate.start_now(gate.case_dir, RUN, "ex1")["machines"]
    t.join(15)
    assert out == {"ok": True}
    assert {w["vhir.host_key"] for w in gate.writes} == {m["key"]}
    assert hi.load(gate.case_dir).machine_of_key(m["key"]).state == hi.STARTED_NOW


def test_a_host_list_naming_every_unit_starts_the_run_with_no_examiner_action(gate):
    command, args = _listed(gate)
    command(args)  # never waits: it would block this thread
    assert gate.status()["hosts_confirmed"] is True  # what the launch reads
    assert gate.writes and RUN not in hi.load(gate.case_dir).waits
    assert {w["host.id"] for w in gate.writes} == {"WKS71"}


def test_a_name_the_ai_gave_waits_even_with_the_host_list_naming_it(gate):
    host_proposal.upload_host_list(gate.case_dir, "h1\n", "ex1")
    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    data = gate.waiting()
    (h,) = data["hosts"]
    # held for the AI's origin: the reason names it ("named only by the AI's …")
    assert "named only by" in h["artifacts"][0]["note"]
    host_gate.cancel(gate.case_dir, RUN, "ex1")
    t.join(15)
    assert gate.writes == []


def test_a_memory_image_given_no_name_waits_until_the_examiner_names_it(gate):
    command, args = _memory(gate, hostname="")
    try:
        t, out = gate.start(command, args)
        gate.waiting()
        assert "h1" not in {raw for _, raw in hi.load(gate.case_dir).names}
        pending = _pending_pairs(gate)  # what the image's file name suggests, at most
        unit = hi.load(gate.case_dir).waits[RUN][0]
        hi.append_decision(gate.case_dir, {"action": "confirm", "examiner": "ex1", "args": {
            "machines": [{"key": hi.new_machine_key(), "canonical": "DC01",
                          "pairs": [[unit, "DC01"], *[list(p) for p in pending]]}]}},
            hi.load(gate.case_dir).obs_offset)  # fmt: skip
        t.join(15)
    finally:
        gate.undo()
    assert out == {"ok": True}
    assert {(w["host.name"], w["host.id"]) for w in gate.writes} == {("DC01", "DC01")}


def test_an_unfinished_host_rename_refuses_the_run(gate, capsys):
    command, args = _listed(gate)
    (gate.case_dir / hi.OPS).write_text(
        json.dumps(
            {"ops": {"op-1": {"state": "incomplete", "kind": "rename", "canonical": "WKS02"}}}
        )
    )
    # A refusal that regressed would wait at the gate for good: the run gets
    # its own bound (a thread and a join, no pytest plugin), so it fails instead
    ended = {}

    def run():
        try:
            command(args)
        except SystemExit as e:
            ended["exit"] = e.code

    runner = threading.Thread(target=run, daemon=True)
    runner.start()
    runner.join(timeout=30)
    assert not runner.is_alive(), "the run waited at the host gate instead of being refused"
    assert ended.get("exit") == 1
    assert (
        "host operation op-1 (rename to 'WKS02') is incomplete: the examiner resumes it"
        in capsys.readouterr().err
    )
    assert gate.writes == []
    assert gate.status()["status"] == "failed"


def test_a_list_step_skipped_during_a_host_rename_is_applied_once_it_ends(gate, monkeypatch):
    """The scan met a running rename and skipped the list's confirmations;
    the rename ended before the gate. The gate applies the list, so the run
    goes on without waiting for the examiner."""
    command, args = _listed(gate)
    op = {"kind": "rename", "canonical": "WKS02"}
    (gate.case_dir / hi.OPS).write_text(json.dumps({"ops": {"op-1": {**op, "state": "running"}}}))
    real = cli._gate

    def the_rename_ends_first(*a, **k):
        (gate.case_dir / hi.OPS).write_text(json.dumps({"ops": {"op-1": {**op, "state": "done"}}}))
        return real(*a, **k)

    monkeypatch.setattr(cli, "_gate", the_rename_ends_first)
    t, out = gate.start(command, args)
    t.join(15)
    if t.is_alive():  # it waits: end it
        host_gate.cancel(gate.case_dir, RUN, "ex1")
        t.join(15)
    assert out == {"ok": True}
    assert RUN not in hi.load(gate.case_dir).waits
    assert {w["host.id"] for w in gate.writes} == {"WKS71"}


def test_the_case_lock_is_let_go_when_the_command_ends(gate):
    command, args = _listed(gate)
    command(args)
    assert gate.locked == [True]  # held while it wrote
    with hi.case_lock(gate.case_dir, shared=False):
        pass  # a host rename can now take the case


# -- the MCP answer


def test_a_launch_says_its_run_waits_for_host_confirmation(gate, monkeypatch):
    monkeypatch.setattr(srv, "_GATE_ANSWER_SECONDS", 5.0)
    resp = {"status": "started"}

    def worker():
        time.sleep(0.2)
        ingest_status.write_status(
            gate.case_id, 4242, RUN, host_gate.AWAITING,
            [{"hostname": "h1", "artifacts": [{"name": "host confirmation",
                                               "note": "evidence/x: not confirmed"}]}],
            {"unresolved": 1}, "t0", message=host_gate.WAIT_MESSAGE,
        )  # fmt: skip

    threading.Thread(target=worker).start()
    out = srv._answer_after_gate(resp, gate.case_id, 4242, RUN)
    assert out["status"] == host_gate.AWAITING and out["unresolved"] == 1
    assert out["unresolved_hosts"] == ["evidence/x: not confirmed"]
    assert host_gate.WAIT_MESSAGE in out["message"]


def test_a_launch_whose_hosts_pass_says_started(gate, monkeypatch):
    monkeypatch.setattr(srv, "_GATE_ANSWER_SECONDS", 5.0)
    ingest_status.write_status(gate.case_id, 4243, RUN, "running", [], {}, "t0")
    ingest_status.mark_hosts_confirmed(gate.case_id, 4243, RUN)
    ingest_status.write_status(gate.case_id, 4243, RUN, "running", [], {"indexed": 3}, "t0")
    out = srv._answer_after_gate({"status": "started"}, gate.case_id, 4243, RUN)
    assert out == {"status": "started"}  # the mark survives the worker's own writes


def test_a_launch_that_cannot_know_yet_says_where_to_look(gate, monkeypatch):
    monkeypatch.setattr(srv, "_GATE_ANSWER_SECONDS", 0.2)
    out = srv._answer_after_gate({"status": "started"}, gate.case_id, 4244, RUN)
    assert out["status"] == "started" and host_gate.AWAITING in out["hosts_note"]


# -- what the examiner hasn't confirmed is marked in results


def _review(monkeypatch, keys, note=""):
    monkeypatch.setattr(srv, "_host_review", lambda case_id="": (set(keys), note))


def test_search_hits_from_unconfirmed_machines_are_marked(monkeypatch):
    _review(monkeypatch, {"k-new"})
    hits = [{"_source": {"vhir.host_key": "k-new"}}, {"_source": {"vhir.host_key": "k-ok"}}]
    resp = {"results": [{"_id": "1"}, {"_id": "2"}]}
    srv._annotate_hosts(resp, "c1", hits=hits)
    assert [d.get("host_unconfirmed") for d in resp["results"]] == [True, None]


def test_counts_and_buckets_say_how_much_comes_from_unconfirmed_machines(monkeypatch):
    _review(monkeypatch, {"k-new"})
    client = mock.MagicMock()
    client.search.return_value = {
        "hits": {"total": {"value": 4}},
        "aggregations": {"agg": {"buckets": [{"key": "WKS01", "doc_count": 4}]}},
    }
    resp = {"buckets": [{"key": "WKS01", "count": 9}, {"key": "WKS02", "count": 1}]}
    srv._annotate_hosts(resp, "c1", client, "case-x-*", {"match_all": {}}, "host.id")
    assert resp["host_unconfirmed"] == 4
    assert [b.get("host_unconfirmed") for b in resp["buckets"]] == [4, None]
    body = client.search.call_args.kwargs["body"]
    assert body["query"]["bool"]["filter"] == [{"terms": {"vhir.host_key": ["k-new"]}}]


def test_every_result_says_a_host_rename_is_incomplete(monkeypatch):
    note = "host operation op-1 (rename to 'WKS02') is incomplete: the examiner resumes it"
    _review(monkeypatch, set(), note)
    resp = srv._annotate_hosts({"count": 3}, "c1")
    assert resp["host_note"] == note


def test_a_failed_count_of_unconfirmed_documents_is_said_and_leaves_the_answer(monkeypatch):
    _review(monkeypatch, {"k-new"})
    client = mock.MagicMock()
    client.search.side_effect = RuntimeError("cluster down")
    resp = srv._annotate_hosts({"count": 3}, "c1", client, "case-x-*", {"match_all": {}})
    assert resp["count"] == 3
    assert resp["host_unconfirmed_error"] == (
        "documents from machines not yet confirmed couldn't be counted: RuntimeError: cluster down"
    )


def test_the_review_lists_machines_not_yet_confirmed(gate):
    u = hi.unit_key("evidence/a")
    hi.append_observations(gate.case_dir, [{"kind": "unit", "unit": u}])
    started = hi.new_machine_key()
    hi.append_decision(gate.case_dir, {"action": "start_now", "args": {"machines": [
        {"key": started, "canonical": "A", "pairs": [[u, "A"]]}]}},
        hi.load(gate.case_dir).obs_offset)  # fmt: skip
    key, _ = hi.get_or_mint(gate.case_dir, u, "B")  # a new machine
    done = hi.new_machine_key()
    hi.append_decision(gate.case_dir, {"action": "confirm", "args": {"machines": [
        {"key": done, "canonical": "C", "pairs": [[u, "C"]]}]}},
        hi.load(gate.case_dir).obs_offset)  # fmt: skip
    keys, note = srv._host_review(gate.case_id)
    assert keys == {started, key} and note == ""  # never the confirmed one


# -- the dry run encourages a host list


def test_a_dry_run_encourages_a_host_list_until_one_is_loaded(gate, monkeypatch):
    monkeypatch.setattr(srv, "_get_active_case", lambda: gate.case_id)
    resp = srv._with_host_list_hint({}, gate.case_id)
    assert resp["host_list_hint"] == host_gate.HOST_LIST_HINT
    host_proposal.upload_host_list(gate.case_dir, "h1\n", "ex1")
    assert srv._with_host_list_hint({}, gate.case_id) == {}


def test_names_a_forwarded_log_gives_past_the_scan_are_their_own_machines(gate):
    """A WEC01 collector's log: the scan samples the first rows (SRC1); three
    sources appear only later. Each is its own machine, never WEC01's."""
    from opensearch_mcp import names_scan

    rows = ["2026-01-01T00:00:00Z,SRC1,a"] * names_scan.ROWS
    rows += ["2026-01-01T00:00:01Z,SRC2,b", "2026-01-01T00:00:02Z,SRC3,c",
             "2026-01-01T00:00:03Z,SRC4,d"]  # fmt: skip
    f = gate.tmp / "forwarded.csv"
    f.write_text("when,Computer,what\n" + "\n".join(rows) + "\n")
    args = argparse.Namespace(path=str(f), case=None, hostname="WEC01", time_field="when")
    t, out = gate.start(cli.cmd_ingest_delimited, args)
    gate.waiting()
    assert {raw for _, raw in _pending_pairs(gate)} == {"WEC01", "SRC1"}
    host_gate.start_now(gate.case_dir, RUN, "ex1")
    t.join(15)
    assert out == {"ok": True}
    machines = {w["host.name"]: (w["host.id"], w["vhir.host_key"]) for w in gate.writes}
    assert set(machines) == {"SRC1", "SRC2", "SRC3", "SRC4"}
    assert len({k for _, k in machines.values()}) == 4  # four machines
    assert "WEC01" not in {h for h, _ in machines.values()}
    state = hi.load(gate.case_dir)
    for name in ("SRC2", "SRC3", "SRC4"):  # met while ingesting: new, awaiting the examiner
        assert state.machine_of_key(machines[name][1]).state == hi.NEW


# -- admission, walks, and a waiting run's status


@pytest.fixture
def others():
    """Starts processes standing in for other ingests: `others(run_id)` gives
    the pid of a live process whose environment names that run, as a worker's
    does. They are ended after the row."""
    procs: list[subprocess.Popen] = []

    def spawn(run_id):
        env = {**os.environ, "VHIR_INGEST_RUN_ID": run_id}
        procs.append(subprocess.Popen(["sleep", "300"], env=env))
        return procs[-1].pid

    yield spawn
    for p in procs:
        p.kill()
        p.wait()


def _running(others, n):
    """`n` other ingests running, each in its own process and case; the
    (case, pid, run) of each."""
    runs = []
    for i in range(n):
        run = (f"case-{i}", others(f"run-r{i}"), f"run-r{i}")
        ingest_status.write_status(*run, "running", [], {}, "t0")
        runs.append(run)
    return runs


def _end(run):
    ingest_status.write_status(*run, "complete", [], {}, "t0")


def _until(check, timeout=15.0):
    """`check()`'s first true value, polled (bounded)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("it never happened")


def _slot_wait(gate):
    data = gate.status()
    return data if data.get("message") == SLOT_WAIT else None


def test_runs_waiting_for_their_hosts_take_no_place_at_admission(gate, others):
    for n in range(srv._MAX_CONCURRENT_INGESTS):
        ingest_status.write_status(f"case-{n}", os.getpid(), f"run-w{n}", host_gate.AWAITING,
                                   [], {"unresolved": 1}, "t0")  # fmt: skip
    assert srv._admission_refusal() is None  # a fourth run is admitted, and queues
    _running(others, srv._MAX_CONCURRENT_INGESTS)
    refused = srv._admission_refusal()
    assert refused["error"].startswith("Too many concurrent ingests (3 running, max 3).")
    assert sorted(r["run_id"] for r in refused["running"]) == ["run-r0", "run-r1", "run-r2"]


def test_a_confirmed_run_waits_for_a_place_while_three_run(gate, monkeypatch, others):
    monkeypatch.setattr(cli, "_SLOT_POLL", 0.05, raising=False)
    first, *_ = _running(others, 3)
    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    gate.waiting()
    host_gate.start_now(gate.case_dir, RUN, "ex1")
    data = _until(lambda: _slot_wait(gate))
    assert data["status"] == host_gate.AWAITING
    assert data["message"] == SLOT_WAIT
    time.sleep(0.3)
    assert t.is_alive() and gate.writes == []  # it writes nothing meanwhile
    _end(first)
    t.join(15)
    assert out == {"ok": True} and gate.writes


def test_runs_confirmed_together_start_only_up_to_the_cap(gate, others):
    first, _ = _running(others, 2)
    started: list[str] = []
    runs = {rid: (gate.case_id, others(rid), rid) for rid in ("run-a", "run-b")}
    for run in runs.values():
        ingest_status.write_status(*run, host_gate.AWAITING, [], {"unresolved": 1}, "t0")

    def take(rid):  # each run is its own process, confirmed at the same moment
        waiting = functools.partial(
            ingest_status.write_status, *runs[rid], host_gate.AWAITING, [], {}, "t0",
            message=SLOT_WAIT,
        )  # fmt: skip
        while not ingest_status.take_slot(*runs[rid], waiting):
            time.sleep(0.05)
        started.append(rid)

    threads = [threading.Thread(target=take, args=(r,), daemon=True) for r in runs]
    for t in threads:
        t.start()
    _until(lambda: started)
    time.sleep(0.3)
    assert len(started) == 1  # three running: the other waits
    (other,) = set(runs) - set(started)
    statuses = {r["run_id"]: r for r in ingest_status.active_runs()}
    assert statuses[started[0]]["status"] == "running"
    assert statuses[other]["message"] == SLOT_WAIT
    _end(first)
    for t in threads:
        t.join(15)
    assert sorted(started) == ["run-a", "run-b"]


def test_a_cancel_while_it_waits_for_a_place_ends_it_and_holds_no_lock(gate, monkeypatch, others):
    import fcntl

    monkeypatch.setattr(cli, "_SLOT_POLL", 0.05, raising=False)
    _running(others, 3)
    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    gate.waiting()
    host_gate.start_now(gate.case_dir, RUN, "ex1")
    _until(lambda: _slot_wait(gate))
    host_gate.cancel(gate.case_dir, RUN, "ex1")
    t.join(15)
    assert out == {"exit": 1} and gate.writes == []
    data = gate.status()
    assert data["status"] == host_gate.CANCELLED
    assert data["error"] == f"run {RUN} was cancelled in the Hosts tab"
    with open(gate.tmp / "status" / "slots.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # nothing holds it
    with hi.case_lock(gate.case_dir, shared=False):
        pass  # nor the case lock


def test_a_cancel_and_a_free_place_in_the_same_sleep_ends_the_run(gate, monkeypatch, others):
    """The examiner cancels while it sleeps, and a place frees before it looks
    again: the cancel wins, and nothing is written."""
    first, *_ = _running(others, 3)
    real_sleep = time.sleep

    def sleep(seconds):  # both happen while the waiting run sleeps
        if not hi.load(gate.case_dir).cancelled:
            host_gate.cancel(gate.case_dir, RUN, "ex1")
            _end(first)
        real_sleep(0.01)

    monkeypatch.setattr(cli, "time", mock.Mock(wraps=time, sleep=sleep))
    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    gate.waiting()
    host_gate.start_now(gate.case_dir, RUN, "ex1")
    t.join(15)
    assert out == {"exit": 1} and gate.writes == []
    data = gate.status()
    assert data["status"] == host_gate.CANCELLED
    assert data["error"] == f"run {RUN} was cancelled in the Hosts tab"


def test_an_archive_image_with_two_other_ingests_starts_at_once(gate, monkeypatch, others):
    """An archive's images run inside the process of the archive's own run,
    whose record stays live: that run isn't another ingest."""
    monkeypatch.setattr(cli, "_SLOT_POLL", 0.05, raising=False)
    _running(others, 2)
    for run in ("run-arc", "run-arc-1"):  # the archive's run, and its first image's
        ingest_status.write_status(gate.case_id, os.getpid(), run, "starting", [], {}, "t0")
    done: list[bool] = []
    t = threading.Thread(target=lambda: done.append(
        cli._take_slot(gate.case_dir, gate.case_id, "run-arc-1", "t0") is None),
        daemon=True)  # fmt: skip
    t.start()
    t.join(5)
    alive = t.is_alive()
    if alive:  # let a waiting image end, so no thread outlives the row
        for run in [r for r in ingest_status.active_runs() if r["run_id"].startswith("run-r")]:
            _end((run["case_id"], run["pid"], run["run_id"]))
        t.join(15)
    assert not alive and done == [True]
    image = {r["run_id"]: r for r in ingest_status.active_runs()}["run-arc-1"]
    assert image["status"] == "starting" and image.get("hosts_confirmed")  # it goes on


def test_three_archives_each_with_images_all_run_their_images(gate, others):
    """Three archive runs, each in its own process with two images: every
    image starts, each one after the one before it in its archive."""
    archives = {a: (gate.case_id, others(a), a) for a in ("run-a", "run-b", "run-c")}
    for archive in archives.values():
        ingest_status.write_status(*archive, "starting", [], {}, "t0")
    for n in (1, 2):
        for case_id, pid, a in archives.values():
            image = (case_id, pid, f"{a}-{n}")
            waited = []
            assert ingest_status.take_slot(*image, lambda: waited.append(1)), image
            assert waited == []
            _end(image)


def _archive(others, a, case_id="case-a"):
    """An archive run `a` in its own process, its record live; (case, pid, run)."""
    run = (case_id, others(a), a)
    ingest_status.write_status(*run, "running", [], {}, "t0")
    return run


def _self_made(case_id, pid, run, status):
    """A record as the process writes it for a run id it made itself (an
    archive's image): the sweep checks only that its pid lives."""
    ingest_status.write_status(case_id, pid, run, status, [], {}, "t0")
    path = ingest_status._status_path_safe(case_id, pid, run)
    path.write_text(json.dumps({**json.loads(path.read_text()), "run_id_from_env": False}))


def _image(archive, n):
    """Image `n` of an archive, asking for a place in the archive's process."""
    case_id, pid, a = archive
    _self_made(case_id, pid, f"{a}-{n}", host_gate.AWAITING)
    waited = []
    took = ingest_status.take_slot(case_id, pid, f"{a}-{n}", lambda: waited.append(1))
    return took and not waited


def test_three_archives_each_running_an_image_all_run(gate, others):
    """One archive already runs its first image; the other two images ask."""
    a, b, c = (_archive(others, r) for r in ("run-a", "run-b", "run-c"))
    assert _image(a, 1)
    assert _image(b, 1) and _image(c, 1)
    held = [r["run_id"] for r in ingest_status.active_runs() if r["status"] == "running"]
    assert sorted(held) == ["run-a", "run-a-1", "run-b", "run-b-1", "run-c", "run-c-1"]


def test_four_archive_processes_none_waits_forever(gate, others):
    """Four archives live at once (only an admission race gets here): each
    image uses its archive's place, so none waits on the others."""
    archives = [_archive(others, f"run-{x}") for x in "abcd"]
    assert [_image(a, 1) for a in archives] == [True] * 4


def test_an_image_never_waits_on_its_own_archive(gate, others):
    _running(others, 3)  # every place is taken by other processes
    assert _image(_archive(others, "run-arc"), 1)


def test_two_archives_each_running_an_image_leave_a_place(gate, others):
    """Two processes hold places, with two records each: a third run starts."""
    for a in (_archive(others, "run-a"), _archive(others, "run-b")):
        assert _image(a, 1)
    waited = []
    run = ("case-x", others("run-x"), "run-x")
    assert ingest_status.take_slot(*run, lambda: waited.append(1)) and waited == []


def test_a_new_run_under_a_reused_pid_waits_for_a_place(gate, others):
    """A dead archive's image record (pid-only liveness) stays live under a pid
    a new ingest now has. That ingest isn't an image of it: with three other
    processes running, it waits."""
    _running(others, 3)
    pid = others("run-x")
    _self_made("case-old", pid, "run-old-1", "running")
    assert "run-old-1" in {r["run_id"] for r in ingest_status.active_runs()}
    waited = []
    assert not ingest_status.take_slot("case-x", pid, "run-x", lambda: waited.append(1))
    assert waited == [1]
    # nor does a run named like an image of the dead archive
    assert not ingest_status.take_slot("case-x", pid, "run-old-2", lambda: waited.append(1))


def test_the_status_doc_names_the_wait_for_a_place():
    doc = " ".join(srv.idx_ingest_status.__doc__.split())
    assert f'"{SLOT_WAIT}"' in doc
    assert ingest_status.SLOT_WAIT == SLOT_WAIT


def test_a_walk_over_three_hosts_waits_once_for_all_of_them(gate, monkeypatch):
    root = gate.tmp / "hosts"
    for h in ("H1", "H2", "H3"):
        (root / h).mkdir(parents=True)
        (root / h / "e.csv").write_text("when,what\n2026-01-01T00:00:00Z,a\n")
    args = argparse.Namespace(path=str(root), case=None, hostname=None, time_field="when",
                              recursive=True)  # fmt: skip
    calls = []
    real_gate = cli._gate
    monkeypatch.setattr(cli, "_gate", lambda *a, **k: calls.append(1) or real_gate(*a, **k))
    t, out = gate.start(cli.cmd_ingest_delimited, args)
    gate.waiting()
    assert len(hi.load(gate.case_dir).waits[RUN]) == 3  # every host, in one wait
    host_gate.start_now(gate.case_dir, RUN, "ex1")
    t.join(15)
    assert out == {"ok": True}
    assert {w["host.name"] for w in gate.writes} == {"H1", "H2", "H3"}
    assert calls == [1]  # the leaves went through the walk's one pass


def test_a_waiting_runs_status_outlives_the_cleanup_by_age(gate):
    import os

    command, args = _delimited(gate)
    t, out = gate.start(command, args)
    gate.waiting()
    (f,) = [f for f in (gate.tmp / "status").glob("*.json")]
    old = time.time() - 25 * 3600
    os.utime(f, (old, old))  # a day without a write
    # the waiting run rewrites its status on its next poll; wait for that
    # (bounded), not for a fixed time a loaded machine can overrun
    deadline = time.monotonic() + 10
    while f.stat().st_mtime < old + 3600 and time.monotonic() < deadline:
        time.sleep(0.05)
    ingest_status.cleanup_old()
    assert f.exists() and json.loads(f.read_text())["status"] == host_gate.AWAITING
    host_gate.cancel(gate.case_dir, RUN, "ex1")
    t.join(15)


def test_a_memory_ingest_from_the_vhir_cli_needs_no_hostname():
    from opensearch_mcp import vhir_plugin

    parser = argparse.ArgumentParser()
    vhir_plugin.register(parser.add_subparsers(dest="cmd"), set())
    args = parser.parse_args(["ingest-memory", "mem.raw"])
    assert args.hostname == ""


def test_a_launch_whose_run_was_cancelled_says_so(gate, monkeypatch):
    monkeypatch.setattr(srv, "_GATE_ANSWER_SECONDS", 5.0)
    ingest_status.write_status(gate.case_id, 4245, RUN, "cancelled", [], {}, "t0",
                               error="run run-gate was cancelled in the Hosts tab")  # fmt: skip
    out = srv._answer_after_gate({"status": "started"}, gate.case_id, 4245, RUN)
    assert out["status"] == "cancelled" and "cancelled in the Hosts tab" in out["error"]


def test_a_cancelled_run_stays_cancelled(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    ingest_status.write_status("c1", 4246, RUN, "cancelled", [], {}, "t0")
    for live in ("running", "starting", host_gate.AWAITING):
        ingest_status.write_status("c1", 4246, RUN, live, [], {}, "t0")
    (f,) = (tmp_path / "status").glob("*.json")
    assert json.loads(f.read_text())["status"] == "cancelled"


def _three_hosts(gate):
    root = gate.tmp / "hosts"
    for h in ("H1", "H2", "H3"):
        (root / h).mkdir(parents=True)
        (root / h / "e.csv").write_text("when,what\n2026-01-01T00:00:00Z,a\n")
    return root


def test_a_walks_dry_run_never_waits_at_the_gate(gate):
    args = argparse.Namespace(path=str(_three_hosts(gate)), case=None, hostname=None,
                              time_field="when", recursive=True, dry_run=True)  # fmt: skip
    t, out = gate.start(cli.cmd_ingest_delimited, args)
    t.join(10)
    assert not t.is_alive() and "error" not in out
    assert RUN not in hi.load(gate.case_dir).waits and gate.writes == []


def test_a_walks_leaves_never_end_its_run(gate, monkeypatch):
    seen = []
    real = cli.write_status

    def spy(case_id, pid, run_id, status, *a, **k):
        if run_id == RUN:
            seen.append(status)
        return real(case_id, pid, run_id, status, *a, **k)

    monkeypatch.setattr(cli, "write_status", spy)
    args = argparse.Namespace(path=str(_three_hosts(gate)), case=None, hostname=None,
                              time_field="when", recursive=True)  # fmt: skip
    t, out = gate.start(cli.cmd_ingest_delimited, args)
    gate.waiting()
    host_gate.start_now(gate.case_dir, RUN, "ex1")
    t.join(15)
    assert out == {"ok": True}
    terminal = [i for i, st in enumerate(seen) if st in ("complete", "failed")]
    assert terminal == [len(seen) - 1]  # the walk ends its run, once, last
