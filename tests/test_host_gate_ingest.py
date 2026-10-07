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
    mp.setattr(pm, "_register_memory_evidence", lambda *a, **k: None)
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
    assert h["artifacts"][0]["note"].endswith("named only by the AI or an unregistered file")
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
        json.dumps({"ops": {"op-1": {"state": "incomplete", "from": "WKS01", "to": "WKS02"}}})
    )
    with pytest.raises(SystemExit):
        command(args)
    assert "host rename incomplete: WKS01 → WKS02" in capsys.readouterr().err
    assert gate.writes == []
    assert gate.status()["status"] == "failed"


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
    _review(monkeypatch, set(), "host rename incomplete: WKS01 → WKS02")
    resp = srv._annotate_hosts({"count": 3}, "c1")
    assert resp["host_note"] == "host rename incomplete: WKS01 → WKS02"


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


def test_runs_waiting_for_their_hosts_count_at_admission_and_are_listed(gate, monkeypatch):
    import os

    for n in range(srv._MAX_CONCURRENT_INGESTS):
        ingest_status.write_status(f"case-{n}", os.getpid(), f"run-w{n}", host_gate.AWAITING,
                                   [], {"unresolved": 1}, "t0")  # fmt: skip
    refused = srv._admission_refusal()
    assert "3 of them wait for host confirmation" in refused["error"]
    assert sorted(r["case_id"] for r in refused["running"]) == ["case-0", "case-1", "case-2"]
    assert {r["status"] for r in refused["running"]} == {host_gate.AWAITING}


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
    time.sleep(0.3)  # a few polls
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
