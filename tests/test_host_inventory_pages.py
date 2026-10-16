"""idx_host_inventory stays a page long however many names wait.

Before, each run awaiting host confirmation returned every held name, and each
name its whole evidence list, whatever `limit` said: UAT-B's limit=5 on a
29-host Kansa case was 153,593 characters, and the client refused it. Now
every list in the reply is paged by offset and limit and carries its total;
each waiting run counts its held names by reason and gives a row per unit; a
name shows its first 5 evidence items and their total. The host logs are real;
the cluster is a stand-in. Values are synthetic.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sift_common import host_gate
from sift_common import host_identity as hi

from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.host_gate

MODULES = [
    "AppCompatCache", "Arp", "Autorunsc", "CertStore", "DNSCache", "HostInfo", "LocalAdmins",
    "Netstat", "ProcsWMI", "SchedTasks", "SmbSession", "SmbShare", "Services", "Prefetch",
    "ProcsNTQSI", "DiskInfo", "LogUserAssist", "Tasks", "WMIEvtFilter", "WMIEvtConsumer",
    "WMIFltConBind", "RecycleBin", "Handle", "SvcFail",
]  # fmt: skip
NOT_CONFIRMED = host_gate.REASON_UNCONFIRMED
BY_FILE = host_gate.reason_named_by({"file-name"})
BY_ARG = host_gate.reason_named_by({"argument"})


class Cluster:
    def search(self, index, body, **k):
        return {"aggregations": {"k": {"buckets": []}}}


@pytest.fixture
def case(monkeypatch):
    cid = f"hpage-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    hi.ensure_host_files(d)
    monkeypatch.setattr(srv, "_get_active_case", lambda: cid)
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster())
    return d


def kansa(case, hosts=29, modules=MODULES, evidence=12):
    """UAT-B's shape: per host folder, one unit holding the hostname given to
    the run, a name per Kansa module (from its file name) and two names its
    records carry, each read from `evidence` files. One run waits on all."""
    recs, units = [], []
    for i in range(hosts):
        host = f"host{i:02d}"
        u = hi.unit_key(f"evidence/kansa/{host}")
        units.append(u)
        recs.append({"kind": "unit", "unit": u, "locator": f"evidence/kansa/{host}"})
        recs.append({"kind": "name", "unit": u, "raw": f"{host}.shieldbase.com",
                     "evidence": "the run's hostname", "origin": "argument"})  # fmt: skip
        recs += [{"kind": "name", "unit": u, "raw": m, "evidence": f"{host}-{m}.csv",
                  "origin": "file-name"} for m in modules]  # fmt: skip
        raws = (host.upper(), f"{host.upper()}-SVC")
        recs += [{"kind": "name", "unit": u, "raw": raw, "evidence": f"{host}-{n:03d}.evtx",
                  "origin": "artifact"} for raw in raws for n in range(evidence)]  # fmt: skip
    hi.append_observations(case, recs)
    host_gate.record_wait(case, "run-kansa", units)
    return units


def _size(resp) -> int:
    return len(json.dumps(resp, ensure_ascii=False))


# --- the measured RED shape: 783 held names, limit=5 --------------------------


def test_a_run_of_783_held_names_returns_a_page_with_its_totals(case):
    units = kansa(case)
    inv = srv.idx_host_inventory(limit=5)
    (run,) = inv["awaiting_host_confirmation"]
    assert run["run_id"] == "run-kansa"
    assert run["unresolved_total"] == 783 and len(run["unresolved"]) == 5
    assert run["unresolved_by_reason"] == {BY_ARG: 29, BY_FILE: 696, NOT_CONFIRMED: 58}
    assert sum(run["unresolved_by_reason"].values()) == 783
    assert run["units_total"] == 29 and run["units"] == units[:5]
    assert run["unresolved_units_total"] == 29
    assert run["unresolved_by_unit"] == [
        {"unit": u, "count": 27, "first_reason": BY_ARG} for u in units[:5]
    ]
    assert _size(inv) < 20_000, _size(inv)


def test_the_page_is_the_first_entries_in_the_gates_own_order(case):
    units = kansa(case)
    held = host_gate.unresolved(hi.load(case), units)
    (run,) = srv.idx_host_inventory(limit=5)["awaiting_host_confirmation"]
    assert run["unresolved"] == held[:5]


def test_a_name_shows_its_first_five_evidence_items_and_their_total(case):
    kansa(case, hosts=1, evidence=200)  # G-020: ~200 evtx files per raw name
    inv = srv.idx_host_inventory()
    named = {n["raw"]: n for n in inv["names_without_machine"]}
    host = named["HOST00"]
    assert host["evidence"] == [f"host00-{n:03d}.evtx" for n in range(5)]
    assert host["evidence_total"] == 200
    assert named["Arp"]["evidence"] == ["host00-Arp.csv"] and named["Arp"]["evidence_total"] == 1


# --- walking the pages --------------------------------------------------------


@pytest.mark.parametrize("limit", [5, 50, 200])
def test_offset_paging_walks_every_held_name_once(case, limit):
    units = kansa(case)
    held = host_gate.unresolved(hi.load(case), units)
    seen, rows, walked_units = [], [], []
    for offset in range(0, 800, limit):
        (run,) = srv.idx_host_inventory(offset=offset, limit=limit)["awaiting_host_confirmation"]
        assert run["unresolved_total"] == 783 and run["units_total"] == 29
        seen += run["unresolved"]
        rows += run["unresolved_by_unit"]
        walked_units += run["units"]
    assert seen == held and len(seen) == 783
    assert len({json.dumps(e, sort_keys=True) for e in seen}) == 783
    assert [r["unit"] for r in rows] == units and walked_units == units
    assert sum(r["count"] for r in rows) == 783


def test_a_page_past_the_end_still_lists_the_run_and_its_totals(case):
    kansa(case, hosts=2)
    (run,) = srv.idx_host_inventory(offset=1000, limit=5)["awaiting_host_confirmation"]
    assert run["unresolved_total"] == 54 and run["units_total"] == 2
    assert run["unresolved"] == run["unresolved_by_unit"] == run["units"] == []
    assert run["unresolved_by_reason"] == {BY_ARG: 2, BY_FILE: 48, NOT_CONFIRMED: 4}


@pytest.mark.parametrize("asked,got", [(0, 1), (-3, 1), (1, 1), (200, 200), (5000, 200)])
def test_the_limit_is_clamped_to_one_through_200_for_every_list(case, asked, got):
    kansa(case, hosts=10)  # 270 held names, 270 names without a machine
    inv = srv.idx_host_inventory(limit=asked)
    (run,) = inv["awaiting_host_confirmation"]
    assert inv["limit"] == got
    assert len(run["unresolved"]) == got and len(inv["names_without_machine"]) == got
    assert len(run["unresolved_by_unit"]) == len(run["units"]) == min(got, 10)


def test_a_negative_offset_reads_from_the_start(case):
    units = kansa(case, hosts=3)
    (run,) = srv.idx_host_inventory(offset=-7, limit=4)["awaiting_host_confirmation"]
    assert run["unresolved"] == host_gate.unresolved(hi.load(case), units)[:4]


# --- each run is its own page; reasons and units counted ---------------------


def test_each_waiting_run_is_paged_and_counted_on_its_own(case):
    a = hi.unit_key("evidence/a")
    b = hi.unit_key("evidence/b")
    hi.append_observations(case, [
        {"kind": "unit", "unit": a, "locator": "evidence/a"},
        {"kind": "unit", "unit": b, "locator": "evidence/b"},
        *({"kind": "name", "unit": a, "raw": f"N{i}", "evidence": "f", "origin": "artifact"}
          for i in range(7)),
    ])  # fmt: skip
    host_gate.record_wait(case, "run-a", [a])
    host_gate.record_wait(case, "run-b", [b])  # a unit with no name at all
    runs = {r["run_id"]: r for r in srv.idx_host_inventory(limit=3)["awaiting_host_confirmation"]}
    assert runs["run-a"]["unresolved_total"] == 7 and len(runs["run-a"]["unresolved"]) == 3
    assert runs["run-a"]["unresolved_by_unit"] == [
        {"unit": a, "count": 7, "first_reason": NOT_CONFIRMED}
    ]
    assert runs["run-b"]["unresolved_total"] == 1
    assert runs["run-b"]["unresolved_by_reason"] == {host_gate.REASON_NO_NAME: 1}
    assert runs["run-b"]["unresolved_by_unit"] == [
        {"unit": b, "count": 1, "first_reason": host_gate.REASON_NO_NAME}
    ]


def test_a_units_first_reason_is_the_reason_of_its_first_held_name(case):
    u = hi.unit_key("evidence/x")
    hi.append_observations(case, [
        {"kind": "unit", "unit": u, "locator": "evidence/x"},
        {"kind": "name", "unit": u, "raw": "Arp", "evidence": "x.csv", "origin": "file-name"},
        {"kind": "name", "unit": u, "raw": "X01", "evidence": "S.evtx", "origin": "artifact"},
    ])  # fmt: skip
    host_gate.record_wait(case, "run-x", [u])
    (run,) = srv.idx_host_inventory()["awaiting_host_confirmation"]
    first = run["unresolved"][0]["reason"]
    assert run["unresolved_by_unit"] == [{"unit": u, "count": 2, "first_reason": first}]
    assert run["unresolved_by_reason"] == {BY_FILE: 1, NOT_CONFIRMED: 1}


SEED_RAWS = ["日本語-PC", "it's", 'q"uote', "back\\slash", "<b>html</b>", "invoice‮gpj",
             "tab\there", "x" * 255]  # fmt: skip


def test_seed_shaped_names_page_and_count_as_they_are(case):
    u = hi.unit_key("evidence/seed")
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": "evidence/seed"}] + [
        {"kind": "name", "unit": u, "raw": r, "evidence": "e", "origin": "artifact"}
        for r in SEED_RAWS])  # fmt: skip
    host_gate.record_wait(case, "run-seed", [u])
    pages = [srv.idx_host_inventory(offset=o, limit=3)["awaiting_host_confirmation"][0]
             for o in (0, 3, 6)]  # fmt: skip
    assert [e["raw"] for p in pages for e in p["unresolved"]] == SEED_RAWS
    assert pages[0]["unresolved_by_reason"] == {NOT_CONFIRMED: len(SEED_RAWS)}


# --- suggestions --------------------------------------------------------------


def test_suggestions_are_paged_with_their_total(case):
    hi.append_observations(case, [
        {"kind": "suggestion", "origin": "ai", "tool": "case_host_fix", "raw": f"R{i}",
         "canonical": f"C{i}"} for i in range(7)])  # fmt: skip
    first = srv.idx_host_inventory(limit=5)
    rest = srv.idx_host_inventory(offset=5, limit=5)
    assert first["suggestions_total"] == rest["suggestions_total"] == 7
    assert [s["raw"] for s in first["suggestions"] + rest["suggestions"]] == [
        f"R{i}" for i in range(7)
    ]


# --- twins: the small shape is as it was, plus its totals ---------------------


def test_twin_the_three_host_shape_is_unchanged_apart_from_the_totals(case):
    def unit(locator, name):
        u = hi.unit_key(locator)
        hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": locator}] + [
            {"kind": "name", "unit": u, "raw": name, "evidence": ev, "origin": "artifact"}
            for ev in ("SYSTEM ComputerName", "Security.evtx Computer")])  # fmt: skip
        return u

    a, _, c = unit("evidence/a", "WKS01"), unit("evidence/b", "SRV9"), unit("evidence/c", "DC01")
    hi.append_decision(case, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": hi.new_machine_key(), "canonical": "WKS01", "pairs": [[a, "WKS01"]]}]}},
        hi.load(case).obs_offset)  # fmt: skip
    host_gate.record_wait(case, "run-1", [c])
    srv.case_host_fix("SRV9", "SRV09")
    inv = srv.idx_host_inventory()
    state = hi.load(case)
    (run,) = inv["awaiting_host_confirmation"]
    new = {"units_total", "unresolved_total", "unresolved_by_reason", "unresolved_units_total",
           "unresolved_by_unit"}  # fmt: skip
    old = {"run_id": "run-1", "units": [c], "unresolved": host_gate.unresolved(state, [c])}
    assert {k: v for k, v in run.items() if k not in new} == old
    assert run["unresolved_total"] == 1 and run["units_total"] == 1
    for n in inv["names_without_machine"] + inv["machines"][0]["names"]:
        info = state.names[(n["unit"], n["raw"])]
        assert n["evidence"] == list(info["evidence"]) and n["evidence_total"] == 2
    assert inv["suggestions"] == list(state.suggestions) and inv["suggestions_total"] == 1
    assert inv["names_without_machine_total"] == 2 and inv["machines_total"] == 1


@pytest.mark.parametrize("n", [1, 4, 5, 6])
def test_twin_evidence_at_and_under_five_is_shown_whole(case, n):
    u = hi.unit_key("evidence/e")
    hi.append_observations(case, [{"kind": "unit", "unit": u, "locator": "evidence/e"}] + [
        {"kind": "name", "unit": u, "raw": "E01", "evidence": f"f{i}", "origin": "artifact"}
        for i in range(n)])  # fmt: skip
    (name,) = srv.idx_host_inventory()["names_without_machine"]
    assert name["evidence"] == [f"f{i}" for i in range(min(n, 5))]
    assert name["evidence_total"] == n


# --- the reply's size at the 29 x 24 shape ------------------------------------


@pytest.mark.parametrize("limit,most", [(5, 5_000), (50, 25_000), (200, 80_000)])
def test_the_reply_at_29_hosts_by_24_modules_stays_bounded(case, limit, most):
    kansa(case, evidence=200)
    inv = srv.idx_host_inventory(limit=limit)
    print(f"limit={limit} reply={_size(inv)} characters")  # the audit quotes it
    assert _size(inv) < most, _size(inv)
