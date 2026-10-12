"""Record ids keep distinct records apart.

Three parsers gave two distinct records one id, and the bulk write's `create`
then kept only the first, counted as "already in the case":
- an access log: a 1-second timestamp and no line number, user, version or
  referrer in the id;
- vol3 netscan, netstat and svcscan: a key without the object's offset, state
  or creation time, and a null read as "None";
- per-profile EZ tools (shellbags, jumplists, lnk, timeline): no source path.
Their ids now keep such records apart, and a record written with a changed id
carries `vhir.id_scheme: 2`.

A re-ingest of evidence stored before 0.6.5 keeps what is stored and adds only
what 0.6.4 missed: each changed record carries the id 0.6.4 stored it under
(pinned to e0adcc0's own writes below), one lookup per batch finds it, and a
stored record without the marker, from the same evidence and not yet claimed
by another record of this process, is that record. Each (case, unit, type)
says "kept N … already stored; added M …", and a lookup that fails says
"couldn't check".

The parsers, the write stamp and the bulk path are real; the cluster is an
in-memory stand-in (record_ids_cluster), and the EZ tools and vol3 are
stubbed at their call boundary. Every run has its own audit id.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import itertools
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from record_ids_cluster import Cluster, make_case
from test_accesslog_status import run  # noqa: F401 - the accesslog command's fixture
from test_evidence_volume_lost import other_device, scan  # noqa: F401 - the scan's

from opensearch_mcp import bulk, ingest, ingest_cli, ingest_status, tools
from opensearch_mcp import parse_memory as pm
from opensearch_mcp import write_context as wc
from opensearch_mcp.parse_accesslog import ingest_accesslog

STEP = itertools.count(1)


def step() -> str:
    """Every run its own audit id, as the CLI's are."""
    return f"aud-{os.getpid()}-{next(STEP)}"


@pytest.fixture
def cluster(monkeypatch):
    c = Cluster()
    monkeypatch.setattr(bulk.helpers, "bulk", c.bulk)
    return c


@pytest.fixture
def cases(tmp_path, monkeypatch):
    d = tmp_path / "cases"
    d.mkdir()
    monkeypatch.setenv("VHIR_CASES_DIR", str(d))
    return d


@pytest.fixture(autouse=True)
def new_process(monkeypatch):
    """Each test is a new process: no write context open, nothing claimed
    or reported (an earlier test's files with no time field included: the
    status adds that note too)."""
    from opensearch_mcp import paths

    for attr in FILL_STATE:
        if hasattr(wc, attr):  # a version before the fill-in has none
            monkeypatch.setattr(wc, attr, type(getattr(wc, attr))())
    no_time = list(paths.NO_TIME_FIELD)  # imported by name elsewhere: emptied in place
    paths.NO_TIME_FIELD.clear()
    yield
    wc.set_current(None)
    paths.NO_TIME_FIELD[:] = no_time


# what a process remembers: the fill-in's, and the indices it prepared
FILL_STATE = ("FILL", "_FILL_CLAIMED", "FILL_UNCHECKED", "_FILL_SAID", "_MARKED", "_prepared")


def open_run(cases, name, locator, host, source):
    case = make_case(cases, name)
    ctx = wc.open_unit(case, locator, host, source=source)
    wc.set_current(ctx)
    return case, ctx


def new_run(*attrs):
    """What a new process starts with (between two runs in one test)."""
    for attr in attrs:
        if hasattr(wc, attr):
            getattr(wc, attr).clear()


# --- access log -------------------------------------------------------------

LINE = ('203.0.113.5 - {user} [25/Jan/2023:15:10:30 +0000] "POST /wp-login.php {ver}" '
        '200 2312 "{ref}" "Mozilla/5.0"')  # fmt: skip
SAME = LINE.format(user="-", ver="HTTP/1.1", ref="-")


def access_run(cluster, cases, case, folder, name, lines, unit="logs/web01"):
    """One run of one file, as cmd_ingest_accesslog makes it: the unit open,
    its own step, source_file the same case-relative locator each time."""
    case_dir, _ = open_run(cases, case, unit, "web01", "access log")
    f = case_dir / folder / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(lines) + "\n")
    index = wc.index_name("accesslog")
    bulk.reset_circuit_breaker()
    s = step()
    with wc.op(s):
        n = ingest_accesslog(f, cluster.client(), index, "web01",
                             source_file=f"evidence/{name}", ingest_audit_id=s,
                             pipeline_version="opensearch-mcp-0.6.4")[0]  # fmt: skip
    return index, n, bulk.get_already_present()


def test_three_identical_requests_in_one_second_are_three_records(cluster, cases):
    index, n, present = access_run(cluster, cases, "c1a", "d1", "access.log", [SAME] * 3)
    assert (len(cluster.docs(index)), n, present) == (3, 3, 0)


def test_a_new_run_of_the_same_access_log_adds_nothing(cluster, cases):
    index, _, _ = access_run(cluster, cases, "c1b", "d1", "access.log", [SAME] * 3)
    ids = [i for i, _ in cluster.docs(index)]
    index, n, present = access_run(cluster, cases, "c1b", "d1", "access.log", [SAME] * 3)
    assert [i for i, _ in cluster.docs(index)] == ids and (n, present) == (0, 3)


def test_one_access_log_sent_twice_in_one_run_is_stored_once_per_line(cluster, cases):
    case_dir, _ = open_run(cases, "c1c", "logs/web01", "web01", "access log")
    f = case_dir / "access.log"
    f.write_text("\n".join([SAME] * 3) + "\n")
    index = wc.index_name("accesslog")
    bulk.reset_circuit_breaker()
    with wc.op(step()):
        first = ingest_accesslog(f, cluster.client(), index, "web01", source_file="evidence/a")
        second = ingest_accesslog(f, cluster.client(), index, "web01", source_file="evidence/a")
    assert (first[0], second[0], len(cluster.docs(index))) == (3, 0, 3)


@pytest.mark.parametrize(
    "field,other",
    [
        ("user.name", LINE.format(user="alice", ver="HTTP/1.1", ref="-")),
        ("http.version", LINE.format(user="-", ver="HTTP/2.0", ref="-")),
        (
            "http.request.referrer",
            LINE.format(user="-", ver="HTTP/1.1", ref="https://evil.example/"),
        ),
    ],
)
def test_a_second_collection_at_one_case_path_keeps_its_own_line(cluster, cases, field, other):
    """Line 1 of the two collections differs only in `field`."""
    access_run(cluster, cases, "c1d", "col1", "access.log", [SAME])
    index, _, _ = access_run(cluster, cases, "c1d", "col2", "access.log", [other])
    values = sorted(str(s.get(field)) for _, s in cluster.docs(index))
    assert len(values) == 2 and len(set(values)) == 2


def test_lines_in_three_seconds_from_two_files_are_six_records(cluster, cases):
    lines = [SAME.replace(":15:10:30", f":15:10:3{i}") for i in range(3)]
    index, _, _ = access_run(cluster, cases, "c1g", "d1", "access.log", lines)
    access_run(cluster, cases, "c1g", "d1", "other.log", lines)
    assert len(cluster.docs(index)) == 6


# --- vol3 netscan, netstat, svcscan -----------------------------------------

IMG = "/cases/mem/evidence/mem.raw"
NET_A = {"Offset": 0xE0012A3B4010, "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49710,
         "ForeignAddr": "203.0.113.7", "ForeignPort": 443, "State": "CLOSED", "PID": None,
         "Owner": None, "Created": "2026-10-01T10:00:00+00:00", "__children": []}  # fmt: skip
NET_B = {**NET_A, "Offset": 0xE0012A9F8A20, "State": "ESTABLISHED",
         "Created": "2026-10-01T11:30:00+00:00"}  # fmt: skip
SVC_1 = {"Offset": 0x1D0A1B0, "Order": 210, "PID": None, "Start": "SERVICE_DEMAND_START",
         "State": "SERVICE_STOPPED", "Type": "SERVICE_WIN32_OWN_PROCESS", "Name": "updsvc",
         "Display": "Update Service", "Binary": "C:\\Program Files\\Upd\\upd.exe",
         "__children": []}  # fmt: skip
SVC_2 = {**SVC_1, "Offset": 0x1D0C3F0, "Binary": "C:\\Users\\Public\\upd.exe"}


@pytest.fixture
def mem(cases):
    open_run(cases, "mem", "evidence/mem.raw", "HOST-M", "memory image")


def vol(cluster, plugin, rows):
    index = wc.index_name("vol-" + plugin.split(".")[-1])
    bulk.reset_circuit_breaker()
    s = step()
    with wc.op(s):
        n = pm._index_vol3_records([dict(r) for r in rows], cluster.client(), index, plugin,
                                   "HOST-M", IMG, s, "opensearch-mcp-0.6.4")[0]  # fmt: skip
    return index, n, bulk.get_already_present()


@pytest.mark.parametrize(
    "plugin,rows,key",
    [
        ("windows.netscan", [NET_A, NET_B], "State"),
        ("windows.netscan", [{**NET_A, "PID": 4, "Owner": "System"},
                             {**NET_B, "PID": 4, "Owner": "System"}], "State"),
        ("windows.netstat", [{**NET_A, "PID": 4}, {**NET_B, "PID": 4}], "State"),
        ("windows.svcscan", [SVC_1, SVC_2], "Binary"),
        ("windows.svcscan", [{**SVC_1, "PID": 812}, {**SVC_2, "PID": 812}], "Binary"),
    ],
    ids=["netscan-pid-null", "netscan-pid-4", "netstat-pid-4", "svcscan-pid-null",
         "svcscan-pid-812"],
)  # fmt: skip
def test_two_vol3_objects_that_differ_in_offset_are_two_records(cluster, mem, plugin, rows, key):
    index, _, _ = vol(cluster, plugin, rows)
    assert sorted(s[key] for _, s in cluster.docs(index)) == sorted(r[key] for r in rows)


def test_netscan_rows_with_no_pid_key_stay_apart(cluster, mem):
    rows = [{k: v for k, v in r.items() if k != "PID"} for r in (NET_A, NET_B)]
    index, _, _ = vol(cluster, "windows.netscan", rows)
    assert len(cluster.docs(index)) == 2


def test_one_netscan_row_sent_twice_in_a_batch_is_one_record(cluster, mem):
    row = {**NET_A, "PID": 4}
    index, _, present = vol(cluster, "windows.netscan", [row, row])
    assert (len(cluster.docs(index)), present) == (1, 1)


def test_the_same_image_ingested_again_adds_nothing(cluster, mem):
    rows = [{**NET_A, "PID": 4}, NET_A, NET_B]
    index, _, _ = vol(cluster, "windows.netscan", rows)
    ids = [i for i, _ in cluster.docs(index)]
    index, n, present = vol(cluster, "windows.netscan", rows)
    assert [i for i, _ in cluster.docs(index)] == ids and (n, present) == (0, 3)


def test_other_plugins_keep_their_exact_ids(mem):
    assert {
        "pslist PID4": pm._vol3_doc_id(
            "idx", "windows.pslist", {"PID": 4, "CreateTime": "2023-01-15T10:00:00Z"}, IMG
        ),
        "pslist PID0 CreateTime null": pm._vol3_doc_id(
            "idx", "windows.pslist", {"PID": 0, "CreateTime": None}, IMG
        ),
        "dlllist": pm._vol3_doc_id(
            "idx", "windows.dlllist", {"PID": 4, "Base": 140737, "Name": None}, IMG
        ),
    } == {
        "pslist PID4": "34f987a8c890048d1586",
        "pslist PID0 CreateTime null": "7c80219e0c06b2ecae70",
        "dlllist": "68a6c7703ef8aab6b372",
    }


@pytest.mark.parametrize(
    "plugin,row",
    [
        ("windows.netscan", {**NET_A, "PID": 4, "Owner": "System"}),
        ("windows.netscan", {**NET_A, "Proto": "UDPv4", "State": "", "ForeignAddr": "*",
                             "ForeignPort": 0}),
        ("windows.netscan", {**NET_A, "State": "LISTENING", "PID": 4, "Created": None}),
        ("windows.svcscan", SVC_1),
    ],
    ids=["tcp-fully-keyed", "udp-state-empty", "listener-created-null", "service-pid-null"],
)  # fmt: skip
def test_a_newer_vol3_column_keeps_the_id(mem, plugin, row):
    assert pm._vol3_doc_id("idx", plugin, dict(row), IMG) == pm._vol3_doc_id(
        "idx", plugin, {**row, "NewColumn": "x"}, IMG
    )


# --- per-profile EZ tools ---------------------------------------------------

COLS = {
    "shellbags": ["BagPath", "Slot", "NodeSlot", "MRUPosition", "AbsolutePath", "ShellType",
                  "Value", "LastWriteTime", "SourceFile"],
    "lnk": ["SourceFile", "TargetIDAbsolutePath", "LocalPath", "TargetModified"],
    "jumplists": ["SourceFile", "AppId", "Path", "LastModified"],
    "timeline": ["SourceFile", "Id", "AppId", "LastModifiedTime"],
    "registry": ["SourceFile", "KeyPath", "ValueName", "LastWriteTimestamp", "PluginDetailFile"],
}  # fmt: skip
COLS["registry_user"] = COLS["registry"]
VALS = {
    "shellbags": ["BagMRU\\0", "0", "1", "0", "My Computer\\C:", "Drive letter", "C:",
                  "2026-09-01 08:00:00"],
    "lnk": ["C:\\Tools\\x.exe", "C:\\Tools\\x.exe", "2026-09-01 08:00:00"],
    "jumplists": ["5d696d521de238c3", "C:\\Shared\\plan.docx", "2026-09-01 08:00:00"],
    "timeline": ["{7f3a}", "Microsoft.Windows.Explorer", "2026-09-01 08:00:00"],
    "registry": ["ROOT\\Software\\X", "(default)", "2026-01-02 03:04:05", ""],
}  # fmt: skip
VALS["registry_user"] = VALS["registry"]
PAIRS = {
    "shellbags": ("Users/alice", "Users/bob"),
    "jumplists": ("Users/alice/AppData/Roaming/Microsoft/Windows/Recent",
                  "Users/bob/AppData/Roaming/Microsoft/Windows/Recent"),
    "lnk": ("Users/alice/AppData/Roaming/Microsoft/Windows/Recent", "Users/alice/Desktop"),
    "timeline": ("Users/alice/AppData/Local/ConnectedDevicesPlatform",
                 "Users/bob/AppData/Local/ConnectedDevicesPlatform"),
}  # fmt: skip


@pytest.fixture
def ez(cases, monkeypatch):
    return ez_stub(cases, monkeypatch)


def ez_stub(cases, monkeypatch):
    """The EZ tool stand-in: one CSV row, the same each time but for its
    SourceFile (the tool's own path into the evidence, volatile)."""
    state = {"tool": None, "runs": 0}

    def run_tool(cmd, label):
        out = Path(cmd[cmd.index("--csv") + 1])
        target = cmd[cmd.index("-d") + 1] if "-d" in cmd else cmd[cmd.index("-f") + 1]
        tool = state["tool"]
        state["runs"] += 1
        values = list(VALS[tool])
        values.insert(COLS[tool].index("SourceFile"), f"/mnt/run-{state['runs']}{target}/f.dat")
        (out / f"20260102030405_{tool}.csv").write_text(
            ",".join(COLS[tool]) + "\n" + ",".join(f'"{v}"' for v in values) + "\n"
        )
        return "", ""

    monkeypatch.setattr(tools, "_run_tool", run_tool)
    case_dir, _ = open_run(cases, "prof", "evidence/HOST-S", "HOST-S", "evidence folder")
    return SimpleNamespace(state=state, case_dir=case_dir)


def profile(cluster, ez, tool, rel, seen=None, collided=None, root="vol"):
    ez.state["tool"] = tool
    p = ez.case_dir / root / rel
    p.mkdir(parents=True, exist_ok=True)
    bulk.reset_circuit_breaker()
    s = step()
    with wc.op(s):
        n = tools.run_and_ingest(tool, p, cluster.client(), "prof", "HOST-S", source_file=rel,
                                 ingest_audit_id=s, pipeline_version="opensearch-mcp-0.6.4",
                                 seen=seen, collided=collided)[0]  # fmt: skip
    return wc.index_name(tools.TOOLS[tool].index_suffix), n, bulk.get_already_present()


def sources(cluster, index):
    return sorted(s["vhir.source_file"] for _, s in cluster.docs(index))


@pytest.mark.parametrize("tool", sorted(PAIRS))
def test_the_same_row_from_two_profiles_in_one_run_is_two_records(cluster, ez, tool):
    seen: dict = {}
    first, second = PAIRS[tool]
    profile(cluster, ez, tool, first, seen, {})
    index, _, _ = profile(cluster, ez, tool, second, seen, {})
    assert sources(cluster, index) == sorted(PAIRS[tool])


@pytest.mark.parametrize("tool", sorted(PAIRS))
def test_the_same_row_from_two_profiles_in_two_runs_is_two_records(cluster, ez, tool):
    first, second = PAIRS[tool]
    profile(cluster, ez, tool, first)
    index, _, _ = profile(cluster, ez, tool, second)
    assert sources(cluster, index) == sorted(PAIRS[tool])


@pytest.mark.parametrize("tool", sorted(PAIRS))
def test_a_profile_collected_again_under_another_mount_adds_nothing(cluster, ez, tool):
    index, _, _ = profile(cluster, ez, tool, PAIRS[tool][0])
    ids = [i for i, _ in cluster.docs(index)]
    index, n, present = profile(cluster, ez, tool, PAIRS[tool][0], root="vol-recollected")
    assert [i for i, _ in cluster.docs(index)] == ids and (n, present) == (0, 1)


def test_registry_hives_keep_their_ids(cluster, ez, monkeypatch):
    """registry and registry_user are hashed as before: no id source passed,
    no marker. (Their exact ids depend on this run's paths, so the formula's
    input is checked, not a constant.)"""
    passed = []
    real = tools.ingest_csv

    def spy(*a, **kw):
        passed.append(kw.get("id_source", ""))
        return real(*a, **kw)

    monkeypatch.setattr(tools, "ingest_csv", spy)
    for tool, rel in (("registry", "Windows/System32/config/SYSTEM"),
                      ("registry_user", "Users/alice/NTUSER.DAT")):  # fmt: skip
        ez.state["tool"] = tool
        p = ez.case_dir / "vol" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"regf")
        with wc.op(step()):
            tools.run_and_ingest(tool, p, cluster.client(), "prof", "HOST-S", source_file=rel)
    stored = cluster.docs(wc.index_name("registry"))
    assert passed == ["", ""] and len(stored) == 2
    assert not any("vhir.id_scheme" in s for _, s in stored)


# --- the id 0.6.4 stored each changed record under ----------------------------

MACHINE = "0123456789abcdef"
SINGLE = {  # one record of each changed type
    "netscan": ("windows.netscan", {**NET_A, "PID": 4}),
    "netstat": ("windows.netstat", {**NET_A, "PID": 4}),
    "svcscan": ("windows.svcscan", SVC_1),  # a null PID
}


def one_record(cluster, cases, monkeypatch, atype) -> str:
    """One record of `atype` from fixed evidence, case and machine key, as
    every version ingests it: its index."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    if atype == "accesslog":
        return access_run(cluster, cases, "pin", "d", "access.log", [SAME])[0]
    if atype in SINGLE:
        open_run(cases, "mem", "evidence/mem.raw", "HOST-M", "memory image")
        plugin, row = SINGLE[atype]
        return vol(cluster, plugin, [row])[0]
    return profile(cluster, ez_stub(cases, monkeypatch), atype, PAIRS[atype][0])[0]


# Each stored id as 0.6.4 (e0adcc0) wrote it, measured through its own
# parsers and stamp with one_record
STORED_064 = {
    "accesslog": "16334c03827dc16d46a1",
    "shellbags": "444c4ba435a573850277",
    "jumplists": "c0eb68fff63ecf003a39",
    "lnk": "63c58943c67d7acca64f",
    "timeline": "b5e1c974508eb7784d70",
    "netscan": "86a0492e7fbc018b65c4",
    "netstat": "505a830f22967529cd1e",
    "svcscan": "30430033e1b764e6db5b",
}


@pytest.mark.parametrize("atype", sorted(STORED_064))
def test_each_changed_record_carries_the_id_0_6_4_stored_it_under(
    cluster, cases, monkeypatch, atype
):
    carried = []
    real = wc.stamp_or_refuse

    def stamp_or_refuse(actions, client=None):
        real(actions, client)
        carried.extend(a.get("_vhir_old_id") for a in actions)  # bulk.OLD_ID_KEY

    monkeypatch.setattr(wc, "stamp_or_refuse", stamp_or_refuse)
    suffix = f"vol-{atype}" if atype in SINGLE else atype
    cluster.created.add(f"case-000000000000-{suffix}-0")  # 0.6.4 made it: no marker
    index = one_record(cluster, cases, monkeypatch, atype)
    assert carried == [STORED_064[atype]]
    assert cluster.asked == [(index, STORED_064[atype])]  # the fill-in looks it up
    ((stored, src),) = cluster.docs(index)  # sent without it, under its 0.6.5 id
    assert stored != STORED_064[atype] and src.get("vhir.id_scheme") == 2


# --- a re-ingest of evidence stored before 0.6.5 keeps it ---------------------

BOB = LINE.format(user="bob", ver="HTTP/1.1", ref="-")
LINES = [SAME, SAME, BOB]  # 0.6.4's id ignored the user: one record stored
VOL = {  # two objects 0.6.4 keyed alike: the first stored
    "windows.netscan": [{**NET_A, "PID": 4}, {**NET_B, "PID": 4}],
    "windows.netstat": [{**NET_A, "PID": 4}, {**NET_B, "PID": 4}],
    "windows.svcscan": [SVC_1, SVC_2],
}
TYPES = ["accesslog", "jumplists", "lnk", "shellbags", "timeline", "vol-netscan",
         "vol-netstat", "vol-svcscan"]  # fmt: skip


FIXTURES = Path(__file__).parent / "fixtures" / "record_ids_064"


def stored_by_064(cluster, scenario: str) -> None:
    """What 0.6.4 (e0adcc0's own parsers and stamp) stored of this evidence,
    in step 1's order: written by step_064 under e0adcc0 and saved."""
    for index, _id, version, src in json.loads((FIXTURES / f"{scenario}.json").read_text()):
        cluster.store[(index, _id)] = src
        cluster.versions[(index, _id)] = version
        cluster.created.add(index)


def ingest_all(
    cluster, cases, monkeypatch, reverse=False, extra=None, vol_rows=VOL, lines=LINES
) -> dict:
    """The changed parsers over the same evidence: {type: index}. `reverse`
    reads the profiles bob first and the vol3 objects last first; `extra`
    gives each vol3 object a newer column."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    out = {"accesslog": access_run(cluster, cases, "fill", "d", "access.log", lines)[0]}
    ez = ez_stub(cases, monkeypatch)
    for tool in sorted(PAIRS):
        for rel in PAIRS[tool][::-1] if reverse else PAIRS[tool]:
            index = profile(cluster, ez, tool, rel)[0]
        out[wc.artifact_type_of(index)] = index
    open_run(cases, "fill", "evidence/mem.raw", "HOST-M", "memory image")
    for plugin, rows in vol_rows.items():
        rows = [{**r, **(extra or {})} for r in (rows[::-1] if reverse else rows)]
        index = vol(cluster, plugin, rows)[0]
        out[wc.artifact_type_of(index)] = index
    wc.set_current(None)
    return out


def evidence(cluster, out) -> dict:
    """What each index holds, by what tells its records apart."""
    field = {t: "Offset" if t.startswith("vol-") else "vhir.source_file" for t in TYPES}
    field["accesslog"] = "user.name"
    return {t: sorted(str(s.get(field[t])) for _, s in cluster.docs(i)) for t, i in out.items()}


def report() -> dict:
    """Each type's fill-in report ("" from a version that has none)."""
    note = getattr(wc, "fill_note", lambda **k: "")
    return {t: note(artifact_type=t) for t in TYPES}


def kept(n, m):
    s = "" if n == 1 else "s"
    return f"kept {n} record{s} already stored; added {m} not stored before"


ONCE = {  # each record exactly once: accesslog [-, -, bob], EZ [alice, bob], vol3 2 objects
    "accesslog": sorted(["None", "None", "bob"]),
    **{t: sorted(PAIRS[t]) for t in PAIRS},
    **{f"vol-{p.split('.')[1]}": sorted(str(r["Offset"]) for r in rs) for p, rs in VOL.items()},
}
SAID = {t: f"{t}: {kept(1, 2 if t == 'accesslog' else 1)}" for t in TYPES}


NO_OFFSET = {
    p: [{k: v for k, v in r.items() if k != "Offset"} for r in rs] for p, rs in VOL.items()
}


# a line, 999 others, then the line again: the two land in different batches
SPLIT = [SAME] + [SAME.replace("/wp-login.php", f"/p{i}") for i in range(999)] + [SAME]


def step_064(scenario, cluster, cases, monkeypatch, **kw) -> None:
    """Step 1, as every version runs it (run under e0adcc0 to make the
    fixtures stored_by_064 reads)."""
    if scenario == "split":
        from sift_common import host_identity

        monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
        access_run(cluster, cases, "fill", "d", "access.log", SPLIT)
    elif scenario == "memory":
        memory_cli(cluster, cases, monkeypatch, "mem-run-1", VOL["windows.netscan"], **kw)
    else:
        rows = NO_OFFSET if scenario == "no-offset" else VOL
        ingest_all(cluster, cases, monkeypatch, vol_rows=rows)


def re_ingest(cluster, cases, monkeypatch, enriched=False, vol_rows=VOL, **kw) -> dict:
    """0.6.4's ingest, then (a new process) this one's, reading the profiles
    bob first and the vol3 objects in reverse. `enriched`: every stored
    record then gets triage and a relabelled host.id."""
    stored_by_064(cluster, "no-offset" if vol_rows is NO_OFFSET else "evidence")
    if enriched:
        for src in cluster.store.values():
            src.update({"triage.verdict": "EXPECTED", "host.id": "RENAMED"})
    new_run(*FILL_STATE)
    return ingest_all(cluster, cases, monkeypatch, reverse=True, vol_rows=vol_rows, **kw)


@pytest.mark.parametrize("enriched", [False, True], ids=["as-stored", "enriched"])
def test_a_re_ingest_keeps_each_stored_record_and_adds_what_0_6_4_missed(
    cluster, cases, monkeypatch, enriched
):
    out = re_ingest(cluster, cases, monkeypatch, enriched)
    assert evidence(cluster, out) == ONCE
    assert report() == SAID


def test_no_stored_record_is_written_to(cluster, cases, monkeypatch):
    stored_by_064(cluster, "evidence")
    for src in cluster.store.values():
        src.update({"triage.verdict": "EXPECTED", "host.id": "RENAMED"})
    before = {k: (dict(v), cluster.versions[k]) for k, v in cluster.store.items()}
    new_run(*FILL_STATE)
    ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert {k: (cluster.store[k], cluster.versions[k]) for k in before} == before


def test_a_second_re_ingest_adds_nothing(cluster, cases, monkeypatch):
    out = re_ingest(cluster, cases, monkeypatch)
    new_run(*FILL_STATE)
    ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert evidence(cluster, out) == ONCE
    assert report() == {t: f"{t}: {kept(1, 0)}" for t in TYPES}


def test_the_same_evidence_twice_in_one_process_is_kept_once(cluster, cases, monkeypatch):
    out = re_ingest(cluster, cases, monkeypatch)
    ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert evidence(cluster, out) == ONCE
    assert report() == SAID


def test_a_newer_vol3_column_is_kept_not_stored_twice(cluster, cases, monkeypatch):
    out = re_ingest(cluster, cases, monkeypatch, extra={"NewColumn": "x"})
    assert evidence(cluster, out) == ONCE
    assert report() == SAID


def test_vol3_objects_with_no_offset_are_written_and_said(cluster, cases, monkeypatch):
    """Regression guard: neither side's offset proves the object, so nothing
    is skipped onto a stored record (no loss), and the duplicate is said."""
    out = re_ingest(cluster, cases, monkeypatch, vol_rows=NO_OFFSET)
    for plugin, rs in NO_OFFSET.items():
        t = f"vol-{plugin.split('.')[1]}"
        held = [s for _, s in cluster.docs(out[t])]
        assert len(held) == 3  # the first object stored by 0.6.4 and again, the second once
        key = "Binary" if "svcscan" in plugin else "State"
        assert sorted({s[key] for s in held}) == sorted({r[key] for r in rs})  # none lost
        assert report()[t] == f"{t}: {kept(0, 2)}"


@pytest.mark.parametrize("fail", ["request", "items", "short"])
def test_a_lookup_that_fails_writes_everything_and_says_so(cluster, cases, monkeypatch, fail):
    """Regression guard (9f8bd8c never looks up): nothing raises, every record
    is written under its 0.6.5 id, and each (case, unit, type) says it."""
    stored_by_064(cluster, "evidence")
    if fail == "request":
        cluster.mget_error = RuntimeError("stand-in cluster: mget refused")
        why = "stand-in cluster: mget refused"
    elif fail == "items":
        cluster.mget_item_error = {"type": "shard_not_available_exception", "reason": "x"}
        why = str(cluster.mget_item_error)
    else:  # one answer fewer than the ids asked
        cluster.mget_short = True
        why = None
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert {t: len(cluster.docs(i)) for t, i in out.items()} == {
        t: 4 if t == "accesslog" else 3 for t in TYPES
    }
    for t in TYPES:
        n = {"accesslog": 3}.get(t, 2 if t.startswith("vol-") else 1)  # its first batch's ids
        reason = why or f"{n - 1} answers for {n} ids"
        assert (
            report()[t] == f"couldn't check for records stored before 0.6.5 in {out[t]}: {reason}"
        )
    assert err.getvalue().count("WARNING: couldn't check") == len(TYPES)


def test_an_index_not_found_answer_is_not_stored_not_unchecked(cluster, cases, monkeypatch):
    """Regression guard: when exists() can't be answered, no index is created
    before the write (so none carries the marker) and the lookup runs against
    an index that isn't there yet. mget answers each such id with an
    index_not_found_exception item, which means "not stored"."""

    def unanswered(index=None, **k):
        raise RuntimeError("stand-in cluster: exists unanswered")

    monkeypatch.setattr(cluster.client.indices, "exists", unanswered)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = ingest_all(cluster, cases, monkeypatch)
    assert cluster.asked and not cluster.mappings  # looked up; nothing made with the marker
    assert {t: len(cluster.docs(i)) for t, i in out.items()} == {t: len(ONCE[t]) for t in TYPES}
    assert report() == dict.fromkeys(TYPES, "") and "couldn't check" not in err.getvalue()


def test_a_fresh_case_ingested_twice_says_nothing(cluster, cases, monkeypatch):
    """Regression guard: no record stored before 0.6.5, nothing kept or said."""
    out = ingest_all(cluster, cases, monkeypatch)
    new_run(*FILL_STATE)
    ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert evidence(cluster, out) == ONCE
    assert report() == dict.fromkeys(TYPES, "")


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-fill")  # the accesslog route's run
    return path


def bg_status(ctx, host):
    """The accesslog route's terminal status note (_write_bg_status)."""
    ingest_cli._write_bg_status(ctx.case_dir.name, "run-fill", "complete", host, "accesslog",
                                "2026-10-11T00:00:00+00:00", indexed=1)  # fmt: skip
    files = sorted(ingest_status._STATUS_DIR.glob("*run-fill*.json"))
    art = json.loads(files[-1].read_text())["hosts"][0]["artifacts"][0] if files else {}
    for f in files:
        f.unlink()
    return art.get("note", "")


def scan_note(ctx, host, index):
    """The scan route's artifact note (_add_second_copy_notes)."""
    hr = SimpleNamespace(artifacts=[SimpleNamespace(artifact="shellbags", index=index, note="")])
    status_hosts = [{"artifacts": [{"name": "shellbags"}]}]
    ingest._add_second_copy_notes(SimpleNamespace(hostname=host, write_ctx=ctx), 0, hr,
                                  status_hosts)  # fmt: skip
    return status_hosts[0]["artifacts"][0].get("note", "")


def test_the_report_rides_on_the_status_and_the_scan_route(
    cluster, cases, monkeypatch, status_dir
):
    re_ingest(cluster, cases, monkeypatch)
    ctx = wc.open_unit(cases / "fill", "logs/web01", "web01", source="access log")
    assert bg_status(ctx, "web01") == SAID["accesslog"]
    ctx = wc.open_unit(cases / "prof", "evidence/HOST-S", "HOST-S", source="evidence folder")
    wc.set_current(ctx)
    assert scan_note(ctx, "HOST-S", wc.index_name("shellbags")) == SAID["shellbags"]


def test_the_report_is_printed_once_per_case_unit_and_type(cluster, cases, monkeypatch):
    re_ingest(cluster, cases, monkeypatch)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        for _ in range(2):  # a second Done line in the process prints nothing new
            getattr(wc, "print_fill_report", lambda: None)()
    assert sorted(err.getvalue().splitlines()) == sorted(f"NOTE: {SAID[t]}" for t in TYPES)


def memory_cli(cluster, cases, monkeypatch, run_id, read, status_dir=None):
    """One cmd_ingest_memory run of windows.netscan reading `read`: vol3
    stubbed, the cluster the stand-in. Its status entry's note and the NOTE
    lines it printed."""
    from sift_common import host_identity

    image = cases / "fillm" / "evidence" / "mem.raw"
    make_case(cases, "fillm")
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"\0" * 64)
    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    monkeypatch.setattr(pm, "_find_vol3", lambda: "true")
    monkeypatch.setattr(pm, "run_vol3_plugin", lambda *a, **k: [dict(r) for r in read])
    monkeypatch.setattr(ingest_cli, "get_client", cluster.client)
    for name in ("_preflight_shard_capacity", "_ensure_case_active"):
        monkeypatch.setattr(ingest_cli, name, mock.MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "fillm")
    audit = cases.parent / "audit"
    audit.mkdir(exist_ok=True)
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(audit))
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", run_id)
    args = argparse.Namespace(path=str(image), case="fillm", hostname="HOST-M", tier=1,
                              plugins="windows.netscan", yes=True, timeout=10)  # fmt: skip
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        ingest_cli.cmd_ingest_memory(args)
    wc.set_current(None)
    printed = [x for x in err.getvalue().splitlines() if "NOTE" in x]
    if status_dir is None:
        return "", printed
    (status,) = [json.loads(f.read_text()) for f in status_dir.glob(f"*{run_id}*.json")]
    (entry,) = status["hosts"][0]["artifacts"]
    return entry.get("note", ""), printed


def test_the_memory_plugin_status_entry_and_done_line_carry_the_report(
    cluster, cases, status_dir, monkeypatch
):
    rows = VOL["windows.netscan"]
    stored_by_064(cluster, "memory")
    said = f"vol-netscan: {kept(1, 1)}"
    note, printed = memory_cli(cluster, cases, monkeypatch, "mem-run-2", rows[::-1], status_dir)
    held = [s for _, s in cluster.docs(next(i for i, _ in cluster.store))]
    assert sorted(s["Offset"] for s in held) == sorted(r["Offset"] for r in rows)
    assert (note, printed) == (said, [f"NOTE: {said}"])


def test_an_access_log_read_in_another_order_loses_no_line(cluster, cases, monkeypatch):
    """The stored line's user, version and referrer decide, not the order:
    bob's line, read first now, isn't taken for the stored line."""
    stored_by_064(cluster, "evidence")
    out = ingest_all(cluster, cases, monkeypatch, reverse=True, lines=[BOB, SAME, SAME])
    assert evidence(cluster, out)["accesslog"] == ONCE["accesslog"]
    assert report()["accesslog"] == SAID["accesslog"]


def test_a_record_at_a_0_6_4_id_that_carries_the_marker_is_not_kept(cluster, cases, monkeypatch):
    stored_by_064(cluster, "evidence")
    for src in cluster.store.values():
        src["vhir.id_scheme"] = 2
    out = ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert {t: len(cluster.docs(i)) for t, i in out.items()} == {
        t: len(ONCE[t]) + 1 for t in TYPES
    }
    assert report() == dict.fromkeys(TYPES, "")


SEEDED = ("000000000000", "web01", "accesslog")


def test_the_accesslog_command_prints_the_report_at_its_done_line(run, capsys):  # noqa: F811
    from test_accesslog_status import GOOD

    wc.FILL[SEEDED] = [1, 2]
    run({"a.log": GOOD})
    out, err = capsys.readouterr()
    assert "Done." in out and f"NOTE: accesslog: {kept(1, 2)}" in err.splitlines()


def test_the_scan_command_prints_the_report_at_its_done_line(scan, capsys):  # noqa: F811
    wc.FILL[("000000000000", "dev01", "shellbags")] = [1, 1]
    scan(unmount=False)
    out, err = capsys.readouterr()
    assert "Done in" in out and f"NOTE: shellbags: {kept(1, 1)}" in err.splitlines()


def test_after_a_failed_lookup_a_later_run_adds_no_copy(cluster, cases, monkeypatch):
    """The first batch's lookup fails: its records are written under their
    0.6.5 ids, and said. The line's twin, in the next batch, is then taken
    for the stored line. A later run reads the line again: already stored
    under its 0.6.5 id, it isn't taken for the stored line too, so the twin
    isn't written a third time."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    stored_by_064(cluster, "split")
    real, failed = cluster.client.mget, []

    def mget_once(self, body=None, **k):  # the first lookup only
        if not failed:
            failed.append(1)
            raise RuntimeError("stand-in cluster: one lookup refused")
        return real(self, body=body, **k)

    monkeypatch.setattr(cluster.client, "mget", mget_once)
    with contextlib.redirect_stderr(io.StringIO()):
        index = access_run(cluster, cases, "fill", "d", "access.log", SPLIT)[0]
    after_failure = len(cluster.docs(index))
    new_run(*FILL_STATE)
    access_run(cluster, cases, "fill", "d", "access.log", SPLIT)
    assert len(cluster.docs(index)) == after_failure
    # the first batch's records are already stored under their 0.6.5 ids
    assert report()["accesslog"] == f"accesslog: {kept(1, 0)}"


def test_an_index_this_version_created_isnt_looked_up(cluster, cases, monkeypatch):
    """Its mapping carries the marker: every record in it has its 0.6.5 id."""
    out = ingest_all(cluster, cases, monkeypatch)
    new_run(*FILL_STATE)  # a new process reads the marker from the mapping
    ingest_all(cluster, cases, monkeypatch, reverse=True)
    # no 0.6.4 id asked for: only stored ids, by the bulk's own 409 check
    assert cluster.asked and set(cluster.asked) <= set(cluster.store)
    assert all(cluster.mappings[i]["_meta"] == {"vhir_ids": "0.6.5"} for i in out.values())
    assert evidence(cluster, out) == ONCE and report() == dict.fromkeys(TYPES, "")


def test_an_index_whose_mapping_cant_be_read_is_looked_up(cluster, cases, monkeypatch):
    """Without the marker read, the lookup runs: slower, never wrong."""
    stored_by_064(cluster, "evidence")
    cluster.mapping_error = RuntimeError("stand-in cluster: mapping refused")
    out = ingest_all(cluster, cases, monkeypatch, reverse=True)
    assert evidence(cluster, out) == ONCE and report() == SAID
