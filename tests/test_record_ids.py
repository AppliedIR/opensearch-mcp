"""Record ids keep distinct records apart, and a re-ingest of evidence stored
before 0.6.5 says it adds a second copy.

Three parsers gave two distinct records one id, and the bulk write's `create`
then kept only the first, counted as "already in the case":
- an access log: a 1-second timestamp and no line number, user, version or
  referrer in the id;
- vol3 netscan, netstat and svcscan: a key without the object's offset, state
  or creation time, and a null read as "None";
- per-profile EZ tools (shellbags, jumplists, lnk, timeline): no source path.
Their ids now keep such records apart, and a record written with a changed id
carries `vhir.id_scheme: 2`. A run that writes such records looks once for
records of the same machine, unit, method and source stored without the
marker, and says so in its status and once on stderr.

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
    """Each test is a new process: no write context open, no per-process
    record of what was checked or noted (an earlier test's files with no time
    field included: the status adds that note too)."""
    from opensearch_mcp import paths

    for attr in ("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING"):
        if hasattr(wc, attr):
            monkeypatch.setattr(wc, attr, type(getattr(wc, attr))())
    no_time = list(paths.NO_TIME_FIELD)  # imported by name elsewhere: emptied in place
    paths.NO_TIME_FIELD.clear()
    yield
    wc.set_current(None)
    paths.NO_TIME_FIELD[:] = no_time


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


# --- SPEC-001: access log ---------------------------------------------------

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


# --- SPEC-002: vol3 netscan, netstat, svcscan --------------------------------

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


# --- SPEC-003: per-profile EZ tools ------------------------------------------

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


# --- SPEC-004/005: a re-ingest of evidence stored before 0.6.5 ----------------

NS = {"Offset": 1, "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49710,
      "ForeignAddr": "203.0.113.7", "ForeignPort": 443, "State": "CLOSED", "PID": 4,
      "Owner": "System", "Created": "2026-10-01T10:00:00+00:00"}  # fmt: skip
NS_ROWS = [NS, {**NS, "Offset": 2, "State": "ESTABLISHED"}, {**NS, "LocalPort": 50000}]


def note(index: str, atype: str) -> str:
    """SPEC-005's text: the PROPOSED wording, pending Steve (FK-065-3)."""
    return (f"{index}: records of this machine from the evidence this run read were stored "
            "before 0.6.5 under ids that 0.6.5 computes differently, so the index now holds "
            "them under both the old and the new ids. To keep one copy, an examiner deletes "
            f"{index} outside Valhuntir (as setup-opensearch.sh deletes its test index) and "
            f"then ingests every machine's {atype} evidence in this case again, because that "
            "index holds all of it")  # fmt: skip


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-c4")  # the accesslog route's run
    return path


@pytest.fixture
def bags(monkeypatch):
    def run_tool(cmd, label):  # two bags of one profile
        out = Path(cmd[cmd.index("--csv") + 1])
        (out / "20260102030405_sb.csv").write_text(
            "BagPath,Value,LastWriteTime,SourceFile\n"
            f'"BagMRU\\0","C:","2026-09-01 08:00:00","/mnt/x{cmd[2]}/UsrClass.dat"\n'
            f'"BagMRU\\1","D:","2026-09-01 08:00:00","/mnt/x{cmd[2]}/UsrClass.dat"\n'
        )
        return "", ""

    monkeypatch.setattr(tools, "_run_tool", run_tool)


def ingest_all(cluster, cases, case, host="web01", logs=("access.log", "access-b.log"),
               profile_rel="Users/alice", image="/cases/x/mem.raw", unit=None,
               parsers=("accesslog", "vol", "sb")):  # fmt: skip
    """One run of each changed parser over the same evidence, in one unit:
    {type: index}, and the accesslog run's status note."""
    case_dir, ctx = open_run(cases, case, unit or f"evidence/{host}", host, "evidence folder")
    out, said = {}, {}
    if "accesslog" in parsers:
        for name in logs:
            f = case_dir / name
            f.write_text("\n".join([SAME] * 3) + "\n")
            bulk.reset_circuit_breaker()
            s = step()
            with wc.op(s):
                ingest_accesslog(f, cluster.client(), wc.index_name("accesslog"), host,
                                 source_file=f"evidence/{name}", ingest_audit_id=s)  # fmt: skip
        out["accesslog"] = wc.index_name("accesslog")
        said["accesslog"] = bg_status(ctx, host)
    if "vol" in parsers:
        s = step()
        with wc.op(s):
            pm._index_vol3_records([dict(r) for r in NS_ROWS], cluster.client(),
                                   wc.index_name("vol-netscan"), "windows.netscan", host, image,
                                   s, "v")  # fmt: skip
        out["vol-netscan"] = wc.index_name("vol-netscan")
        said["vol-netscan"] = wc.second_copy_note(host, "vol-netscan")
    if "sb" in parsers:
        p = case_dir / "vol" / profile_rel
        p.mkdir(parents=True, exist_ok=True)
        s = step()
        with wc.op(s):
            tools.run_and_ingest("shellbags", p, cluster.client(), case, host,
                                 source_file=profile_rel, ingest_audit_id=s)  # fmt: skip
        out["shellbags"] = wc.index_name("shellbags")
        said["shellbags"] = scan_note(ctx, host, out["shellbags"])
    return out, said


def bg_status(ctx, host):
    """The accesslog route's terminal status note (_write_bg_status)."""
    ingest_cli._write_bg_status(ctx.case_dir.name, "run-c4", "complete", host, "accesslog",
                                "2026-10-11T00:00:00+00:00", indexed=1)  # fmt: skip
    files = sorted(ingest_status._STATUS_DIR.glob("*run-c4*.json"))
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


def stored_before_065(cluster):
    """What a 0.6.4 ingest left of this evidence: records with no id-scheme
    marker, under ids 0.6.5 doesn't compute (one per log, two netscan rows,
    both bags). Made from this run's records, then the run is forgotten."""
    kept, seen_logs = {}, set()
    for (index, _id), src in sorted(cluster.store.items()):
        src = {k: v for k, v in src.items() if k != "vhir.id_scheme"}
        if "accesslog" in index:
            if src["vhir.source_file"] in seen_logs:
                continue
            seen_logs.add(src["vhir.source_file"])
        if "netscan" in index and sum("netscan" in i for i, _ in kept) == 2:
            continue
        kept[(index, f"old-{_id}")] = src
    cluster.store.clear()
    cluster.store.update(kept)
    return set(kept)


def test_a_re_ingest_of_evidence_stored_before_065_says_it_adds_a_second_copy(
    cluster, cases, status_dir, bags, monkeypatch
):
    ingest_all(cluster, cases, "c4")
    old = stored_before_065(cluster)
    new_run("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):  # the image now read from an archive's temp copy
        out, said = ingest_all(cluster, cases, "c4", image="/home/x/tmp/vhir-mem-r2/mem.raw")
    assert old <= set(cluster.store)
    new = {t: sum(1 for (i, d) in cluster.store if i == index and (i, d) not in old)
           for t, index in out.items()}  # fmt: skip
    assert new == {"accesslog": 6, "vol-netscan": 3, "shellbags": 2}
    assert said == {t: note(index, t) for t, index in out.items()}
    lines = [ln for ln in err.getvalue().splitlines() if "0.6.5" in ln]
    assert sorted(lines) == sorted(f"WARNING: {note(i, t)}" for t, i in out.items())


@pytest.mark.parametrize(
    "kw,seeded",
    [
        ({}, False),
        ({"host": "web02"}, True),
        ({"logs": ("other.log",), "profile_rel": "Users/bob", "parsers": ("accesslog", "sb")},
         True),
        ({"unit": "evidence/web01-volD"}, True),
    ],
    ids=["fresh-case", "another-machine", "another-file-and-profile", "another-unit"],
)  # fmt: skip
def test_no_note_unless_this_machine_unit_and_source_were_stored_before_065(
    cluster, cases, status_dir, bags, kw, seeded
):
    if seeded:
        ingest_all(cluster, cases, "c4")
        stored_before_065(cluster)
        new_run("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        _, said = ingest_all(cluster, cases, "c4" if seeded else "c4-fresh", **kw)
    assert not any(said.values()) and "0.6.5" not in err.getvalue()


def test_an_unchanged_re_ingest_by_a_new_process_adds_nothing_and_says_nothing(
    cluster, cases, status_dir, bags
):
    ingest_all(cluster, cases, "c4-n4")
    before = len(cluster.store)
    new_run("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        _, said = ingest_all(cluster, cases, "c4-n4")
    assert len(cluster.store) == before
    assert not any(said.values()) and "0.6.5" not in err.getvalue()


def test_no_note_when_the_re_ingest_stored_nothing_because_the_write_was_refused(
    cluster, cases, status_dir, bags
):
    """Old records exist, but the bulk write refuses every new one: nothing
    holds both ids, so nothing is said."""
    ingest_all(cluster, cases, "c4r", parsers=("accesslog",))
    stored_before_065(cluster)
    before = dict(cluster.store)
    new_run("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING")
    cluster.reject = True
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        _, said = ingest_all(cluster, cases, "c4r", parsers=("accesslog",))
    assert cluster.store == before
    assert not any(said.values()) and "0.6.5" not in err.getvalue()


def test_no_note_when_a_row_keeps_its_id_and_is_already_present(cluster, cases, status_dir):
    """A netscan row with no Offset keeps its content-hash id, which a
    pre-0.6.5 run stored without the marker: the re-ingest is a 409 and
    stores nothing new, so nothing holds two ids."""
    no_offset = {k: v for k, v in NS.items() if k != "Offset"}
    open_run(cases, "c4f", "evidence/web01", "web01", "evidence folder")
    index = wc.index_name("vol-netscan")

    def run():
        s = step()
        with wc.op(s):
            pm._index_vol3_records([dict(no_offset)], cluster.client(), index,
                                   "windows.netscan", "web01", "/x/mem.raw", s, "v")  # fmt: skip
        return bulk.get_already_present()

    run()
    for key in list(cluster.store):  # as 0.6.4 stored it: the same id, no marker
        cluster.store[key].pop("vhir.id_scheme", None)
    new_run("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING")
    bulk.reset_circuit_breaker()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        present = run()
    assert (len(cluster.store), present) == (1, 1)
    assert wc.second_copy_note("web01", "vol-netscan") == ""
    assert "0.6.5" not in err.getvalue()


def test_the_memory_plugin_status_entry_carries_the_note(
    cluster, cases, status_dir, tmp_path, monkeypatch
):
    """Through cmd_ingest_memory: vol3 stubbed, the cluster the stand-in."""
    image = cases / "c4m" / "evidence" / "mem.raw"
    make_case(cases, "c4m")
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\0" * 64)
    monkeypatch.setattr(pm, "_find_vol3", lambda: "true")
    monkeypatch.setattr(pm, "run_vol3_plugin", lambda *a, **k: [dict(r) for r in NS_ROWS])
    monkeypatch.setattr(ingest_cli, "get_client", cluster.client)
    for name in ("_preflight_shard_capacity", "_ensure_case_active"):
        monkeypatch.setattr(ingest_cli, name, mock.MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "c4m")
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    (tmp_path / "audit").mkdir()
    args = argparse.Namespace(path=str(image), case="c4m", hostname="HOST-M", tier=1,
                              plugins="windows.netscan", yes=True, timeout=10)  # fmt: skip

    def run(run_id):
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", run_id)
        with contextlib.redirect_stderr(io.StringIO()):
            ingest_cli.cmd_ingest_memory(args)
        wc.set_current(None)
        (status,) = [json.loads(f.read_text()) for f in status_dir.glob(f"*{run_id}*.json")]
        (entry,) = status["hosts"][0]["artifacts"]
        return entry

    run("mem-run-1")
    index = next(i for i, _ in cluster.store)
    cluster.store = {(i, f"old-{d}"): {k: v for k, v in s.items() if k != "vhir.id_scheme"}
                     for (i, d), s in cluster.store.items()}  # fmt: skip
    new_run("OLD_IDS", "_OLD_IDS_CHECKED", "_OLD_IDS_PENDING")
    assert run("mem-run-2").get("note", "") == note(index, "vol-netscan")


def test_the_note_names_the_index_and_gives_no_command():
    """SPEC-005: the text, verbatim. PROPOSED, pending Steve (FK-065-3)."""
    assert wc.OLD_IDS_NOTE.format(index="case-x-accesslog", atype="accesslog") == note(
        "case-x-accesslog", "accesslog"
    )
    assert "curl" not in wc.OLD_IDS_NOTE and "DELETE" not in wc.OLD_IDS_NOTE
