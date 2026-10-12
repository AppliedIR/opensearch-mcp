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

The parsers, the write stamp and the bulk path are real; the cluster is an
in-memory stand-in (record_ids_cluster), and the EZ tools and vol3 are
stubbed at their call boundary. Every run has its own audit id.
"""

from __future__ import annotations

import itertools
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from record_ids_cluster import Cluster, make_case

from opensearch_mcp import bulk, tools
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
    """Each test is a new process: no write context open (an earlier test's
    files with no time field included: the status adds that note too)."""
    from opensearch_mcp import paths

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
