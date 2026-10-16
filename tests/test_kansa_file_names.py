"""Kansa names its output <host>-<Module>.csv: the host is the stem's left part,
not the module after the last `-`. Each reader of file names (the names scan,
ingest_cli's split by host, server's detector) reads the host the file is
known by, and Tool-HOST.csv / hayabusa-case-HOST.csv still give HOST. Names
are synthetic."""

from __future__ import annotations

from pathlib import Path

import pytest
from sift_common import host_gate
from sift_common import host_identity as hi

from opensearch_mcp import ingest_cli, names_scan
from opensearch_mcp.server import _detect_hostnames_from_filenames

MODULES = ["AppCompatCache", "Arp", "Autorunsc", "CertStore", "DNSCache", "HostInfo",
           "LocalAdmins", "Netstat", "ProcsWMI", "SchedTasks", "SmbSession",
           "SmbShare"]  # fmt: skip
MODULES_24 = MODULES + ["Services", "Prefetch", "Handle", "DNSServers", "FileVersions",
                        "LogUserAssist", "RdpConnections", "Products", "Tasks", "Shares",
                        "WMIEvtConsumer", "Users"]  # fmt: skip


def files(folder: Path, names) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for n in names:
        (folder / n).write_text("a,b\n1,2\n")
        out.append(folder / n)
    return out


def scan_names(folder: Path, hostname: str, fs) -> set[str]:
    return {n.raw for n in names_scan.files_unit(folder, hostname, fs, None).names}


# -- row 1: one host's Kansa files give one name, the host (probe p126's shape)


@pytest.mark.parametrize("host", ["rd01.shieldbase.com", "RD01.ShieldBase.com", "rd01"])
def test_one_hosts_kansa_files_give_the_host_only(tmp_path, host):
    fs = files(tmp_path / host, [f"{host}-{m}.csv" for m in MODULES])
    assert {names_scan.filename_host(f) for f in fs} == {host}
    assert scan_names(tmp_path / host, host, fs) == {host}


def test_kansa_files_in_an_unnamed_folder_give_the_host_from_the_hostname_argument(tmp_path):
    fs = files(tmp_path / "upload", [f"rd01.shieldbase.com-{m}.csv" for m in MODULES])
    assert scan_names(tmp_path / "upload", "rd01.shieldbase.com", fs) == {"rd01.shieldbase.com"}
    # the argument's first label is enough
    assert scan_names(tmp_path / "upload", "RD01", fs) == {"RD01", "rd01.shieldbase.com"}


# -- row 2: twins, unchanged through every reader


@pytest.mark.parametrize("pattern", ["{m}-{h}.csv", "hayabusa-case-{h}.csv"])
def test_tool_host_and_hayabusa_names_still_give_the_host(tmp_path, pattern):
    hosts = ["HOST1", "HOST2", "HOST3"]
    mods = ["EvtxECmd"] if "hayabusa" in pattern else ["EvtxECmd", "MFTECmd", "RECmd"]
    flat = tmp_path / "evidence"
    fs = files(flat, [pattern.format(m=m, h=h) for h in hosts for m in mods])
    assert {names_scan.filename_host(f) for f in fs} == set(hosts)
    assert {ingest_cli._filename_host(f, {h.lower() for h in hosts}) for f in fs} == {
        h.lower() for h in hosts}  # fmt: skip
    assert {ingest_cli._filename_host(f) for f in fs} == {h.lower() for h in hosts}
    assert _detect_hostnames_from_filenames(flat) == {h.lower() for h in hosts}
    for h in hosts:
        own = [f for f in fs if f.stem.endswith(h)]
        assert scan_names(flat, "", own) == {h}


def test_a_tool_host_file_in_its_hosts_folder_gives_the_host(tmp_path):
    fs = files(tmp_path / "rd01", ["EvtxECmd-rd01.csv", "MFTECmd-rd01.csv", "RECmd-rd01.csv"])
    assert {names_scan.filename_host(f) for f in fs} == {"rd01"}
    assert _detect_hostnames_from_filenames(tmp_path / "rd01") == {"rd01"}
    assert scan_names(tmp_path / "rd01", "rd01", fs) == {"rd01"}


def test_a_hostname_argument_that_matches_the_last_part_keeps_it(tmp_path):
    # the argument names <last>: <last> wins over a <left> also named for a host
    (f,) = files(tmp_path / "x", ["web01-db01.csv"])
    assert names_scan.filename_host(f, ("db01",)) == "db01"
    assert names_scan.filename_host(f, ("web01",)) == "web01"
    assert names_scan.filename_host(f, ("web01", "db01")) == "db01"


# -- row 3: 29 hosts x 24 modules, by host, give 29 units and no module name


def test_29_hosts_by_24_modules_give_29_units_and_no_module_name(tmp_path):
    hosts = [f"wkstn{i:02d}.shieldbase.com" for i in range(1, 30)]
    units = []
    for h in hosts:
        d = tmp_path / "kansa-by-host" / h.split(".")[0]
        units.append(names_scan.files_unit(d, h, files(d, [f"{h}-{m}.csv" for m in MODULES_24]),
                                           None))  # fmt: skip
    assert len(units) == 29
    named = {n.raw for u in units for n in u.names}
    assert named == set(hosts)
    assert not {n.lower() for n in named} & {m.lower() for m in MODULES_24}


# -- row 4: a host name with a `-` in it


@pytest.mark.parametrize("hostname", ["web-01", "", "WEB-01.corp.example"])
def test_a_hyphenated_host_in_its_folder_gives_the_host(tmp_path, hostname):
    fs = files(tmp_path / "web-01", ["web-01-Netstat.csv", "web-01-Arp.csv"])
    assert {names_scan.filename_host(f) for f in fs} == {"web-01"}
    assert {ingest_cli._filename_host(f, {"web-01"}) for f in fs} == {"web-01"}
    assert _detect_hostnames_from_filenames(tmp_path / "web-01") == {"web-01"}
    assert scan_names(tmp_path / "web-01", hostname, fs) == {"web-01"} | ({hostname} - {""})


# -- row 5: Start now on the Kansa shape makes one machine per host (probe p127's leg 2)


@pytest.mark.host_gate
def test_start_now_on_kansa_units_makes_one_machine_per_host(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    hi.ensure_host_files(case)
    hostnames = ["admin01.shieldbase.com", "rd01.shieldbase.com", "dev01.shieldbase.com"]
    mods = MODULES[:4]
    units = []
    for h in hostnames:
        d = case / "evidence" / "kansa-by-host" / h.split(".")[0]
        units.append(names_scan.files_unit(d, h, files(d, [f"{h}-{m}.csv" for m in mods]), case))
    names_scan.record(case, units)
    host_gate.record_wait(case, "run-1", [u.key for u in units])
    host_gate.start_now(case, "run-1", "ex1", seen_offset=hi.load(case).obs_offset)
    made = sorted(m.canonical for m in hi.load(case).machines.values())
    assert len(made) == 3, made
    assert not {c.split(" (")[0].split(".")[0].lower() for c in made} & {m.lower() for m in mods}


# -- row 8: Kansa's own layout, Output_<stamp>/<Module>/<host>-<Module>.csv


def test_kansas_own_output_layout_gives_host_names_through_every_reader(tmp_path):
    hosts = ["rd01", "web-01", "dc01.shieldbase.com"]
    run = tmp_path / "Output_20261016120000"
    for m in ["Netstat", "Arp", "SvcAll"]:
        fs = files(run / m, [f"{h}-{m}.csv" for h in hosts])
        assert {names_scan.filename_host(f) for f in fs} == set(hosts)
        assert {ingest_cli._filename_host(f, {h.lower() for h in hosts}) for f in fs} == {
            h.lower() for h in hosts}  # fmt: skip
        assert _detect_hostnames_from_filenames(run / m) == {h.lower() for h in hosts}
        assert scan_names(run / m, "", fs) == set(hosts)


@pytest.mark.parametrize("parent", ["kansa-all", "evidence", "Output_2026101612000x"])
def test_kansas_layout_under_any_folder_gives_dotted_hosts_through_every_reader(tmp_path, parent):
    # the case reaches the run through its own folder name (a link, a copy):
    # gate3's kansa-post-intrusion-all and kansa-rd01-dc01-dev01
    hosts = ["rd01.shieldbase.com", "dc01.shieldbase.com", "10.0.0.5"]
    for m in ["Netstat", "Arp", "SvcAll"]:
        fs = files(tmp_path / parent / m, [f"{h}-{m}.csv" for h in hosts])
        assert {names_scan.filename_host(f) for f in fs} == set(hosts)
        assert {ingest_cli._filename_host(f) for f in fs} == set(hosts)
        assert _detect_hostnames_from_filenames(tmp_path / parent / m) == set(hosts)
        assert scan_names(tmp_path / parent / m, "", fs) == set(hosts)


def test_kansas_run_reached_through_a_link_gives_the_hosts(tmp_path):
    run = tmp_path / "srv" / "Output_20230129122316"
    hosts = [f"wkstn{i:02d}.shieldbase.com" for i in range(1, 30)]
    fs = files(run / "Arp", [f"{h}-Arp.csv" for h in hosts])
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "kansa-post-intrusion-all").symlink_to(run)
    linked = [tmp_path / "evidence" / "kansa-post-intrusion-all" / "Arp" / f.name for f in fs]
    for got in (fs, linked):
        assert {names_scan.filename_host(f) for f in got} == set(hosts)
        assert scan_names(got[0].parent, "", got) == set(hosts)
    # 29 hosts in one folder: each under the detector's 30% share, so none (base: "arp")
    assert _detect_hostnames_from_filenames(linked[0].parent) == set()


def test_short_host_names_in_a_module_folder_not_under_a_kansa_run_give_the_module(tmp_path):
    # kept as before, host list or not: no Kansa output seen has this shape
    # (its left parts are DNS names); the runbook line covers it
    fs = files(tmp_path / "kansa-all" / "Arp", ["rd01-Arp.csv", "web-01-Arp.csv"])
    assert {names_scan.filename_host(f) for f in fs} == {"Arp"}
    assert {ingest_cli._filename_host(f, {"rd01", "web-01"}) for f in fs} == {"arp"}


@pytest.mark.parametrize("name, known, want", [
    ("EvtxECmd-rd01.csv", (), "rd01"),                 # twin: a host folder of Tool-HOST files
    ("EvtxECmd-rd01.csv", ("rd01",), "rd01"),
    ("EvtxECmd-rd01.csv", ("EvtxECmd", "rd01"), "rd01"),  # both known: the folder's name wins
    ("EvtxECmd-rd01.csv", ("EvtxECmd",), "rd01"),      # a host list naming the left part only
    (".-rd01.csv", (), "rd01"),                        # dots alone are no name
    ("..-rd01.csv", (), "rd01"),
    ("rd01.-rd01.csv", (), "rd01"),                    # an end dot alone isn't a dotted name
])  # fmt: skip
def test_a_host_folder_of_tool_host_files_keeps_the_host(tmp_path, name, known, want):
    (f,) = files(tmp_path / "rd01", [name])
    assert names_scan.filename_host(f, known) == want


@pytest.mark.parametrize("parent", [
    "Output_2026101612000", "Output_202610161200000", "Output_2026101612000x",
    "output-20261016120000", "rd01"])  # fmt: skip
def test_a_folder_not_named_like_a_kansa_run_keeps_the_tool_host_reading(tmp_path, parent):
    # Tool-HOST.csv in a folder named for the host, under any other parent
    fs = files(tmp_path / parent / "rd01", ["EvtxECmd-rd01.csv", "MFTECmd-rd01.csv"])
    assert {names_scan.filename_host(f) for f in fs} == {"rd01"}


def test_under_a_kansa_run_a_file_not_named_for_its_folder_reads_as_ever(tmp_path):
    (f,) = files(tmp_path / "Output_20261016120000" / "Netstat", ["EvtxECmd-rd01.csv"])
    assert names_scan.filename_host(f) == "rd01"


# -- row 9: the by-host copy


def test_the_by_host_copy_gives_host_names_through_every_reader(tmp_path):
    for h in ["rd01", "web-01", "dc01.shieldbase.com"]:
        d = tmp_path / "kansa-by-host" / h
        fs = files(d, [f"{h}-{m}.csv" for m in MODULES])
        assert {names_scan.filename_host(f) for f in fs} == {h}
        assert {ingest_cli._filename_host(f, {h.lower()}) for f in fs} == {h.lower()}
        assert _detect_hostnames_from_filenames(d) == {h.lower()}
        assert scan_names(d, h, fs) == {h}


# -- row 10: a date after the host is never a host name


def test_a_date_after_the_host_is_not_a_host_name(tmp_path):
    (evtx,) = files(tmp_path / "rd01", ["rd01-20261016.evtx"])
    assert names_scan.filename_host(evtx) == "rd01"  # base: "20261016"
    (csv,) = files(tmp_path / "logs", ["rd01-20261016.csv"])
    assert names_scan.filename_host(csv) == "rd01"  # no folder context: digits are never a host
    assert ingest_cli._filename_host(csv) == "rd01"
    assert _detect_hostnames_from_filenames(tmp_path / "logs") == {"rd01"}
    # the detector reads .csv/.tsv only: an event log alone gives it nothing, before and after
    assert _detect_hostnames_from_filenames(tmp_path / "rd01") == set()


# -- ingest_cli's split by host, with the hosts the run splits by


def test_ingest_clis_split_puts_each_kansa_file_with_its_host(tmp_path):
    hosts = {"rd01", "web-01"}
    fs = files(tmp_path / "upload", [f"{h}-{m}.csv" for h in hosts for m in MODULES[:3]])
    for h in hosts:
        own = [f for f in fs if ingest_cli._filename_host(f, hosts) == h]
        assert sorted(f.name for f in own) == sorted(f"{h}-{m}.csv" for m in MODULES[:3])
    # the hosts not given: the module is read, as before (the runbook's host-list upload)
    assert {ingest_cli._filename_host(f) for f in fs} == {m.lower() for m in MODULES[:3]}


# -- seed shapes


@pytest.mark.parametrize("name, known, want", [
    ("noseparator.csv", (), ""),
    ("rd01-a.csv", (), ""),                        # one-letter last part: none, as before
    ("-Netstat.csv", ("rd01",), "Netstat"),        # empty left part
    ("rd01-Netstat.csv", ("",), "Netstat"),        # an empty hostname is no host
    ("rd01-Netstat.csv", (None,), "Netstat"),
    ("rd01-Netstat.csv", ("  RD01  ",), "rd01"),   # spaces around the argument
    ("RD01-Netstat.csv", ("rd01.example",), "RD01"),
    ("rd01.example-Netstat.csv", ("rd01",), "rd01.example"),
    ("rd01-Netstat.CSV", ("rd01",), "rd01"),
    ("a-b-c-Netstat.csv", ("a-b-c",), "a-b-c"),
    ("rd01-2026.csv", (), "rd01"),
    ("rd01-0.csv", (), ""),
    ("rd01-12.csv", (), "rd01"),
])  # fmt: skip
def test_seed_shapes(tmp_path, name, known, want):
    (f,) = files(tmp_path / "x", [name])
    assert names_scan.filename_host(f, known) == want
