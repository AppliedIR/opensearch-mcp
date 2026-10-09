"""The names scan records every evidence unit and the host names it gives,
before anything is written, and never mounts, extracts or calls sudo. Hives
and event logs are stand-ins that answer what the readers ask; names and
values are synthetic."""

from __future__ import annotations

import argparse
import json
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sift_common import host_identity

from opensearch_mcp import containers, ingest_cli, names_scan
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import discover


class _Hive:
    """A hive file holding JSON: {key path: {value name: data}}."""

    def __init__(self, path):
        self.keys = json.loads(Path(path).read_text())

    def get_key(self, path):
        values = self.keys[path]
        return SimpleNamespace(
            iter_values=lambda: [SimpleNamespace(name=k, value=v) for k, v in values.items()]
        )


@pytest.fixture(autouse=True)
def hives(monkeypatch):
    import regipy.registry

    monkeypatch.setattr(regipy.registry, "RegistryHive", _Hive)


def windows_volume(root: Path, computer: str, hostname: str = "", domain: str = "", guid=""):
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True, exist_ok=True)
    keys = {"\\ControlSet001\\Control\\ComputerName\\ComputerName": {"ComputerName": computer}}
    tcpip = {}
    if hostname:
        tcpip["Hostname"] = hostname
    if domain:
        tcpip["Domain"] = domain
    keys["\\ControlSet001\\Services\\Tcpip\\Parameters"] = tcpip
    (config / "SYSTEM").write_text(json.dumps(keys))
    if guid:
        soft = {"\\Microsoft\\Cryptography": {"MachineGuid": guid}}
        (config / "SOFTWARE").write_text(json.dumps(soft))
    return root


def case():
    return wc.case_dir_for(f"scan-{uuid.uuid4().hex[:8]}")


# -- folders


def test_a_folder_and_its_event_logs_give_one_unit_with_both_names(
    tmp_path, monkeypatch, mock_evtx_record
):
    import evtx

    root = windows_volume(tmp_path / "WKS01", "WKS01")
    logs = root / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"x")
    records = [mock_evtx_record(computer="wks01.corp.example.test", record_id=n) for n in range(3)]

    class Parser:
        def __init__(self, path):
            pass

        def records_json(self):
            return iter(records)

    monkeypatch.setattr(evtx, "PyEvtxParser", Parser)
    (root / "Users").mkdir()
    (root / "Users" / "logons.csv").write_text("Computer,Event\nWKS01-OLD,4624\n")
    (host,) = discover(root)
    unit = names_scan.host_folder_unit(host, None)
    names = {(n.raw, n.evidence, n.origin) for n in unit.names}
    assert any(n[0] == "WKS01-OLD" and n[1].endswith("logons.csv host column") for n in names)
    assert ("wks01.corp.example.test", "Security.evtx Computer", "artifact") in names
    assert ("WKS01", "SYSTEM ComputerName", "artifact") in names


def test_tcpip_names_and_domain_are_read_beside_the_computer_name(tmp_path):
    guid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
    root = windows_volume(
        tmp_path / "mail",
        "CORPORATE-MAIL-",
        "corporate-mail-server",
        "corp.example.test",
        guid=guid,
    )
    names, attrs = names_scan.registry_names(root)
    assert ("CORPORATE-MAIL-", "SYSTEM ComputerName") in names
    assert ("corporate-mail-server.corp.example.test", "SYSTEM Tcpip Hostname+Domain") in names
    assert attrs == {"machine_guid": guid}


def test_every_host_folder_is_scanned_with_no_cap(tmp_path):
    for n in range(12):
        windows_volume(tmp_path / f"WKS{n:02d}", f"WKS{n:02d}")
    hosts = discover(tmp_path)
    units = [names_scan.host_folder_unit(h, None) for h in hosts]
    seen = {n.raw for u in units for n in u.names if n.evidence == "SYSTEM ComputerName"}
    assert seen == {f"WKS{n:02d}" for n in range(12)}


def test_host_columns_in_a_folders_files_are_names_and_an_ai_file_is_marked(tmp_path):
    d = case()
    folder = d / "evidence" / "kape"
    folder.mkdir(parents=True)
    (folder / "rows.csv").write_text("Computer,Event\nSRV03,1\nSRV04,2\n")
    ai = d / "extractions"
    ai.mkdir()
    (ai / "made.json").write_text(json.dumps({"Hostname": "DC01"}) + "\n")
    unit = names_scan.files_unit(folder, "", [folder / "rows.csv", ai / "made.json"], d)
    origins = {n.raw: n.origin for n in unit.names}
    assert origins == {"SRV03": "artifact", "SRV04": "artifact", "DC01": "ai"}


def test_a_name_given_as_an_argument_or_in_a_file_name_keeps_that_origin(tmp_path):
    d = case()
    f = d / "evidence" / "EvtxECmd-HOST7.csv"
    f.parent.mkdir(parents=True)
    f.write_text("a,b\n1,2\n")
    unit = names_scan.files_unit(f, "HOST7-ARG", [f], d)
    assert {(n.raw, n.origin) for n in unit.names} == {
        ("HOST7-ARG", "argument"), ("HOST7", "file-name")}  # fmt: skip


# -- containers


def test_a_velociraptor_collection_is_one_unit_with_its_clients_names(tmp_path):
    coll = tmp_path / "x"
    coll.mkdir()
    client = {"client_id": "C.1a2b3c4d5e6f7a8b", "hostname": "WKS07",
              "fqdn": "wks07.corp.example.test"}  # fmt: skip
    (coll / "collection_context.json").write_text(json.dumps({"client_info": client}))
    unit = names_scan.velociraptor_unit(coll, tmp_path / "collection.zip", None)
    assert {n.raw for n in unit.names} == {"WKS07", "wks07.corp.example.test"}
    assert unit.attrs == {"client_id": "C.1a2b3c4d5e6f7a8b"}


def _scan_stub(monkeypatch, extract, seen, velociraptor=False, mount=None):
    class Stop(Exception):
        pass

    def scan(case_id, input_path, hosts, image_notes, extra=(), archive=None):
        seen.update(hosts=hosts, notes=image_notes, extra=list(extra), archive=archive)
        raise Stop

    work = Path(seen["work"])
    monkeypatch.setattr(containers, "detect_container", lambda p: "archive")
    monkeypatch.setattr(containers, "cleanup_orphaned_mounts", lambda: None)
    monkeypatch.setattr(containers, "extract_container", extract)
    monkeypatch.setattr(containers, "is_velociraptor_collection", lambda p: velociraptor)
    monkeypatch.setattr(containers, "make_ingest_tmpdir", lambda case_id: work)
    monkeypatch.setattr(containers, "cleanup_tmpdir", lambda *a, **k: None)
    if mount:
        monkeypatch.setattr(containers, "mount_image", mount)
    monkeypatch.setattr(ingest_cli, "_record_scan", scan)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "scan-c1")
    monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda c: None)
    return Stop


def test_a_velociraptor_collections_host_is_the_collections_unit(tmp_path, monkeypatch):
    seen = {"work": tmp_path / "work"}
    (tmp_path / "work").mkdir()

    def extract(path, dest, password=None):
        client = {"client_id": "C.1a2b3c4d5e6f7a8b", "hostname": "WKS07"}
        (dest / "collection_context.json").write_text(json.dumps({"client_info": client}))
        windows_volume(dest / "uploads" / "auto" / "C:", "WKS07")

    stop = _scan_stub(monkeypatch, extract, seen, velociraptor=True)
    archive = tmp_path / "evidence" / "collection.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK")
    with pytest.raises(stop):
        ingest_cli.cmd_scan(
            argparse.Namespace(path=str(archive), case=None, yes=True, hostname=None)
        )
    (velo,) = seen["extra"]
    assert velo.attrs["client_id"] == "C.1a2b3c4d5e6f7a8b"
    assert {h.unit_locator for h in seen["hosts"]} == {velo.locator}


def test_an_archive_of_two_disk_images_ingests_both_each_as_its_own_unit(tmp_path, monkeypatch):
    seen = {"work": tmp_path / "work"}
    (tmp_path / "work").mkdir()

    def extract(path, dest, password=None):
        for name in ("a.raw", "b.E01"):
            (dest / name).write_bytes(b"\0")

    _scan_stub(monkeypatch, extract, seen)
    runs = []

    def each(command, args, archive, images, examiner):
        runs.extend((archive, i.name) for i in images)

    monkeypatch.setattr(ingest_cli, "_ingest_each_extracted", each)
    archive = tmp_path / "evidence" / "two.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK")
    ingest_cli.cmd_scan(argparse.Namespace(path=str(archive), case=None, yes=True, hostname=None))
    assert sorted(n for _, n in runs) == ["a.raw", "b.E01"]


def test_each_extracted_image_runs_with_its_archive_and_name(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-9")
    calls = []

    def command(sub, examiner=""):
        calls.append((sub.path, sub.from_archive, sub.archive_member,
                      __import__("os").environ["VHIR_INGEST_RUN_ID"]))  # fmt: skip
        if sub.archive_member == "a.raw":
            raise RuntimeError("bad image")  # one image failing doesn't stop the next

    archive = tmp_path / "two.zip"
    images = [tmp_path / "b.E01", tmp_path / "a.raw"]
    args = argparse.Namespace(path=str(archive))
    with pytest.raises(SystemExit):  # the run fails when an image did
        ingest_cli._ingest_each_extracted(command, args, archive, images, "")
    assert calls == [
        (str(tmp_path / "a.raw"), str(archive), "a.raw", "run-9-1"),
        (str(tmp_path / "b.E01"), str(archive), "b.E01", "run-9-2"),
    ]


def test_an_image_volume_no_reader_covers_is_an_unnamed_candidate(tmp_path):
    d = case()
    image = d / "evidence" / "dual.raw"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\0")
    host = DiscoveredHost(hostname="WKS20", volume_root=windows_volume(tmp_path / "v1", "WKS20"))
    host.unit_locator = host_identity.unit_locator(image, d, offset=1048576)
    summary = ingest_cli._record_scan(d.name, image, [host], [(2097152, "p2: locked volume")])
    by_unit = {u["locator"]: u for u in summary}
    assert by_unit[host.unit_locator]["names"] == ["WKS20"]
    candidate = by_unit[host_identity.unit_locator(image, d, offset=2097152)]
    assert candidate["names"] == [] and candidate["note"] == "p2: locked volume"
    units = host_identity.load(d).units
    assert units[host_identity.unit_key(candidate["locator"])]["note"] == "p2: locked volume"


def test_a_memory_image_records_its_file_archive_and_given_names(tmp_path):
    d = case()
    unit = names_scan.memory_unit(tmp_path / "x" / "dc01-mem.raw", d / "evidence" / "mem.zip",
                                  "dc01-mem.raw", "DC01", d)  # fmt: skip
    assert {(n.raw, n.origin) for n in unit.names} == {
        ("DC01", "argument"), ("dc01-mem", "file-name"), ("mem", "file-name")}  # fmt: skip
    assert unit.locator == "evidence/mem.zip!dc01-mem.raw"


# -- recording, and what the scan never does


def test_the_scan_is_recorded_before_any_write_with_its_details(tmp_path):
    d = case()
    root = windows_volume(
        d / "evidence" / "WKS30", "WKS30", guid="aaaabbbb-cccc-dddd-eeee-ffff00001111"
    )
    (host,) = discover(root)
    names_scan.record(d, [names_scan.host_folder_unit(host, d)])
    state = host_identity.load(d)
    (unit,) = state.units.values()
    assert unit["machine_guid"] == "aaaabbbb-cccc-dddd-eeee-ffff00001111"
    assert {p[1] for p in state.names} == {"WKS30"}
    assert not state.machines  # recorded only: nothing is bound yet


def test_the_scan_never_mounts_extracts_or_calls_sudo(tmp_path, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError(f"the scan called {a[:1]}")

    for name in ("mount_image", "mount_vss", "extract_container"):
        monkeypatch.setattr(containers, name, refuse)
    real_run = subprocess.run

    def run(cmd, *a, **k):
        if any(word in str(cmd) for word in ("sudo", "mount", "7z")):
            refuse(cmd)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", run)
    d = case()
    root = windows_volume(d / "evidence" / "WKS40", "WKS40")
    (host,) = discover(root)
    units = [names_scan.host_folder_unit(host, d),
             names_scan.memory_unit(d / "m.raw", d / "m.raw", "", "M", d),
             names_scan.files_unit(root, "", [], d)]  # fmt: skip
    assert names_scan.record(d, units)


# -- dry runs say what the scan found


@pytest.fixture
def dry(monkeypatch):
    from opensearch_mcp import server as srv

    d = case()
    monkeypatch.setattr(srv, "_get_active_case", lambda: d.name)
    (Path.home() / ".vhir").mkdir(parents=True, exist_ok=True)
    (Path.home() / ".vhir" / "active_case").write_text(str(d))
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    monkeypatch.setattr(srv, "_get_os", lambda: SimpleNamespace(count=lambda **k: {"count": 0}))
    yield srv, d
    (Path.home() / ".vhir" / "active_case").unlink()


def test_a_folder_dry_run_returns_and_records_the_scan(dry):
    srv, d = dry
    root = windows_volume(d / "evidence" / "WKS50", "WKS50")
    resp = srv.idx_ingest(path=str(root), dry_run=True)
    (unit,) = resp["scan"]
    assert unit["names"] == ["WKS50"] and unit["locator"] == "evidence/WKS50"
    assert host_identity.load(d).units  # recorded before any ingest


def test_a_disk_image_dry_run_lists_its_volumes_not_a_name_from_the_file(dry, monkeypatch):
    from opensearch_mcp import parse_plaso

    srv, d = dry
    image = d / "evidence" / "2018-09-03T144144_win7-EricWorkstation.vhd"
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"\0" * 1024)
    leaves = [
        {"selector": {"partitions": "p1"}, "offset": 1048576, "fs": "NTFS", "os": "windows"},
        {"selector": {"partitions": "p2"}, "offset": 9437184, "fs": "NTFS"},
    ]
    monkeypatch.setattr(parse_plaso, "volume_inventory", lambda image: (leaves, ""))
    resp = srv.idx_ingest(path=str(image), dry_run=True)
    assert "suggested_hostname" not in resp
    vols = resp["scan"]["volumes"]
    assert [(v["volume"], v["names"]) for v in vols] == [("p1", []), ("p2", [])]
    assert vols[1]["note"] == "no operating system found on this volume"


def test_a_memory_dry_run_returns_the_scan(dry):
    srv, d = dry
    image = d / "evidence" / "dc01.raw"
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"\0")
    (unit,) = srv.idx_ingest_memory(path=str(image), hostname="DC01", dry_run=True)["scan"]
    assert unit["names"] == ["DC01", "dc01"]


def test_a_partition_that_did_not_mount_is_an_unnamed_candidate(tmp_path, monkeypatch):
    seen = {"work": tmp_path / "work"}
    (tmp_path / "work").mkdir()

    def mount(img, dest, ctx):
        ctx.failures.append("partition type 'x' at offset 2097152 did not mount: bad superblock")
        ctx.failed_offsets[2097152] = ctx.failures[-1]
        return [windows_volume(dest / "p1", "WKS60")]

    def extract(path, dest, password=None):
        (dest / "disk.raw").write_bytes(b"\0")

    stop = _scan_stub(monkeypatch, extract, seen, mount=mount)
    monkeypatch.setattr(ingest_cli, "_image_hosts", lambda *a, **k: ([], {}, []))
    archive = tmp_path / "evidence" / "one.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK")
    with pytest.raises(stop):
        ingest_cli.cmd_scan(
            argparse.Namespace(path=str(archive), case=None, yes=True, hostname=None)
        )
    assert seen["notes"] == [(2097152, "partition type 'x' at offset 2097152 did not mount: "
                                       "bad superblock")]  # fmt: skip
    assert seen["archive"] == (archive, "disk.raw")  # named by the archive, not the run's copy


def test_a_memory_images_computer_name_variables_are_observed():
    from opensearch_mcp.parse_memory import observe_envar_names

    d = case()
    ctx = wc.open_unit(d, "evidence/m.raw", "M", source="memory image", origin="argument")
    records = [
        {"Variable": "COMPUTERNAME", "Value": "WKS70", "PID": 4},
        {"Variable": "COMPUTERNAME", "Value": "WKS70", "PID": 8},
        {"Variable": "USERDOMAIN", "Value": "CORP"},
        {"Variable": "PATH", "Value": "C:\\x"},
    ]
    with wc.writing(ctx):
        assert observe_envar_names(records) == ["WKS70", "CORP"]
    names = host_identity.load(d).names
    assert names[(ctx.unit, "WKS70")]["evidence"] == ["windows.envars COMPUTERNAME"]
    assert not host_identity.load(d).machines  # observed, not bound


def test_an_archives_disk_image_units_are_named_by_the_archive_and_the_image():
    d = case()
    archive = d / "evidence" / "two.zip"
    vol = Path("/tmp/extract/mnt/p1")
    host = DiscoveredHost(hostname="WKS80", volume_root=vol)
    ingest_cli._set_units(
        [host], d.name, Path("/tmp/extract/a.raw"), Path("/tmp/extract"), None, "",
        offsets={vol: 1048576}, archive=(archive, "a.raw"),
    )  # fmt: skip
    assert host.unit_locator == "evidence/two.zip!a.raw@1048576"


def test_a_velociraptor_collections_names_are_recorded_with_its_host(tmp_path):
    d = case()
    coll = tmp_path / "x"
    coll.mkdir()
    client = {"client_id": "C.0a0b0c0d0e0f0a0b", "fqdn": "wks90.corp.example.test"}
    (coll / "collection_context.json").write_text(json.dumps({"client_info": client}))
    velo = names_scan.velociraptor_unit(coll, d / "evidence" / "c.zip", d)
    host = DiscoveredHost(hostname="WKS90", volume_root=windows_volume(tmp_path / "C", "WKS90"))
    host.unit_locator = velo.locator
    (unit,) = ingest_cli._record_scan(d.name, d / "evidence" / "c.zip", [host], [], [velo])
    assert set(unit["names"]) >= {"WKS90", "wks90.corp.example.test"}


def test_a_memory_ingest_at_tier_2_observes_the_computer_name_variables(monkeypatch):
    from opensearch_mcp import parse_memory

    d = case()
    ctx = wc.open_unit(d, "evidence/mem2.raw", "MEM2", source="memory image", origin="argument")
    envars = [{"Variable": "COMPUTERNAME", "Value": "WKS95"}]
    monkeypatch.setattr(parse_memory, "_find_vol3", lambda: "vol")
    monkeypatch.setattr(parse_memory.subprocess, "run", lambda *a, **k: SimpleNamespace(stderr=""))
    monkeypatch.setattr(parse_memory, "run_vol3_plugin", lambda image, plugin, timeout: envars)
    monkeypatch.setattr(parse_memory, "_index_vol3_records", lambda **kw: (1, 0, 0))
    with wc.writing(ctx):
        parse_memory.ingest_memory(d / "evidence" / "mem2.raw", None, d.name, "MEM2",
                                   plugins=["windows.envars"])  # fmt: skip
    assert (ctx.unit, "WKS95") in host_identity.load(d).names


def test_a_file_the_ai_registered_as_evidence_gives_ai_names(tmp_path):
    d = case()
    f = d / "evidence" / "made.csv"
    f.parent.mkdir(parents=True)
    f.write_text("Computer,x\nDC01,1\n")
    registry = {"files": [{"path": str(f.resolve()), "registered_via": "mcp"}]}
    (d / "evidence.json").write_text(json.dumps(registry))
    unit = names_scan.files_unit(f, "", [f], d)
    assert {(n.raw, n.origin) for n in unit.names} == {("DC01", "ai")}


def test_a_file_the_ai_registered_by_a_case_relative_path_gives_ai_names(tmp_path):
    d = case()
    f = d / "evidence" / "made2.csv"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("Computer,x\nDC02,1\n")
    registry = {"files": [{"path": "evidence/made2.csv", "registered_via": "mcp"}]}
    (d / "evidence.json").write_text(json.dumps(registry))
    unit = names_scan.files_unit(f, "", [f], d)
    assert {(n.raw, n.origin) for n in unit.names} == {("DC02", "ai")}


def test_a_file_the_examiner_registered_gives_artifact_names(tmp_path):
    d = case()
    f = d / "evidence" / "kept.csv"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("Computer,x\nDC03,1\n")
    registry = {"files": [{"path": str(f.resolve()), "registered_via": "cli"}]}
    (d / "evidence.json").write_text(json.dumps(registry))
    unit = names_scan.files_unit(f, "", [f], d)
    assert {(n.raw, n.origin) for n in unit.names} == {("DC03", "artifact")}
