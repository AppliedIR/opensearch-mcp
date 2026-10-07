"""Linux and macOS volumes are read by Plaso straight off the disk image.

A helper (run under Plaso's own interpreter, which has dfVFS) lists the
image's volumes. Each Linux or macOS file system gets its own Plaso run with
--partitions/--volumes: no mount and no root, so LVM, APFS and .dmg images
are read too, and Plaso applies each volume's own time zone. Windows volumes
stay with the mounts. A mounted Linux root is left to the image run that
covered its offset; any other is parsed from its mount. Volumes nothing
parses are named in the status.

Most rows use recorded helper output. Rows on real images run when
VHIR_TEST_IMAGES lists folders holding them (os.pathsep-separated) and Plaso
is installed; otherwise they skip.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from opensearch_mcp import ingest_cli, parse_plaso
from opensearch_mcp.containers import detect_container
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.parse_plaso import _ingest_jsonl, plan_image_runs, plaso_status

DUAL = [  # Windows on p1; Linux in an LVM volume on p2; an empty second volume
    {"selector": {"partitions": "p1"}, "offset": 1048576, "kind": "filesystem", "fs": "EXT",
     "os": "windows"},
    {"selector": {"partitions": "p2", "volumes": "lvm1"}, "offset": 3145728,
     "kind": "filesystem", "fs": "EXT", "os": "linux", "localtime": "link",
     "zone": "America/New_York"},
    {"selector": {"partitions": "p2", "volumes": "lvm2"}, "offset": 3145728,
     "kind": "no_filesystem", "type": "LVM"},
]  # fmt: skip


def _gpt12():
    leaves = [
        {"selector": {"partitions": f"p{n}"}, "offset": n * 1048576, "kind": "no_filesystem",
         "type": "GPT"}
        for n in range(3, 12)
    ]  # fmt: skip
    for n in (1, 2, 12):
        leaves.append(
            {"selector": {"partitions": f"p{n}"}, "offset": n * 1048576, "kind": "filesystem",
             "fs": "EXT", "os": "linux"}
        )  # fmt: skip
    return leaves


# Planning the runs


def test_a_linux_volume_in_lvm_is_one_run_and_the_empty_volume_is_reported():
    runs, notes = plan_image_runs(DUAL)
    assert runs == [
        {
            "label": "p2:lvm1",
            "args": ["--partitions", "2", "--volumes", "1", "--vss_stores", "none"],
            "os": "linux",
            "offset": 3145728,
            "zone": "America/New_York",
            "localtime": "link",
        }
    ]
    assert notes == [(3145728, "p2/lvm2 at offset 3145728: no file system found; not parsed")]


def test_a_selector_of_10_or_more_is_reported_not_run():
    """Plaso reads --partitions 12 as 1 and 2: it parsed the wrong ones."""
    runs, notes = plan_image_runs(_gpt12())
    assert [r["label"] for r in runs] == ["p1", "p2"]
    assert all("12" not in r["args"] for r in runs)
    assert (
        12 * 1048576,
        f"p12 at offset {12 * 1048576}: Plaso can't select partitions numbered 10 or higher; "
        "not parsed",
    ) in notes


def test_a_windows_volume_is_left_to_the_mounts():
    runs, notes = plan_image_runs([{**DUAL[0], "selector": {}, "offset": 0}])
    assert runs == [] and notes == []


def test_an_apfs_container_is_one_run_over_all_its_volumes():
    leaves = [
        {"selector": {"partitions": "p1", "volumes": f"apfs{n}"}, "offset": 20480,
         "kind": "filesystem", "fs": "APFS", **({"os": "macos"} if n == 1 else {})}
        for n in (1, 2)
    ]  # fmt: skip
    runs, notes = plan_image_runs(leaves)
    assert [(r["label"], r["args"], r["os"]) for r in runs] == [
        ("p1:apfs", ["--partitions", "1", "--volumes", "all", "--vss_stores", "none"], "macos")
    ]
    assert notes == []


def test_a_container_with_a_locked_volume_is_reported_not_run():
    leaves = [
        {"selector": {"partitions": "p1", "volumes": "apfs1"}, "offset": 20480,
         "kind": "filesystem", "fs": "APFS", "os": "macos"},
        {"selector": {"partitions": "p1", "volumes": "apfs2"}, "offset": 20480,
         "kind": "locked", "type": "APFS_CONTAINER"},
    ]  # fmt: skip
    runs, notes = plan_image_runs(leaves)
    assert runs == []
    assert notes == [
        (20480, "APFS container p1 at offset 20480: a volume is locked (encrypted); not parsed")
    ]


@pytest.mark.parametrize(
    "leaf, note",
    [
        ({"selector": {}, "offset": 0, "kind": "locked", "type": "LUKSDE"},
         "image at offset 0: locked (encrypted); not parsed"),
        ({"selector": {"volumes": "lvm1"}, "offset": 0, "kind": "filesystem", "fs": "XFS"},
         "lvm1 at offset 0: XFS with no OS root; not parsed from the image"),
    ],
    ids=["locked", "no OS root"],
)  # fmt: skip
def test_volumes_no_run_covers_are_named(leaf, note):
    assert plan_image_runs([leaf]) == ([], [(0, note)])


# Hosts, names and zones


@pytest.fixture
def inventory(monkeypatch):
    def set_leaves(leaves, error=""):
        monkeypatch.setattr(parse_plaso, "volume_inventory", lambda image: (leaves, error))

    return set_leaves


def test_an_image_host_is_named_for_the_image_never_the_registry(inventory, tmp_path):
    inventory(DUAL)
    image = tmp_path / "dual.raw"
    hosts, covered, notes = ingest_cli._image_hosts(image, "dual-0a1b2c3d", None)
    (host,) = hosts
    assert (host.hostname, host.os, host.volume_label) == (
        "dual-0a1b2c3d-p2-lvm1",
        "linux",
        "p2:lvm1",
    )
    assert host.image_path == image and host.artifacts == [("plaso", image)]
    assert host.image_args == ["--partitions", "2", "--volumes", "1", "--vss_stores", "none"]
    assert host.zone_note == (
        "time zone America/New_York (the volume's etc/localtime, as Plaso read it)"
    )
    assert covered == {3145728: "dual-0a1b2c3d-p2-lvm1"}
    assert len(notes) == 1


def test_the_examiners_hostname_names_an_image_host(inventory, tmp_path):
    inventory(DUAL)
    (host,), _, _ = ingest_cli._image_hosts(tmp_path / "d.raw", "d-0a1b2c3d", "LNX01")
    assert host.hostname == "LNX01"


@pytest.mark.parametrize(
    "extra, note",
    [
        ({"localtime": "file"}, "etc/localtime is not a link: Plaso may have used UTC or a "
                                "fixed-offset abbreviation"),
        ({}, "time zone unknown: local-time events stored as recorded"),
    ],
    ids=["a copied zone file", "no zone file"],
)  # fmt: skip
def test_a_zone_plaso_may_misread_is_said(inventory, tmp_path, extra, note):
    leaf = {k: v for k, v in DUAL[1].items() if k not in ("localtime", "zone")}
    inventory([{**leaf, **extra}])
    (host,), _, _ = ingest_cli._image_hosts(tmp_path / "d.raw", "d", None)
    assert host.zone_note == note


def test_a_failed_listing_keeps_the_mounts_and_says_so(inventory, tmp_path):
    why = "volumes not listed (missing chunk data); the image is parsed from its mounts only"
    inventory([], why)
    assert ingest_cli._image_hosts(tmp_path / "x.E01", "x", None) == ([], {}, [(-1, why)])


def test_the_helper_failing_to_start_is_a_note(monkeypatch, tmp_path):
    monkeypatch.setattr(parse_plaso, "plaso_python", lambda: str(tmp_path / "no-python"))
    leaves, error = parse_plaso.volume_inventory(tmp_path / "x.raw")
    assert leaves == [] and error.startswith("volumes not listed (")
    assert error.endswith("the image is parsed from its mounts only")


def _linux_root(root: Path) -> Path:
    for rel, text in (("etc/passwd", "root:x:0:0::/root:/bin/sh\n"), ("etc/os-release", "ID=x\n")):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def test_a_mounted_linux_root_an_image_run_covered_is_left_to_it(tmp_path):
    covered_root = _linux_root(tmp_path / "vol1")
    other_root = _linux_root(tmp_path / "vol2")
    offsets = {covered_root: 3145728, other_root: 6291456}
    parsed: set = set()
    hosts = ingest_cli._discover_volumes(
        [covered_root, other_root], None, True, "img", [], offsets, {3145728}, parsed
    )
    assert [h.hostname for h in hosts] == ["img-vol2"]  # read from its mount instead
    assert parsed == {6291456}


# Documents and status


def _record(i: int) -> dict:
    return {
        "_event_values_hash": f"run-specific-{i}",
        "data_type": "syslog:line",
        "display_name": "EXT:/var/log/auth.log",
        "filename": "/var/log/auth.log",
        "message": "line",
        "parser": "text/syslog_traditional",
        "pathspec": {"location": f"/tmp/run{i}/dual.raw"},
        "timestamp": 1791280801000000,
    }


@pytest.fixture
def sent(monkeypatch):
    out: list[dict] = []

    def flush(client, actions):
        out.extend(actions)
        return len(actions), 0

    monkeypatch.setattr(parse_plaso, "flush_bulk", flush)
    return out


def test_two_volumes_with_the_same_events_stay_apart(tmp_path, sent):
    for i, volume in enumerate(("p2:lvm1", "p2:lvm2")):
        jsonl = tmp_path / f"{i}.jsonl"
        jsonl.write_text(json.dumps(_record(i)) + "\n")
        _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume=volume)
    assert len({d["_id"] for d in sent}) == 2
    for d, volume in zip(sent, ("p2:lvm1", "p2:lvm2")):
        assert d["_source"]["vhir.volume"] == volume
        assert d["_source"]["vhir.source_file"] == "var/log/auth.log"
        assert d["_source"]["@timestamp"] == "2026-10-06T10:00:01+00:00"


def test_the_same_volume_read_twice_gets_the_same_ids(tmp_path, sent):
    for i in (0, 1):  # a moved image: another path, another _event_values_hash
        jsonl = tmp_path / f"{i}.jsonl"
        jsonl.write_text(json.dumps(_record(i)) + "\n")
        _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume="p2:lvm1")
    assert sent[0]["_id"] == sent[1]["_id"]


def test_an_unread_file_inside_an_image_is_named_by_its_own_path(tmp_path):
    spec = (
        f"type: OS, location: {tmp_path}/img/warn.ext4\n"
        "type: EXT, inode: 16, location: /var/log/syslog.2.gz\ntype: GZIP\n"
    )
    pinfo = {"storage_counters": {"warnings_by_path_spec": {spec: 1}}}
    not_read, _ = plaso_status(pinfo, tmp_path / "img/warn.ext4", "linux", None, "", "zone")
    assert not_read == ["var/log/syslog.2.gz (1 extraction warnings)"]


def test_an_image_run_takes_its_selectors_and_no_root_or_zone(tmp_path, monkeypatch):
    from opensearch_mcp import ingest
    from opensearch_mcp.results import HostResult

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    image = tmp_path / "dual.raw"
    host = DiscoveredHost(hostname="img-p2-lvm1", volume_root=image)
    host.os, host.image_path, host.volume_label = "linux", image, "p2:lvm1"
    host.image_args = ["--partitions", "2", "--volumes", "1", "--vss_stores", "none"]
    host.system_timezone, host.zone_note = "America/New_York", "the zone note"
    seen = []

    def run(parsers, source, workdir, read_as_root, zone, extra=()):
        seen.append((parsers, source, read_as_root, zone, extra))
        jsonl = workdir / "out.jsonl"
        jsonl.write_text(json.dumps(_record(0)) + "\n")
        return jsonl, {}

    monkeypatch.setattr(parse_plaso, "run_plaso_volume", run)
    monkeypatch.setattr(parse_plaso, "can_sudo", lambda: pytest.fail("no sudo for an image"))
    monkeypatch.setattr(parse_plaso, "flush_bulk", lambda c, a: (len(a), 0))
    monkeypatch.setattr(ingest, "_safe_count", lambda c, i: 0)
    status = [{"hostname": "h", "artifacts": [{"name": "plaso", "status": "pending"}]}]

    class Audit:
        def _next_audit_id(self):
            return "aid-1"

        def log(self, **kw):
            pass

    ingest._ingest_plaso_volume(
        None, Audit(), "c1", host, 0, HostResult(hostname="h"), status, lambda *a, **k: None,
        lambda: None,
    )  # fmt: skip
    assert seen == [("linux", image, False, None, tuple(host.image_args))]
    (entry,) = status[0]["artifacts"]
    assert entry["status"] == "complete" and "the zone note" in entry["note"]
    assert "copy" not in entry["note"] and "read as the examiner" not in entry["note"]


@pytest.mark.parametrize("name", ["x.dmg", "x.sparseimage", "X.DMG"])
def test_a_dmg_is_an_image_that_is_never_mounted(tmp_path, name):
    assert detect_container(tmp_path / name) == "dmg"


# Real images

IMAGE_DIRS = [Path(d) for d in os.environ.get("VHIR_TEST_IMAGES", "").split(os.pathsep) if d]


def _image(name: str) -> Path:
    for d in IMAGE_DIRS:
        if (d / name).exists():
            return d / name
    pytest.skip(f"{name} not in VHIR_TEST_IMAGES")


needs_plaso = pytest.mark.skipif(not shutil.which("log2timeline.py"), reason="Plaso not installed")


@needs_plaso
@pytest.mark.parametrize(
    "name, expected",
    [
        ("winetc.ext4", [("", "windows")]),  # a Windows tree with an etc folder
        ("dual.raw", [("p1", "windows"), ("p2/lvm1", "linux"), ("p2/lvm2", None)]),
        ("tz_la_copy.ext4", [("", "linux")]),
    ],
)
def test_the_helper_lists_volumes_with_windows_checked_first(name, expected):
    leaves, error = parse_plaso.volume_inventory(_image(name))
    assert error == ""
    got = [("/".join(leaf["selector"].values()), leaf.get("os")) for leaf in leaves]
    assert got == expected


@needs_plaso
def test_a_copied_zone_file_is_reported_as_a_copy():
    (leaf,), _ = parse_plaso.volume_inventory(_image("tz_la_copy.ext4"))
    assert leaf["localtime"] == "file" and "zone" not in leaf


@needs_plaso
def test_a_missing_e01_segment_fails_the_listing_and_says_so():
    leaves, error = parse_plaso.volume_inventory(_image("e01only/image-split.E01"))
    assert leaves == [] and error.startswith("volumes not listed (")


@needs_plaso
def test_a_linux_root_in_lvm_is_parsed_off_the_image(tmp_path, sent):
    image = _image("dual.raw")
    (run,), _ = plan_image_runs(parse_plaso.volume_inventory(image)[0])
    jsonl, _ = parse_plaso.run_plaso_volume(
        "linux", image, tmp_path / "wd", extra=tuple(run["args"])
    )
    _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume=run["label"])
    docs = [d["_source"] for d in sent]
    assert len(docs) == 146
    assert sum(1 for d in docs if d.get("parser") != "filestat") == 26
    assert {d["vhir.volume"] for d in docs} == {"p2:lvm1"}
    assert not [d for d in docs if str(d["vhir.source_file"]).startswith("/")]
    (apt,) = [d for d in docs if d.get("parser") == "text/apt_history"]
    assert apt["@timestamp"].startswith("2026-10-06T14:20")  # 10:20 in New York


@needs_plaso
def test_an_unreadable_file_on_an_image_is_named(tmp_path):
    image = _image("warn.ext4")
    _, pinfo = parse_plaso.run_plaso_volume("linux", image, tmp_path / "wd")
    not_read, _ = plaso_status(pinfo, image, "linux", None, "", "zone")
    assert not_read == ["var/log/syslog.2.gz (1 extraction warnings)"]


SFDISK = shutil.which("sfdisk", path=os.pathsep.join([os.environ["PATH"], "/usr/sbin", "/sbin"]))


@needs_plaso
@pytest.mark.skipif(not SFDISK, reason="sfdisk not installed")
def test_an_mbrs_meta_entries_are_not_listed_as_volumes(tmp_path):
    import subprocess

    image = tmp_path / "mbr.raw"
    image.write_bytes(b"\0" * 8 * 1048576)
    subprocess.run(
        [SFDISK, "-q", str(image)],
        input="label: dos\n2048,4096,83\n6144,4096,83\n",
        text=True,
        check=True,
        capture_output=True,
    )
    leaves, error = parse_plaso.volume_inventory(image)
    assert error == ""
    assert [leaf["selector"] for leaf in leaves] == [{"partitions": "p1"}, {"partitions": "p2"}]


@needs_plaso
def test_an_apfs_dmg_is_parsed_off_the_image(tmp_path, sent):
    image = _image("apfs.dmg")
    (run,), notes = plan_image_runs(parse_plaso.volume_inventory(image)[0])
    assert run["args"][:4] == ["--partitions", "1", "--volumes", "all"] and notes == []
    jsonl, _ = parse_plaso.run_plaso_volume(
        "macos,unified_logging", image, tmp_path / "wd", extra=tuple(run["args"])
    )
    _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume=run["label"])
    assert sent and {d["_source"]["vhir.volume"] for d in sent} == {"p1:apfs"}


@needs_plaso
def test_a_dmg_with_no_os_root_is_named_not_parsed():
    runs, notes = plan_image_runs(parse_plaso.volume_inventory(_image("hfsplus_zlib.dmg"))[0])
    assert runs == []
    assert notes == [(20480, "p1 at offset 20480: HFS with no OS root; not parsed from the image")]


# Fixes after review


def test_a_partition_numbered_exactly_10_is_reported_not_run():
    leaf = {"selector": {"partitions": "p10"}, "offset": 10 * 1048576, "kind": "filesystem",
            "fs": "EXT", "os": "linux"}  # fmt: skip
    runs, notes = plan_image_runs([leaf])
    assert runs == [] and "numbered 10 or higher" in notes[0][1]


def test_the_folder_timeline_message_is_relative_so_ids_survive_a_move(tmp_path, sent):
    """filestat names the file by its full path in `message`; two copies of
    one folder (or an archive extracted again to a new temp folder) must
    give the same documents."""
    ids = []
    for where in ("first/extract-1/srv01", "second/extract-2/srv01"):
        root = tmp_path / where
        root.mkdir(parents=True)
        full = f"{root.resolve()}/etc/passwd"
        record = {"data_type": "fs:stat", "parser": "filestat", "filename": full,
                  "display_name": f"OS:{full}", "message": f"{full} Type: file",
                  "timestamp": 1791280801000000}  # fmt: skip
        jsonl = tmp_path / f"{len(ids)}.jsonl"
        jsonl.write_text(json.dumps(record) + "\n")
        start = len(sent)
        _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume_root=root)
        ids += [d["_id"] for d in sent[start:]]
    assert ids[0] == ids[1]
    assert sent[0]["_source"]["message"] == "etc/passwd Type: file"


def test_an_examiner_zone_wins_over_the_volumes_own(tmp_path, monkeypatch):
    from opensearch_mcp import ingest
    from opensearch_mcp.discover import EXAMINER_ZONE
    from opensearch_mcp.results import HostResult

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    image = tmp_path / "dual.raw"
    host = DiscoveredHost(hostname="img-p2-lvm1", volume_root=image)
    host.os, host.image_path, host.volume_label = "linux", image, "p2:lvm1"
    host.image_args = ["--partitions", "2", "--volumes", "1", "--vss_stores", "none"]
    host.zone_note = "the volume's own zone"
    host.system_timezone, host.timezone_source = "Europe/Berlin", EXAMINER_ZONE
    seen = []

    def run(parsers, source, workdir, read_as_root, zone, extra=()):
        seen.append(zone)
        jsonl = workdir / "out.jsonl"
        jsonl.write_text("")
        return jsonl, {}

    monkeypatch.setattr(parse_plaso, "run_plaso_volume", run)
    monkeypatch.setattr(ingest, "_safe_count", lambda c, i: 0)
    status = [{"hostname": "h", "artifacts": [{"name": "plaso", "status": "pending"}]}]

    class Audit:
        def _next_audit_id(self):
            return "aid-1"

        def log(self, **kw):
            pass

    ingest._ingest_plaso_volume(
        None, Audit(), "c1", host, 0, HostResult(hostname="h"), status, lambda *a, **k: None,
        lambda: None,
    )  # fmt: skip
    assert seen == ["Europe/Berlin"]
    (entry,) = status[0]["artifacts"]
    assert "time zone Europe/Berlin (examiner override)" in entry["note"]
    assert "the volume's own zone" not in entry["note"]


def test_a_plaso_note_survives_the_rebuilt_status():
    from opensearch_mcp.results import ArtifactResult, HostResult

    h = HostResult(hostname="h")
    h.artifacts.append(ArtifactResult(artifact="plaso", index="i", note="events by parser: x 1"))
    (entry,) = ingest_cli._rebuilt_status_host(h)["artifacts"]
    assert entry["note"] == "events by parser: x 1"


def test_the_dual_boot_warning_names_the_image_host(tmp_path, monkeypatch):
    import opensearch_mcp.hostname as hn

    monkeypatch.setattr(hn, "detect_hostname_from_volume", lambda v: "WIN10A")
    win = tmp_path / "vol1"
    (win / "Windows/System32/config").mkdir(parents=True)
    lnx = _linux_root(tmp_path / "vol2")
    notes: list = []
    ingest_cli._hostname_from_volumes([win, lnx], notes, "disk", {lnx: "disk-p2"})
    assert "(disk-vol1, disk-p2)" in notes[0][1]


def test_image_hosts_reach_the_host_dictionary_from_a_relative_path(tmp_path, monkeypatch):
    import argparse

    import opensearch_mcp.containers as C

    folder = tmp_path / "evidence"
    folder.mkdir()
    (folder / "dual.raw").write_bytes(b"\0")
    monkeypatch.chdir(folder)
    given = []

    def inventory(image):
        given.append(image)
        return DUAL, ""

    class Stop(Exception):
        pass

    seen = {}

    def preflight(case_id, scan_root, hosts):
        seen["hosts"] = [(h.hostname, h.os) for h in hosts]
        raise Stop

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(parse_plaso, "volume_inventory", inventory)
    monkeypatch.setattr(C, "cleanup_orphaned_mounts", lambda: None)
    monkeypatch.setattr(C, "make_ingest_tmpdir", lambda case_id: work)
    monkeypatch.setattr(C, "mount_image", lambda img, dest, ctx: [])
    monkeypatch.setattr(ingest_cli, "_preflight_host_discovery", preflight)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda c: None)
    args = argparse.Namespace(path="dual.raw", case="c1", yes=True, hostname=None)
    with pytest.raises(Stop):
        ingest_cli.cmd_scan(args)
    assert given == [folder / "dual.raw"] and given[0].is_absolute()
    image_id = ingest_cli._image_id("dual", folder / "dual.raw")
    assert seen["hosts"] == [(f"{image_id}-p2-lvm1", "linux")]
