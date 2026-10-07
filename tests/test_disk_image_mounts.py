"""Every filesystem partition of a disk image is mounted, an E01 is mounted so
root can read it, and a partition that won't mount is reported.

No command runs here: subprocess.run is replaced by a recorder that answers
fdisk with real util-linux output and accepts every other call.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

import pytest

import opensearch_mcp.containers as containers

MBR = """\
Disk /evidence/disk.raw: 64 MiB, 67108864 bytes, 131072 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x39ac1510

Device               Boot  Start    End Sectors Size Id Type
/evidence/disk.raw1  *      2048 104447  102400  50M  7 HPFS/NTFS/exFAT
/evidence/disk.raw2       104448 124927   20480  10M  7 HPFS/NTFS/exFAT
/evidence/disk.raw3       124928 129023    4096   2M 27 Hidden NTFS WinRE
"""

GPT = """\
Disk /evidence/gpt.raw: 64 MiB, 67108864 bytes, 131072 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 569E3953-A526-3045-9178-49B182A1A1B0

Device              Start   End Sectors Size Type
/evidence/gpt.raw1   2048 22527   20480  10M Microsoft basic data
"""


class Calls(list):
    """Every command run, in order; fdisk answers with `fdisk_text`."""

    fdisk_text = ""


@pytest.fixture
def calls(monkeypatch):
    recorded = Calls()

    def record(cmd, *a, **k):
        cmd = [str(c) for c in cmd]
        recorded.append(cmd)
        out = recorded.fdisk_text if cmd[:2] == ["fdisk", "-l"] else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(containers.subprocess, "run", record)
    return recorded


def _mount_offsets(calls) -> list[str]:
    return [
        next(o for o in c[3].split(",") if o.startswith("offset=") or o == "noexec")
        for c in calls
        if c[:2] == ["sudo", "mount"]
    ]


def test_every_mbr_partition_is_mounted_with_its_size(calls, tmp_path):
    calls.fdisk_text = MBR
    mounted = containers._mount_raw_partitions(
        Path("/evidence/disk.raw"), tmp_path, containers.MountContext()
    )
    assert _mount_offsets(calls) == [
        f"offset={2048 * 512}",
        f"offset={104448 * 512}",
        f"offset={124928 * 512}",  # 27 Hidden NTFS WinRE is a filesystem too
    ]
    # each loop device ends where its partition does, so the second can mount too
    assert [
        o
        for c in calls
        if c[:2] == ["sudo", "mount"]
        for o in c[3].split(",")
        if o.startswith("sizelimit=")
    ] == ["sizelimit=52428800", "sizelimit=10485760", "sizelimit=2097152"]
    assert [p.name for p in mounted] == ["vol0", "vol1", "vol2"]


def test_a_gpt_basic_data_partition_is_still_mounted(calls, tmp_path):
    calls.fdisk_text = GPT
    containers._mount_raw_partitions(
        Path("/evidence/gpt.raw"), tmp_path, containers.MountContext()
    )
    assert _mount_offsets(calls) == [f"offset={2048 * 512}"]


def test_an_e01_is_mounted_by_root_for_the_examiner_and_unmounted_with_sudo(calls, tmp_path):
    calls.fdisk_text = MBR
    ctx = containers.MountContext()
    image = tmp_path / "disk.E01"
    containers._mount_ewf(image, tmp_path, ctx)
    ewf = tmp_path / "_ewf"
    assert calls[0] == ["sudo", "-n", "true"]  # sudo is checked before anything mounts
    assert calls[1] == ["sudo", "ewfmount", "-X", "allow_other", str(image), str(ewf)]
    assert ["fdisk", "-l", str(ewf / "ewf1")] in calls
    calls.clear()
    ctx.cleanup()
    umounts = [c[2] for c in calls if c[:2] == ["sudo", "umount"]]
    assert umounts == [str(tmp_path / v) for v in ("vol2", "vol1", "vol0")] + [str(ewf)]
    assert not [c for c in calls if c[0] == "fusermount"]


PCIX = """\
Disk /evidence/pcix.raw: 64 MiB, 67108864 bytes, 131072 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x9a7ddf52

Device              Boot Start   End Sectors Size Id Type
/evidence/pcix.raw1       2048 22527   20480  10M 75 PC/IX
/evidence/pcix.raw2      22528 43007   20480  10M  7 HPFS/NTFS/exFAT
"""


def test_an_mbr_partition_of_any_filesystem_id_is_mounted(calls, tmp_path):
    calls.fdisk_text = PCIX
    containers._mount_raw_partitions(
        Path("/evidence/pcix.raw"), tmp_path, containers.MountContext()
    )
    assert _mount_offsets(calls) == [f"offset={2048 * 512}", f"offset={22528 * 512}"]


# Real util-linux 2.37.2 `fdisk -l` lines for each skipped type, beside types
# that must be tried (83 Linux, Linux filesystem, LVM, APFS, LDM data, ...).
MBR_SKIPS = """\
Disk /evidence/mbr1.img: 64 MiB, 67108864 bytes, 131072 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
Disklabel type: dos

Device               Boot Start    End Sectors Size Id Type
/evidence/mbr1.img1  *     2048   6143    4096   2M  7 HPFS/NTFS/exFAT
/evidence/mbr1.img2        6144  14335    8192   4M  7 HPFS/NTFS/exFAT
/evidence/mbr1.img3       14336  18431    4096   2M 82 Linux swap / Solaris
/evidence/mbr1.img4       18432 131071  112640  55M  5 Extended
/evidence/mbr1.img5       20480  24575    4096   2M  7 HPFS/NTFS/exFAT
/evidence/mbr1.img6       26624  30719    4096   2M 83 Linux
/evidence/mbr1.img7       32768  36863    4096   2M 27 Hidden NTFS WinRE
"""

_EXTENDED = """\
Disk /evidence/mbr2.img: 32 MiB, 33554432 bytes, 65536 sectors
Sector size (logical/physical): 512 bytes / 512 bytes
Disklabel type: dos

Device               Boot Start   End Sectors Size Id Type
/evidence/mbr2.img1        2048  6143    4096   2M  c W95 FAT32 (LBA)
/evidence/mbr2.img2        8192 65535   57344  28M {}
/evidence/mbr2.img5       10240 14335    4096   2M  7 HPFS/NTFS/exFAT
"""
MBR_EXTENDED_LBA = _EXTENDED.format(" f W95 Ext'd (LBA)")
MBR_EXTENDED_LINUX = _EXTENDED.format("85 Linux extended")

GPT_SKIPS = """\
Disk /evidence/gpt1.img: 64 MiB, 67108864 bytes, 131072 sectors
Sector size (logical/physical): 512 bytes / 512 bytes
Disklabel type: gpt

Device               Start   End Sectors Size Type
/evidence/gpt1.img1   2048  4095    2048   1M BIOS boot
/evidence/gpt1.img2   4096  8191    4096   2M EFI System
/evidence/gpt1.img3   8192 12287    4096   2M Microsoft reserved
/evidence/gpt1.img4  12288 20479    8192   4M Microsoft basic data
/evidence/gpt1.img5  20480 24575    4096   2M Windows recovery environment
/evidence/gpt1.img6  24576 28671    4096   2M Linux swap
/evidence/gpt1.img7  28672 32767    4096   2M Linux filesystem
/evidence/gpt1.img8  32768 36863    4096   2M Linux LVM
/evidence/gpt1.img9  36864 40959    4096   2M Apple HFS/HFS+
/evidence/gpt1.img10 40960 45055    4096   2M Apple APFS
/evidence/gpt1.img11 45056 49151    4096   2M Linux RAID
/evidence/gpt1.img12 49152 53247    4096   2M Microsoft LDM metadata
/evidence/gpt1.img13 53248 57343    4096   2M Microsoft LDM data
"""


def _tried(calls) -> list[tuple[int, int]]:
    """(offset, sizelimit) of each partition mount, in order."""
    out = []
    for c in calls:
        if c[:2] == ["sudo", "mount"]:
            opts = dict(o.split("=") for o in c[3].split(",") if "=" in o)
            out.append((int(opts["offset"]), int(opts["sizelimit"])))
    return out


@pytest.mark.parametrize(
    "table, tried",
    [
        # 82 swap and 5 Extended skipped; 7, 7, 7, 83 Linux and 27 tried
        (MBR_SKIPS, [(2048, 4096), (6144, 8192), (20480, 4096), (26624, 4096), (32768, 4096)]),
        # f and 85 extended containers skipped; c FAT32 and the logical 7 tried
        (MBR_EXTENDED_LBA, [(2048, 4096), (10240, 4096)]),
        (MBR_EXTENDED_LINUX, [(2048, 4096), (10240, 4096)]),
        # BIOS boot, Microsoft reserved and Linux swap skipped; the rest tried
        (
            GPT_SKIPS,
            [(4096, 4096), (12288, 8192), (20480, 4096)]
            + [(s, 4096) for s in (28672, 32768, 36864, 40960, 45056, 49152, 53248)],
        ),
    ],
    ids=["mbr", "mbr extended f", "mbr extended 85", "gpt"],
)
def test_every_partition_but_the_non_filesystem_types_is_tried(calls, tmp_path, table, tried):
    calls.fdisk_text = table
    containers._mount_raw_partitions(Path("/evidence/x.img"), tmp_path, containers.MountContext())
    assert _tried(calls) == [(start * 512, sectors * 512) for start, sectors in tried]


@pytest.mark.parametrize(
    "fdisk_text",
    [
        "Disk /evidence/vol.img: 32 MiB, 33554432 bytes, 65536 sectors\n",  # no table
        "fdisk: cannot open /evidence/vol.img: Input/output error\n",
    ],
    ids=["no partition table", "unreadable table"],
)
def test_a_volume_image_is_mounted_whole(calls, tmp_path, fdisk_text):
    calls.fdisk_text = fdisk_text
    mounted = containers._mount_raw_partitions(
        Path("/evidence/vol.img"), tmp_path, containers.MountContext()
    )
    mounts = [c for c in calls if c[:2] == ["sudo", "mount"]]
    assert [m[3] for m in mounts] == ["ro,loop,noexec"]
    assert [p.name for p in mounted] == ["vol0"]


def test_a_partition_that_does_not_mount_is_reported(monkeypatch, tmp_path, capsys):
    def run(cmd, *a, **k):
        cmd = [str(c) for c in cmd]
        if cmd[:2] == ["fdisk", "-l"]:
            return subprocess.CompletedProcess(cmd, 0, MBR, "")
        if cmd[:2] == ["sudo", "mount"] and f"offset={104448 * 512}" in cmd[3]:
            raise subprocess.CalledProcessError(
                32, cmd, b"", b"mount: /x: wrong fs type, bad option.\nmore detail\n"
            )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(containers.subprocess, "run", run)
    ctx = containers.MountContext()
    mounted = containers._mount_raw_partitions(Path("/evidence/disk.raw"), tmp_path, ctx)
    want = (
        f"partition type '7 HPFS/NTFS/exFAT' at offset {104448 * 512} did not mount: "
        "mount: /x: wrong fs type, bad option."
    )
    assert ctx.failures == [want]
    assert want in capsys.readouterr().err
    assert [p.name for p in mounted] == ["vol0", "vol2"]  # the others still mount


def test_each_status_note_is_a_labelled_warning(tmp_path, monkeypatch):
    from opensearch_mcp import ingest_status

    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    ingest_status.write_status("c1", 7, "r", "running", [], {}, "2026-10-07T00:00:00Z")
    ingest_status.finish_status("c1", 7, notes=[("triage", "t"), ("mount", "m")])
    (path,) = (tmp_path / "status").glob("*.json")
    data = __import__("json").loads(path.read_text())
    assert data["status"] == "complete"
    assert [(h["hostname"], h["artifacts"]) for h in data["hosts"]] == [
        ("triage", [{"name": "triage", "note": "t", "warnings_only": True}]),
        ("mount", [{"name": "mount", "note": "m", "warnings_only": True}]),
    ]


def _volume(root: Path, name: str, windows: bool) -> Path:
    v = root / name
    v.mkdir()
    if windows:
        (v / "Windows/System32/config").mkdir(parents=True)
        (v / "Windows/System32/config/SYSTEM").write_bytes(b"x")
        logs = v / "Windows/System32/winevt/Logs"
        logs.mkdir(parents=True)
        (logs / "Security.evtx").write_bytes(b"x" * 100)
    return v


@pytest.fixture
def registry(monkeypatch):
    """detect_hostname_from_volume answers from the volume's name."""
    read: list[str] = []
    names = {"vol1": "WIN10A", "vol2": "WIN11B"}

    def detect(v):
        read.append(v.name)
        return names.get(v.name)

    import opensearch_mcp.hostname as hostname

    monkeypatch.setattr(hostname, "detect_hostname_from_volume", detect)
    return read


def test_the_registry_name_comes_from_the_one_windows_volume(tmp_path, registry):
    from opensearch_mcp import ingest_cli

    volumes = [_volume(tmp_path, "vol0", False), _volume(tmp_path, "vol1", True)]
    notes: list = []
    assert ingest_cli._hostname_from_volumes(volumes, notes, "disk") == "WIN10A"
    assert registry == ["vol1"] and notes == []


def test_two_windows_installs_force_no_name_and_are_listed(tmp_path, registry, capsys):
    from opensearch_mcp import ingest_cli

    volumes = [
        _volume(tmp_path, n, w) for n, w in (("vol0", False), ("vol1", True), ("vol2", True))
    ]
    notes: list = []
    assert ingest_cli._hostname_from_volumes(volumes, notes, "dual-boot-0a1b2c3d") is None
    ((label, note),) = notes
    assert label == "hostname"
    assert note.startswith(
        "2 Windows installs on this image (vol1: WIN10A, vol2: WIN11B); each is ingested "
        "as its own host (dual-boot-0a1b2c3d-vol1, dual-boot-0a1b2c3d-vol2). "
        "Pass --hostname only if"
    )
    assert note in capsys.readouterr().err


def test_each_windows_install_on_an_image_is_its_own_host(tmp_path):
    from opensearch_mcp import ingest_cli

    volumes = [
        _volume(tmp_path, n, w) for n, w in (("vol0", False), ("vol1", True), ("vol2", True))
    ]
    hosts = ingest_cli._discover_volumes(volumes, None, True, "disk")
    assert [(h.hostname, h.volume_root.name) for h in hosts] == [
        ("disk-vol1", "vol1"),
        ("disk-vol2", "vol2"),
    ]


def _dual_boot(root: Path) -> list[Path]:
    root.mkdir()
    return [_volume(root, n, w) for n, w in (("vol0", False), ("vol1", True), ("vol2", True))]


def test_two_dual_boot_images_in_one_case_keep_four_hosts_and_indices(tmp_path):
    from opensearch_mcp import ingest_cli
    from opensearch_mcp.paths import build_index_name

    first = ingest_cli._image_id("lab-pc", tmp_path / "lab-pc.raw")
    second = ingest_cli._image_id("kiosk 7", tmp_path / "kiosk 7.E01")
    a = ingest_cli._discover_volumes(_dual_boot(tmp_path / "a"), None, True, first)
    b = ingest_cli._discover_volumes(_dual_boot(tmp_path / "b"), None, True, second)
    names = [h.hostname for h in a + b]
    assert [re.sub("-[0-9a-f]{8}-", "-*-", n) for n in names] == [
        "lab-pc-*-vol1",
        "lab-pc-*-vol2",
        "kiosk-7-*-vol1",
        "kiosk-7-*-vol2",
    ]
    assert len({build_index_name("c1", "evtx", n) for n in names}) == 4


def _names(tmp_path, image_id: str) -> list[str]:
    from opensearch_mcp import ingest_cli

    vols = _dual_boot(tmp_path / f"m{len(list(tmp_path.glob('m*')))}")
    return [h.hostname for h in ingest_cli._discover_volumes(vols, None, True, image_id)]


def test_two_images_with_the_same_name_in_different_folders_keep_their_own_hosts(tmp_path):
    from opensearch_mcp import ingest_cli

    one = ingest_cli._image_id("disk", tmp_path / "site1" / "disk.E01")
    two = ingest_cli._image_id("disk", tmp_path / "site2" / "disk.E01")
    assert not set(_names(tmp_path, one)) & set(_names(tmp_path, two))


@pytest.mark.parametrize("stems", [("lab pc", "lab-pc"), ("Alpha", "alpha")])
def test_image_names_that_differ_only_in_case_or_spacing_keep_their_own_hosts(tmp_path, stems):
    from opensearch_mcp import ingest_cli

    one, two = (ingest_cli._image_id(s, tmp_path / f"{s}.raw") for s in stems)
    assert not set(_names(tmp_path, one)) & set(_names(tmp_path, two))


def test_the_same_image_gets_the_same_host_names_each_time(tmp_path):
    from opensearch_mcp import ingest_cli

    image = tmp_path / "disk.E01"
    assert ingest_cli._image_id("disk", image) == ingest_cli._image_id("disk", image)
    assert re.fullmatch(r"disk-[0-9a-f]{8}", ingest_cli._image_id("disk", image))


def test_a_disk_image_inside_an_archive_names_its_hosts_after_the_image(tmp_path, monkeypatch):
    import opensearch_mcp.containers as C
    from opensearch_mcp import ingest_cli

    work = tmp_path / "work"
    work.mkdir()
    archive = tmp_path / "evidence" / "collection.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK")

    def extract(path, dest, password=None):
        (dest / "dual.raw").write_bytes(b"\0")

    def mount(img, dest, ctx):
        return _dual_boot(dest / "mnt")

    seen = {}

    class Stop(Exception):
        pass

    def preflight(case_id, scan_root, hosts):
        seen["hosts"] = [h.hostname for h in hosts]
        raise Stop

    monkeypatch.setattr(C, "detect_container", lambda p: "archive")
    monkeypatch.setattr(C, "cleanup_orphaned_mounts", lambda: None)
    monkeypatch.setattr(C, "extract_container", extract)
    monkeypatch.setattr(C, "is_velociraptor_collection", lambda p: False)
    monkeypatch.setattr(C, "make_ingest_tmpdir", lambda case_id: work)
    monkeypatch.setattr(C, "mount_image", mount)
    monkeypatch.setattr(C, "cleanup_tmpdir", lambda *a, **k: None)
    monkeypatch.setattr(ingest_cli, "_preflight_host_discovery", preflight)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda c: None)
    import opensearch_mcp.hostname as hn

    monkeypatch.setattr(hn, "detect_hostname_from_volume", lambda v: None)
    args = argparse.Namespace(path=str(archive), case="c1", yes=True, hostname=None)
    with pytest.raises(Stop):
        ingest_cli.cmd_scan(args)
    want = ingest_cli._image_id("dual", archive / "dual.raw")
    assert seen["hosts"] == [f"{want}-vol1", f"{want}-vol2"]
    assert want.startswith("dual-")


def test_a_one_install_image_with_a_registry_name_keeps_it(tmp_path):
    from opensearch_mcp import ingest_cli

    volumes = [_volume(tmp_path, "vol0", False), _volume(tmp_path, "vol1", True)]
    hosts = ingest_cli._discover_volumes(volumes, "WIN10A", True, "disk")
    assert [(h.hostname, h.volume_root.name) for h in hosts] == [("WIN10A", "vol1")]


def test_a_host_folder_on_a_volume_keeps_its_own_name(tmp_path):
    from opensearch_mcp import ingest_cli

    data = tmp_path / "vol3"
    data.mkdir()
    _volume(data, "HOSTA", True)  # a triage copy of another machine on a data partition
    hosts = ingest_cli._discover_volumes([data], None, True, "disk")
    assert [h.hostname for h in hosts] == ["HOSTA"]


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root can search a mode-000 folder, so it can't stand in for lost+found",
)
def test_a_folder_that_cannot_be_searched_does_not_stop_discovery(tmp_path):
    from opensearch_mcp import ingest_cli

    win = _volume(tmp_path, "vol1", True)
    ext4 = tmp_path / "vol3"
    (ext4 / "lost+found").mkdir(parents=True)
    os.chmod(ext4 / "lost+found", 0o000)  # as root's lost+found looks to the examiner
    try:
        hosts = ingest_cli._discover_volumes([win, ext4], None, True, "disk")
    finally:
        os.chmod(ext4 / "lost+found", 0o700)
    assert [(h.hostname, h.volume_root.name) for h in hosts] == [("disk-vol1", "vol1")]
