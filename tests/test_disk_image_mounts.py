"""MBR NTFS partitions are mounted, and an E01 is mounted so root can read it.

No command runs here: subprocess.run is replaced by a recorder that answers
fdisk with real util-linux output and accepts every other call.
"""

from __future__ import annotations

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


def test_mbr_ntfs_partitions_are_mounted_and_others_are_not(calls, tmp_path):
    calls.fdisk_text = MBR
    mounted = containers._mount_raw_partitions(
        Path("/evidence/disk.raw"), tmp_path, containers.MountContext()
    )
    assert _mount_offsets(calls) == [f"offset={2048 * 512}", f"offset={104448 * 512}"]
    # each loop device ends where its partition does, so the second can mount too
    assert [
        o
        for c in calls
        if c[:2] == ["sudo", "mount"]
        for o in c[3].split(",")
        if o.startswith("sizelimit=")
    ] == ["sizelimit=52428800", "sizelimit=10485760"]
    assert f"offset={124928 * 512}" not in str(calls)  # 27 Hidden NTFS WinRE
    assert [p.name for p in mounted] == ["vol0", "vol1"]


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
    assert umounts == [str(tmp_path / "vol1"), str(tmp_path / "vol0"), str(ewf)]
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


def test_an_mbr_id_that_only_starts_with_7_is_not_mounted(calls, tmp_path):
    calls.fdisk_text = PCIX
    containers._mount_raw_partitions(
        Path("/evidence/pcix.raw"), tmp_path, containers.MountContext()
    )
    assert _mount_offsets(calls) == [f"offset={22528 * 512}"]  # not the 75 at 2048
