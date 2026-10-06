"""Startup nbd cleanup touches only this user's own orphaned ingest mounts.

A device is cleaned only when every mount of it lies under this HOME's own
ingest temp dirs and that ingest's process is gone. Foreign mounts, other
users' ingests, unmounted devices and live ingests are left alone.

Nothing here runs a command: subprocess.run is replaced by a recorder, and
the device size files, the mount table and the partition list are fakes.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import opensearch_mcp.containers as containers
import opensearch_mcp.ingest_status as ingest_status


def _dead_pid() -> int:
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


LIVE = os.getpid()
DEAD = _dead_pid()


def _esc(path: str) -> str:
    """A path as the kernel writes it in /proc/self/mounts."""
    return path.replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")


def _own(home: Path, pid: int, case: str = "c1", part: str = "nbd0p1") -> str:
    return str(
        home.resolve() / ".vhir/cases" / case / "tmp" / f"ingest-20261006T070705-{pid}" / part
    )


class Host:
    def __init__(
        self,
        tmp_path: Path,
        monkeypatch,
        home_symlink: bool = False,
        home_name: bytes = b"realhome",
    ):
        self.root = tmp_path / "host"
        real_home = Path(os.fsdecode(os.fsencode(tmp_path) + b"/" + home_name))
        (real_home / ".vhir/cases").mkdir(parents=True)
        self.home = real_home
        if home_symlink:
            self.home = tmp_path / "home"
            self.home.symlink_to(real_home)
        monkeypatch.setenv("HOME", str(self.home))
        monkeypatch.setattr(ingest_status, "_STATUS_DIR", self.home / ".vhir/ingest-status")
        self.calls: list[list[str]] = []
        self.parts: dict[str, list[str]] = {}
        real_path = containers.Path

        def fake_path(p, *rest):
            s = str(p)
            for prefix in ("/sys/block", "/proc/self/mounts"):
                if s.startswith(prefix):
                    return real_path(str(self.root) + s, *rest)
            return real_path(p, *rest)

        def record(cmd, *a, **k):
            self.calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(containers, "Path", fake_path)
        monkeypatch.setattr(containers.subprocess, "run", record)
        monkeypatch.setattr(containers.glob, "glob", lambda pat: sorted(self.parts.get(pat, [])))

    def state(
        self, sizes: dict, mounts: list, parts: dict | None = None, status=None, raw: bytes = b""
    ):
        for i in range(8):
            d = self.root / f"sys/block/nbd{i}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "size").write_text(f"{sizes.get(i, 0)}\n")
        table = self.root / "proc/self/mounts"
        table.parent.mkdir(parents=True, exist_ok=True)
        table.write_bytes(
            os.fsencode(
                "".join(
                    f"{_esc(src)} {_esc(mp)} fuseblk ro,nosuid,nodev 0 0\n" for src, mp in mounts
                )
            )
            + raw
            + b"/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n"
        )
        for dev, ps in (parts or {"/dev/nbd0": ["/dev/nbd0p1"]}).items():
            self.parts[f"{dev}p*"] = ps
        if status:
            st, pid = status
            sd = self.home / ".vhir/ingest-status"
            sd.mkdir(parents=True, exist_ok=True)
            (sd / f"c1-{pid}.json").write_text(
                json.dumps({"pid": pid, "status": st, "run_id": "", "case_id": "c1"})
            )

    def clean(self) -> list[list[str]]:
        containers.cleanup_orphaned_mounts()
        return self.calls


@pytest.fixture
def host(tmp_path, monkeypatch):
    return Host(tmp_path, monkeypatch)


def _cleaned(calls, dev):
    return ["sudo", "qemu-nbd", "-d", dev] in calls


def test_nothing_in_use_does_nothing(host):
    host.state({}, [])
    assert host.clean() == []


LEAVE_ALONE = {
    "a device mounted somewhere else": dict(mounts=[("/dev/nbd0p1", "/mnt/examiner evidence")]),
    "a device connected but not mounted": dict(mounts=[]),
    "another home's dead ingest": dict(
        mounts=[
            ("/dev/nbd0p1", f"/home/other/.vhir/cases/c9/tmp/ingest-20261006T070705-{DEAD}/nbd0p1")
        ]
    ),
    "another home's live ingest": dict(
        mounts=[
            (
                "/dev/nbd0p1",
                f"/home/examiner/.vhir/cases/c2/tmp/ingest-20261006T070705-{LIVE}/nbd0p1",
            )
        ]
    ),
}


@pytest.mark.parametrize("shape", list(LEAVE_ALONE))
def test_a_device_that_is_not_this_users_orphan_is_left_alone(host, shape):
    host.state({0: 2048}, **LEAVE_ALONE[shape])
    assert host.clean() == []


@pytest.mark.parametrize("status", ["starting", None])
def test_this_users_live_ingest_is_left_alone(host, status):
    host.state(
        {0: 2048},
        [("/dev/nbd0p1", _own(host.home, LIVE))],
        status=(status, LIVE) if status else None,
    )
    assert host.clean() == []


def test_this_users_running_ingest_is_left_alone(host):
    host.state({0: 2048}, [("/dev/nbd0p1", _own(host.home, LIVE))], status=("running", LIVE))
    assert host.clean() == []


def test_a_device_with_one_foreign_partition_is_left_alone(host):
    host.state(
        {0: 2048},
        [("/dev/nbd0p1", _own(host.home, DEAD)), ("/dev/nbd0p2", "/mnt/x")],
        parts={"/dev/nbd0": ["/dev/nbd0p1", "/dev/nbd0p2"]},
    )
    assert host.clean() == []


def test_only_the_own_orphan_is_cleaned_beside_a_foreign_device(host):
    host.state(
        {0: 2048, 1: 4096},
        [("/dev/nbd0p1", "/mnt/x"), ("/dev/nbd1p1", _own(host.home, DEAD, part="nbd1p1"))],
        parts={"/dev/nbd0": ["/dev/nbd0p1"], "/dev/nbd1": ["/dev/nbd1p1"]},
    )
    calls = host.clean()
    assert _cleaned(calls, "/dev/nbd1")
    assert not [c for c in calls if any("nbd0" in a for a in c)], calls


@pytest.mark.parametrize("case", ["c1", "case one"])
def test_this_users_orphan_from_a_dead_ingest_is_cleaned(host, case):
    mountpoint = _own(host.home, DEAD, case=case)
    host.state({0: 2048}, [("/dev/nbd0p1", mountpoint)])
    calls = host.clean()
    assert _cleaned(calls, "/dev/nbd0")
    assert calls.index(["sudo", "qemu-nbd", "-d", "/dev/nbd0"]) == len(calls) - 1
    # unmounted by its real mount point or its partition, never the escaped text
    (umount,) = calls[:-1]
    assert umount[:2] == ["sudo", "umount"] and umount[2] in (mountpoint, "/dev/nbd0p1")


def test_an_orphan_with_two_partitions_is_unmounted_then_cleaned(host):
    host.state(
        {0: 2048},
        [
            ("/dev/nbd0p1", _own(host.home, DEAD)),
            ("/dev/nbd0p2", _own(host.home, DEAD, part="nbd0p2")),
        ],
        parts={"/dev/nbd0": ["/dev/nbd0p1", "/dev/nbd0p2"]},
    )
    calls = host.clean()
    assert [c[:2] for c in calls] == [["sudo", "umount"]] * 2 + [["sudo", "qemu-nbd"]]


def test_an_orphan_under_a_symlinked_home_is_cleaned(tmp_path, monkeypatch):
    host = Host(tmp_path, monkeypatch, home_symlink=True)
    host.state({0: 2048}, [("/dev/nbd0p1", _own(host.home, DEAD))])
    assert _cleaned(host.clean(), "/dev/nbd0")


def test_a_mount_path_that_is_not_utf8_does_not_stop_the_cleanup(host):
    # e.g. a Latin-1 volume label mounted elsewhere on the host
    host.state(
        {0: 2048},
        [("/dev/nbd0p1", _own(host.home, DEAD))],
        raw=b"/dev/sdb1 /media/user/Donn\xe9es vfat rw,nosuid,nodev 0 0\n",
    )
    assert _cleaned(host.clean(), "/dev/nbd0")


def test_an_orphan_under_a_home_that_is_not_utf8_is_unmounted_by_its_own_bytes(
    tmp_path, monkeypatch
):
    host = Host(tmp_path, monkeypatch, home_name=b"home-\xe9t\xe9")
    mountpoint = _own(host.home, DEAD)
    host.state({0: 2048}, [("/dev/nbd0p1", mountpoint)])
    calls = host.clean()
    assert _cleaned(calls, "/dev/nbd0")
    (umount,) = calls[:-1]
    assert umount[:2] == ["sudo", "umount"]
    assert os.fsencode(umount[2]) in (os.fsencode(mountpoint), b"/dev/nbd0p1")
    assert b"\xe9t\xe9" in os.fsencode(mountpoint)
