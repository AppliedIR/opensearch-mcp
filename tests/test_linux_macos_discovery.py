"""Linux and macOS roots are found, on folders and on each volume of an image.

Discovery knew only Windows (`Windows/System32/config`), so a Linux or macOS
tree gave no host and an image volume holding one was dropped without a word.
Now a macOS root (`SystemVersion.plist`) and a Linux root (`etc/passwd` plus a
release file) each give a host with one Plaso artifact over the volume, and
the volume's own time zone, read from inside the volume only. On an image,
installs of every OS count, so a Windows name is never forced onto a Linux
volume, and a volume with no root is reported. Trees are synthetic.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opensearch_mcp import ingest_cli
from opensearch_mcp.discover import make_host, os_of_root, scan_triage_directory


def _write(root: Path, rel: str, text: str = "x\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def _windows(root: Path) -> Path:
    _write(root, "Windows/System32/config/SYSTEM")
    _write(root, "Windows/System32/winevt/Logs/Security.evtx", "x" * 100)
    return root


def _linux(root: Path, zone: str = "Etc/UTC") -> Path:
    _write(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    _write(root, "etc/os-release", 'ID=ubuntu\nVERSION_ID="22.04"\n')
    _write(root, "var/log/auth.log", "Oct  6 10:00:01 h sshd[1]: Accepted\n")
    os.symlink(f"../usr/share/zoneinfo/{zone}", root / "etc/localtime")
    return root


def _macos(root: Path, zone: str = "America/New_York") -> Path:
    # As on a real Mac: etc links to private/etc, which holds passwd.
    _write(root, "System/Library/CoreServices/SystemVersion.plist", "<plist/>\n")
    _write(root, "private/etc/passwd", "root:*:0:0:System Administrator:/var/root:/bin/sh\n")
    os.symlink(f"/var/db/timezone/zoneinfo/{zone}", root / "private/etc/localtime")
    os.symlink("private/etc", root / "etc")
    _write(root, "private/var/log/system.log", "Oct  6 10:00:01 m kernel[0]: boot\n")
    return root


# Recognition


@pytest.mark.parametrize(
    "build, os_name", [(_linux, "linux"), (_macos, "macos")], ids=["linux", "macos"]
)
def test_a_linux_or_macos_tree_is_one_host_with_a_plaso_artifact(tmp_path, build, os_name):
    root = build(tmp_path / "srv01")
    (host,) = scan_triage_directory(root)
    assert (host.hostname, host.os, host.volume_root) == ("srv01", os_name, root)
    assert host.artifacts == [("plaso", root)]


def test_a_folder_of_windows_linux_and_macos_hosts_gives_all_three(tmp_path):
    _windows(tmp_path / "case" / "win01")
    _linux(tmp_path / "case" / "lnx01")
    _macos(tmp_path / "case" / "mac01")
    hosts = scan_triage_directory(tmp_path / "case")
    assert [(h.hostname, h.os) for h in hosts] == [
        ("lnx01", "linux"),
        ("mac01", "macos"),
        ("win01", "windows"),
    ]


def test_a_root_one_folder_down_is_found_as_today(tmp_path):
    _linux(tmp_path / "lnx01" / "C")
    (host,) = scan_triage_directory(tmp_path)
    assert (host.hostname, host.os, host.volume_root.name) == ("lnx01", "linux", "C")


@pytest.mark.parametrize(
    "files",
    [
        ["etc/passwd"],
        ["etc/os-release"],
        ["home/u/.bashrc", "var/log/syslog"],
    ],
    ids=["passwd alone", "a release file alone", "neither"],
)
def test_a_tree_without_both_linux_markers_is_not_a_linux_root(tmp_path, files):
    for f in files:
        _write(tmp_path / "t", f)
    assert os_of_root(tmp_path / "t") is None
    assert scan_triage_directory(tmp_path) == []


@pytest.mark.parametrize(
    "release",
    [
        "usr/lib/os-release",
        "etc/lsb-release",
        "etc/debian_version",
        "etc/redhat-release",
        "etc/alpine-release",
        "etc/SuSE-release",
    ],
)
def test_each_release_file_marks_a_linux_root(tmp_path, release):
    _write(tmp_path, "etc/passwd")
    _write(tmp_path, release)
    assert os_of_root(tmp_path) == "linux"


def test_a_windows_root_keeps_its_artifacts(tmp_path):
    host = make_host("win01", _windows(tmp_path / "w"))
    assert host.os == "windows" and host.evtx_dir is not None
    assert all(name != "plaso" for name, _ in host.artifacts)


# The volume's own time zone


def test_the_zone_comes_from_the_localtime_link(tmp_path):
    host = make_host("lnx01", _linux(tmp_path / "l", "America/New_York"))
    assert (host.system_timezone, host.timezone_source) == ("America/New_York", "etc/localtime")


def test_a_mac_zone_is_read_through_its_etc_link(tmp_path):
    host = make_host("mac01", _macos(tmp_path / "m", "Europe/Berlin"))
    assert (host.system_timezone, host.timezone_source) == ("Europe/Berlin", "etc/localtime")


def test_without_a_link_the_zone_comes_from_etc_timezone(tmp_path):
    root = _linux(tmp_path / "l")
    (root / "etc/localtime").unlink()
    _write(root, "etc/timezone", "Asia/Kolkata\n")
    host = make_host("lnx01", root)
    assert (host.system_timezone, host.timezone_source) == ("Asia/Kolkata", "etc/timezone")


@pytest.mark.parametrize("value", ["UTC+12", "Not/AZone", ""], ids=["posix", "unknown", "empty"])
def test_a_zone_plaso_cannot_use_is_left_unset(tmp_path, value):
    root = _linux(tmp_path / "l")
    (root / "etc/localtime").unlink()
    _write(root, "etc/timezone", value + "\n")
    host = make_host("lnx01", root)
    assert (host.system_timezone, host.timezone_source) == (None, "")


def test_a_zone_file_linked_out_of_the_volume_is_not_read(tmp_path):
    outside = _write(tmp_path / "analysis-host", "timezone", "America/Chicago\n")
    root = _linux(tmp_path / "l")
    (root / "etc/localtime").unlink()
    os.symlink(outside, root / "etc/timezone")  # absolute, out of the volume
    assert make_host("lnx01", root).system_timezone is None


def test_an_etc_linked_out_of_the_volume_is_not_read(tmp_path):
    host_etc = tmp_path / "analysis-host" / "etc"
    _write(host_etc, "timezone", "America/Chicago\n")
    os.symlink("/usr/share/zoneinfo/America/Chicago", host_etc / "localtime")
    root = tmp_path / "l"
    _write(root, "System/Library/CoreServices/SystemVersion.plist")
    os.symlink(host_etc, root / "etc")  # absolute, out of the volume
    assert make_host("mac01", root).system_timezone is None


# Disk images


@pytest.fixture
def registry(monkeypatch):
    """The Windows volume's registry names it WIN10A."""
    import opensearch_mcp.hostname as hostname

    monkeypatch.setattr(hostname, "detect_hostname_from_volume", lambda v: "WIN10A")


def test_a_dual_boot_with_linux_forces_no_windows_name_onto_it(tmp_path, registry, capsys):
    volumes = [_windows(tmp_path / "vol1"), _linux(tmp_path / "vol2")]
    notes: list = []
    assert ingest_cli._hostname_from_volumes(volumes, notes, "disk-0a1b2c3d") is None
    ((label, note),) = notes
    assert label == "hostname"
    assert note.startswith(
        "2 OS installs on this image (vol1: windows WIN10A, vol2: linux ?); each is "
        "ingested as its own host (disk-0a1b2c3d-vol1, disk-0a1b2c3d-vol2)."
    )
    hosts = ingest_cli._discover_volumes(volumes, None, True, "disk-0a1b2c3d", [])
    assert [(h.hostname, h.os) for h in hosts] == [
        ("disk-0a1b2c3d-vol1", "windows"),
        ("disk-0a1b2c3d-vol2", "linux"),
    ]


def test_a_linux_only_image_is_named_for_the_image_and_volume(tmp_path, registry):
    volumes = [tmp_path / "vol1", _linux(tmp_path / "vol2")]
    volumes[0].mkdir()
    assert ingest_cli._hostname_from_volumes(volumes, [], "disk-0a1b2c3d") is None
    hosts = ingest_cli._discover_volumes(volumes, None, True, "disk-0a1b2c3d", [])
    assert [(h.hostname, h.os) for h in hosts] == [("disk-0a1b2c3d-vol2", "linux")]


def test_a_volume_with_no_root_is_reported(tmp_path, capsys):
    volumes = [_windows(tmp_path / "vol1"), tmp_path / "vol2"]
    _write(volumes[1], "EFI/BOOT/BOOTX64.EFI")
    notes: list = []
    hosts = ingest_cli._discover_volumes(volumes, None, True, "disk", notes)
    assert [h.hostname for h in hosts] == ["disk-vol1"]
    note = "vol2 mounted; no Windows, Linux or macOS root found; nothing on it was parsed"
    assert notes == [("volume", note)]
    assert note in capsys.readouterr().err
