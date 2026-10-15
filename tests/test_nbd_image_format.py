"""qemu-nbd opens a disk image in the format its name says, never a probed one.

A VMDK description file is plain text naming extent files by path. Named
.vhdx and opened without -f, qemu probes it as vmdk and serves the bytes of
whatever file it names, as root on the mount path. With -f from the suffix,
qemu refuses it.

Nothing here runs sudo: subprocess.run is replaced by a recorder for the mount
path, and the refusal is checked with qemu-img, unprivileged.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import opensearch_mcp.containers as containers


def _nbd_argv(monkeypatch, tmp_path: Path, image: Path) -> list[str]:
    """The qemu-nbd argv _mount_nbd runs for `image`, captured, not run."""
    calls: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        calls.append([str(c) for c in cmd])
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    dest = tmp_path / "dest"
    dest.mkdir()
    with monkeypatch.context() as m:  # subprocess.run is the real one again after
        m.setattr(containers, "check_sudo", lambda: None)
        m.setattr(containers, "_find_free_nbd", lambda: "/dev/nbd7")
        m.setattr(containers.subprocess, "run", fake_run)
        m.setattr(containers.time, "sleep", lambda s: None)
        m.setattr(containers.glob, "glob", lambda p: [])
        containers._mount_nbd(image, dest, containers.MountContext())
    return next(c for c in calls if c[:2] == ["sudo", "qemu-nbd"])


def _evil_description(tmp_path: Path, name: str) -> Path:
    """A VMDK description named `name`, whose one extent is a file beside it."""
    (tmp_path / "outside.bin").write_bytes(b"S" * (1 << 20))
    image = tmp_path / name
    image.write_text(
        "# Disk DescriptorFile\n"
        "version=1\n"
        "CID=fffffffe\n"
        "parentCID=ffffffff\n"
        'createType="monolithicFlat"\n'
        'RW 2048 FLAT "outside.bin" 0\n'
        'ddb.adapterType = "ide"\n'
    )
    return image


@pytest.mark.parametrize(
    ("suffix", "fmt"), [(".vhdx", "vhdx"), (".vhd", "vpc"), (".vmdk", "vmdk"), (".VHDX", "vhdx")]
)
def test_qemu_nbd_gets_the_format_its_name_says(monkeypatch, tmp_path, suffix, fmt):
    image = tmp_path / f"disk{suffix}"
    image.write_bytes(b"")
    argv = _nbd_argv(monkeypatch, tmp_path, image)
    assert argv == ["sudo", "qemu-nbd", "-r", "-f", fmt, "-c", "/dev/nbd7", str(image)]


def test_a_vmdk_description_named_vhdx_is_refused(monkeypatch, tmp_path):
    image = _evil_description(tmp_path, "evil.vhdx")
    # without a format, qemu probes the content and follows the description
    probed = subprocess.run(["qemu-img", "info", str(image)], capture_output=True, text=True)
    assert "file format: vmdk" in probed.stdout
    argv = _nbd_argv(monkeypatch, tmp_path, image)
    fmt = argv[argv.index("-f") + 1]
    opened = subprocess.run(
        ["qemu-img", "info", "-f", fmt, str(image)], capture_output=True, text=True
    )
    assert opened.returncode != 0
    assert "Could not open" in opened.stderr
