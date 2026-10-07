"""Shadow copies are found on a partitioned disk image.

vshadowinfo read the whole image, which on a partitioned disk finds no
shadow copies, so `--vss` silently gave none. Each mounted NTFS volume is
now read at its own offset, and one with none says so. vshadowinfo,
vshadowmount and sudo are stand-ins here; the image is synthetic.
"""

from __future__ import annotations

import argparse
import inspect
import os
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import containers
from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp.containers import MountContext, mount_vss

GPT_DATA = 22020096  # the second partition of a small GPT disk
STUBS = {
    # Two stores only when read where a volume with shadow copies starts
    "vshadowinfo": """#!/bin/sh
echo "$*" >> "$VSS_LOG"
off=0; [ "$1" = "-o" ] && off="$2"
for at in $VSS_AT; do
  if [ "$at" = "$off" ]; then printf 'Volume\\n\\tNumber of stores:\\t2\\n'; exit 0; fi
done
echo "No Volume Shadow Snapshots found."; exit 1
""",
    "vshadowmount": """#!/bin/sh
echo "vshadowmount $*" >> "$VSS_LOG"
for last; do :; done
touch "$last/vss1" "$last/vss2"
""",
    "sudo": "#!/bin/sh\nexit 0\n",
}


@pytest.fixture
def vss(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in STUBS.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    log = tmp_path / "vss.log"
    log.touch()
    monkeypatch.setenv("VSS_LOG", str(log))
    image = tmp_path / "disk.raw"
    with open(image, "wb") as f:
        f.truncate(GPT_DATA + 4096)

    def run(ntfs_at, stores_at, offsets):
        with open(image, "r+b") as f:
            for off in ntfs_at:
                f.seek(off + 3)
                f.write(b"NTFS    ")
        monkeypatch.setenv("VSS_AT", " ".join(str(o) for o in stores_at))
        dest = tmp_path / "mnt"
        dest.mkdir()
        notes: list = []
        if "offsets" in inspect.signature(mount_vss).parameters:
            found = mount_vss(image, dest, MountContext(), offsets, notes)
        else:  # a release before volumes were passed: the whole image
            found = mount_vss(image, dest, MountContext())
        return [v for v, _ in found], notes, log.read_text()

    return run


def test_a_partitioned_images_shadow_copies_are_read_at_the_ntfs_partition(vss):
    ids, notes, log = vss([GPT_DATA], [GPT_DATA], {"vol0": 1048576, "vol1": GPT_DATA})
    assert ids == ["vss1", "vss2"] and notes == []
    assert f"-o {GPT_DATA}" in log
    assert "-o 1048576" not in log  # not NTFS: not read


def test_a_volume_images_shadow_copies_are_still_found(vss):
    ids, notes, _ = vss([0], [0], {"vol0": 0})
    assert ids == ["vss1", "vss2"]


def test_an_ntfs_partition_without_shadow_copies_says_so(vss):
    ids, notes, _ = vss([GPT_DATA], [], {"vol0": 1048576, "vol1": GPT_DATA})
    assert ids == []
    assert notes == [("vss", f"no shadow copies found on vol1 (offset {GPT_DATA})")]


def test_two_ntfs_partitions_keep_their_shadow_copies_apart(vss):
    ids, _, _ = vss([1048576, GPT_DATA], [1048576, GPT_DATA], {"vol0": 1048576, "vol1": GPT_DATA})
    assert ids == ["vol0-vss1", "vol0-vss2", "vol1-vss1", "vol1-vss2"]


def test_a_disk_image_scan_reads_shadow_copies_at_its_volumes(tmp_path, monkeypatch):
    image = tmp_path / "disk.raw"
    image.write_bytes(b"\0" * 4096)
    seen = {}

    def mount_image(path, dest, ctx):
        (dest / "vol1").mkdir()
        ctx.offsets[dest / "vol1"] = GPT_DATA
        return [dest / "vol1"]

    def vss(raw, dest, ctx, offsets=None, notes=None):
        seen.update(offsets=offsets, notes=notes)
        return []

    monkeypatch.setattr(cli, "mount_image", mount_image, raising=False)
    monkeypatch.setattr(containers, "mount_image", mount_image)
    monkeypatch.setattr(containers, "mount_vss", vss)
    monkeypatch.setattr(containers, "check_sudo", lambda: None)
    monkeypatch.setattr(cli, "discover", lambda *a, **k: [])
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    args = argparse.Namespace(
        path=str(image), case="c1", yes=True, hostname="WKS10", all_logs=False,
        no_hayabusa=True, skip_triage=True, vss=True,
    )  # fmt: skip
    with pytest.raises(SystemExit):  # nothing to ingest on the stand-in volume
        cli.cmd_scan(args)
    assert seen["offsets"] == {"vol1": GPT_DATA} and seen["notes"] is not None
