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
from pathlib import Path
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
[ -n "$VSS_BROKEN" ] && { echo "Unable to open volume: read error at 4096" >&2; exit 1; }
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
    "fusermount": "#!/bin/sh\nexit 0\n",  # the scan's cleanup: nothing was really mounted
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

    def run(ntfs_at, stores_at, offsets, ctx=None):
        with open(image, "r+b") as f:
            for off in ntfs_at:
                f.seek(off + 3)
                f.write(b"NTFS    ")
        monkeypatch.setenv("VSS_AT", " ".join(str(o) for o in stores_at))
        dest = tmp_path / "mnt"
        dest.mkdir()
        notes: list = []
        ctx = ctx or MountContext()
        if "offsets" in inspect.signature(mount_vss).parameters:
            found = mount_vss(image, dest, ctx, offsets, notes)
        else:  # a release before volumes were passed: the whole image
            found = mount_vss(image, dest, ctx)
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


def test_shadow_copies_that_cannot_be_read_are_said_so_not_called_none(vss, monkeypatch):
    monkeypatch.setenv("VSS_BROKEN", "1")
    ctx = MountContext()
    ids, notes, _ = vss([GPT_DATA], [GPT_DATA], {"vol0": 1048576, "vol1": GPT_DATA}, ctx)
    assert ids == [] and notes == []  # never "no shadow copies found"
    assert ctx.failures == [
        f"shadow copies on vol1 (offset {GPT_DATA}) couldn't be read: "
        "Unable to open volume: read error at 4096"
    ]


def test_shadow_copies_that_wont_mount_are_said_so(vss, monkeypatch, tmp_path):
    (tmp_path / "bin" / "vshadowmount").write_text(
        "#!/bin/sh\necho 'fuse: no device' >&2\nexit 1\n"
    )
    ctx = MountContext()
    ids, notes, _ = vss([GPT_DATA], [GPT_DATA], {"vol1": GPT_DATA}, ctx)
    assert ids == [] and notes == []
    assert ctx.failures == [
        f"shadow copies on vol1 (offset {GPT_DATA}) couldn't be read: "
        "vshadowmount failed: fuse: no device"
    ]


def test_each_shadow_copy_knows_the_volume_it_came_from(vss):
    ctx = MountContext()
    vss([1048576, GPT_DATA], [1048576, GPT_DATA], {"vol0": 1048576, "vol1": GPT_DATA}, ctx)
    assert ctx.vss_sources == {
        "vol0-vss1": "vol0",
        "vol0-vss2": "vol0",
        "vol1-vss1": "vol1",
        "vol1-vss2": "vol1",
    }


def test_each_shadow_copy_is_attributed_to_its_own_volumes_host(tmp_path, monkeypatch):
    from _helpers import make_windows_tree

    image = tmp_path / "disk.raw"
    image.write_bytes(b"\0" * 4096)
    offsets = {"vol0": 1048576, "vol1": GPT_DATA}

    def mount_image(path, dest, ctx):
        mounted = []
        for name, off in offsets.items():
            make_windows_tree(dest / name)
            ctx.offsets[dest / name] = off
            mounted.append(dest / name)
        return mounted

    def vss(raw, dest, ctx, offsets=None, notes=None):
        found = []
        for name in ("vol0", "vol1"):
            make_windows_tree(dest / f"{name}-vss1")
            ctx.__dict__.setdefault("vss_sources", {})[f"{name}-vss1"] = name
            found.append((f"{name}-vss1", dest / f"{name}-vss1"))
        return found

    seen = {}

    def ingest(hosts, **kw):
        seen["hosts"] = list(hosts)
        raise SystemExit(0)

    monkeypatch.setattr(containers, "mount_image", mount_image)
    monkeypatch.setattr(containers, "mount_vss", vss)
    monkeypatch.setattr(containers, "check_sudo", lambda: None)
    monkeypatch.setattr(cli, "ingest", ingest)
    monkeypatch.setattr(cli, "_image_hosts", lambda *a, **k: ([], set(), []))
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    args = argparse.Namespace(
        path=str(image), case="c1", yes=True, hostname=None, all_logs=False,
        no_hayabusa=True, skip_triage=True, vss=True,
    )  # fmt: skip
    with pytest.raises(SystemExit):
        cli.cmd_scan(args)
    by_vss = {h.vss_id: h for h in seen["hosts"]}
    live = {Path(h.volume_root).name: h for h in seen["hosts"] if h.vss_id == "live"}
    assert set(live) == {"vol0", "vol1"}
    assert live["vol0"].unit_locator != live["vol1"].unit_locator  # two units to tell apart
    for name in ("vol0", "vol1"):
        shadow = by_vss[f"{name}-vss1"]
        assert shadow.hostname == live[name].hostname
        assert shadow.unit_locator == live[name].unit_locator


def _scan_shadow_copies(tmp_path, monkeypatch, capsys, wiped=(), hostname=None, live=("vol0",)):
    """cmd_scan of a two-volume image whose shadow copies are on vol1: each
    volume in `live` holds Windows, a `wiped` one holds nothing. The real
    mount_vss runs, with the stand-in tools; returns the hosts and stdout."""
    from _helpers import make_windows_tree

    image = tmp_path / "disk.raw"
    with open(image, "r+b") as f:
        f.seek(GPT_DATA + 3)
        f.write(b"NTFS    ")
    monkeypatch.setenv("VSS_AT", str(GPT_DATA))
    offsets = {"vol0": 1048576, "vol1": GPT_DATA}

    def mount_image(path, dest, ctx):
        for name, off in offsets.items():
            if name in live:
                make_windows_tree(dest / name)
            else:
                (dest / name).mkdir()
            ctx.offsets[dest / name] = off
        return [dest / name for name in offsets]

    seen = {"hosts": []}

    def ingest(hosts, **kw):
        seen["hosts"] = list(hosts)
        raise SystemExit(0)

    def stores(raw, dest, ctx, *a, **k):  # vssN files become trees, as mounted
        found = mount_vss(raw, dest, ctx, *a, **k)
        for _, mp in found:
            make_windows_tree(mp)
        return found

    monkeypatch.setattr(containers, "mount_image", mount_image)
    monkeypatch.setattr(containers, "mount_vss", stores)
    monkeypatch.setattr(containers, "check_sudo", lambda: None)
    monkeypatch.setattr(cli, "ingest", ingest)
    monkeypatch.setattr(cli, "_image_hosts", lambda *a, **k: ([], set(), []))
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    args = argparse.Namespace(
        path=str(image), case="c1", yes=True, hostname=hostname, all_logs=False,
        no_hayabusa=True, skip_triage=True, vss=True,
    )  # fmt: skip
    with pytest.raises(SystemExit):
        cli.cmd_scan(args)
    return seen["hosts"], capsys.readouterr()


def test_a_shadow_copy_of_a_wiped_volume_keeps_that_volumes_unit(
    vss, tmp_path, monkeypatch, capsys
):
    hosts, _ = _scan_shadow_copies(tmp_path, monkeypatch, capsys)
    (shadow,) = [h for h in hosts if h.vss_id == "vss1"]
    (live,) = [h for h in hosts if h.vss_id == "live"]  # vol0's
    assert shadow.unit_locator.endswith(f"disk.raw@{GPT_DATA}")
    assert shadow.unit_locator != live.unit_locator
    assert shadow.hostname.endswith("-vol1") and shadow.hostname != live.hostname
    assert shadow.name_origin == "folder"


def test_a_shadow_copy_of_a_wiped_volume_takes_the_examiners_name(
    vss, tmp_path, monkeypatch, capsys
):
    hosts, _ = _scan_shadow_copies(tmp_path, monkeypatch, capsys, hostname="WKS50")
    (shadow,) = [h for h in hosts if h.vss_id == "vss1"]
    assert (shadow.hostname, shadow.name_origin) == ("WKS50", "argument")
    assert shadow.unit_locator.endswith(f"disk.raw@{GPT_DATA}")


def test_a_shadow_copy_with_no_live_host_has_a_unit_that_outlasts_the_run(
    vss, tmp_path, monkeypatch, capsys
):
    hosts, _ = _scan_shadow_copies(tmp_path, monkeypatch, capsys, live=())
    assert sorted(h.vss_id for h in hosts) == ["vss1", "vss2"]
    (unit,) = {h.unit_locator for h in hosts}  # both stores: vol1's unit
    assert unit.endswith(f"disk.raw@{GPT_DATA}")
    assert "ingest-" not in unit  # never the run's temporary mount


def test_shadow_copies_whose_stores_all_fail_to_mount_are_not_called_none(
    vss, tmp_path, monkeypatch, capsys
):
    (tmp_path / "bin" / "sudo").write_text("#!/bin/sh\nexit 32\n")
    hosts, out = _scan_shadow_copies(tmp_path, monkeypatch, capsys, live=())
    assert hosts == []  # nothing to ingest
    assert "No volume shadow copies found" not in out.out
    assert f"shadow copies on vol1 (offset {GPT_DATA}) couldn't be read: " in out.err
    assert "none of its 2 stores mounted" in out.err


def test_shadow_copies_with_no_reader_installed_are_not_called_none(
    vss, tmp_path, monkeypatch, capsys
):
    (tmp_path / "bin" / "vshadowinfo").unlink()
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))  # the stand-ins, and no vshadowinfo
    hosts, out = _scan_shadow_copies(tmp_path, monkeypatch, capsys)
    assert len(hosts) == 1  # vol0, and no shadow copy
    assert "No volume shadow copies found" not in out.out
    assert f"shadow copies on vol1 (offset {GPT_DATA}) couldn't be read: " in out.err
    assert "vshadowinfo didn't run" in out.err


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_volume_whose_boot_sector_cannot_be_read_is_not_called_none(vss, tmp_path):
    image = tmp_path / "disk.raw"
    image.chmod(0)
    ctx, notes = MountContext(), []
    try:
        found = mount_vss(image, tmp_path, ctx, {"vol1": GPT_DATA}, notes)
    finally:
        image.chmod(0o600)
    assert found == [] and notes == []  # never "no shadow copies found"
    assert ctx.failures == [
        f"shadow copies on vol1 (offset {GPT_DATA}) couldn't be read: "
        "its boot sector couldn't be read (Permission denied)"
    ]
