"""`--vss` reads the shadow copies of a disk image found inside an archive.

The scan found the image's shadow copies and printed "Found N volume shadow
copies", then never ingested them: hosts for shadow copies were made only for
a disk image given directly. An E01 in an archive was also read at the E01
file instead of its raw stream, so its shadow copies were never found. Mounts,
shadow-copy reads and the ingest itself are stand-ins; the volumes are trees
on disk.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.containers as C
import opensearch_mcp.hostname as hn
from opensearch_mcp import ingest_cli as cli

LIVE_OFFSET = 1048576


def _volume(root: Path, name: str, windows: bool) -> Path:
    v = root / name
    v.mkdir(parents=True)
    if windows:
        (v / "Windows/System32/config").mkdir(parents=True)
        (v / "Windows/System32/config/SYSTEM").write_bytes(b"x")
        logs = v / "Windows/System32/winevt/Logs"
        logs.mkdir(parents=True)
        (logs / "Security.evtx").write_bytes(b"x" * 100)
    return v


class Stop(Exception):
    pass


def _scan(tmp_path, monkeypatch, image_name, live_windows=True, decoy=False):
    """Scan a zip holding `image_name`, with --vss. Returns what the shadow-copy
    read was given and the hosts handed to ingest."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    work = tmp_path / "work"
    work.mkdir()
    archive = tmp_path / "evidence" / "collection.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK")
    seen: dict = {}

    def extract(path, dest, password=None):
        (dest / image_name).write_bytes(b"\0")
        if decoy:  # a file in the archive at the path an E01's stream is mounted
            (dest / "_ewf").mkdir()
            (dest / "_ewf" / "ewf1").write_bytes(b"decoy")

    def mount(img, dest, ctx):
        if img.suffix.lower() in (".e01", ".ex01"):  # as _mount_ewf does
            (dest / "_ewf").mkdir()
            (dest / "_ewf" / "ewf1").write_bytes(b"\0")
        v = _volume(dest, "vol0", live_windows)
        ctx.offsets[v] = LIVE_OFFSET
        return [v]

    def vss(raw, dest, ctx, offsets=None, notes=None):
        seen["raw"] = raw
        shadow = _volume(dest / "vss", "vss1", True)
        ctx.vss_sources["vss1"] = "vol0"
        return [("vss1", shadow)]

    def ingest(hosts=None, **kw):
        seen["hosts"] = hosts
        raise Stop

    for name, value in (
        ("detect_container", lambda p: "archive"),
        ("cleanup_orphaned_mounts", lambda: None),
        ("extract_container", extract),
        ("is_velociraptor_collection", lambda p: False),
        ("make_ingest_tmpdir", lambda case_id: work),
        ("mount_image", mount),
        ("mount_vss", vss),
        ("cleanup_tmpdir", lambda *a, **k: None),
        ("check_sudo", lambda: None),
    ):
        monkeypatch.setattr(C, name, value)
    monkeypatch.setattr(cli, "ingest", ingest)
    monkeypatch.setattr(
        cli, "_preflight_host_discovery", lambda *a: ({"decisions_applied": []}, None)
    )
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(hn, "detect_hostname_from_volume", lambda v: None)
    args = argparse.Namespace(
        path=str(archive), case="c1", yes=True, hostname=None, vss=True,
        all_logs=False, no_hayabusa=True, skip_triage=True,
    )  # fmt: skip
    with pytest.raises((Stop, SystemExit)) as stopped:
        cli.cmd_scan(args)
    seen["exit"] = stopped.value.code if isinstance(stopped.value, SystemExit) else None
    return seen, work


def _by_vss(hosts):
    return {h.vss_id: h for h in hosts}


def test_a_raw_image_s_shadow_copy_is_ingested_as_its_volume_s_host(tmp_path, monkeypatch):
    seen, work = _scan(tmp_path, monkeypatch, "disk.raw")
    assert seen["exit"] is None
    hosts = _by_vss(seen["hosts"])
    assert set(hosts) == {"live", "vss1"}
    assert seen["raw"] == work / "disk.raw"
    live, shadow = hosts["live"], hosts["vss1"]
    # The same machine: its host name and evidence unit
    assert (shadow.hostname, shadow.unit_locator) == (live.hostname, live.unit_locator)


def test_an_e01_s_shadow_copies_are_read_from_its_raw_stream(tmp_path, monkeypatch):
    seen, work = _scan(tmp_path, monkeypatch, "disk.E01")
    assert seen["raw"] == work / "_ewf" / "ewf1"
    assert set(_by_vss(seen["hosts"])) == {"live", "vss1"}


def test_a_shadow_copy_of_a_wiped_volume_is_filed_under_that_volume(tmp_path, monkeypatch):
    """The live volume holds no OS; its shadow copy does."""
    seen, _ = _scan(tmp_path, monkeypatch, "disk.raw", live_windows=False)
    assert seen["exit"] is None  # never "Use --hostname"
    (shadow,) = seen["hosts"]
    assert shadow.vss_id == "vss1"
    assert shadow.hostname.endswith("-vol0")


def test_a_file_where_an_e01_s_stream_would_be_isn_t_read_for_a_raw_image(tmp_path, monkeypatch):
    seen, work = _scan(tmp_path, monkeypatch, "disk.raw", decoy=True)
    assert seen["raw"] == work / "disk.raw"
