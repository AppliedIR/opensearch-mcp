"""What a scan had to say reaches its status even when it stops early.

A scan's warnings (a shadow-copy read that failed, a volume that didn't mount)
were written to the status only by its last step. A scan that stopped before
it, for example a zip whose image's live volume holds no host, kept them only
in its log, and the status shows only the log's last lines. They are now
written to the status when the scan stops early too. Mounts, the archive and
the ingest are stand-ins.
"""

from __future__ import annotations

import argparse
import os
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.containers as C
import opensearch_mcp.hostname as hn
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv

UNREAD = "shadow copies on vol0 (offset 1048576) couldn't be read: none of its 2 stores mounted"


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-1")  # the worker's run, as launched
    # the launcher's record, as idx_ingest writes it before the worker starts
    ingest_status.write_status(
        "c1", os.getpid(), "run-1", "starting", [], {}, "2026-10-08T00:00:00Z"
    )
    return path


def _scan(tmp_path, monkeypatch, live_windows, ingest):
    """Scan a zip holding a raw image with --vss: its shadow-copy read fails."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    work = tmp_path / "work"
    work.mkdir()
    archive = tmp_path / "evidence" / "collection.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK")

    def mount(img, dest, ctx):
        v = dest / "vol0"
        v.mkdir()
        if live_windows:
            (v / "Windows/System32/config").mkdir(parents=True)
            (v / "Windows/System32/config/SYSTEM").write_bytes(b"x")
        ctx.offsets[v] = 1048576
        return [v]

    def vss(raw, dest, ctx, offsets=None, notes=None):  # as mount_vss reports a failed read
        ctx.failures.append(UNREAD)
        return []

    for name, value in (
        ("detect_container", lambda p: "archive"),
        ("cleanup_orphaned_mounts", lambda: None),
        (
            "extract_container",
            lambda path, dest, password=None: (dest / "disk.raw").write_bytes(b"\0"),
        ),
        ("is_velociraptor_collection", lambda p: False),
        ("make_ingest_tmpdir", lambda case_id: work),
        ("mount_image", mount),
        ("mount_vss", vss),
        ("cleanup_tmpdir", lambda *a, **k: None),
        ("check_sudo", lambda: None),
    ):
        monkeypatch.setattr(C, name, value)
    monkeypatch.setattr(cli, "ingest", ingest)
    monkeypatch.setattr(cli, "_image_hosts", lambda *a, **k: ([], set(), []))
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(hn, "detect_hostname_from_volume", lambda v: None)
    args = argparse.Namespace(
        path=str(archive), case="c1", yes=True, hostname=None, vss=True,
        all_logs=False, no_hayabusa=True, skip_triage=True,
    )  # fmt: skip
    cli.cmd_scan(args)


def _warnings():
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status.get("warnings", [])


def test_a_scan_that_finds_no_host_keeps_its_shadow_copy_warning(
    tmp_path, monkeypatch, status_dir
):
    """The live volume holds no host and its shadow copies couldn't be read."""
    with pytest.raises(SystemExit):
        _scan(tmp_path, monkeypatch, False, MagicMock())
    assert f"mount: {UNREAD}" in _warnings()


def test_a_scan_whose_ingest_fails_keeps_its_shadow_copy_warning(
    tmp_path, monkeypatch, status_dir
):
    def ingest(**kw):
        raise RuntimeError("cluster unreachable")

    with pytest.raises(RuntimeError):
        _scan(tmp_path, monkeypatch, True, ingest)
    assert f"mount: {UNREAD}" in _warnings()
