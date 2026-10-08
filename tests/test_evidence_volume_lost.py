"""An evidence volume that goes away mid-ingest fails the host's `evidence`
row, instead of the artifacts read after it reading as done and empty.

The scan, the status and the hayabusa phase's rebuild are real; the tools are
stand-ins. After amcache the volume is "unmounted": its root becomes an empty
folder on another device (what a mount point is after `umount`), or, for a
root inside the mount, goes away. Values are synthetic.
"""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import bulk, ingest_status, parse_delimited
from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost

HAYABUSA = (
    '#!/bin/sh\ncase "$1" in --help|dfir-timeline) [ "$2" = "--help" ] && exit 1 ;; esac\nexit 0\n'
)
ARTIFACTS = ["amcache", "shimcache", "registry", "recyclebin"]


@pytest.fixture
def other_device(tmp_path):
    """An empty folder on a device other than tmp_path's."""
    for base in ("/dev/shm", tempfile.gettempdir(), str(Path.home())):
        if os.path.isdir(base) and os.access(base, os.W_OK):
            if os.stat(base).st_dev != os.stat(tmp_path).st_dev:
                d = Path(tempfile.mkdtemp(dir=base))
                yield d
                shutil.rmtree(d, ignore_errors=True)
                return
    pytest.skip("no writable folder on another device")


@pytest.fixture
def scan(tmp_path, monkeypatch, other_device):
    """`run(layout, unmount, hayabusa)`: a scan of dev01; returns its status.
    layout "root": the mount point is the volume root; "inside": the root is
    M/dev01/C."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-vol")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(
        cli, "_preflight_host_discovery", lambda *a, **k: ({"decisions_applied": []}, None)
    )
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    monkeypatch.setattr(ing, "parse_and_index", MagicMock(return_value=(500, 0, 0)))
    hb = tmp_path / "bin" / "hayabusa"  # writes no CSV: a note, never a failure
    hb.parent.mkdir()
    hb.write_text(HAYABUSA)
    hb.chmod(0o755)
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda n, *a, **k: str(hb) if n == "hayabusa" else real_which(n)
    )
    (tmp_path / "rules" / "config").mkdir(parents=True)
    monkeypatch.setattr(ing, "_resolve_hayabusa_rules_dir", lambda: tmp_path / "rules")
    monkeypatch.setattr(ing, "vhir_dir", lambda: tmp_path / "vhir")
    monkeypatch.setattr(parse_delimited, "ingest_delimited", lambda *a, **k: (0, 0, 0, 0))

    def run(layout="root", unmount=True, hayabusa=False):
        mount = tmp_path / "M"
        root = mount if layout == "root" else mount / "dev01" / "C"
        evtx = root / "Windows/System32/winevt/Logs"
        evtx.mkdir(parents=True)
        (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
        host = DiscoveredHost(hostname="dev01", volume_root=root)
        host.evtx_dir = evtx
        for a in ARTIFACTS:
            (root / a).write_bytes(b"x")
            host.artifacts.append((a, root / a))
        monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])

        def tool(**kw):  # after amcache, the volume is unmounted
            if kw["tool_name"] == "amcache" and unmount:
                shutil.rmtree(mount)
                if layout == "root":
                    mount.symlink_to(other_device)  # an empty folder on another device
            return 10, 0, 0

        monkeypatch.setattr(ing, "run_and_ingest", tool)
        bulk.reset_circuit_breaker()
        cli.cmd_scan(argparse.Namespace(path=str(tmp_path), case="c1", yes=True, hostname="dev01",
                                        all_logs=False, no_hayabusa=not hayabusa,
                                        skip_triage=True))  # fmt: skip
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status, root

    return run


def _evidence(status):
    return [c for c in status["checklist"] if c["artifact"] == "evidence"]


@pytest.mark.parametrize("hayabusa", [False, True], ids=["no hayabusa", "hayabusa"])
@pytest.mark.parametrize("layout", ["root", "inside"])
def test_a_volume_unmounted_mid_ingest_fails_the_hosts_evidence_row(scan, layout, hayabusa):
    status, root = scan(layout, hayabusa=hayabusa)
    (row,) = _evidence(status)
    assert row["status"] == "failed" and str(root) in row["detail"], row
    assert "missing or incomplete" in row["detail"]
    assert status["message"].startswith("Ingest complete with 1 error(s)"), status["message"]


@pytest.mark.parametrize("hayabusa", [False, True], ids=["no hayabusa", "hayabusa"])
def test_anchor_a_volume_that_stays_mounted_has_no_evidence_row(scan, hayabusa):
    status, _ = scan(unmount=False, hayabusa=hayabusa)
    assert _evidence(status) == []
    assert not status["message"].startswith("Ingest complete with"), status["message"]
