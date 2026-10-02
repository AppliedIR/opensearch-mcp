"""An ingest whose worker dies before writing a status still shows, as failed.

`idx_ingest` wrote no status at all, and the memory launcher's only record
was a pid-0 placeholder it removed after the spawn, so a worker that died
at argparse or at mount left nothing: the start said `started`, and
idx_ingest_status showed nothing. The launchers now write a `starting`
record under the worker's pid, and a dead worker's status carries the end of
its log. These run real workers, in a scratch HOME; the cluster isn't used.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

from opensearch_mcp import ingest_status, shard_capacity
from opensearch_mcp import server as srv

FAKE_WORKER = """
import os, sys, time
from datetime import datetime, timezone
from opensearch_mcp.ingest_status import write_status
rid = os.environ["VHIR_INGEST_RUN_ID"]
t0 = datetime.now(timezone.utc).isoformat()
hosts = [{"hostname": "h1", "artifacts": [{"name": "x", "status": "running"}]}]
write_status("c1", os.getpid(), rid, "running", hosts, {"indexed": 5}, t0)
time.sleep(float(sys.argv[1]))
hosts[0]["artifacts"][0]["status"] = "complete"
write_status("c1", os.getpid(), rid, "complete", hosts, {"indexed": 10}, t0)
"""


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A scratch HOME with an active case, an image and a memory dump; the
    workers inherit the HOME, so their status files land beside ours."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / ".vhir" / "ingest-status")
    case_dir = tmp_path / "cases" / "c1"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: c1\n")
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "active_case").write_text(str(case_dir))
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.raw").write_bytes(b"\0" * 4096)
    (evidence / "mem.raw").write_bytes(b"\0" * 4096)
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    monkeypatch.setattr(srv, "get_client", lambda: mock.MagicMock())
    monkeypatch.setattr(srv, "_get_os", lambda: mock.MagicMock())
    return evidence


def _final(timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        ingests = srv.idx_ingest_status(case_id="c1").get("ingests", [])
        if ingests and ingests[0]["status"] in ("failed", "complete"):
            return ingests[0]
        if time.monotonic() > deadline:
            return {"status": None, "ingests": ingests}
        time.sleep(0.25)


def test_a_memory_worker_that_dies_at_argparse(case, monkeypatch):
    spawn = srv._spawn_ingest
    monkeypatch.setattr(srv, "_spawn_ingest", lambda cmd, *a: spawn(cmd + ["--no-such-flag"], *a))
    assert (
        srv.idx_ingest_memory(path=str(case / "mem.raw"), hostname="h1", dry_run=False)["status"]
        == "started"
    )
    status = _final()
    assert status["status"] == "failed", status
    assert any("unrecognized arguments: --no-such-flag" in line for line in status["log_tail"]), (
        status
    )


def test_an_image_that_cannot_be_mounted(case, monkeypatch, tmp_path):
    """The mount step needs fdisk; the worker's PATH here has none."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    path = f"{bindir}:/usr/bin:/bin"
    if shutil.which("fdisk", path=path):
        pytest.skip("fdisk is on /usr/bin or /bin here")
    monkeypatch.setenv("PATH", path)
    resp = srv.idx_ingest(path=str(case / "disk.raw"), hostname="h1", dry_run=False)
    assert resp["status"] == "started", resp
    status = _final()
    assert status["status"] == "failed", status
    tail = status["log_tail"]
    assert "Mounting disk.raw..." in tail, status
    assert any("'fdisk'" in line for line in tail), status


def test_a_worker_that_runs_still_goes_running_then_complete(case, monkeypatch, tmp_path):
    worker = tmp_path / "worker.py"
    worker.write_text(FAKE_WORKER)
    spawn = srv._spawn_ingest
    monkeypatch.setattr(
        srv, "_spawn_ingest", lambda cmd, *a: spawn([sys.executable, str(worker), "2"], *a)
    )
    srv.idx_ingest_memory(path=str(case / "mem.raw"), hostname="h1", dry_run=False)
    seen = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ingests = srv.idx_ingest_status(case_id="c1").get("ingests", [])
        status = ingests[0]["status"] if ingests else None
        if not seen or seen[-1] != status:
            seen.append(status)
        if status == "complete":
            break
        time.sleep(0.1)
    assert "failed" not in seen, json.dumps(seen)
    assert seen[-1] == "complete" and "running" in seen, seen


def test_a_starting_record_never_replaces_the_workers(case):
    ingest_status.write_status("c1", 77, "r", "running", [], {"indexed": 3}, "t0")
    ingest_status.write_status("c1", 77, "r", "starting", [], {"indexed": 0}, "t0")
    (path,) = ingest_status._STATUS_DIR.glob("*.json")
    record = json.loads(path.read_text())
    assert (record["status"], record["totals"]) == ("running", {"indexed": 3})


def test_an_archive_password_reaches_neither_the_log_nor_the_status(case, monkeypatch, tmp_path):
    """A failed extraction printed the exception, which quotes the 7z
    command and its -p<password>. This 7z echoes its arguments back too."""
    secret = "s3cret-Pw-7f2a"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "7z").write_text('#!/bin/sh\necho "ERROR: Wrong password, args: $*" >&2\nexit 2\n')
    (bindir / "7z").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setenv("VHIR_ARCHIVE_PASSWORD", secret)
    (case / "mem.zip").write_bytes(b"PK\x03\x04" + b"\0" * 60)
    resp = srv.idx_ingest_memory(path=str(case / "mem.zip"), hostname="h1", dry_run=False)
    assert resp["status"] == "started", resp
    status = _final()
    assert status["status"] == "failed", status
    assert secret not in json.dumps(status)
    assert secret not in Path(resp["log_file"]).read_text()
    assert any(
        "Failed to extract" in line and "7z exited 2" in line for line in status["log_tail"]
    )


def _pieces(secret: str, n: int = 5) -> list[str]:
    return [secret[i : i + n] for i in range(len(secret) - n + 1)]


def test_no_piece_of_the_password_survives_the_cut(case, monkeypatch, tmp_path):
    """7z's output is cut to its last 500 characters. Cut before replacing
    the password, and a window starting inside it keeps a piece."""
    secret = "s3cret-Pw-7f2a"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "7z").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in -p*) pw="${a#-p}";; esac; done\n'
        "printf 'ERROR %s' \"$pw\" >&2\n"
        "head -c 495 /dev/zero | tr '\\0' y >&2\n"
        "exit 2\n"
    )
    (bindir / "7z").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setenv("VHIR_ARCHIVE_PASSWORD", secret)
    (case / "mem.zip").write_bytes(b"PK\x03\x04" + b"\0" * 60)
    resp = srv.idx_ingest_memory(path=str(case / "mem.zip"), hostname="h1", dry_run=False)
    status = _final()
    assert status["status"] == "failed", status
    seen = json.dumps(status) + Path(resp["log_file"]).read_text()
    assert [p for p in _pieces(secret) if p in seen] == []
    assert any("7z exited 2" in line for line in status["log_tail"]), status


def test_a_7z_timeout_doesnt_print_the_password(case, monkeypatch, capsys):
    """A timeout's message quotes the command too."""
    import subprocess

    from opensearch_mcp import ingest_cli

    secret = "s3cret-Pw-7f2a"
    monkeypatch.setenv("VHIR_ARCHIVE_PASSWORD", secret)
    real_run = subprocess.run

    def run(cmd, *a, **k):
        if cmd and cmd[0] == "7z":
            raise subprocess.TimeoutExpired(cmd, 600)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", run)
    (case / "mem.zip").write_bytes(b"PK\x03\x04" + b"\0" * 60)
    args = argparse.Namespace(
        path=str(case / "mem.zip"), case="c1", hostname="h1", tier=1, plugins=None, yes=True
    )
    with pytest.raises(SystemExit):
        ingest_cli.cmd_ingest_memory(args)
    out = capsys.readouterr()
    printed = out.out + out.err
    assert secret not in printed
    assert "7z timed out after 600s" in printed
