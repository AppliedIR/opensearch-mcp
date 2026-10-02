"""A password-protected archive ingested through MCP extracts, or fails at once.

The worker read VHIR_ARCHIVE_PASSWORD only when a config file was given,
which MCP never passes, so 7z ran without -p and prompted. And every worker
inherited the server's stdin, which under MCP is the JSON-RPC pipe: 7z
waited on it, or took a request as the password. Each row runs a server in a
child process whose stdin is a pipe held open, as MCP's is, and ingests a
real zip through the real launcher and worker.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("7z") is None, reason="7z isn't installed")

PASSWORD = "Corr3ct-PW-81"

SERVER = """
import json, sys, time
from unittest import mock
import opensearch_mcp.shard_capacity as sc
sc.check_shard_headroom = lambda *a, **k: (True, "")
from opensearch_mcp import server as srv
srv.get_client = lambda: mock.MagicMock()
srv._get_os = lambda: mock.MagicMock()
if sys.argv[1] == "ingest":
    r = srv.idx_ingest(path=sys.argv[2], hostname="h1", password=sys.argv[3], dry_run=False)
    print(json.dumps({"log_file": r["log_file"]}), flush=True)
else:
    log = open(sys.argv[2], "w")
    worker = [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()), flush=True)"]
    srv._spawn_ingest(worker, {"PATH": sys.argv[3]}, log, "stdin-row")
    print(json.dumps({"log_file": sys.argv[2]}), flush=True)
time.sleep(60)
"""


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    case = home / "cases" / "c1"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: c1\n")
    (home / ".vhir").mkdir()
    (home / ".vhir" / "active_case").write_text(str(case))
    return home


def _server(home: Path, *args: str, feed: bytes = b"", until=(), timeout: float = 20) -> str:
    """Run the server child, write `feed` into its stdin and keep it open,
    and return its worker's log once it contains one of `until`."""
    env = {
        "HOME": str(home),
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "PYTHONPATH": os.pathsep.join(sys.path),
    }
    proc = subprocess.Popen(
        [sys.executable, "-c", SERVER, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env=env,
    )
    text = ""
    try:
        proc.stdin.write(feed)
        proc.stdin.flush()
        log = Path(json.loads(proc.stdout.readline())["log_file"])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = log.read_text(errors="replace") if log.exists() else ""
            if any(u in text for u in until):
                break
            time.sleep(0.25)
    finally:
        proc.stdin.close()  # a worker still waiting on the pipe sees EOF
        proc.kill()
        proc.wait()
    return text


def _ingest(tmp_path: Path, password: str) -> str:
    home = _home(tmp_path)
    content = tmp_path / "content" / "host-a"
    content.mkdir(parents=True)
    (content / "notes.txt").write_text("not an artifact\n")
    archive = tmp_path / "triage.zip"
    subprocess.run(
        ["7z", "a", f"-p{PASSWORD}", "-tzip", str(archive), "host-a"],
        cwd=content.parent,
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    return _server(
        home, "ingest", str(archive), password, until=("Scanning...", "CalledProcessError")
    )


def test_the_right_password_extracts(tmp_path):
    log = _ingest(tmp_path, PASSWORD)
    assert "Extracting triage.zip..." in log and "Scanning..." in log, log
    assert PASSWORD not in log


def test_a_wrong_password_fails_at_once(tmp_path):
    log = _ingest(tmp_path, "wrong-pw-55")
    assert "CalledProcessError" in log and "-p***" in log, log
    assert "wrong-pw-55" not in log


def test_no_password_fails_at_once(tmp_path):
    log = _ingest(tmp_path, "")
    assert "CalledProcessError" in log, log


@pytest.mark.parametrize("launch", ["scope", "scope failed", "no systemd-run"])
def test_a_worker_reads_nothing_from_the_servers_stdin(tmp_path, launch):
    """Each of the launcher's three ways of starting a worker."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if launch == "scope failed":
        (bindir / "systemd-run").write_text("#!/bin/sh\nexit 1\n")
        (bindir / "systemd-run").chmod(0o755)
        (bindir / "systemctl").write_text("#!/bin/sh\nexit 0\n")
        (bindir / "systemctl").chmod(0o755)
    path = str(bindir) if launch == "no systemd-run" else f"{bindir}:/usr/bin:/bin"
    request = b'{"jsonrpc": "2.0", "id": 7, "method": "tools/call"}\n'
    log = _server(
        _home(tmp_path), "spawn", str(tmp_path / "worker.log"), path, feed=request, until=("'",)
    )
    assert log.strip().splitlines()[-1] == "''", log
