"""Importing the server leaves child exit statuses intact.

The module installed a SIGCHLD handler that reaped any child with
waitpid(-1). A captured-output subprocess was then reaped before Python
waited on it, and its exit status read 0: a failed `sudo -n true` read as
sudo available, and a failed systemd-run as started, so the fallback never ran.
Each row runs in a fresh interpreter that imports the server.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path


def _stub(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def _run(tmp_path: Path, code: str, bindir: Path | None = None) -> object:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        "HOME": str(home),
        "PATH": f"{bindir}:/usr/bin:/bin" if bindir else "/usr/bin:/bin",
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        "LANG": "C.UTF-8",
    }
    script = "import json, subprocess\nimport opensearch_mcp.server as server\n" + textwrap.dedent(
        code
    )
    out = subprocess.run(
        [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=120
    )
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_a_captured_exit_status(tmp_path):
    codes = _run(
        tmp_path,
        """
        r = [subprocess.run(["sh", "-c", "echo x; exit 3"], capture_output=True).returncode
             for _ in range(20)]
        print(json.dumps(r))
        """,
    )
    assert codes == [3] * 20


def test_the_dry_run_sees_sudo_unavailable(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _stub(bindir, "sudo", "exit 1")
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "active_case").write_text(str(tmp_path / "cases" / "CASE-1"))
    image = home / "evidence" / "disk.dd"
    image.parent.mkdir()
    image.write_bytes(b"")
    warned = _run(
        tmp_path,
        f"""
        r = [server.idx_ingest(path={str(image)!r}, hostname="h") for _ in range(10)]
        print(json.dumps(["warning" in x for x in r]))
        """,
        bindir,
    )
    assert warned == [True] * 10


def test_a_failed_systemd_run_falls_back(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _stub(bindir, "systemd-run", "exit 1")
    _stub(bindir, "systemctl", "exit 0")  # reset-failed on the stub unit
    args = _run(
        tmp_path,
        f"""
        cmd = ["sh", "-c", "true"]
        env = {{"PATH": {f"{bindir}:/usr/bin:/bin"!r}}}
        r = []
        for i in range(5):
            proc = server._spawn_ingest(cmd, env, subprocess.DEVNULL, f"run{{i:010d}}")
            proc.wait()
            r.append(proc.args == cmd)
        print(json.dumps(r))
        """,
        bindir,
    )
    assert args == [True] * 5
