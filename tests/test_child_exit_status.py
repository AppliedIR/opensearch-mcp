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
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


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


# systemd-run --scope runs the command in place and returns its exit status.
_SCOPE_STUB = 'while [ "${1#--}" != "$1" ]; do shift; done\nexec "$@"'


def _launches(tmp_path, env: dict, exit_code: int = 3, runs: int = 3) -> list[list[str]]:
    """Each run's launches of a worker that exits at once, as the cgroup
    each launch ran in."""
    return _run(
        tmp_path,
        f"""
        import uuid
        r = []
        for i in range({runs}):
            log = {str(tmp_path)!r} + f"/launches-{{i}}"
            open(log, "w").close()
            body = f"/usr/bin/tail -1 /proc/self/cgroup >> {{log}}; exit {exit_code}"
            cmd = ["/bin/sh", "-c", body]
            proc = server._spawn_ingest(cmd, dict({env!r}), subprocess.DEVNULL, str(uuid.uuid4()))
            proc.wait()
            r.append([line.rsplit("/", 1)[-1] for line in open(log).read().splitlines()])
        print(json.dumps(r))
        """,
    )


def test_a_worker_that_fails_fast_is_launched_once(tmp_path):
    """With --scope the worker's exit status comes back as systemd-run's, so
    a worker that failed within the first 0.3 s was run again, outside its
    memory limit."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _stub(bindir, "systemd-run", _SCOPE_STUB)
    _stub(bindir, "systemctl", "exit 0")
    runs = _launches(tmp_path, {"PATH": f"{bindir}:/usr/bin:/bin"})
    assert [len(r) for r in runs] == [1, 1, 1], runs


def _user_scopes_start() -> bool:
    env = {
        **os.environ,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }
    try:
        cmd = ["systemd-run", "--user", "--scope", "--quiet", "true"]
        return subprocess.run(cmd, env=env, capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(not _user_scopes_start(), reason="no user systemd scopes here")
def test_a_worker_that_fails_fast_is_launched_once_in_its_scope(tmp_path):
    runs = _launches(tmp_path, {"PATH": "/usr/bin:/bin"})
    assert [len(r) for r in runs] == [1, 1, 1], runs
    assert all(r[0].startswith("vhir-ingest-") for r in runs), runs


def test_with_no_systemd_run_the_worker_is_launched_once(tmp_path):
    bindir = tmp_path / "empty"
    bindir.mkdir()
    runs = _launches(tmp_path, {"PATH": str(bindir)})
    assert [len(r) for r in runs] == [1, 1, 1], runs


@pytest.mark.skipif(shutil.which("systemd-run") is None, reason="no systemd-run here")
def test_with_no_user_bus_the_worker_is_launched_once(tmp_path):
    nowhere = tmp_path / "no-runtime"
    env = {
        "PATH": "/usr/bin:/bin",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={nowhere}/bus",
        "XDG_RUNTIME_DIR": str(nowhere),
    }
    runs = _launches(tmp_path, env, exit_code=0)
    assert [len(r) for r in runs] == [1, 1, 1], runs
    assert not any(r[0].startswith("vhir-ingest-") for r in runs), runs
