"""An archive password never appears on 7z's command line, which any local
user can read in /proc. 7z gets it on stdin, in a new session with no
terminal to ask on instead. The archives are real and made here; the
passwords are synthetic.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from opensearch_mcp.containers import _extract_7z

pytestmark = pytest.mark.skipif(shutil.which("7z") is None, reason="7z isn't installed")

PASSWORD = "Synth-Pw-4c19"


def _archive(tmp_path, name, *args, files=("a.txt",), password=PASSWORD):
    src = tmp_path / f"src-{name}"
    src.mkdir()
    for f in files:
        (src / f).write_text(f"content of {f}\n")
    out = tmp_path / name
    pw = [f"-p{password}"] if password else []
    subprocess.run(["7z", "a", *pw, *args, str(out), *files], cwd=src, check=True,
                   capture_output=True)  # fmt: skip
    return out


@pytest.fixture
def archives(tmp_path):
    return {
        "7z, names encrypted": _archive(tmp_path, "h.7z", "-mhe=on"),
        "AES zip": _archive(tmp_path, "aes.zip", "-tzip", "-mem=AES256"),
        "two-entry AES zip": _archive(
            tmp_path, "two.zip", "-tzip", "-mem=AES256", files=("a.txt", "b.txt")
        ),
    }


def test_the_password_is_never_on_a_command_line_while_7z_runs(tmp_path):
    """A poller reads every process's command line during repeated extractions."""
    arc = _archive(tmp_path, "p.7z", "-mhe=on")
    seen, done = [], threading.Event()

    def poll():
        needle = PASSWORD.encode()
        while not done.is_set():
            for pid in os.listdir("/proc"):
                if pid.isdigit():
                    try:
                        if needle in Path(f"/proc/{pid}/cmdline").read_bytes():
                            seen.append(pid)
                    except OSError:
                        pass

    t = threading.Thread(target=poll, daemon=True)
    t.start()
    try:
        for i in range(150):
            dest = tmp_path / f"out{i}"
            dest.mkdir()
            _extract_7z(arc, dest, PASSWORD)
    finally:
        done.set()
        t.join(10)
    assert seen == []


def test_anchor_the_right_password_extracts_every_kind(tmp_path, archives):
    for kind, arc in archives.items():
        dest = tmp_path / f"out-{arc.name}"
        dest.mkdir()
        _extract_7z(arc, dest, PASSWORD)
        assert (dest / "a.txt").read_text() == "content of a.txt\n", kind
    assert (tmp_path / "out-two.zip" / "b.txt").is_file()


@pytest.mark.parametrize("password", ["wrong-pw-55", None], ids=["wrong", "none"])
def test_anchor_a_wrong_or_missing_password_fails_at_once(tmp_path, archives, password):
    for arc in archives.values():
        dest = tmp_path / f"out-{arc.name}-{password}"
        dest.mkdir()
        with pytest.raises(subprocess.CalledProcessError) as e:
            _extract_7z(arc, dest, password)
        assert PASSWORD not in " ".join(e.value.cmd)


def test_anchor_an_unencrypted_archive_with_a_password_given_extracts(tmp_path):
    arc = _archive(tmp_path, "plain.7z", password=None)
    dest = tmp_path / "out"
    dest.mkdir()
    _extract_7z(arc, dest, PASSWORD)
    assert (dest / "a.txt").is_file()


def test_a_caller_with_a_terminal_still_extracts(tmp_path):
    """7z would ask on the caller's terminal, and wait there for an answer."""
    import fcntl
    import termios

    arc = _archive(tmp_path, "t.7z", "-mhe=on")
    dest = tmp_path / "out"
    dest.mkdir()
    master, slave = os.openpty()

    def take_the_terminal():  # in the child: a session whose terminal is the pty
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    code = (
        "import sys; from pathlib import Path; from opensearch_mcp.containers import _extract_7z;"
        f" _extract_7z(Path({str(arc)!r}), Path({str(dest)!r}), {PASSWORD!r}); print('done')"
    )
    p = subprocess.Popen([sys.executable, "-c", code], stdin=slave, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, preexec_fn=take_the_terminal)  # fmt: skip
    os.close(slave)
    try:
        out, err = p.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        pytest.fail("7z waited on the caller's terminal")
    finally:
        os.close(master)
    assert p.returncode == 0 and out.strip() == b"done", err
    assert (dest / "a.txt").is_file()
