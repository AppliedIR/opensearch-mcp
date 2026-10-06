"""MountContext.cleanup() runs twice: the scan's own call, then the atexit hook.

A release that succeeded is never repeated; one that failed is retried by the
next call.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from opensearch_mcp.containers import MountContext


def _context(tmp_path):
    ctx = MountContext()
    ctx.add_nbd("/dev/nbd0")
    ctx.add_loop("/dev/loop7")
    ctx.add_mount(tmp_path / "nbd0p1")
    ctx.add_fuse(tmp_path / "ewf")
    return ctx


RELEASES = [
    ["sudo", "umount", "{tmp}/nbd0p1"],
    ["fusermount", "-u", "{tmp}/ewf"],
    ["sudo", "qemu-nbd", "-d", "/dev/nbd0"],
    ["sudo", "losetup", "-d", "/dev/loop7"],
]


def _releases(tmp_path):
    return [[a.format(tmp=tmp_path) for a in cmd] for cmd in RELEASES]


def test_a_second_cleanup_releases_nothing_again(tmp_path):
    ctx = _context(tmp_path)
    with patch("opensearch_mcp.containers.subprocess.run") as run:
        run.return_value.returncode = 0
        ctx.cleanup()  # the scan's own call
        ctx.cleanup()  # the atexit hook's call
    assert [c.args[0] for c in run.call_args_list] == _releases(tmp_path)


@pytest.mark.parametrize("umount_fails", [1, 2], ids=["lazy umount works", "lazy umount fails"])
def test_a_release_that_failed_is_retried_by_the_next_cleanup(tmp_path, umount_fails):
    ctx = _context(tmp_path)
    fails = {"umount": umount_fails, "fusermount": 1, "qemu-nbd": 1, "losetup": 1}

    def run(cmd, **kw):
        tool = cmd[1] if cmd[0] == "sudo" else cmd[0]
        if fails[tool]:
            fails[tool] -= 1
            return SimpleNamespace(returncode=1, stderr=b"busy")
        return SimpleNamespace(returncode=0, stderr=b"")

    calls = []
    with patch("opensearch_mcp.containers.subprocess.run", side_effect=run) as spy:
        for _ in range(3):
            spy.reset_mock()
            ctx.cleanup()
            calls.append([c.args[0] for c in spy.call_args_list])
    mount = str(tmp_path / "nbd0p1")
    assert calls[0][:2] == [["sudo", "umount", mount], ["sudo", "umount", "-l", mount]]
    retried = _releases(tmp_path)[(1 if umount_fails == 1 else 0) :]
    assert calls[1] == retried  # exactly the releases that failed
    assert calls[2] == []
