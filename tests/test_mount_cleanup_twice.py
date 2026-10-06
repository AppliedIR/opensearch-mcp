"""A second MountContext.cleanup() (the atexit hook after the scan's own call) does nothing."""

from unittest.mock import patch

from opensearch_mcp.containers import MountContext


def test_a_second_cleanup_unmounts_and_disconnects_nothing(tmp_path):
    ctx = MountContext()
    ctx.add_nbd("/dev/nbd0")
    ctx.add_mount(tmp_path / "nbd0p1")
    with patch("opensearch_mcp.containers.subprocess.run") as run:
        run.return_value.returncode = 0
        ctx.cleanup()  # the scan's own call
        ctx.cleanup()  # the atexit hook's call
    calls = [c.args[0] for c in run.call_args_list]
    assert calls == [
        ["sudo", "umount", str(tmp_path / "nbd0p1")],
        ["sudo", "qemu-nbd", "-d", "/dev/nbd0"],
    ]
