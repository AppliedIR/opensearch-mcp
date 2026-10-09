"""Ingest hashes its input files through sift-common's file identity.

One hash for every place that records what a file is, so an ingest's hash of
a file can be compared with the registry's and run_command's. A FIFO, device
or directory is refused as an OSError without being read; it used to be
opened and read, which blocks for ever on a FIFO nothing writes.
"""

from __future__ import annotations

import hashlib
import os
import threading

import pytest

from opensearch_mcp import ingest
from opensearch_mcp.manifest import sha256_file


def _bounded(fn, *args):
    """fn(*args) in a thread, so a regression that blocks fails instead of
    hanging the suite."""
    out: dict = {}

    def run():
        try:
            out["value"] = fn(*args)
        except BaseException as e:  # noqa: BLE001
            out["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(10)
    assert not t.is_alive(), f"{fn.__name__} blocked"
    return out


def test_a_files_hash_is_its_file_identity_hash(tmp_path):
    from sift_common.file_identity import hash_file

    f = tmp_path / "Security.evtx"
    f.write_bytes(b"ElfFile\x00" * 4096)
    assert sha256_file(f) == hashlib.sha256(f.read_bytes()).hexdigest()
    assert sha256_file(f) == hash_file(f).sha256


@pytest.mark.parametrize("kind", ["fifo", "device", "directory"])
def test_a_file_that_isnt_regular_is_an_oserror_and_isnt_read(tmp_path, kind):
    path = {"device": "/dev/null", "directory": str(tmp_path)}.get(kind)
    if kind == "fifo":
        path = str(tmp_path / "pipe")
        os.mkfifo(path)
    out = _bounded(sha256_file, path)
    assert isinstance(out.get("error"), OSError), out
    assert "not a regular file" in str(out["error"])
    assert _bounded(ingest._sha256_or_empty, path) == {"value": ""}


def test_it_requires_a_sift_common_with_file_identity():
    """0.6.4 is the first sift-common with file_identity; an older one would
    fail at import, so it can't be installed under this one."""
    from pathlib import Path

    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert '"sift-common>=0.6.4",' in pyproject
