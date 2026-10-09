"""SHA-256 file hashing for forensic provenance."""

from __future__ import annotations

from pathlib import Path

from sift_common.file_identity import NotRegularFile, hash_file


def sha256_file(path: Path) -> str:
    """SHA-256 of a regular file, through sift-common's file identity, so it
    matches the registry's and run_command's hash of the same file. A FIFO,
    device or directory is an OSError, without being read."""
    try:
        return hash_file(path).sha256
    except NotRegularFile as e:
        raise OSError(str(e)) from e
