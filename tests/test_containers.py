"""Tests for container handling (containers.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.containers import (
    MountContext,
    cleanup_tmpdir,
    detect_container,
    extract_container,
    is_velociraptor_collection,
    normalize_velociraptor,
    read_velociraptor_hostname,
)

# ---------------------------------------------------------------------------
# detect_container
# ---------------------------------------------------------------------------


class TestDetectContainer:
    def test_zip(self, tmp_path):
        f = tmp_path / "triage.zip"
        f.touch()
        assert detect_container(f) == "archive"

    def test_7z(self, tmp_path):
        f = tmp_path / "triage.7z"
        f.touch()
        assert detect_container(f) == "archive"

    def test_tar_gz(self, tmp_path):
        f = tmp_path / "triage.tar.gz"
        f.touch()
        assert detect_container(f) == "archive"

    def test_tar(self, tmp_path):
        f = tmp_path / "triage.tar"
        f.touch()
        assert detect_container(f) == "archive"

    def test_e01(self, tmp_path):
        f = tmp_path / "evidence.e01"
        f.touch()
        assert detect_container(f) == "ewf"

    def test_ex01(self, tmp_path):
        f = tmp_path / "evidence.ex01"
        f.touch()
        assert detect_container(f) == "ewf"

    def test_vmdk(self, tmp_path):
        f = tmp_path / "disk.vmdk"
        f.touch()
        assert detect_container(f) == "nbd"

    def test_vhd(self, tmp_path):
        f = tmp_path / "disk.vhd"
        f.touch()
        assert detect_container(f) == "nbd"

    def test_vhdx(self, tmp_path):
        f = tmp_path / "disk.vhdx"
        f.touch()
        assert detect_container(f) == "nbd"

    def test_dd(self, tmp_path):
        f = tmp_path / "disk.dd"
        f.touch()
        assert detect_container(f) == "raw"

    def test_raw(self, tmp_path):
        f = tmp_path / "disk.raw"
        f.touch()
        assert detect_container(f) == "raw"

    def test_img(self, tmp_path):
        f = tmp_path / "disk.img"
        f.touch()
        assert detect_container(f) == "raw"

    def test_iso(self, tmp_path):
        f = tmp_path / "evidence.iso"
        f.touch()
        assert detect_container(f) == "raw"

    def test_iso_uppercase(self, tmp_path):
        f = tmp_path / "evidence.ISO"
        f.touch()
        assert detect_container(f) == "raw"

    def test_directory(self, tmp_path):
        assert detect_container(tmp_path) == "directory"

    def test_unknown(self, tmp_path):
        f = tmp_path / "evidence.xyz"
        f.touch()
        assert detect_container(f) == "unknown"


# ---------------------------------------------------------------------------
# extract_container
# ---------------------------------------------------------------------------


class TestExtractContainer:
    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_calls_7z(self, mock_subprocess, tmp_path):
        mock_subprocess.run.return_value = MagicMock(returncode=0)
        src = tmp_path / "test.zip"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        call_args = mock_subprocess.run.call_args[0][0]
        assert call_args[0] == "7z"
        assert str(src) in call_args

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_with_password(self, mock_subprocess, tmp_path):
        mock_subprocess.run.return_value = MagicMock(returncode=0)
        src = tmp_path / "test.7z"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest, password="infected")
        call_args = mock_subprocess.run.call_args[0][0]
        assert "-pinfected" in call_args

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_exit_1_is_warning(self, mock_subprocess, tmp_path):
        """7z exit code 1 (warning) should not raise."""
        mock_subprocess.run.return_value = MagicMock(returncode=1)
        src = tmp_path / "test.zip"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)  # should not raise

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_exit_2_raises(self, mock_subprocess, tmp_path):
        """7z exit code 2+ (error) should raise."""
        import subprocess

        mock_subprocess.run.return_value = MagicMock(returncode=2, stdout=b"", stderr=b"error")
        mock_subprocess.CalledProcessError = subprocess.CalledProcessError
        src = tmp_path / "test.zip"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(subprocess.CalledProcessError):
            extract_container(src, dest)

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_tar(self, mock_subprocess, tmp_path):
        mock_subprocess.run.return_value = MagicMock(returncode=0)
        src = tmp_path / "test.tar.gz"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        call_args = mock_subprocess.run.call_args[0][0]
        assert call_args[0] == "tar"

    def test_unknown_format_raises(self, tmp_path):
        src = tmp_path / "test.xyz"
        src.touch()
        with pytest.raises(ValueError, match="Unknown archive"):
            extract_container(src, tmp_path)


# ---------------------------------------------------------------------------
# MountContext
# ---------------------------------------------------------------------------


class TestMountContext:
    @patch("opensearch_mcp.containers.subprocess")
    def test_cleanup_calls_umount(self, mock_subprocess):
        mock_subprocess.run.return_value.returncode = 0
        ctx = MountContext()
        ctx.add_mount(Path("/mnt/vol0"))
        ctx.add_mount(Path("/mnt/vol1"))
        ctx.cleanup()
        # umount called twice in reverse order
        calls = mock_subprocess.run.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == ["sudo", "umount", "/mnt/vol1"]
        assert calls[1][0][0] == ["sudo", "umount", "/mnt/vol0"]

    @patch("opensearch_mcp.containers.subprocess")
    def test_cleanup_fuse_and_nbd(self, mock_subprocess):
        mock_subprocess.run.return_value.returncode = 0
        ctx = MountContext()
        ctx.add_fuse(Path("/mnt/ewf"))
        ctx.add_nbd("/dev/nbd0")
        ctx.cleanup()
        calls = mock_subprocess.run.call_args_list
        cmds = [c[0][0] for c in calls]
        assert ["fusermount", "-u", "/mnt/ewf"] in cmds
        assert ["sudo", "qemu-nbd", "-d", "/dev/nbd0"] in cmds


# ---------------------------------------------------------------------------
# Velociraptor
# ---------------------------------------------------------------------------


class TestVelociraptor:
    def test_is_velociraptor_collection_true(self, tmp_path):
        (tmp_path / "uploads" / "auto").mkdir(parents=True)
        assert is_velociraptor_collection(tmp_path)

    def test_is_velociraptor_collection_false(self, tmp_path):
        assert not is_velociraptor_collection(tmp_path)

    def test_normalize_velociraptor_decodes_paths(self, tmp_path):
        auto = tmp_path / "uploads" / "auto"
        (auto / "C%3A" / "Windows" / "System32" / "config").mkdir(parents=True)
        (auto / "C%3A" / "Windows" / "System32" / "config" / "SYSTEM").touch()
        (auto / "C%3A" / "Program%20Files").mkdir(parents=True)

        result = normalize_velociraptor(tmp_path)
        assert result == auto
        # C%3A should be renamed to C:
        assert (auto / "C:" / "Windows" / "System32" / "config" / "SYSTEM").is_file()
        # Program%20Files should be renamed to Program Files
        assert (auto / "C:" / "Program Files").is_dir()

    def test_normalize_velociraptor_no_auto_dir_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Not a Velociraptor"):
            normalize_velociraptor(tmp_path)

    def test_read_velociraptor_hostname(self, tmp_path):
        ctx = {
            "client_info": {
                "fqdn": "WORKSTATION01.corp.local",
                "hostname": "WORKSTATION01",
            }
        }
        (tmp_path / "collection_context.json").write_text(json.dumps(ctx))
        assert read_velociraptor_hostname(tmp_path) == "WORKSTATION01.corp.local"

    def test_read_velociraptor_hostname_fallback(self, tmp_path):
        ctx = {"client_info": {"hostname": "WKS01"}}
        (tmp_path / "collection_context.json").write_text(json.dumps(ctx))
        assert read_velociraptor_hostname(tmp_path) == "WKS01"

    def test_read_velociraptor_hostname_missing(self, tmp_path):
        assert read_velociraptor_hostname(tmp_path) is None

    def test_read_velociraptor_hostname_invalid_json(self, tmp_path):
        (tmp_path / "collection_context.json").write_text("not json")
        assert read_velociraptor_hostname(tmp_path) is None


# ---------------------------------------------------------------------------
# cleanup_tmpdir
# ---------------------------------------------------------------------------


class TestCleanupTmpdir:
    def test_removes_directory(self, tmp_path):
        d = tmp_path / "ingest-tmp"
        d.mkdir()
        (d / "file.txt").write_text("test")
        cleanup_tmpdir(d)
        assert not d.exists()

    def test_nonexistent_dir_warns(self, tmp_path, capsys):
        d = tmp_path / "nonexistent"
        cleanup_tmpdir(d)  # should not raise
        # No assertion needed — just verify it doesn't crash


# ---------------------------------------------------------------------------
# _parse_fdisk_output
# ---------------------------------------------------------------------------


class TestParseFdiskOutput:
    def test_parses_mbr_output(self):
        from opensearch_mcp.containers import _parse_fdisk_output

        output = """Disk /dev/sda: 50 GiB, 53687091200 bytes, 104857600 sectors
Sector size (logical/physical): 512 bytes / 512 bytes

Device     Boot   Start       End   Sectors  Size Id Type
/dev/sda1  *       2048   1023999   1021952  499M  7 HPFS/NTFS/exFAT
/dev/sda2       1024000 104857599 103833600 49.5G  7 HPFS/NTFS/exFAT
"""
        parts = _parse_fdisk_output(output)
        assert len(parts) == 2
        assert parts[0]["start"] == 2048
        assert parts[0]["sector_size"] == 512

    def test_empty_output(self):
        from opensearch_mcp.containers import _parse_fdisk_output

        assert _parse_fdisk_output("") == []
