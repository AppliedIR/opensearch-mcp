"""Tests for manifest generation and verification."""

import json

from opensearch_mcp.manifest import (
    _manifest_hash,
    sha256_file,
    verify_manifest,
    write_manifest,
)


class TestSha256File:
    def test_known_content(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = sha256_file(f)
        assert len(h) == 64
        assert h == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        h = sha256_file(f)
        assert len(h) == 64

    def test_binary_file(self, tmp_path):
        f = tmp_path / "binary.bin"
        f.write_bytes(bytes(range(256)) * 1000)
        h = sha256_file(f)
        assert len(h) == 64


class TestManifestHash:
    def test_deterministic(self):
        data = {"a": 1, "b": 2, "manifest_sha256": ""}
        h1 = _manifest_hash(data)
        h2 = _manifest_hash(data)
        assert h1 == h2

    def test_changes_on_different_data(self):
        d1 = {"a": 1, "manifest_sha256": ""}
        d2 = {"a": 2, "manifest_sha256": ""}
        assert _manifest_hash(d1) != _manifest_hash(d2)

    def test_ignores_manifest_sha256_value(self):
        d1 = {"a": 1, "manifest_sha256": "old_hash"}
        d2 = {"a": 1, "manifest_sha256": "different_hash"}
        assert _manifest_hash(d1) == _manifest_hash(d2)


class TestWriteManifest:
    def test_creates_manifest_file(self, tmp_path):
        manifest_dir = tmp_path / "manifests"
        path = write_manifest(
            manifest_dir=manifest_dir,
            case_id="test-001",
            hostname="HOST01",
            index_name="case-test-001-evtx-host01",
            examiner="tester",
            file_results=[
                {
                    "path": "/evidence/Security.evtx",
                    "sha256": "abc123",
                    "bytes": 1024,
                    "events_indexed": 100,
                    "events_skipped": 2,
                    "status": "ok",
                }
            ],
            filters={"time_from": None, "time_to": None, "reduced": False},
            elapsed_seconds=5.0,
        )
        assert path.exists()
        assert path.suffix == ".json"

        data = json.loads(path.read_text())
        assert data["manifest_version"] == 1
        assert data["case_id"] == "test-001"
        assert data["hostname"] == "HOST01"
        assert data["examiner"] == "tester"
        assert len(data["files"]) == 1
        assert data["files"][0]["sha256"] == "abc123"
        assert data["totals"]["events_indexed"] == 100
        assert data["totals"]["events_skipped"] == 2
        assert data["totals"]["files_failed"] == 0
        assert data["manifest_sha256"] != ""

    def test_self_hash_verifiable(self, tmp_path):
        manifest_dir = tmp_path / "manifests"
        path = write_manifest(
            manifest_dir=manifest_dir,
            case_id="test-001",
            hostname="HOST01",
            index_name="case-test-001-evtx-host01",
            examiner="tester",
            file_results=[],
            filters={},
            elapsed_seconds=1.0,
        )
        valid, msg = verify_manifest(path)
        assert valid, msg

    def test_tampered_manifest_fails_verification(self, tmp_path):
        manifest_dir = tmp_path / "manifests"
        path = write_manifest(
            manifest_dir=manifest_dir,
            case_id="test-001",
            hostname="HOST01",
            index_name="case-test-001-evtx-host01",
            examiner="tester",
            file_results=[],
            filters={},
            elapsed_seconds=1.0,
        )
        # Tamper with the manifest
        data = json.loads(path.read_text())
        data["case_id"] = "tampered"
        path.write_text(json.dumps(data))

        valid, msg = verify_manifest(path)
        assert not valid
        assert "mismatch" in msg.lower()

    def test_replaces_chain(self, tmp_path):
        manifest_dir = tmp_path / "manifests"
        # First ingest
        p1 = write_manifest(
            manifest_dir=manifest_dir,
            case_id="test-001",
            hostname="HOST01",
            index_name="case-test-001-evtx-host01",
            examiner="tester",
            file_results=[],
            filters={},
            elapsed_seconds=1.0,
        )
        d1 = json.loads(p1.read_text())
        assert d1["replaces"] is None

        # Second ingest (re-ingest)
        p2 = write_manifest(
            manifest_dir=manifest_dir,
            case_id="test-001",
            hostname="HOST01",
            index_name="case-test-001-evtx-host01",
            examiner="tester",
            file_results=[],
            filters={},
            elapsed_seconds=2.0,
        )
        d2 = json.loads(p2.read_text())
        assert d2["replaces"] == p1.name

    def test_failed_files_recorded(self, tmp_path):
        manifest_dir = tmp_path / "manifests"
        path = write_manifest(
            manifest_dir=manifest_dir,
            case_id="test-001",
            hostname="HOST01",
            index_name="case-test-001-evtx-host01",
            examiner="tester",
            file_results=[
                {
                    "path": "/evidence/Good.evtx",
                    "sha256": "aaa",
                    "bytes": 1024,
                    "events_indexed": 50,
                    "events_skipped": 0,
                    "status": "ok",
                },
                {
                    "path": "/evidence/Bad.evtx",
                    "sha256": "bbb",
                    "bytes": 512,
                    "events_indexed": 0,
                    "events_skipped": 0,
                    "status": "failed",
                    "error": "corrupt header",
                },
            ],
            filters={},
            elapsed_seconds=3.0,
        )
        data = json.loads(path.read_text())
        assert data["totals"]["files_failed"] == 1
        assert data["files"][1]["status"] == "failed"
        assert data["files"][1]["error"] == "corrupt header"
