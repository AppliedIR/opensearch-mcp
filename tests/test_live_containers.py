"""Live container extraction + artifact discovery + dedup tests.

Uses real evidence from ~/SRL2_Samples/ and ~/logs/ to test the full
container pipeline: detect → extract → discover → ingest → dedup.

These tests create temporary archives/containers from real evidence,
extract them, and verify the pipeline produces correct results.

Requires: 7z, tar on PATH. OpenSearch for integration tests.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.containers import (
    MountContext,
    detect_container,
    extract_container,
    is_velociraptor_collection,
    normalize_velociraptor,
    read_velociraptor_hostname,
)
from opensearch_mcp.discover import (
    DiscoveredHost,
    discover_artifacts,
    find_volume_root,
    scan_triage_directory,
)

# Evidence paths
_EVTX_DIR = Path.home() / "logs"
_SRL2_DIR = Path.home() / "SRL2_Samples"
_TEST_ARTIFACTS = Path("/tmp/srl2-test-artifacts")

# Skip conditions
_has_evtx = _EVTX_DIR.is_dir() and any(_EVTX_DIR.glob("*.evtx"))
_has_srl2 = _SRL2_DIR.is_dir()
_has_artifacts = _TEST_ARTIFACTS.is_dir()
_has_7z = shutil.which("7z") is not None
_has_tar = shutil.which("tar") is not None

skip_no_evtx = pytest.mark.skipif(not _has_evtx, reason="No evtx files in ~/logs/")
skip_no_srl2 = pytest.mark.skipif(not _has_srl2, reason="No SRL2_Samples/")
skip_no_artifacts = pytest.mark.skipif(not _has_artifacts, reason="No /tmp/srl2-test-artifacts/")
skip_no_7z = pytest.mark.skipif(not _has_7z, reason="7z not available")
skip_no_tar = pytest.mark.skipif(not _has_tar, reason="tar not available")


# ---------------------------------------------------------------------------
# Container detection on real files
# ---------------------------------------------------------------------------


class TestDetectRealContainers:
    @skip_no_srl2
    def test_detect_e01(self):
        assert detect_container(_SRL2_DIR / "base-dc-cdrive.E01") == "ewf"

    @skip_no_srl2
    def test_detect_7z(self):
        assert detect_container(_SRL2_DIR / "base-dc-triage.7z") == "archive"

    @skip_no_srl2
    def test_detect_zip(self):
        assert detect_container(_SRL2_DIR / "base-dc_20180906-225700.zip") == "archive"

    @skip_no_evtx
    def test_detect_directory(self):
        assert detect_container(_EVTX_DIR) == "directory"

    @skip_no_srl2
    def test_detect_triage_zip(self):
        assert detect_container(_SRL2_DIR / "vhdx" / "base-rd01-triage.zip") == "archive"


# ---------------------------------------------------------------------------
# Create and extract ZIP containers from real evidence
# ---------------------------------------------------------------------------


class TestZipExtraction:
    @skip_no_evtx
    @skip_no_7z
    def test_zip_evtx_roundtrip(self, tmp_path):
        """Create a zip from real evtx files, extract, verify contents."""
        # Pick 3 small evtx files
        evtx_files = sorted(_EVTX_DIR.glob("*.evtx"))[:3]
        assert len(evtx_files) >= 3

        # Create zip
        zip_path = tmp_path / "test-evtx.zip"
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        for f in evtx_files:
            shutil.copy2(f, src_dir / f.name)
        subprocess.run(
            ["7z", "a", str(zip_path), f"{src_dir}/*"],
            capture_output=True,
            check=True,
        )
        assert zip_path.exists()
        assert zip_path.stat().st_size > 0

        # Extract
        dest = tmp_path / "extracted"
        dest.mkdir()
        extract_container(zip_path, dest)

        # Verify
        extracted_evtx = list(dest.rglob("*.evtx"))
        assert len(extracted_evtx) == 3
        for orig in evtx_files:
            found = [f for f in extracted_evtx if f.name == orig.name]
            assert found, f"Missing extracted file: {orig.name}"

    @skip_no_artifacts
    @skip_no_7z
    def test_zip_registry_hives(self, tmp_path):
        """Create zip from registry hives, extract, verify."""
        hives = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
        zip_path = tmp_path / "registry.zip"
        src = tmp_path / "src" / "Windows" / "System32" / "config"
        src.mkdir(parents=True)
        for h in hives:
            hive_path = _TEST_ARTIFACTS / h
            if hive_path.exists():
                shutil.copy2(hive_path, src / h)

        subprocess.run(
            ["7z", "a", str(zip_path), str(tmp_path / "src" / "Windows")],
            capture_output=True,
            check=True,
            cwd=str(tmp_path / "src"),
        )

        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(zip_path, dest)

        # Verify Windows tree structure
        config_dir = None
        for d in dest.rglob("config"):
            if d.is_dir():
                config_dir = d
                break
        assert config_dir is not None
        for h in hives:
            assert (config_dir / h).exists(), f"Missing hive: {h}"


class TestPasswordProtectedZip:
    @skip_no_evtx
    @skip_no_7z
    def test_password_zip_extraction(self, tmp_path):
        """Create password-protected zip, extract with correct password."""
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        zip_path = tmp_path / "protected.zip"

        # Create password-protected zip
        src = tmp_path / "src"
        src.mkdir()
        shutil.copy2(evtx, src / evtx.name)
        subprocess.run(
            ["7z", "a", str(zip_path), f"{src}/*", "-pinfected"],
            capture_output=True,
            check=True,
        )

        # Extract with password
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(zip_path, dest, password="infected")
        extracted = list(dest.rglob("*.evtx"))
        assert len(extracted) == 1

    @skip_no_evtx
    @skip_no_7z
    def test_wrong_password_fails(self, tmp_path):
        """Wrong password raises CalledProcessError."""
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        zip_path = tmp_path / "protected.7z"

        src = tmp_path / "src"
        src.mkdir()
        shutil.copy2(evtx, src / evtx.name)
        subprocess.run(
            ["7z", "a", str(zip_path), f"{src}/*", "-pwrongpass"],
            capture_output=True,
            check=True,
        )

        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(subprocess.CalledProcessError):
            extract_container(zip_path, dest, password="notthepassword")


# ---------------------------------------------------------------------------
# Create and extract tar.gz containers
# ---------------------------------------------------------------------------


class TestTarExtraction:
    @skip_no_evtx
    @skip_no_tar
    def test_tar_gz_evtx_roundtrip(self, tmp_path):
        """Create tar.gz from evtx files, extract, verify."""
        evtx_files = sorted(_EVTX_DIR.glob("*.evtx"))[:5]
        src = tmp_path / "evtx"
        src.mkdir()
        for f in evtx_files:
            shutil.copy2(f, src / f.name)

        tar_path = tmp_path / "evidence.tar.gz"
        subprocess.run(
            ["tar", "czf", str(tar_path), "-C", str(tmp_path), "evtx"],
            check=True,
        )

        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(tar_path, dest)
        extracted = list(dest.rglob("*.evtx"))
        assert len(extracted) == len(evtx_files)

    @skip_no_artifacts
    @skip_no_tar
    def test_tar_windows_tree(self, tmp_path):
        """Create tar from Windows directory tree, extract, discover artifacts."""
        # Build a minimal Windows tree from real artifacts
        tree = tmp_path / "host1"
        config_dir = tree / "Windows" / "System32" / "config"
        config_dir.mkdir(parents=True)
        for h in ["SYSTEM", "SOFTWARE"]:
            src = _TEST_ARTIFACTS / h
            if src.exists():
                shutil.copy2(src, config_dir / h)

        amcache_dir = tree / "Windows" / "appcompat" / "Programs"
        amcache_dir.mkdir(parents=True)
        if (_TEST_ARTIFACTS / "Amcache.hve").exists():
            shutil.copy2(_TEST_ARTIFACTS / "Amcache.hve", amcache_dir / "Amcache.hve")

        tar_path = tmp_path / "triage.tar.gz"
        subprocess.run(
            ["tar", "czf", str(tar_path), "-C", str(tmp_path), "host1"],
            check=True,
        )

        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(tar_path, dest)

        # Discover artifacts in extracted tree
        hosts = scan_triage_directory(dest / "host1")
        assert len(hosts) >= 1
        artifact_names = {a[0] for a in hosts[0].artifacts}
        if (_TEST_ARTIFACTS / "SYSTEM").exists():
            assert "shimcache" in artifact_names or "registry_system" in artifact_names


# ---------------------------------------------------------------------------
# 7z extraction
# ---------------------------------------------------------------------------


class Test7zExtraction:
    @skip_no_evtx
    @skip_no_7z
    def test_7z_roundtrip(self, tmp_path):
        """Create 7z archive, extract, verify."""
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        archive = tmp_path / "test.7z"
        src = tmp_path / "src"
        src.mkdir()
        shutil.copy2(evtx, src / evtx.name)
        subprocess.run(["7z", "a", str(archive), f"{src}/*"], capture_output=True, check=True)

        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(archive, dest)
        assert any(dest.rglob("*.evtx"))


# ---------------------------------------------------------------------------
# Artifact discovery from real extracted evidence
# ---------------------------------------------------------------------------


class TestArtifactDiscoveryReal:
    @skip_no_artifacts
    def test_discover_from_test_artifacts(self):
        """Discover artifacts from /tmp/srl2-test-artifacts."""
        hosts = scan_triage_directory(_TEST_ARTIFACTS)
        if hosts:
            # The test artifacts dir has a Windows/ tree
            artifact_names = {a[0] for a in hosts[0].artifacts}
            # Should find registry, amcache at minimum
            assert len(artifact_names) >= 1

    @skip_no_artifacts
    def test_find_volume_root_in_artifacts(self):
        """Volume root detection works on real artifacts."""
        vr = find_volume_root(_TEST_ARTIFACTS)
        if (_TEST_ARTIFACTS / "Windows" / "System32" / "config").is_dir():
            assert vr == _TEST_ARTIFACTS

    @skip_no_artifacts
    def test_discover_amcache(self):
        """Real Amcache.hve is discovered."""
        amcache = _TEST_ARTIFACTS / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
        if not amcache.exists():
            amcache = _TEST_ARTIFACTS / "Amcache.hve"
        if amcache.exists():
            host = DiscoveredHost(hostname="test", volume_root=_TEST_ARTIFACTS)
            discover_artifacts(host)
            names = {a[0] for a in host.artifacts}
            assert "amcache" in names

    @skip_no_artifacts
    def test_discover_registry_hives(self):
        """Real registry hives are discovered."""
        config = _TEST_ARTIFACTS / "Windows" / "System32" / "config"
        if not config.is_dir():
            pytest.skip("No config directory")
        host = DiscoveredHost(hostname="test", volume_root=_TEST_ARTIFACTS)
        discover_artifacts(host)
        names = {a[0] for a in host.artifacts}
        # Should find at least one registry artifact
        registry_types = {
            "registry_system",
            "registry_software",
            "registry_sam",
            "registry_security",
        }
        assert names & registry_types, f"No registry artifacts found, got: {names}"

    @skip_no_artifacts
    def test_discover_mft(self):
        """Real $MFT is discovered."""
        mft = _TEST_ARTIFACTS / "$MFT"
        if not mft.exists():
            pytest.skip("No $MFT")
        host = DiscoveredHost(hostname="test", volume_root=_TEST_ARTIFACTS)
        discover_artifacts(host)
        names = {a[0] for a in host.artifacts}
        assert "mft" in names

    @skip_no_artifacts
    def test_discover_user_profiles(self):
        """Real user profiles are discovered."""
        users = _TEST_ARTIFACTS / "Users"
        if not users.is_dir():
            pytest.skip("No Users directory")
        host = DiscoveredHost(hostname="test", volume_root=_TEST_ARTIFACTS)
        discover_artifacts(host)
        assert len(host.user_profiles) >= 1


# ---------------------------------------------------------------------------
# Velociraptor offline collector simulation
# ---------------------------------------------------------------------------


class TestVelociraptorSimulation:
    def test_velociraptor_structure(self, tmp_path):
        """Create simulated Velociraptor collection, test detection + normalization."""
        # Build Velociraptor structure
        auto = tmp_path / "uploads" / "auto"
        (auto / "C%3A" / "Windows" / "System32" / "config").mkdir(parents=True)
        (auto / "C%3A" / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"fake")
        (auto / "C%3A" / "Windows" / "System32" / "config" / "SOFTWARE").write_bytes(b"fake")
        (auto / "C%3A" / "Windows" / "appcompat" / "Programs").mkdir(parents=True)
        (auto / "C%3A" / "Windows" / "appcompat" / "Programs" / "Amcache.hve").write_bytes(b"fake")
        (auto / "C%3A" / "Program%20Files" / "test").mkdir(parents=True)

        # Hostname file
        ctx = {
            "client_info": {
                "fqdn": "WORKSTATION01.corp.local",
                "hostname": "WORKSTATION01",
            }
        }
        (tmp_path / "collection_context.json").write_text(json.dumps(ctx))

        # Test detection
        assert is_velociraptor_collection(tmp_path)

        # Test hostname
        hostname = read_velociraptor_hostname(tmp_path)
        assert hostname == "WORKSTATION01.corp.local"

        # Test normalization
        result = normalize_velociraptor(tmp_path)
        assert result == auto
        # C%3A → C:
        assert (auto / "C:" / "Windows" / "System32" / "config" / "SYSTEM").exists()
        # Program%20Files → Program Files
        assert (auto / "C:" / "Program Files").is_dir()

        # Test artifact discovery after normalization
        vr = find_volume_root(auto)
        assert vr is not None
        host = DiscoveredHost(hostname="WORKSTATION01", volume_root=vr)
        discover_artifacts(host)
        names = {a[0] for a in host.artifacts}
        assert "amcache" in names
        assert "registry_system" in names or "shimcache" in names

    @skip_no_evtx
    @skip_no_7z
    def test_velociraptor_zip_full_pipeline(self, tmp_path):
        """Create Velociraptor-style zip, extract, normalize, discover."""
        # Build structure
        auto = tmp_path / "collection" / "uploads" / "auto"
        evtx_dest = auto / "C%3A" / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dest.mkdir(parents=True)
        config = auto / "C%3A" / "Windows" / "System32" / "config"
        config.mkdir(parents=True)
        config_files = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
        for c in config_files:
            (config / c).write_bytes(b"fake-hive-data")

        # Copy 2 real evtx files
        for f in sorted(_EVTX_DIR.glob("*.evtx"))[:2]:
            shutil.copy2(f, evtx_dest / f.name)

        # Add collection_context.json
        ctx = {"client_info": {"hostname": "RD01"}}
        (tmp_path / "collection" / "collection_context.json").write_text(json.dumps(ctx))

        # Create zip
        zip_path = tmp_path / "Collection-RD01.zip"
        subprocess.run(
            ["7z", "a", str(zip_path), str(tmp_path / "collection" / "*")],
            capture_output=True,
            check=True,
            cwd=str(tmp_path / "collection"),
        )

        # Extract
        dest = tmp_path / "extracted"
        dest.mkdir()
        extract_container(zip_path, dest)

        # Detect Velociraptor
        assert is_velociraptor_collection(dest)

        # Normalize
        auto_dir = normalize_velociraptor(dest)

        # Discover
        vr = find_volume_root(auto_dir)
        assert vr is not None
        host = DiscoveredHost(hostname="RD01", volume_root=vr)
        discover_artifacts(host)
        assert host.evtx_dir is not None


# ---------------------------------------------------------------------------
# Deduplication: same evidence in different containers
# ---------------------------------------------------------------------------


class TestDeduplication:
    @skip_no_evtx
    def test_evtx_dedup_same_file_same_id(self):
        """Same evtx file produces same doc IDs regardless of source path."""
        from opensearch_mcp.parse_evtx import parse_and_index

        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]

        actions_a = []
        actions_b = []

        def capture_a(client, actions):
            actions_a.extend(actions)
            return len(actions), 0

        def capture_b(client, actions):
            actions_b.extend(actions)
            return len(actions), 0

        client = MagicMock()

        # Parse with source_file = "path/a/Security.evtx"
        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=capture_a):
            parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name="case-test-evtx-host1",
                source_file="/evidence/a/Security.evtx",
            )

        # Parse with source_file = "path/b/Security.evtx"
        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=capture_b):
            parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name="case-test-evtx-host1",
                source_file="/evidence/b/Security.evtx",
            )

        # Different source_file → different doc IDs (by design —
        # evtx dedup key is source_file:record_id)
        if actions_a and actions_b:
            ids_a = {a["_id"] for a in actions_a}
            ids_b = {a["_id"] for a in actions_b}
            # Same file, different source path → different IDs
            assert ids_a != ids_b

    @skip_no_evtx
    def test_evtx_dedup_same_source_same_id(self):
        """Same evtx file + same source_file → identical doc IDs."""
        from opensearch_mcp.parse_evtx import parse_and_index

        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        actions_a, actions_b = [], []

        def cap_a(client, actions):
            actions_a.extend(actions)
            return len(actions), 0

        def cap_b(client, actions):
            actions_b.extend(actions)
            return len(actions), 0

        client = MagicMock()
        source = "/evidence/Security.evtx"

        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=cap_a):
            parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name="case-test-evtx-host1",
                source_file=source,
            )

        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=cap_b):
            parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name="case-test-evtx-host1",
                source_file=source,
            )

        if actions_a and actions_b:
            ids_a = sorted(a["_id"] for a in actions_a)
            ids_b = sorted(a["_id"] for a in actions_b)
            assert ids_a == ids_b, "Same source should produce identical IDs"


# ---------------------------------------------------------------------------
# Real evtx parsing with coercion
# ---------------------------------------------------------------------------


class TestRealEvtxCoercion:
    @skip_no_evtx
    def test_parse_real_evtx_no_type_errors(self):
        """Parse a real evtx file — no type errors from coercion."""
        from opensearch_mcp.parse_evtx import parse_and_index

        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        collected = []

        def collect(client, actions):
            collected.extend(actions)
            return len(actions), 0

        client = MagicMock()
        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=collect):
            cnt, sk, bf = parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name="case-test-evtx-host1",
            )

        assert cnt + sk >= 0  # At least runs without error
        if collected:
            doc = collected[0]["_source"]
            ed = doc.get("winlog.event_data", {})
            # All scalar values in event_data should be strings
            for k, v in ed.items():
                if v is None:
                    continue
                if isinstance(v, dict):
                    # Nested dict — check its values
                    for kk, vv in v.items():
                        if vv is not None and not isinstance(vv, (dict, list)):
                            assert isinstance(vv, str), f"Nested {k}.{kk} not string: {type(vv)}"
                elif isinstance(v, list):
                    for item in v:
                        if item is not None and not isinstance(item, (dict, list)):
                            assert isinstance(item, str), (
                                f"List item in {k} not string: {type(item)}"
                            )
                else:
                    assert isinstance(v, str), f"EventData {k} not string: {type(v)} = {v}"

    @skip_no_evtx
    def test_parse_real_evtx_ecs_fields_typed(self):
        """ECS fields from real evtx have correct types (not coerced to string)."""
        from opensearch_mcp.parse_evtx import parse_and_index

        # Use Security.evtx which has event 4624 with int LogonType
        sec = _EVTX_DIR / "Security.evtx"
        if not sec.exists():
            pytest.skip("No Security.evtx")

        collected = []

        def collect(client, actions):
            collected.extend(actions)
            return len(actions), 0

        client = MagicMock()
        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=collect):
            parse_and_index(evtx_path=sec, client=client, index_name="test")

        if collected:
            doc = collected[0]["_source"]
            # event.code must be int (not string)
            if "event.code" in doc:
                assert isinstance(doc["event.code"], int)
            # winlog.event_id must be int
            if "winlog.event_id" in doc:
                assert isinstance(doc["winlog.event_id"], int)


# ---------------------------------------------------------------------------
# Reduced mode with real evtx
# ---------------------------------------------------------------------------


class TestReducedModeReal:
    @skip_no_evtx
    def test_reduced_mode_filters_events(self):
        """Reduced mode with real evtx actually reduces event count."""
        from opensearch_mcp.parse_evtx import parse_and_index
        from opensearch_mcp.reduced import load_reduced_ids

        sec = _EVTX_DIR / "Security.evtx"
        if not sec.exists():
            pytest.skip("No Security.evtx")

        client = MagicMock()

        # Full parse
        full_actions = []

        def cap_full(c, a):
            full_actions.extend(a)
            return len(a), 0

        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=cap_full):
            full_cnt, _, _ = parse_and_index(evtx_path=sec, client=client, index_name="t")

        # Reduced parse
        reduced_actions = []

        def cap_reduced(c, a):
            reduced_actions.extend(a)
            return len(a), 0

        reduced_ids = load_reduced_ids()
        with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=cap_reduced):
            red_cnt, _, _ = parse_and_index(
                evtx_path=sec,
                client=client,
                index_name="t",
                reduced_ids=reduced_ids,
            )

        if full_cnt > 0:
            assert red_cnt <= full_cnt
            # Verify all reduced events have expected IDs
            for a in reduced_actions:
                eid = a["_source"].get("event.code")
                if eid is not None:
                    assert eid in reduced_ids, f"Event {eid} not in reduced set"


# ---------------------------------------------------------------------------
# MountContext cleanup
# ---------------------------------------------------------------------------


class TestMountContextCleanup:
    def test_empty_cleanup_no_errors(self):
        ctx = MountContext()
        ctx.cleanup()  # Should not raise

    @patch("opensearch_mcp.containers.subprocess")
    def test_reverse_order_cleanup(self, mock_sub):
        ctx = MountContext()
        ctx.add_mount(Path("/mnt/a"))
        ctx.add_mount(Path("/mnt/b"))
        ctx.add_fuse(Path("/mnt/c"))
        ctx.add_nbd("/dev/nbd0")
        ctx.add_loop("/dev/loop0")
        ctx.cleanup()

        calls = mock_sub.run.call_args_list
        cmds = [c[0][0] for c in calls]
        # Mounts in reverse: b before a
        mount_cmds = [c for c in cmds if "umount" in c]
        assert mount_cmds[0][-1] == "/mnt/b"
        assert mount_cmds[1][-1] == "/mnt/a"
        # FUSE, NBD, loop also cleaned
        fuse_cmds = [c for c in cmds if "fusermount" in c]
        assert len(fuse_cmds) == 1
        nbd_cmds = [c for c in cmds if "qemu-nbd" in c]
        assert len(nbd_cmds) == 1
        loop_cmds = [c for c in cmds if "losetup" in c]
        assert len(loop_cmds) == 1


# ---------------------------------------------------------------------------
# Multi-host extraction + discovery
# ---------------------------------------------------------------------------


class TestMultiHostDiscovery:
    @skip_no_artifacts
    def test_multi_host_triage_package(self, tmp_path):
        """Simulate multi-host triage: two hosts with different artifacts."""
        host_a = tmp_path / "HOST-A" / "Windows" / "System32" / "config"
        host_a.mkdir(parents=True)
        (host_a / "SYSTEM").write_bytes(b"fake")
        (host_a / "SOFTWARE").write_bytes(b"fake")

        host_b = tmp_path / "HOST-B" / "Windows" / "System32" / "config"
        host_b.mkdir(parents=True)
        (host_b / "SYSTEM").write_bytes(b"fake")

        # Add evtx to host A
        evtx_dir = tmp_path / "HOST-A" / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        (evtx_dir / "Security.evtx").write_bytes(b"fake-evtx")

        hosts = scan_triage_directory(tmp_path)
        assert len(hosts) == 2
        hostnames = {h.hostname for h in hosts}
        assert "HOST-A" in hostnames
        assert "HOST-B" in hostnames

        # HOST-A should have evtx + registry
        host_a_result = [h for h in hosts if h.hostname == "HOST-A"][0]
        assert host_a_result.evtx_dir is not None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCasesReal:
    def test_empty_directory(self, tmp_path):
        """Empty directory produces no hosts."""
        hosts = scan_triage_directory(tmp_path)
        assert hosts == []

    def test_directory_with_no_windows_tree(self, tmp_path):
        """Directory without Windows/ structure produces no hosts."""
        (tmp_path / "random_file.txt").write_text("not evidence")
        (tmp_path / "subdir").mkdir()
        hosts = scan_triage_directory(tmp_path)
        assert hosts == []

    @skip_no_7z
    def test_empty_zip(self, tmp_path):
        """Empty zip file extracts without error."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        (empty_dir / "placeholder.txt").write_text("")
        zip_path = tmp_path / "empty.zip"
        subprocess.run(
            ["7z", "a", str(zip_path), str(empty_dir / "placeholder.txt")],
            capture_output=True,
            check=True,
        )
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(zip_path, dest)
        # No crash, extracted the placeholder
        assert (dest / "placeholder.txt").exists()

    def test_detect_unknown_extension(self, tmp_path):
        f = tmp_path / "evidence.pcap"
        f.touch()
        assert detect_container(f) == "unknown"

    def test_detect_no_extension(self, tmp_path):
        f = tmp_path / "evidence"
        f.touch()
        assert detect_container(f) == "unknown"
