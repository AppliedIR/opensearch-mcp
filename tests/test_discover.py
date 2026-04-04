"""Tests for artifact discovery and host detection."""

from pathlib import Path

from _helpers import make_windows_tree

from opensearch_mcp.discover import (
    DiscoveredHost,
    discover_artifacts,
    find_volume_root,
    scan_triage_directory,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_windows(root: Path) -> None:
    """Minimal Windows tree: just the sentinel directory."""
    (root / "Windows" / "System32" / "config").mkdir(parents=True)


# ---------------------------------------------------------------------------
# find_volume_root
# ---------------------------------------------------------------------------


class TestFindVolumeRoot:
    def test_flat_volume(self, tmp_path):
        """Root itself contains Windows/System32/config."""
        make_windows_tree(tmp_path)
        assert find_volume_root(tmp_path) == tmp_path

    def test_with_drive_letter_C(self, tmp_path):
        """host/C/Windows/... layout (KAPE)."""
        make_windows_tree(tmp_path / "C")
        assert find_volume_root(tmp_path) == tmp_path / "C"

    def test_with_drive_letter_D(self, tmp_path):
        """Drive letter D."""
        make_windows_tree(tmp_path / "D")
        assert find_volume_root(tmp_path) == tmp_path / "D"

    def test_with_url_encoded_drive(self, tmp_path):
        """host/C%3A/Windows/... layout (Velociraptor URL-encoded)."""
        make_windows_tree(tmp_path / "C%3A")
        assert find_volume_root(tmp_path) == tmp_path / "C%3A"

    def test_no_windows_dir(self, tmp_path):
        """Directory without Windows artifacts returns None."""
        (tmp_path / "random_file.txt").touch()
        assert find_volume_root(tmp_path) is None

    def test_empty_dir(self, tmp_path):
        """Empty directory returns None."""
        assert find_volume_root(tmp_path) is None

    def test_skips_hidden_directories(self, tmp_path):
        """Hidden directories (starting with .) are skipped."""
        make_windows_tree(tmp_path / ".hidden")
        assert find_volume_root(tmp_path) is None

    def test_skips_long_directory_names(self, tmp_path):
        """Directories with names > 4 chars are skipped (not drive letters)."""
        make_windows_tree(tmp_path / "LongDirName")
        assert find_volume_root(tmp_path) is None

    def test_short_name_exactly_4_chars(self, tmp_path):
        """4-char directory name is accepted (e.g., C%3A)."""
        make_windows_tree(tmp_path / "C%3A")
        assert find_volume_root(tmp_path) == tmp_path / "C%3A"

    def test_five_char_name_rejected(self, tmp_path):
        """5-char directory name is rejected."""
        make_windows_tree(tmp_path / "ABCDE")
        assert find_volume_root(tmp_path) is None


# ---------------------------------------------------------------------------
# discover_artifacts — system artifacts
# ---------------------------------------------------------------------------


class TestDiscoverArtifactsSystem:
    def test_finds_system_hives(self, tmp_path):
        """SYSTEM hive maps to BOTH shimcache AND registry_system."""
        make_windows_tree(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = [a[0] for a in host.artifacts]
        assert "shimcache" in artifact_names
        assert "registry_system" in artifact_names

    def test_finds_amcache(self, tmp_path):
        make_windows_tree(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "amcache" in artifact_names

    def test_finds_registry_software(self, tmp_path):
        make_windows_tree(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "registry_software" in artifact_names

    def test_mft_at_volume_root(self, tmp_path):
        """$MFT at volume root is detected."""
        make_windows_tree(tmp_path, mft=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "mft" in artifact_names

    def test_recycle_bin_directory(self, tmp_path):
        """$Recycle.Bin directory is detected."""
        make_windows_tree(tmp_path, recycle_bin=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "recyclebin" in artifact_names

    def test_recycle_bin_must_be_directory(self, tmp_path):
        """$Recycle.Bin as a file should not be detected."""
        make_windows_tree(tmp_path)
        (tmp_path / "$Recycle.Bin").touch()  # file, not dir
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "recyclebin" not in artifact_names


# ---------------------------------------------------------------------------
# discover_artifacts — evtx
# ---------------------------------------------------------------------------


class TestDiscoverArtifactsEvtx:
    def test_evtx_dir_set_when_logs_exist(self, tmp_path):
        """DiscoveredHost.evtx_dir set when winevt/Logs exists with .evtx files."""
        make_windows_tree(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        assert host.evtx_dir is not None
        assert host.evtx_dir == tmp_path / "Windows" / "System32" / "winevt" / "Logs"

    def test_evtx_dir_none_when_no_evtx_files(self, tmp_path):
        """DiscoveredHost.evtx_dir None when log directory has no .evtx files."""
        _minimal_windows(tmp_path)
        evtx_dir = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        # Directory exists but has no .evtx files
        (evtx_dir / "readme.txt").touch()
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        assert host.evtx_dir is None

    def test_evtx_dir_none_when_no_winevt(self, tmp_path):
        """No winevt/Logs directory at all."""
        _minimal_windows(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        assert host.evtx_dir is None


# ---------------------------------------------------------------------------
# discover_artifacts — user profiles
# ---------------------------------------------------------------------------


class TestDiscoverArtifactsUserProfiles:
    def test_skips_public_default_allusers(self, tmp_path):
        """Public, Default, Default User, All Users profiles are skipped."""
        make_windows_tree(tmp_path, users=["realuser"])
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        profile_names = [p.name for p in host.user_profiles]
        assert "realuser" in profile_names
        assert "Public" not in profile_names
        assert "Default" not in profile_names
        assert "All Users" not in profile_names

    def test_multiple_user_profiles(self, tmp_path):
        """Multiple real user profiles are discovered."""
        make_windows_tree(tmp_path, users=["alice", "bob", "charlie"])
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        assert len(host.user_profiles) == 3

    def test_shellbags_maps_to_profile_dir(self, tmp_path):
        """Shellbags artifact path is the user profile directory itself (not a file)."""
        make_windows_tree(tmp_path, users=["admin"])
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        shellbag_artifacts = [(n, p) for n, p in host.artifacts if n == "shellbags"]
        assert len(shellbag_artifacts) == 1
        # The path should be the profile directory
        assert shellbag_artifacts[0][1] == tmp_path / "Users" / "admin"

    def test_jumplists_autodetect(self, tmp_path):
        """JumpLists auto-detect under AppData/Roaming/.../Recent."""
        make_windows_tree(tmp_path, users=["admin"])
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        jl_artifacts = [(n, p) for n, p in host.artifacts if n == "jumplists"]
        assert len(jl_artifacts) == 1

    def test_lnk_autodetect_multiple_paths(self, tmp_path):
        """LNK auto-detect finds both Recent and Desktop directories."""
        make_windows_tree(tmp_path, users=["admin"])
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        lnk_artifacts = [(n, p) for n, p in host.artifacts if n == "lnk"]
        # Both Recent and Desktop should be found
        assert len(lnk_artifacts) == 2
        lnk_paths = {str(p.name) for _, p in lnk_artifacts}
        assert "Recent" in lnk_paths
        assert "Desktop" in lnk_paths

    def test_timeline_autodetect(self, tmp_path):
        """Timeline (ActivitiesCache.db) auto-detect under ConnectedDevicesPlatform."""
        make_windows_tree(tmp_path, users=["admin"], timeline=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        tl_artifacts = [(n, p) for n, p in host.artifacts if n == "timeline"]
        assert len(tl_artifacts) == 1


# ---------------------------------------------------------------------------
# scan_triage_directory
# ---------------------------------------------------------------------------


class TestScanTriageDirectory:
    def test_single_host_root_is_volume_root(self, tmp_path):
        """When root itself is a volume root, returns single host."""
        make_windows_tree(tmp_path)
        hosts = scan_triage_directory(tmp_path)
        assert len(hosts) == 1
        assert hosts[0].hostname == tmp_path.name

    def test_multi_host_three_subdirs(self, tmp_path):
        """Multi-host triage package with 3 host subdirs."""
        triage = tmp_path / "triage"
        triage.mkdir()
        make_windows_tree(triage / "HOST1")
        make_windows_tree(triage / "HOST2")
        make_windows_tree(triage / "HOST3")
        hosts = scan_triage_directory(triage)
        assert len(hosts) == 3
        names = {h.hostname for h in hosts}
        assert names == {"HOST1", "HOST2", "HOST3"}

    def test_multi_host_with_drive_letter(self, tmp_path):
        """Multi-host where each host has a drive letter subdir."""
        make_windows_tree(tmp_path / "WS05" / "C")
        hosts = scan_triage_directory(tmp_path)
        assert len(hosts) == 1
        assert hosts[0].hostname == "WS05"
        assert hosts[0].volume_root == tmp_path / "WS05" / "C"

    def test_empty_dir_returns_no_hosts(self, tmp_path):
        """Empty directory returns no hosts."""
        hosts = scan_triage_directory(tmp_path)
        assert hosts == []

    def test_dir_without_windows_artifacts_returns_no_hosts(self, tmp_path):
        """Directory with non-Windows content returns no hosts."""
        (tmp_path / "readme.txt").write_text("not evidence")
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "file.csv").touch()
        hosts = scan_triage_directory(tmp_path)
        assert hosts == []

    def test_skips_non_directory_entries(self, tmp_path):
        """Files at root level are skipped, only directories scanned."""
        triage = tmp_path / "triage"
        triage.mkdir()
        make_windows_tree(triage / "HOST1")
        (triage / "notes.txt").touch()
        (triage / "config.yaml").touch()
        hosts = scan_triage_directory(triage)
        assert len(hosts) == 1
        assert hosts[0].hostname == "HOST1"

    def test_skips_hidden_dirs(self, tmp_path):
        """Hidden directories (starting with .) are skipped in multi-host scan."""
        triage = tmp_path / "triage"
        triage.mkdir()
        make_windows_tree(triage / ".hidden_host")
        make_windows_tree(triage / "VISIBLE")
        hosts = scan_triage_directory(triage)
        assert len(hosts) == 1
        assert hosts[0].hostname == "VISIBLE"

    def test_mixed_dirs_some_with_windows(self, tmp_path):
        """Mixed directory: some subdirs have Windows tree, some do not."""
        triage = tmp_path / "triage"
        triage.mkdir()
        make_windows_tree(triage / "HOST_REAL")
        # Create a subdir without Windows tree
        (triage / "LOGS_ONLY").mkdir()
        (triage / "LOGS_ONLY" / "access.log").touch()
        # Create another valid host
        make_windows_tree(triage / "HOST_TWO")
        hosts = scan_triage_directory(triage)
        names = {h.hostname for h in hosts}
        assert names == {"HOST_REAL", "HOST_TWO"}
        assert "LOGS_ONLY" not in names


# ---------------------------------------------------------------------------
# discover_artifacts — $Recycle.Bin and ActivitiesCache.db
# ---------------------------------------------------------------------------


class TestDiscoverArtifactsAdditional:
    def test_recycle_bin_directory_detected(self, tmp_path):
        """$Recycle.Bin directory is detected as recyclebin artifact."""
        make_windows_tree(tmp_path, recycle_bin=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "recyclebin" in artifact_names
        # Find the path
        rb_paths = [p for n, p in host.artifacts if n == "recyclebin"]
        assert len(rb_paths) == 1
        assert rb_paths[0] == tmp_path / "$Recycle.Bin"

    def test_activities_cache_db_detected(self, tmp_path):
        """ActivitiesCache.db under ConnectedDevicesPlatform detected as timeline."""
        make_windows_tree(tmp_path, users=["admin"], timeline=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        tl_artifacts = [(n, p) for n, p in host.artifacts if n == "timeline"]
        assert len(tl_artifacts) == 1
        # Path should be the ConnectedDevicesPlatform directory
        assert "ConnectedDevicesPlatform" in str(tl_artifacts[0][1])

    def test_usn_journal_detected(self, tmp_path):
        """$Extend/$J file detected as usn artifact."""
        make_windows_tree(tmp_path, usn=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "usn" in artifact_names
