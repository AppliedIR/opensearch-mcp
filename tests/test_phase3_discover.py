"""Tests for Phase 3 discover.py additions (prefetch, SRUM)."""

from __future__ import annotations

from _helpers import make_windows_tree

from opensearch_mcp.discover import DiscoveredHost, discover_artifacts


class TestDiscoverPrefetch:
    def test_prefetch_dir_discovered(self, tmp_path):
        make_windows_tree(tmp_path, prefetch=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "prefetch" in artifact_names

    def test_prefetch_path_is_directory(self, tmp_path):
        make_windows_tree(tmp_path, prefetch=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        for name, path in host.artifacts:
            if name == "prefetch":
                assert path.is_dir()

    def test_no_prefetch_when_missing(self, tmp_path):
        make_windows_tree(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "prefetch" not in artifact_names


class TestDiscoverSrum:
    def test_srum_discovered(self, tmp_path):
        make_windows_tree(tmp_path, srum=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "srum" in artifact_names

    def test_srum_path_is_file(self, tmp_path):
        make_windows_tree(tmp_path, srum=True)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        for name, path in host.artifacts:
            if name == "srum":
                assert path.is_file()

    def test_no_srum_when_missing(self, tmp_path):
        make_windows_tree(tmp_path)
        host = DiscoveredHost(hostname="TEST", volume_root=tmp_path)
        discover_artifacts(host)
        artifact_names = {a[0] for a in host.artifacts}
        assert "srum" not in artifact_names


class TestDiscoveredHostVssId:
    def test_default_vss_id_is_empty(self):
        host = DiscoveredHost(hostname="TEST", volume_root="/evidence")
        assert host.vss_id == ""

    def test_vss_id_can_be_set(self):
        host = DiscoveredHost(hostname="TEST", volume_root="/evidence", vss_id="vss1")
        assert host.vss_id == "vss1"
