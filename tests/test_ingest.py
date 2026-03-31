"""Tests for the core ingest orchestrator (ingest.py)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from _helpers import make_windows_tree

from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import (
    _artifact_to_tool,
    _safe_count,
    discover,
    ingest,
)

# ---------------------------------------------------------------------------
# _artifact_to_tool mapping
# ---------------------------------------------------------------------------


class TestArtifactToTool:
    def test_amcache(self):
        assert _artifact_to_tool("amcache") == "amcache"

    def test_shimcache(self):
        assert _artifact_to_tool("shimcache") == "shimcache"

    def test_registry_system(self):
        assert _artifact_to_tool("registry_system") == "registry"

    def test_registry_software(self):
        assert _artifact_to_tool("registry_software") == "registry"

    def test_registry_sam(self):
        assert _artifact_to_tool("registry_sam") == "registry"

    def test_registry_security(self):
        assert _artifact_to_tool("registry_security") == "registry"

    def test_mft(self):
        assert _artifact_to_tool("mft") == "mft"

    def test_usn(self):
        assert _artifact_to_tool("usn") == "usn"

    def test_recyclebin(self):
        assert _artifact_to_tool("recyclebin") == "recyclebin"

    def test_shellbags(self):
        assert _artifact_to_tool("shellbags") == "shellbags"

    def test_jumplists(self):
        assert _artifact_to_tool("jumplists") == "jumplists"

    def test_lnk(self):
        assert _artifact_to_tool("lnk") == "lnk"

    def test_timeline(self):
        assert _artifact_to_tool("timeline") == "timeline"

    def test_unknown_returns_none(self):
        assert _artifact_to_tool("unknown_artifact") is None


# ---------------------------------------------------------------------------
# _safe_count
# ---------------------------------------------------------------------------


class TestSafeCount:
    def test_returns_count_on_success(self):
        client = MagicMock()
        client.count.return_value = {"count": 42}
        assert _safe_count(client, "case-test-evtx-host1") == 42

    def test_returns_zero_when_index_doesnt_exist(self):
        client = MagicMock()
        client.count.side_effect = Exception("index_not_found")
        assert _safe_count(client, "nonexistent-index") == 0


# ---------------------------------------------------------------------------
# discover()
# ---------------------------------------------------------------------------


class TestDiscover:
    def test_hostname_overrides_scan_hostname(self, tmp_path):
        """When hostname is provided, it overrides the directory-name hostname."""
        make_windows_tree(tmp_path)
        hosts = discover(tmp_path, hostname="OVERRIDE-HOST")
        assert len(hosts) == 1
        assert hosts[0].hostname == "OVERRIDE-HOST"

    def test_flat_evtx_directory(self, tmp_path):
        """Flat directory with only evtx files and a hostname provided."""
        (tmp_path / "Security.evtx").touch()
        (tmp_path / "System.evtx").touch()
        hosts = discover(tmp_path, hostname="FLAT-HOST")
        assert len(hosts) == 1
        assert hosts[0].hostname == "FLAT-HOST"
        assert hosts[0].evtx_dir == tmp_path

    def test_empty_directory_returns_no_hosts(self, tmp_path):
        """Empty directory with no hostname returns empty list."""
        hosts = discover(tmp_path)
        assert hosts == []

    def test_empty_directory_with_hostname_returns_empty(self, tmp_path):
        """Empty directory with hostname but no evtx or Windows tree returns empty."""
        (tmp_path / "readme.txt").write_text("not evidence")
        hosts = discover(tmp_path, hostname="HOST")
        assert hosts == []

    def test_windows_tree_without_hostname(self, tmp_path):
        """Windows tree discovered via scan_triage_directory (no hostname override)."""
        make_windows_tree(tmp_path)
        hosts = discover(tmp_path)
        assert len(hosts) == 1
        # hostname derived from directory name
        assert hosts[0].hostname == tmp_path.name

    def test_hostname_override_with_drive_letter_layout(self, tmp_path):
        """Hostname override works with host/C/Windows layout."""
        make_windows_tree(tmp_path / "C")
        hosts = discover(tmp_path, hostname="MYHOST")
        assert len(hosts) == 1
        assert hosts[0].hostname == "MYHOST"


# ---------------------------------------------------------------------------
# ingest()
# ---------------------------------------------------------------------------


class TestIngest:
    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_basic_ingest_populates_result(self, mock_sha, mock_rai):
        """ingest() calls run_and_ingest and populates ArtifactResult."""
        mock_rai.return_value = (100, 5, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence/HOST1"))
        hive = Path("/evidence/HOST1/Windows/System32/config/SYSTEM")
        host.artifacts = [("shimcache", hive)]

        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
        )

        assert len(result.hosts) == 1
        assert result.hosts[0].hostname == "HOST1"
        assert len(result.hosts[0].artifacts) == 1
        ar = result.hosts[0].artifacts[0]
        assert ar.artifact == "shimcache"
        assert ar.indexed == 100
        assert ar.skipped == 5
        assert ar.error == ""

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_skips_tools_not_in_active_tools(self, mock_sha, mock_rai):
        """ingest() skips artifacts whose tool is excluded."""
        mock_rai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence/HOST1"))
        host.artifacts = [
            ("shimcache", Path("/evidence/SYSTEM")),
            ("mft", Path("/evidence/$MFT")),
        ]

        # Default active_tools (no include): tier 1+2 only, no mft (tier 3)
        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
        )

        # shimcache should be processed (tier 1), mft should be skipped (tier 3)
        processed_artifacts = [a.artifact for a in result.hosts[0].artifacts]
        assert "shimcache" in processed_artifacts
        assert "mft" not in processed_artifacts

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_handles_tool_failure(self, mock_sha, mock_rai):
        """ingest() catches RuntimeError from run_and_ingest and continues."""
        mock_rai.side_effect = RuntimeError("Tool crashed")
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence/HOST1"))
        host.artifacts = [
            ("shimcache", Path("/evidence/SYSTEM")),
            ("amcache", Path("/evidence/Amcache.hve")),
        ]

        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
        )

        # Both artifacts should be in results, both with errors
        assert len(result.hosts[0].artifacts) == 2
        for ar in result.hosts[0].artifacts:
            assert ar.error == "Tool crashed"

    @patch("opensearch_mcp.ingest.parse_and_index")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_evtx_path(self, mock_sha, mock_pai, tmp_path):
        """ingest() calls parse_and_index for each evtx file."""
        mock_pai.return_value = (500, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        (evtx_dir / "Security.evtx").write_bytes(b"\x00" * 70000)
        (evtx_dir / "System.evtx").write_bytes(b"\x00" * 70000)
        (evtx_dir / "readme.txt").touch()  # should be ignored

        host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
        host.evtx_dir = evtx_dir

        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
        )

        # parse_and_index called twice (2 evtx files, not the txt)
        assert mock_pai.call_count == 2
        ar = result.hosts[0].artifacts[0]
        assert ar.artifact == "evtx"
        assert ar.indexed == 1000  # 500 * 2

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_seen_runs_dedup(self, mock_sha, mock_rai):
        """Same tool+path (for registry) not run twice due to seen_runs dedup."""
        mock_rai.return_value = (50, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        config_dir = Path("/evidence/Windows/System32/config")
        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        # 4 registry hive files that all map to "registry" tool
        # and all share the same parent directory
        host.artifacts = [
            ("registry_system", config_dir / "SYSTEM"),
            ("registry_software", config_dir / "SOFTWARE"),
            ("registry_sam", config_dir / "SAM"),
            ("registry_security", config_dir / "SECURITY"),
        ]

        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
        )

        # run_and_ingest should only be called once (dedup by parent dir)
        assert mock_rai.call_count == 1
        # But only one artifact result (the first registry run)
        assert len(result.hosts[0].artifacts) == 1

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_pipeline_version_set(self, mock_sha, mock_rai):
        """IngestResult.pipeline_version is set."""
        mock_rai.return_value = (10, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("amcache", Path("/evidence/Amcache.hve"))]

        result = ingest(hosts=[host], client=client, audit=audit, case_id="INC001")

        assert result.pipeline_version.startswith("opensearch-mcp-")
