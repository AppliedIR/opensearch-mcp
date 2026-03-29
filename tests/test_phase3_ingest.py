"""Tests for Phase 3 ingest.py additions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import _artifact_to_tool, ingest


class TestArtifactToToolPhase3:
    def test_prefetch(self):
        assert _artifact_to_tool("prefetch") == "prefetch"

    def test_srum(self):
        assert _artifact_to_tool("srum") == "srum"


class TestIngestWithReducedIds:
    @patch("opensearch_mcp.ingest.parse_and_index")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_reduced_ids_passed_to_evtx(self, mock_sha, mock_pai, tmp_path):
        """reduced_ids is forwarded to parse_and_index."""
        mock_pai.return_value = (100, 50, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        (evtx_dir / "Security.evtx").touch()

        host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
        host.evtx_dir = evtx_dir

        reduced = {4624, 4625, 4688}
        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
            reduced_ids=reduced,
        )

        call_kwargs = mock_pai.call_args[1]
        assert call_kwargs["reduced_ids"] == reduced


class TestIngestWithFull:
    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_full_enables_tier3(self, mock_sha, mock_rai):
        """full=True enables tier 3 tools like MFT."""
        mock_rai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("mft", Path("/evidence/$MFT"))]

        result = ingest(hosts=[host], client=client, audit=audit, case_id="INC001", full=True)

        # MFT (tier 3) should be processed when full=True
        processed = [a.artifact for a in result.hosts[0].artifacts]
        assert "mft" in processed
        mock_rai.assert_called_once()

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_no_full_skips_tier3(self, mock_sha, mock_rai):
        """Without full=True, tier 3 tools are skipped."""
        mock_rai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("mft", Path("/evidence/$MFT"))]

        result = ingest(hosts=[host], client=client, audit=audit, case_id="INC001")

        processed = [a.artifact for a in result.hosts[0].artifacts]
        assert "mft" not in processed
        mock_rai.assert_not_called()


class TestIngestWithVssId:
    @patch("opensearch_mcp.ingest.parse_and_index")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_vss_id_passed_to_evtx(self, mock_sha, mock_pai, tmp_path):
        """host.vss_id is forwarded to parse_and_index."""
        mock_pai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        (evtx_dir / "Security.evtx").touch()

        host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path, vss_id="vss1")
        host.evtx_dir = evtx_dir

        ingest(hosts=[host], client=client, audit=audit, case_id="INC001")

        call_kwargs = mock_pai.call_args[1]
        assert call_kwargs["vss_id"] == "vss1"

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_vss_id_passed_to_ez_tools(self, mock_sha, mock_rai):
        """host.vss_id is forwarded to run_and_ingest."""
        mock_rai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"), vss_id="live")
        host.artifacts = [("shimcache", Path("/evidence/SYSTEM"))]

        ingest(hosts=[host], client=client, audit=audit, case_id="INC001")

        call_kwargs = mock_rai.call_args[1]
        assert call_kwargs["vss_id"] == "live"

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_mft_natural_key_extended_for_vss(self, mock_sha, mock_rai):
        """MFT natural key gets vhir.vss_id appended when VSS is active."""
        mock_rai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"), vss_id="vss1")
        host.artifacts = [("mft", Path("/evidence/$MFT"))]

        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
            include={"mft"},
        )

        call_kwargs = mock_rai.call_args[1]
        nk = call_kwargs["natural_key_override"]
        assert nk.endswith(":vhir.vss_id")

    @patch("opensearch_mcp.ingest.run_and_ingest")
    @patch("opensearch_mcp.ingest.sha256_file", return_value="abc123")
    def test_mft_natural_key_unchanged_without_vss(self, mock_sha, mock_rai):
        """MFT natural key is not modified when no VSS."""
        mock_rai.return_value = (100, 0, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("mft", Path("/evidence/$MFT"))]

        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
            include={"mft"},
        )

        call_kwargs = mock_rai.call_args[1]
        nk = call_kwargs["natural_key_override"]
        assert nk is not None
        assert "vhir.vss_id" not in nk


class TestIngestPlasoArtifacts:
    @patch("opensearch_mcp.parse_plaso.parse_prefetch")
    def test_prefetch_artifact_routed_to_plaso(self, mock_pp):
        """Prefetch artifact discovered and routed to parse_plaso."""
        mock_pp.return_value = (100, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("prefetch", Path("/evidence/Windows/Prefetch"))]

        result = ingest(hosts=[host], client=client, audit=audit, case_id="INC001")

        mock_pp.assert_called_once()
        ar = result.hosts[0].artifacts[0]
        assert ar.artifact == "prefetch"
        assert ar.indexed == 100

    @patch("opensearch_mcp.parse_plaso.parse_srum")
    def test_srum_artifact_routed_to_plaso(self, mock_ps):
        """SRUM artifact routed to parse_plaso."""
        mock_ps.return_value = (50, 0)
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("srum", Path("/evidence/SRUDB.dat"))]

        result = ingest(hosts=[host], client=client, audit=audit, case_id="INC001")

        mock_ps.assert_called_once()
        ar = result.hosts[0].artifacts[0]
        assert ar.artifact == "srum"
        assert ar.indexed == 50

    @patch("opensearch_mcp.parse_plaso.parse_prefetch")
    def test_plaso_artifact_excluded(self, mock_pp):
        """Plaso artifacts respect --exclude."""
        client = MagicMock()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-001"

        host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence"))
        host.artifacts = [("prefetch", Path("/evidence/Windows/Prefetch"))]

        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="INC001",
            exclude={"prefetch"},
        )

        mock_pp.assert_not_called()
