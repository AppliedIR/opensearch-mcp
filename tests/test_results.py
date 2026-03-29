"""Tests for IngestResult dataclass and summary output."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult

# ---------------------------------------------------------------------------
# ArtifactResult
# ---------------------------------------------------------------------------


class TestArtifactResult:
    def test_default_values(self):
        ar = ArtifactResult(artifact="amcache", index="case-test-amcache-host1")
        assert ar.indexed == 0
        assert ar.skipped == 0
        assert ar.bulk_failed == 0
        assert ar.existing_before == 0
        assert ar.source_files == []
        assert ar.error == ""

    def test_with_error_field(self):
        ar = ArtifactResult(
            artifact="shimcache",
            index="case-test-shimcache-host1",
            error="Tool not found",
        )
        assert ar.error == "Tool not found"

    def test_with_counts(self):
        ar = ArtifactResult(
            artifact="evtx",
            index="case-test-evtx-host1",
            indexed=1500,
            skipped=10,
            bulk_failed=3,
            existing_before=500,
        )
        assert ar.indexed == 1500
        assert ar.skipped == 10
        assert ar.bulk_failed == 3
        assert ar.existing_before == 500


# ---------------------------------------------------------------------------
# HostResult
# ---------------------------------------------------------------------------


class TestHostResult:
    def test_total_indexed_sums_artifacts(self):
        hr = HostResult(
            hostname="HOST1",
            artifacts=[
                ArtifactResult(artifact="amcache", index="idx1", indexed=100),
                ArtifactResult(artifact="shimcache", index="idx2", indexed=200),
                ArtifactResult(artifact="evtx", index="idx3", indexed=5000),
            ],
        )
        assert hr.total_indexed == 5300

    def test_total_indexed_empty_artifacts(self):
        hr = HostResult(hostname="HOST1")
        assert hr.total_indexed == 0


# ---------------------------------------------------------------------------
# IngestResult
# ---------------------------------------------------------------------------


class TestIngestResult:
    def test_total_indexed_sums_hosts(self):
        result = IngestResult(
            hosts=[
                HostResult(
                    hostname="HOST1",
                    artifacts=[ArtifactResult(artifact="evtx", index="i1", indexed=1000)],
                ),
                HostResult(
                    hostname="HOST2",
                    artifacts=[ArtifactResult(artifact="evtx", index="i2", indexed=2000)],
                ),
            ]
        )
        assert result.total_indexed == 3000

    def test_empty_ingest_result(self):
        result = IngestResult()
        assert result.total_indexed == 0
        assert result.hosts == []

    def test_to_dict_includes_all_required_keys(self):
        result = IngestResult(
            elapsed_seconds=42.5,
            pipeline_version="opensearch-mcp-0.1.0",
            hosts=[
                HostResult(
                    hostname="HOST1",
                    volume_root="/evidence/HOST1",
                    artifacts=[
                        ArtifactResult(
                            artifact="amcache",
                            index="case-test-amcache-host1",
                            indexed=50,
                            skipped=2,
                            bulk_failed=1,
                            existing_before=10,
                            error="",
                        )
                    ],
                )
            ],
        )
        d = result.to_dict()
        assert "hosts" in d
        assert "elapsed_seconds" in d
        assert "total_indexed" in d
        assert "pipeline_version" in d
        assert d["elapsed_seconds"] == 42.5
        assert d["total_indexed"] == 50
        assert d["pipeline_version"] == "opensearch-mcp-0.1.0"

    def test_to_dict_serializes_correctly(self):
        result = IngestResult(
            elapsed_seconds=10.123,
            hosts=[
                HostResult(
                    hostname="HOST1",
                    volume_root="/vol",
                    artifacts=[
                        ArtifactResult(
                            artifact="evtx",
                            index="case-x-evtx-host1",
                            indexed=100,
                            skipped=5,
                            bulk_failed=0,
                            existing_before=0,
                        )
                    ],
                )
            ],
        )
        d = result.to_dict()
        host = d["hosts"][0]
        assert host["hostname"] == "HOST1"
        assert host["volume_root"] == "/vol"
        art = host["artifacts"][0]
        assert art["artifact"] == "evtx"
        assert art["index"] == "case-x-evtx-host1"
        assert art["indexed"] == 100
        assert art["skipped"] == 5
        assert art["bulk_failed"] == 0
        assert art["existing_before"] == 0
        assert art["error"] == ""
        assert d["elapsed_seconds"] == 10.1  # rounded

    def test_to_dict_rounds_elapsed_seconds(self):
        result = IngestResult(elapsed_seconds=10.789)
        d = result.to_dict()
        assert d["elapsed_seconds"] == 10.8


# ---------------------------------------------------------------------------
# print_summary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def _capture_summary(self, result: IngestResult) -> str:
        """Capture print_summary output."""
        buf = StringIO()
        with patch(
            "builtins.print",
            side_effect=lambda *a, **k: buf.write(" ".join(str(x) for x in a) + "\n"),
        ):
            result.print_summary()
        return buf.getvalue()

    def test_shows_overlapping_when_existing_and_no_new(self):
        """existing_before > 0 and new == 0 -> 'overlapping'."""
        result = IngestResult(
            hosts=[
                HostResult(
                    hostname="HOST1",
                    artifacts=[
                        ArtifactResult(
                            artifact="amcache",
                            index="idx",
                            indexed=50,
                            existing_before=50,
                        )
                    ],
                )
            ]
        )
        output = self._capture_summary(result)
        assert "overlapping" in output
        assert "50 existing" in output

    def test_shows_extended_when_existing_and_new(self):
        """existing_before > 0 and new > 0 -> 'extended'."""
        result = IngestResult(
            hosts=[
                HostResult(
                    hostname="HOST1",
                    artifacts=[
                        ArtifactResult(
                            artifact="amcache",
                            index="idx",
                            indexed=100,
                            existing_before=30,
                        )
                    ],
                )
            ]
        )
        output = self._capture_summary(result)
        assert "extended" in output
        assert "70 new" in output
        assert "30 existing" in output

    def test_shows_entries_when_no_existing(self):
        """No existing_before -> shows 'N entries'."""
        result = IngestResult(
            hosts=[
                HostResult(
                    hostname="HOST1",
                    artifacts=[ArtifactResult(artifact="amcache", index="idx", indexed=250)],
                )
            ]
        )
        output = self._capture_summary(result)
        assert "250 entries" in output

    def test_shows_failed_with_error_message(self):
        """Artifact with error shows FAILED."""
        result = IngestResult(
            hosts=[
                HostResult(
                    hostname="HOST1",
                    artifacts=[
                        ArtifactResult(
                            artifact="shimcache",
                            index="idx",
                            error="Tool crashed",
                        )
                    ],
                )
            ]
        )
        output = self._capture_summary(result)
        assert "FAILED" in output
        assert "Tool crashed" in output

    def test_shows_skipped_and_bulk_failed(self):
        """Skipped and bulk_failed counts are shown when nonzero."""
        result = IngestResult(
            hosts=[
                HostResult(
                    hostname="HOST1",
                    artifacts=[
                        ArtifactResult(
                            artifact="evtx",
                            index="idx",
                            indexed=1000,
                            skipped=15,
                            bulk_failed=3,
                        )
                    ],
                )
            ]
        )
        output = self._capture_summary(result)
        assert "15 skipped" in output
        assert "3 bulk failed" in output

    def test_empty_result_no_crash(self):
        """Empty IngestResult prints nothing but does not crash."""
        result = IngestResult()
        output = self._capture_summary(result)
        # No hosts, so no output beyond maybe empty string
        assert "FAILED" not in output
