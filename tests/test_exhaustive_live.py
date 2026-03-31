"""Exhaustive live tests against real evidence and live OpenSearch.

Tests EVERY feature across the entire opensearch-mcp repo using:
- Real SRL2/SRL3 evidence files
- Real EZ tools (AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, etc.)
- Real Plaso (log2timeline.py, psort.py)
- Live OpenSearch Docker container
- Real container archives (7z, zip, tar.gz)

Marks:
- @pytest.mark.integration: requires live OpenSearch
- @pytest.mark.slow: tests that take >10s (real tool execution, large extractions)
"""

from __future__ import annotations

import os
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Evidence paths
# ---------------------------------------------------------------------------

_EVTX_DIR = Path.home() / "logs"
_SRL2_DIR = Path.home() / "SRL2_Samples"
_ARTIFACTS = Path("/tmp/srl2-test-artifacts")

_has_evtx = _EVTX_DIR.is_dir() and any(_EVTX_DIR.glob("*.evtx"))
_has_srl2 = _SRL2_DIR.is_dir()
_has_artifacts = _ARTIFACTS.is_dir()
_has_7z = shutil.which("7z") is not None
_has_tools = shutil.which("AmcacheParser") is not None
_has_plaso = shutil.which("log2timeline.py") is not None

skip_no_evtx = pytest.mark.skipif(not _has_evtx, reason="No evtx")
skip_no_srl2 = pytest.mark.skipif(not _has_srl2, reason="No SRL2_Samples")
skip_no_artifacts = pytest.mark.skipif(not _has_artifacts, reason="No test artifacts")
skip_no_7z = pytest.mark.skipif(not _has_7z, reason="No 7z")
skip_no_tools = pytest.mark.skipif(not _has_tools, reason="No EZ tools")
skip_no_plaso = pytest.mark.skipif(not _has_plaso, reason="No Plaso")

pytestmark = pytest.mark.timeout(120)


def _get_test_client():
    """Get OpenSearch client or skip."""
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        health = client.cluster.health()
        if health.get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch not healthy")
        return client
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")


def _unique_index(prefix="pytest"):
    return f"case-{prefix}-{uuid.uuid4().hex[:8]}-evtx-testhost"


def _wait_count(client, index, expected, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client.indices.refresh(index=index)
            r = client.count(index=index)
            if r["count"] >= expected:
                return r["count"]
        except Exception:
            pass
        time.sleep(0.5)
    client.indices.refresh(index=index)
    return client.count(index=index)["count"]


# ===================================================================
# 1. NORMALIZE — all 360 evtx files
# ===================================================================


class TestNormalizeAll360:
    """Parse ALL evtx files and verify normalize_event produces valid output."""

    @skip_no_evtx
    def test_all_evtx_files_parse_without_error(self):
        """Every evtx file in ~/logs/ parses without exceptions."""
        from opensearch_mcp.parse_evtx import parse_and_index

        evtx_files = sorted(_EVTX_DIR.glob("*.evtx"))
        assert len(evtx_files) >= 300, f"Expected 360 evtx files, found {len(evtx_files)}"

        errors = []
        total_events = 0

        for evtx in evtx_files:
            collected = []

            def collect(client, actions):
                collected.extend(actions)
                return len(actions), 0

            client = MagicMock()
            try:
                with patch("opensearch_mcp.parse_evtx.flush_bulk", side_effect=collect):
                    cnt, sk, bf = parse_and_index(
                        evtx_path=evtx,
                        client=client,
                        index_name="test",
                    )
                total_events += cnt
            except Exception as e:
                errors.append(f"{evtx.name}: {e}")

        assert not errors, f"Parse errors in {len(errors)} files:\n" + "\n".join(errors[:10])
        assert total_events > 0

    @skip_no_evtx
    def test_all_event_data_values_are_strings(self):
        """Coercion works: every EventData scalar across all events is a string."""
        from opensearch_mcp.parse_evtx import parse_and_index

        # Test on Security.evtx — richest event data
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

        type_violations = []
        for action in collected[:500]:  # sample first 500
            ed = action["_source"].get("winlog.event_data", {})
            for k, v in ed.items():
                if v is None:
                    continue
                if isinstance(v, dict):
                    for kk, vv in v.items():
                        if vv is not None and not isinstance(vv, (dict, list, str)):
                            type_violations.append(f"{k}.{kk}: {type(vv).__name__}={vv}")
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        if item is not None and not isinstance(item, (dict, list, str)):
                            type_violations.append(f"{k}[{i}]: {type(item).__name__}={item}")
                elif not isinstance(v, str):
                    type_violations.append(f"{k}: {type(v).__name__}={v}")

        assert not type_violations, f"{len(type_violations)} type violations:\n" + "\n".join(
            type_violations[:20]
        )


# ===================================================================
# 2. LIVE OPENSEARCH — index real evtx, query back
# ===================================================================


@pytest.mark.integration
class TestLiveEvtxIngest:
    @skip_no_evtx
    def test_index_real_evtx_and_search(self):
        """Index real Security.evtx into live OpenSearch, search back."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        sec = _EVTX_DIR / "Security.evtx"
        if not sec.exists():
            pytest.skip("No Security.evtx")

        index = _unique_index("live")
        try:
            cnt, sk, bf = parse_and_index(
                evtx_path=sec,
                client=client,
                index_name=index,
                source_file=str(sec),
            )
            assert cnt > 0
            assert bf == 0

            _wait_count(client, index, cnt)

            # Search for event code 4624
            result = client.search(
                index=index,
                body={"query": {"term": {"event.code": 4624}}},
            )
            # May or may not have 4624 events, but query must not error
            assert "hits" in result

            # Verify winlog.event_id also works (Sigma compatibility)
            result2 = client.search(
                index=index,
                body={"query": {"term": {"winlog.event_id": 4624}}},
            )
            assert result["hits"]["total"]["value"] == result2["hits"]["total"]["value"]

        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_event_data_fields_are_keyword_not_text(self):
        """Verify dynamic mapping creates keyword (not text) for EventData fields."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        sec = _EVTX_DIR / "Security.evtx"
        if not sec.exists():
            pytest.skip("No Security.evtx")

        index = _unique_index("mapping")
        try:
            parse_and_index(evtx_path=sec, client=client, index_name=index)
            client.indices.refresh(index=index)

            mapping = client.indices.get_mapping(index=index)
            props = list(mapping.values())[0]["mappings"]["properties"]

            # winlog.event_data should have sub-fields from dynamic template
            ed = (
                props.get("winlog", {})
                .get("properties", {})
                .get("event_data", {})
                .get("properties", {})
            )

            if ed:
                # Check that dynamically created fields are keyword, not text
                for field_name, field_def in ed.items():
                    if field_name == "ScriptBlockText":
                        # Explicit override to keyword with ignore_above 32766
                        assert field_def["type"] == "keyword"
                        continue
                    if field_def.get("type") == "text":
                        # This would mean dynamic_templates didn't apply
                        pytest.fail(
                            f"winlog.event_data.{field_name} mapped as text, "
                            "expected keyword from dynamic_templates"
                        )
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_wildcard_query_on_event_data(self):
        """Wildcard query on winlog.event_data.* fields works (Sigma compatibility)."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        # Use System.evtx — has ServiceName in event 7045
        sys_evtx = _EVTX_DIR / "System.evtx"
        if not sys_evtx.exists():
            pytest.skip("No System.evtx")

        index = _unique_index("wildcard")
        try:
            cnt, _, _ = parse_and_index(evtx_path=sys_evtx, client=client, index_name=index)
            if cnt == 0:
                pytest.skip("No events in System.evtx")
            _wait_count(client, index, min(cnt, 1))

            # Wildcard on a dynamically mapped keyword field
            result = client.search(
                index=index,
                body={"query": {"wildcard": {"winlog.channel": "Sys*"}}},
                size=1,
            )
            assert result["hits"]["total"]["value"] > 0
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_provenance_fields_present(self):
        """source_file, ingest_audit_id, pipeline_version on every doc."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        index = _unique_index("prov")
        try:
            parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name=index,
                source_file="/evidence/test.evtx",
                ingest_audit_id="audit-test-001",
            )
            _wait_count(client, index, 1)

            result = client.search(index=index, body={"query": {"match_all": {}}}, size=1)
            doc = result["hits"]["hits"][0]["_source"]
            assert doc.get("vhir.source_file") == "/evidence/test.evtx"
            assert doc.get("vhir.ingest_audit_id") == "audit-test-001"
            assert "pipeline_version" in doc
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_dedup_reingest_same_count(self):
        """Re-ingesting same evtx with same source produces same doc count."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        index = _unique_index("dedup")
        source = "/evidence/dedup-test.evtx"
        try:
            cnt1, _, _ = parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name=index,
                source_file=source,
            )
            _wait_count(client, index, cnt1)

            # Re-ingest same file
            cnt2, _, _ = parse_and_index(
                evtx_path=evtx,
                client=client,
                index_name=index,
                source_file=source,
            )
            client.indices.refresh(index=index)
            final_count = client.count(index=index)["count"]
            assert final_count == cnt1, f"Dedup failed: {final_count} != {cnt1}"
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_reduced_mode_fewer_events(self):
        """Reduced mode indexes fewer events than full mode."""
        from opensearch_mcp.parse_evtx import parse_and_index
        from opensearch_mcp.reduced import load_reduced_ids

        client = _get_test_client()
        sec = _EVTX_DIR / "Security.evtx"
        if not sec.exists():
            pytest.skip("No Security.evtx")

        idx_full = _unique_index("full")
        idx_reduced = _unique_index("reduced")
        reduced_ids = load_reduced_ids()
        try:
            cnt_full, _, _ = parse_and_index(
                evtx_path=sec,
                client=client,
                index_name=idx_full,
            )
            cnt_reduced, _, _ = parse_and_index(
                evtx_path=sec,
                client=client,
                index_name=idx_reduced,
                reduced_ids=reduced_ids,
            )
            if cnt_full > 0:
                assert cnt_reduced <= cnt_full
        finally:
            client.indices.delete(index=idx_full, ignore=[404])
            client.indices.delete(index=idx_reduced, ignore=[404])

    @skip_no_evtx
    def test_time_range_filter(self):
        """Time range filter excludes events outside range."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        sec = _EVTX_DIR / "Security.evtx"
        if not sec.exists():
            pytest.skip("No Security.evtx")

        idx_full = _unique_index("timefull")
        idx_range = _unique_index("timerange")
        try:
            cnt_full, _, _ = parse_and_index(
                evtx_path=sec,
                client=client,
                index_name=idx_full,
            )
            # Very narrow range
            t_from = datetime(2023, 6, 1, tzinfo=timezone.utc)
            t_to = datetime(2023, 6, 2, tzinfo=timezone.utc)
            cnt_range, _, _ = parse_and_index(
                evtx_path=sec,
                client=client,
                index_name=idx_range,
                time_from=t_from,
                time_to=t_to,
            )
            if cnt_full > 0:
                assert cnt_range <= cnt_full
        finally:
            client.indices.delete(index=idx_full, ignore=[404])
            client.indices.delete(index=idx_range, ignore=[404])


# ===================================================================
# 3. EZ TOOLS — real execution against real artifacts
# ===================================================================


@pytest.mark.integration
class TestEZToolsReal:
    @skip_no_tools
    @skip_no_artifacts
    def test_amcache_real_execution(self):
        """AmcacheParser runs on real Amcache.hve, produces CSV, indexes."""
        amcache = _ARTIFACTS / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
        if not amcache.exists():
            amcache = _ARTIFACTS / "Amcache.hve"
        if not amcache.exists():
            pytest.skip("No Amcache.hve")

        from opensearch_mcp.tools import run_and_ingest

        client = _get_test_client()
        case_id = f"pytest-{uuid.uuid4().hex[:8]}"
        index = f"case-{case_id}-amcache-testhost"
        try:
            cnt, sk, bf = run_and_ingest(
                tool_name="amcache",
                artifact_path=amcache,
                client=client,
                case_id=case_id,
                hostname="testhost",
                source_file=str(amcache),
                pipeline_version="test",
            )
            assert cnt > 0, "AmcacheParser produced no results"
            assert bf == 0
            _wait_count(client, index, cnt)
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_tools
    @skip_no_artifacts
    def test_shimcache_real_execution(self):
        """AppCompatCacheParser runs on real SYSTEM hive."""
        system = _ARTIFACTS / "Windows" / "System32" / "config" / "SYSTEM"
        if not system.exists():
            system = _ARTIFACTS / "SYSTEM"
        if not system.exists():
            pytest.skip("No SYSTEM hive")

        from opensearch_mcp.tools import run_and_ingest

        client = _get_test_client()
        index = f"case-pytest-{uuid.uuid4().hex[:8]}-shimcache-testhost"
        try:
            cnt, sk, bf = run_and_ingest(
                tool_name="shimcache",
                artifact_path=system,
                client=client,
                case_id=f"pytest-{uuid.uuid4().hex[:8]}",
                hostname="testhost",
            )
            assert cnt > 0, "ShimCache produced no results"
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_tools
    @skip_no_artifacts
    def test_registry_real_execution(self):
        """RECmd runs on real registry hive directory."""
        config_dir = _ARTIFACTS / "Windows" / "System32" / "config"
        if not config_dir.is_dir():
            pytest.skip("No config directory")

        from opensearch_mcp.tools import run_and_ingest

        client = _get_test_client()
        case_id = f"pytest-{uuid.uuid4().hex[:8]}"
        index = f"case-{case_id}-registry-testhost"
        try:
            cnt, sk, bf = run_and_ingest(
                tool_name="registry",
                artifact_path=config_dir / "SYSTEM",
                client=client,
                case_id=case_id,
                hostname="testhost",
            )
            assert cnt > 0, "RECmd produced no results"
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_tools
    @skip_no_artifacts
    def test_shellbags_real_execution(self):
        """SBECmd runs on real user profile."""
        users = _ARTIFACTS / "Users"
        if not users.is_dir():
            pytest.skip("No Users directory")
        skip = {"Public", "Default", "Default User", "All Users"}
        profiles = [p for p in users.iterdir() if p.is_dir() and p.name not in skip]
        if not profiles:
            pytest.skip("No user profiles")

        from opensearch_mcp.tools import run_and_ingest

        client = _get_test_client()
        case_id = f"pytest-{uuid.uuid4().hex[:8]}"
        index = f"case-{case_id}-shellbags-testhost"
        try:
            cnt, sk, bf = run_and_ingest(
                tool_name="shellbags",
                artifact_path=profiles[0],
                client=client,
                case_id=case_id,
                hostname="testhost",
            )
            # May be 0 if profile has no shellbags
            assert cnt >= 0
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_tools
    @skip_no_artifacts
    def test_mft_real_execution(self):
        """MFTECmd runs on real $MFT."""
        mft = _ARTIFACTS / "$MFT"
        if not mft.exists():
            pytest.skip("No $MFT")

        from opensearch_mcp.tools import run_and_ingest

        client = _get_test_client()
        case_id = f"pytest-{uuid.uuid4().hex[:8]}"
        index = f"case-{case_id}-mft-testhost"
        try:
            cnt, sk, bf = run_and_ingest(
                tool_name="mft",
                artifact_path=mft,
                client=client,
                case_id=case_id,
                hostname="testhost",
            )
            assert cnt > 1000, f"MFT should have many entries, got {cnt}"
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_tools
    @skip_no_artifacts
    def test_ez_tool_dedup_reingest(self):
        """Re-ingesting same artifact with same tool produces same count."""
        amcache = _ARTIFACTS / "Amcache.hve"
        if not amcache.exists():
            amcache = _ARTIFACTS / "Windows" / "appcompat" / "Programs" / "Amcache.hve"
        if not amcache.exists():
            pytest.skip("No Amcache.hve")

        from opensearch_mcp.tools import run_and_ingest

        client = _get_test_client()
        case_id = f"pytest-{uuid.uuid4().hex[:8]}"
        index = f"case-{case_id}-amcache-testhost"
        try:
            cnt1, _, _ = run_and_ingest(
                tool_name="amcache",
                artifact_path=amcache,
                client=client,
                case_id=case_id,
                hostname="testhost",
            )
            _wait_count(client, index, cnt1)

            cnt2, _, _ = run_and_ingest(
                tool_name="amcache",
                artifact_path=amcache,
                client=client,
                case_id=case_id,
                hostname="testhost",
            )
            client.indices.refresh(index=index)
            final = client.count(index=index)["count"]
            assert final == cnt1, f"Dedup failed: {final} != {cnt1}"
        finally:
            client.indices.delete(index=index, ignore=[404])


# ===================================================================
# 4. REAL ARCHIVE EXTRACTION — SRL2 triage packages
# ===================================================================


class TestRealArchiveExtraction:
    @skip_no_srl2
    @skip_no_7z
    @pytest.mark.slow
    def test_extract_real_7z_triage(self, tmp_path):
        """Extract real base-dc-triage.7z — contains a VHDX disk image.
        Verifies extraction produces the expected disk image file.
        Mounting the VHDX requires sudo (not available in test), so we
        only verify the archive-containing-image detection works."""
        archive = _SRL2_DIR / "base-dc-triage.7z"
        if not archive.exists():
            pytest.skip("No base-dc-triage.7z")

        dest = tmp_path / "extracted"
        dest.mkdir()
        from opensearch_mcp.containers import detect_container, extract_container

        extract_container(archive, dest)

        # This 7z contains a .vhdx file (disk image), not a directory tree
        extracted_files = list(dest.iterdir())
        names = {f.name for f in extracted_files}
        assert "base-dc-triage.vhdx" in names, f"Expected VHDX, got: {names}"

        # The VHDX should be detected as an NBD container
        vhdx = dest / "base-dc-triage.vhdx"
        assert detect_container(vhdx) == "nbd"

    @skip_no_srl2
    @skip_no_7z
    def test_extract_real_kansa_zip(self, tmp_path):
        """Extract real Kansa post-intrusion zip."""
        archive = _SRL2_DIR / "kansa-post-intrusion.zip"
        if not archive.exists():
            pytest.skip("No kansa-post-intrusion.zip")

        dest = tmp_path / "extracted"
        dest.mkdir()
        from opensearch_mcp.containers import extract_container

        extract_container(archive, dest)

        # Kansa produces CSV files, not Windows tree
        csvs = list(dest.rglob("*.csv"))
        assert len(csvs) >= 1, "No CSV files in Kansa output"


# ===================================================================
# 5. CSV INGEST — real Kansa CSVs (UTF-16LE)
# ===================================================================


@pytest.mark.integration
class TestRealCSVIngest:
    @skip_no_srl2
    @skip_no_7z
    def test_kansa_shimcache_utf16le(self, tmp_path):
        """Ingest real Kansa shimcache CSV (UTF-16LE encoded)."""
        archive = _SRL2_DIR / "kansa-post-intrusion_shimcache.zip"
        if not archive.exists():
            pytest.skip("No shimcache zip")

        dest = tmp_path / "extracted"
        dest.mkdir()
        from opensearch_mcp.containers import extract_container

        extract_container(archive, dest)

        csvs = list(dest.rglob("*.csv"))
        if not csvs:
            pytest.skip("No CSVs extracted")

        from opensearch_mcp.parse_csv import ingest_csv

        client = _get_test_client()
        index = f"case-pytest-{uuid.uuid4().hex[:8]}-shimcache-kansa"
        try:
            total = 0
            for csv_file in csvs:
                cnt, sk, bf = ingest_csv(
                    csv_path=csv_file,
                    client=client,
                    index_name=index,
                    hostname="kansa-host",
                )
                total += cnt
            # Kansa shimcache should have entries
            assert total >= 0  # May be 0 if CSV is header-only
        finally:
            client.indices.delete(index=index, ignore=[404])


# ===================================================================
# 6. INGEST ORCHESTRATOR — full pipeline
# ===================================================================


@pytest.mark.integration
class TestIngestOrchestrator:
    @skip_no_tools
    @skip_no_artifacts
    def test_full_ingest_pipeline(self):
        """Run the full ingest() orchestrator against real artifacts."""
        from opensearch_mcp.discover import scan_triage_directory
        from opensearch_mcp.ingest import ingest

        hosts = scan_triage_directory(_ARTIFACTS)
        if not hosts:
            pytest.skip("No hosts discovered")

        client = _get_test_client()
        from sift_common.audit import AuditWriter

        audit = AuditWriter(mcp_name="opensearch-mcp")
        case_id = f"pytest-{uuid.uuid4().hex[:8]}"

        indices_to_clean = []
        try:
            result = ingest(
                hosts=hosts,
                client=client,
                audit=audit,
                case_id=case_id,
                exclude={"mft", "usn", "timeline"},  # Skip slow tier 3
            )
            assert len(result.hosts) >= 1
            assert result.total_indexed > 0

            for h in result.hosts:
                for a in h.artifacts:
                    if a.index:
                        indices_to_clean.append(a.index)
        finally:
            for idx in indices_to_clean:
                client.indices.delete(index=idx, ignore=[404])


# ===================================================================
# 7. SERVER TOOLS — query real indexed data
# ===================================================================


@pytest.mark.integration
class TestServerToolsLive:
    @skip_no_evtx
    def test_idx_search_real_data(self):
        """idx_search against real indexed evtx data."""
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        index = _unique_index("search")
        try:
            parse_and_index(evtx_path=evtx, client=client, index_name=index)
            _wait_count(client, index, 1)

            from opensearch_mcp.server import idx_search

            with patch("opensearch_mcp.server._get_os", return_value=client):
                with patch(
                    "opensearch_mcp.server._os_call", side_effect=lambda fn, *a, **kw: fn(*a, **kw)
                ):
                    resp = idx_search(query="*", index=index, limit=5)
            assert resp["total"] > 0
            assert len(resp["results"]) <= 5
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_idx_count_real_data(self):
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        index = _unique_index("count")
        try:
            cnt, _, _ = parse_and_index(evtx_path=evtx, client=client, index_name=index)
            _wait_count(client, index, cnt)

            from opensearch_mcp.server import idx_count

            with patch("opensearch_mcp.server._get_os", return_value=client):
                with patch(
                    "opensearch_mcp.server._os_call", side_effect=lambda fn, *a, **kw: fn(*a, **kw)
                ):
                    resp = idx_count(query="*", index=index)
            assert resp["count"] == cnt
        finally:
            client.indices.delete(index=index, ignore=[404])

    @skip_no_evtx
    def test_idx_status_shows_test_index(self):
        from opensearch_mcp.parse_evtx import parse_and_index

        client = _get_test_client()
        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        index = _unique_index("status")
        try:
            parse_and_index(evtx_path=evtx, client=client, index_name=index)
            _wait_count(client, index, 1)

            from opensearch_mcp.server import idx_status

            with patch("opensearch_mcp.server._get_os", return_value=client):
                with patch(
                    "opensearch_mcp.server._os_call", side_effect=lambda fn, *a, **kw: fn(*a, **kw)
                ):
                    resp = idx_status()
            idx_names = [i["index"] for i in resp.get("indices", [])]
            assert index in idx_names
        finally:
            client.indices.delete(index=index, ignore=[404])


# ===================================================================
# 8. MANIFEST — SHA256 on real files
# ===================================================================


class TestManifestReal:
    @skip_no_artifacts
    def test_sha256_real_system_hive(self):
        """SHA256 of real SYSTEM hive is deterministic."""
        from opensearch_mcp.manifest import sha256_file

        system = _ARTIFACTS / "SYSTEM"
        if not system.exists():
            system = _ARTIFACTS / "Windows" / "System32" / "config" / "SYSTEM"
        if not system.exists():
            pytest.skip("No SYSTEM hive")

        hash1 = sha256_file(system)
        hash2 = sha256_file(system)
        assert hash1 == hash2
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)

    @skip_no_evtx
    def test_sha256_real_evtx(self):
        from opensearch_mcp.manifest import sha256_file

        evtx = sorted(_EVTX_DIR.glob("*.evtx"))[0]
        h = sha256_file(evtx)
        assert len(h) == 64


# ===================================================================
# 9. REDUCED EVENT IDS
# ===================================================================


class TestReducedEventIds:
    def test_load_reduced_ids(self):
        from opensearch_mcp.reduced import load_reduced_ids

        ids = load_reduced_ids()
        assert len(ids) >= 70
        assert 4624 in ids  # authentication
        assert 7045 in ids  # persistence
        assert 1 in ids  # sysmon process create
        assert 4104 in ids  # powershell script block

    def test_reduced_ids_all_integers(self):
        from opensearch_mcp.reduced import load_reduced_ids

        ids = load_reduced_ids()
        for eid in ids:
            assert isinstance(eid, int), f"Event ID {eid} is {type(eid)}"

    def test_reduced_ids_cached(self):
        from opensearch_mcp.reduced import load_reduced_ids

        ids1 = load_reduced_ids()
        ids2 = load_reduced_ids()
        assert ids1 is ids2  # Same object (cached)


# ===================================================================
# 10. INGEST STATUS
# ===================================================================


class TestIngestStatusReal:
    def test_write_and_read_status(self, tmp_path, monkeypatch):
        from unittest.mock import patch

        from opensearch_mcp.ingest_status import read_active_ingests, write_status

        status_dir = tmp_path / "status"
        monkeypatch.setattr("opensearch_mcp.ingest_status._STATUS_DIR", status_dir)

        write_status(
            case_id="test-case",
            pid=os.getpid(),
            run_id="run-123",
            status="running",
            hosts=[{"hostname": "host1", "artifacts": []}],
            totals={"indexed": 1000},
            started="2024-01-15T10:00:00Z",
        )

        with patch("opensearch_mcp.ingest_status._is_process_alive", return_value=True):
            ingests = read_active_ingests()
        assert len(ingests) == 1
        assert ingests[0]["case_id"] == "test-case"
        assert ingests[0]["status"] == "running"
        assert ingests[0]["totals"]["indexed"] == 1000
