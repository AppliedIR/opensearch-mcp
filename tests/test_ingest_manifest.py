"""Tests for _write_ingest_manifest — the renamed/rewritten manifest writer.

Verifies the two load-bearing behaviors of the B-registry-pollution fix:
  1. Manifests land in case/audit/ingest-manifests/ — NOT case/evidence/
  2. No evidence_register call is made — internal audit records don't
     go through the operator-facing registry.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from opensearch_mcp.ingest import _write_ingest_manifest


def _setup_active_case(tmp_path: Path, monkeypatch) -> Path:
    """Point vhir_dir()/active_case at a freshly-created case dir."""
    fake_home = tmp_path / "home"
    fake_vhir = fake_home / ".vhir"
    fake_vhir.mkdir(parents=True)
    case_dir = tmp_path / "cases" / "INC-TEST"
    case_dir.mkdir(parents=True)
    (fake_vhir / "active_case").write_text(str(case_dir))
    monkeypatch.setattr("opensearch_mcp.paths.vhir_home", lambda: fake_home)
    return case_dir


class TestWriteIngestManifest:
    def test_manifest_goes_to_audit_not_evidence(self, tmp_path, monkeypatch):
        case_dir = _setup_active_case(tmp_path, monkeypatch)

        _write_ingest_manifest(
            "/evidence/host1/evtx/Security.evtx",
            "host1",
            "evtx",
            sha256="abc123",
            doc_count=42,
        )

        audit_dir = case_dir / "audit" / "ingest-manifests"
        evidence_dir = case_dir / "evidence"
        assert audit_dir.is_dir()
        assert not evidence_dir.exists() or not any(
            p.suffix == ".json" for p in evidence_dir.iterdir()
        )
        manifests = list(audit_dir.glob("*.manifest.json"))
        assert len(manifests) == 1
        m = json.loads(manifests[0].read_text())
        assert m["hostname"] == "host1"
        assert m["artifact_type"] == "evtx"
        assert m["sha256"] == "abc123"
        assert m["doc_count"] == 42

    def test_does_not_call_evidence_register(self, tmp_path, monkeypatch):
        _setup_active_case(tmp_path, monkeypatch)

        with patch("opensearch_mcp.gateway.call_tool") as mock_call:
            _write_ingest_manifest("/evidence/host1/evtx/App.evtx", "host1", "evtx", doc_count=1)
        assert mock_call.call_count == 0

    def test_no_active_case_is_noop(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        (fake_home / ".vhir").mkdir(parents=True)
        monkeypatch.setattr("opensearch_mcp.paths.vhir_home", lambda: fake_home)
        _write_ingest_manifest("/x/y.evtx", "h", "evtx")  # must not raise

    def test_sha256_omitted_when_empty(self, tmp_path, monkeypatch):
        case_dir = _setup_active_case(tmp_path, monkeypatch)
        _write_ingest_manifest("/x/y.evtx", "host1", "evtx", doc_count=5)
        manifest = next((case_dir / "audit" / "ingest-manifests").glob("*.manifest.json"))
        m = json.loads(manifest.read_text())
        assert "sha256" not in m
        assert m["doc_count"] == 5

    def test_colliding_stems_do_not_overwrite(self, tmp_path, monkeypatch):
        """Real Defender EVTX channels whose first 50 chars of stem
        collide must land in separate manifests. Regression for the
        `[:50]` truncation overwriting on every RDP-enabled Windows host.
        """
        case_dir = _setup_active_case(tmp_path, monkeypatch)

        collisions = [
            "/ev/rd01/evtx/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "/ev/rd01/evtx/Microsoft-Windows-TerminalServices-LocalSessionManager%4Admin.evtx",
        ]
        for p in collisions:
            _write_ingest_manifest(p, "rd01", "evtx", doc_count=1)

        manifests = list((case_dir / "audit" / "ingest-manifests").glob("*.manifest.json"))
        assert len(manifests) == 2, (
            f"Expected 2 manifests; got {len(manifests)}. Stem truncation "
            "is overwriting colliding channel names."
        )
        sources = {json.loads(m.read_text())["source_path"] for m in manifests}
        assert sources == set(collisions)

    def test_written_at_field_name(self, tmp_path, monkeypatch):
        """Field reflects actual semantics — nothing is 'registered' now."""
        case_dir = _setup_active_case(tmp_path, monkeypatch)
        _write_ingest_manifest("/x/y.evtx", "host1", "evtx")
        m = json.loads(
            next((case_dir / "audit" / "ingest-manifests").glob("*.manifest.json")).read_text()
        )
        assert "written_at" in m
        assert "registered_at" not in m
