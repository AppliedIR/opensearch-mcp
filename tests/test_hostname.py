"""Tests for hostname.py — Commit B of host-identity Rev 1.5.

Covers:
  Test 3   — test_detect_hostname_from_volume (registry detect contract)
  Test 14  — test_batch_discovery_writes_host_unmapped_yaml + cleanup
  Test 13  — test_host_field_priority_source_agnostic (shared priority list)
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import yaml

from opensearch_mcp.host_dictionary import HostDictionary
from opensearch_mcp.hostname import (
    _HOST_FIELD_PRIORITY,
    _dotted_get,
    archive_resolved_unmapped_yaml,
    classify_host,
    detect_hostname_from_volume,
    extract_host_from_record,
    write_host_unmapped_yaml,
)

# ---------------------------------------------------------------------------
# Registry detect (Test 3)
# ---------------------------------------------------------------------------


def _fake_val(name, value):
    v = type("V", (), {})()
    v.name = name
    v.value = value
    return v


def _make_system_volume(tmp_path: Path) -> Path:
    cfg = tmp_path / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"regf-placeholder")
    return tmp_path


def _install_fake_regipy(monkeypatch, fake_hive_cls):
    fake_mod = types.ModuleType("regipy.registry")
    fake_mod.RegistryHive = fake_hive_cls
    monkeypatch.setitem(sys.modules, "regipy", types.ModuleType("regipy"))
    monkeypatch.setitem(sys.modules, "regipy.registry", fake_mod)


class TestDetectHostnameFromVolume:
    """Spec Test 3 — registry detect returns FQDN or None, never raises."""

    def test_computer_name_plus_domain(self, tmp_path, monkeypatch):
        """ActiveComputerName + Tcpip Domain → joined FQDN."""
        volume = _make_system_volume(tmp_path)
        seen_paths: list[str] = []

        def _k(values):
            return type("K", (), {"iter_values": lambda self: iter(values)})()

        class FakeHive:
            def __init__(self, p):
                pass

            def get_key(self, path):
                seen_paths.append(path)
                if path.endswith("ActiveComputerName"):
                    return _k([_fake_val("ComputerName", "ADMIN01")])
                if path.endswith("Tcpip\\Parameters"):
                    return _k([_fake_val("Domain", "shieldbase.com")])
                raise Exception("not found")

        _install_fake_regipy(monkeypatch, FakeHive)

        result = detect_hostname_from_volume(volume)
        assert result == "ADMIN01.shieldbase.com"
        # Leading-backslash contract: every captured path must start with \
        for p in seen_paths:
            assert p.startswith("\\"), f"regipy path missing leading \\: {p!r}"

    def test_computer_name_only_no_domain(self, tmp_path, monkeypatch):
        volume = _make_system_volume(tmp_path)

        def _k(values):
            return type("K", (), {"iter_values": lambda self: iter(values)})()

        class FakeHive:
            def __init__(self, p):
                pass

            def get_key(self, path):
                if path.endswith("ActiveComputerName"):
                    return _k([_fake_val("ComputerName", "ADMIN01")])
                raise Exception("not found")

        _install_fake_regipy(monkeypatch, FakeHive)
        assert detect_hostname_from_volume(volume) == "ADMIN01"

    def test_falls_back_to_controlset002(self, tmp_path, monkeypatch):
        volume = _make_system_volume(tmp_path)

        def _k(values):
            return type("K", (), {"iter_values": lambda self: iter(values)})()

        class FakeHive:
            def __init__(self, p):
                pass

            def get_key(self, path):
                if "\\ControlSet002\\" in path and path.endswith("ActiveComputerName"):
                    return _k([_fake_val("ComputerName", "FALLBACK01")])
                raise Exception("ControlSet001 absent")

        _install_fake_regipy(monkeypatch, FakeHive)
        assert detect_hostname_from_volume(volume) == "FALLBACK01"

    def test_no_system_hive_returns_none(self, tmp_path):
        # Empty volume — no SYSTEM hive.
        assert detect_hostname_from_volume(tmp_path) is None

    def test_graceful_on_hive_open_failure(self, tmp_path, monkeypatch):
        volume = _make_system_volume(tmp_path)

        class FakeHive:
            def __init__(self, p):
                raise RuntimeError("corrupt hive")

            def get_key(self, path):
                raise NotImplementedError

        _install_fake_regipy(monkeypatch, FakeHive)
        assert detect_hostname_from_volume(volume) is None


# ---------------------------------------------------------------------------
# _HOST_FIELD_PRIORITY + extract_host_from_record (Test 13)
# ---------------------------------------------------------------------------


class TestHostFieldPrioritySourceAgnostic:
    """Spec Test 13 — shared field list resolves from CSV row + JSON doc
    shapes with the same logic, first-hit-wins."""

    def test_kansa_host_column(self):
        row = {"Host": "admin01.shieldbase.com", "OtherCol": "x"}
        assert extract_host_from_record(row) == "admin01.shieldbase.com"

    def test_windows_computername(self):
        doc = {"ComputerName": "ADMIN01"}
        assert extract_host_from_record(doc) == "ADMIN01"

    def test_flattened_eventdata_computer(self):
        doc = {"Computer": "rd01.shieldbase.com"}
        assert extract_host_from_record(doc) == "rd01.shieldbase.com"

    def test_velociraptor_flat_hostname(self):
        doc = {"Hostname": "admin01"}
        assert extract_host_from_record(doc) == "admin01"

    def test_velociraptor_nested_client_info_hostname(self):
        doc = {"ClientInfo": {"Hostname": "admin01"}}
        assert extract_host_from_record(doc) == "admin01"

    def test_first_hit_wins(self):
        """Earlier field in priority list wins even if later fields also present."""
        doc = {"Host": "admin01", "Hostname": "other01"}
        assert extract_host_from_record(doc) == "admin01"

    def test_pre_stamped_host_name_preserved(self):
        doc = {"host.name": "admin01"}
        # dotted key won't traverse here because "host.name" is a literal
        # dict key, not nested path. Our _dotted_get walks through dict
        # levels — a literal dotted key is a miss.
        # Velociraptor JSON never emits "host.name" at root literally,
        # so this is a nested-shape test:
        assert extract_host_from_record(doc) is None
        # Nested shape matches:
        doc_nested = {"host": {"name": "admin01"}}
        assert extract_host_from_record(doc_nested) == "admin01"

    def test_no_field_returns_none(self):
        assert extract_host_from_record({"random": "value"}) is None

    def test_empty_field_skipped(self):
        """Empty string is not a hit — falls through to next priority."""
        doc = {"Host": "", "ComputerName": "admin01"}
        assert extract_host_from_record(doc) == "admin01"

    def test_whitespace_only_field_skipped(self):
        doc = {"Host": "   ", "ComputerName": "admin01"}
        assert extract_host_from_record(doc) == "admin01"

    def test_priority_list_shape_is_a_tuple(self):
        """Frozen list — accidental mutation would corrupt ingest state."""
        assert isinstance(_HOST_FIELD_PRIORITY, tuple)
        assert "Host" in _HOST_FIELD_PRIORITY
        assert "Hostname" in _HOST_FIELD_PRIORITY
        assert "ClientInfo.Hostname" in _HOST_FIELD_PRIORITY

    def test_dotted_get_gap_returns_none(self):
        """Partial nesting — intermediate key missing → None."""
        assert _dotted_get({"ClientInfo": {"OtherField": 1}}, "ClientInfo.Hostname") is None


# ---------------------------------------------------------------------------
# classify_host
# ---------------------------------------------------------------------------


class TestClassifyHost:
    def test_mapped_via_dict(self):
        d = HostDictionary(hosts={"admin01": {"aliases": ["admin01", "ADMIN01"]}})
        status, raw, proposed, conf = classify_host("ADMIN01", d)
        assert status == "mapped"
        assert proposed == "admin01"
        assert conf == 1.0

    def test_unmapped_with_proposal(self):
        d = HostDictionary(
            hosts={"wkstn01": {"aliases": ["wkstn01"]}},
            domains=["shieldbase.com"],
        )
        status, raw, proposed, conf = classify_host("wksn01", d)
        assert status == "unmapped-with-proposal"
        assert proposed == "wkstn01"
        assert conf >= 0.85

    def test_unmapped_no_proposal(self):
        d = HostDictionary(hosts={"admin01": {"aliases": ["admin01"]}})
        status, raw, proposed, conf = classify_host("WIN-3BVS460J98U", d)
        assert status == "unmapped-no-proposal"
        assert proposed is None

    def test_empty_input(self):
        d = HostDictionary()
        status, raw, proposed, conf = classify_host("", d)
        assert status == "empty"


# ---------------------------------------------------------------------------
# Batch discovery — host-unmapped.yaml (Test 14)
# ---------------------------------------------------------------------------


class TestHostUnmappedYaml:
    """Spec Test 14 — batch writes all unmapped + cleanup rename on re-run."""

    def test_writes_yaml_with_entries(self, tmp_path):
        entries = [
            {
                "raw": "wksn01",
                "first_seen": "2026-04-24T18:00:00Z",
                "sources": ["evtx:admin01:Security:4624"],
                "proposed_canonical": "wkstn01",
                "confidence": 0.857,
                "action_required": ("vhir case host add wksn01 --alias-of wkstn01"),
            },
            {
                "raw": "WIN-3BVS460J98U",
                "first_seen": "2026-04-24T18:02:00Z",
                "sources": ["evtx:elf01:System:6009"],
                "proposed_canonical": None,
                "confidence": 0.0,
                "action_required": ("vhir case host add WIN-3BVS460J98U --new-canonical"),
            },
        ]

        path = write_host_unmapped_yaml(tmp_path, entries)
        assert path == tmp_path / "host-unmapped.yaml"
        assert path.exists()

        payload = yaml.safe_load(path.read_text())
        assert "note" in payload
        assert "host-unmapped.yaml.resolved" in payload["note"]
        assert len(payload["entries"]) == 2
        assert payload["entries"][0]["raw"] == "wksn01"
        assert payload["entries"][0]["proposed_canonical"] == "wkstn01"
        assert payload["entries"][1]["proposed_canonical"] is None

    def test_cleanup_rename_after_resolution(self, tmp_path):
        """After re-run with all entries resolved, file renamed to .resolved.<ts>."""
        write_host_unmapped_yaml(tmp_path, [{"raw": "wksn01"}])
        assert (tmp_path / "host-unmapped.yaml").exists()

        new_path = archive_resolved_unmapped_yaml(tmp_path)
        assert new_path is not None
        assert new_path.parent == tmp_path
        assert new_path.name.startswith("host-unmapped.yaml.resolved.")
        assert new_path.name.endswith("Z")
        assert new_path.exists()
        assert not (tmp_path / "host-unmapped.yaml").exists()

    def test_cleanup_returns_none_when_no_file(self, tmp_path):
        assert archive_resolved_unmapped_yaml(tmp_path) is None


# ---------------------------------------------------------------------------
# peek_hostname_from_evidence — pre-classify fallback affordance
# ---------------------------------------------------------------------------


class TestPeekHostnameFromEvidence:
    """Walks scan_root for the first CSV/JSONL/JSON and extracts a
    hostname from its first record — used as a fallback when registry
    detect fails so host-unmapped.yaml carries a real raw value instead
    of `_mnt_1` directory-scan junk."""

    def test_finds_hostname_in_first_csv(self, tmp_path):
        from opensearch_mcp.hostname import peek_hostname_from_evidence

        csv_file = tmp_path / "kansa.csv"
        csv_file.write_text("Host,other\nadmin01.shieldbase.com,data\n")
        assert peek_hostname_from_evidence(tmp_path) == "admin01.shieldbase.com"

    def test_finds_hostname_in_jsonl(self, tmp_path):
        import json

        from opensearch_mcp.hostname import peek_hostname_from_evidence

        jsonl = tmp_path / "vr.jsonl"
        jsonl.write_text(json.dumps({"Hostname": "admin01"}) + "\n")
        assert peek_hostname_from_evidence(tmp_path) == "admin01"

    def test_finds_hostname_in_nested_json_field(self, tmp_path):
        import json

        from opensearch_mcp.hostname import peek_hostname_from_evidence

        jsonl = tmp_path / "vr.jsonl"
        jsonl.write_text(json.dumps({"ClientInfo": {"Hostname": "rd01"}}) + "\n")
        assert peek_hostname_from_evidence(tmp_path) == "rd01"

    def test_returns_none_when_no_evidence_files(self, tmp_path):
        from opensearch_mcp.hostname import peek_hostname_from_evidence

        assert peek_hostname_from_evidence(tmp_path) is None

    def test_returns_none_when_no_priority_field(self, tmp_path):
        from opensearch_mcp.hostname import peek_hostname_from_evidence

        csv_file = tmp_path / "data.csv"
        csv_file.write_text("col1,col2\nv1,v2\n")
        assert peek_hostname_from_evidence(tmp_path) is None

    def test_skips_index_sidecars(self, tmp_path):
        """Velociraptor binary `.index` offsets must not be parsed."""
        from opensearch_mcp.hostname import peek_hostname_from_evidence

        (tmp_path / "a.json.index").write_bytes(b"\x00\x01\x02\x03")
        import json

        (tmp_path / "a.jsonl").write_text(json.dumps({"Hostname": "admin01"}) + "\n")
        assert peek_hostname_from_evidence(tmp_path) == "admin01"

    def test_nonexistent_scan_root_returns_none(self, tmp_path):
        from opensearch_mcp.hostname import peek_hostname_from_evidence

        assert peek_hostname_from_evidence(tmp_path / "does-not-exist") is None

    def test_walks_subdirectories(self, tmp_path):
        from opensearch_mcp.hostname import peek_hostname_from_evidence

        sub = tmp_path / "host1" / "kansa"
        sub.mkdir(parents=True)
        (sub / "out.csv").write_text("ComputerName,x\nADMIN01,1\n")
        assert peek_hostname_from_evidence(tmp_path) == "ADMIN01"

    def test_first_record_has_empty_priority_falls_through_to_next_file(self, tmp_path):
        import json

        from opensearch_mcp.hostname import peek_hostname_from_evidence

        (tmp_path / "a.jsonl").write_text(json.dumps({"random": "value"}) + "\n")
        (tmp_path / "b.jsonl").write_text(json.dumps({"Hostname": "rd01"}) + "\n")
        assert peek_hostname_from_evidence(tmp_path) == "rd01"
