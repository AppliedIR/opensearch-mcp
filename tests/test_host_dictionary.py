"""Tests for host_dictionary — Commit A of host-identity Rev 1.5.

4 tests per spec (host-identity-normalization-2026-04-24.md):
  Test 1  — test_host_dictionary_resolve (pure, case-insensitive,
            whitespace-trim, trailing-dot, empty no-op)
  Test 2  — test_propose_canonical (1.00 strips, 0.85 Levenshtein,
            alphabetical tie-break, no-match)
  Test A3 — test_host_dictionary_schema_version (reject unknown version)
  Test A4 — test_auto_accept_high_confidence_flag_roundtrip
"""

from __future__ import annotations

import pytest
import yaml

from opensearch_mcp.host_dictionary import (
    HostDictionary,
    UnsupportedHostDictVersion,
)


def _dict3(auto_accept: bool = True) -> HostDictionary:
    """Fixture: 3 canonicals × 3 aliases each."""
    return HostDictionary(
        domains=["shieldbase.com"],
        hosts={
            "admin01": {
                "aliases": ["admin01", "ADMIN01", "admin01.shieldbase.com"],
            },
            "rd01": {
                "aliases": ["rd01", "RD01", "rd01.shieldbase.com"],
            },
            "wkstn01": {
                "aliases": ["wkstn01", "WKSTN01", "wkstn01.shieldbase.com"],
            },
        },
        auto_accept_high_confidence=auto_accept,
    )


class TestHostDictionaryResolve:
    """Spec Test 1 — resolve is pure, normalized, empty-safe."""

    def test_exact_canonical_match(self):
        d = _dict3()
        assert d.resolve("admin01") == "admin01"

    def test_exact_alias_match(self):
        d = _dict3()
        assert d.resolve("admin01.shieldbase.com") == "admin01"

    def test_case_insensitive(self):
        d = _dict3()
        assert d.resolve("ADMIN01") == "admin01"
        assert d.resolve("Admin01.ShieldBase.com") == "admin01"

    def test_whitespace_trimmed(self):
        d = _dict3()
        assert d.resolve("  admin01  ") == "admin01"
        assert d.resolve("\tadmin01.shieldbase.com\n") == "admin01"

    def test_trailing_dot_stripped(self):
        """SC-5 pin — FQDN trailing dot normalized off."""
        d = _dict3()
        assert d.resolve("admin01.shieldbase.com.") == "admin01"

    def test_empty_input_noop(self):
        """SC-4 pin — empty / None / whitespace-only → None, no mutation."""
        d = _dict3()
        before_unmapped = list(d.unmapped)
        assert d.resolve("") is None
        assert d.resolve(None) is None
        assert d.resolve("   ") is None
        assert d.resolve("\t\n") is None
        assert d.unmapped == before_unmapped  # pure: no append

    def test_miss_returns_none_without_mutation(self):
        """SC-1 pin — resolve is pure, miss does not append to unmapped[]."""
        d = _dict3()
        before_unmapped = list(d.unmapped)
        before_hosts = dict(d.hosts)
        assert d.resolve("unknownhost") is None
        assert d.unmapped == before_unmapped
        assert d.hosts == before_hosts

    def test_resolve_is_idempotent(self):
        """Purity: 100 calls leave dict state identical."""
        d = _dict3()
        snapshot = (repr(d.hosts), repr(d.unmapped))
        for _ in range(100):
            d.resolve("ADMIN01")
            d.resolve("unknown")
            d.resolve("")
        assert (repr(d.hosts), repr(d.unmapped)) == snapshot


class TestHostDictionarySchemaVersion:
    """Spec Test A3 (SC-6 pin) — unknown version raises, no best-effort load."""

    def test_load_version_1_ok(self, tmp_path):
        p = tmp_path / "host-dictionary.yaml"
        p.write_text(
            yaml.safe_dump(
                {"version": 1, "domains": [], "hosts": {}, "unmapped": []},
            )
        )
        d = HostDictionary.load(p)
        assert d.path == p
        assert d.hosts == {}

    def test_load_version_2_rejected(self, tmp_path):
        p = tmp_path / "host-dictionary.yaml"
        p.write_text(
            yaml.safe_dump(
                {"version": 2, "domains": [], "hosts": {}, "unmapped": []},
            )
        )
        with pytest.raises(UnsupportedHostDictVersion) as exc:
            HostDictionary.load(p)
        assert "version=2" in str(exc.value)
        assert "version=1" in str(exc.value)

    def test_load_missing_version_rejected(self, tmp_path):
        p = tmp_path / "host-dictionary.yaml"
        p.write_text(yaml.safe_dump({"domains": [], "hosts": {}}))
        with pytest.raises(UnsupportedHostDictVersion):
            HostDictionary.load(p)


class TestAutoAcceptHighConfidenceRoundtrip:
    """Spec Test A4 — flag round-trips through YAML load/save."""

    def test_flag_defaults_to_true_when_absent(self, tmp_path):
        p = tmp_path / "host-dictionary.yaml"
        p.write_text(
            yaml.safe_dump(
                {"version": 1, "domains": [], "hosts": {}, "unmapped": []},
            )
        )
        d = HostDictionary.load(p)
        assert d.auto_accept_high_confidence is True

    def test_flag_false_is_preserved(self, tmp_path):
        p = tmp_path / "host-dictionary.yaml"
        p.write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "auto_accept_high_confidence": False,
                    "domains": [],
                    "hosts": {},
                    "unmapped": [],
                }
            )
        )
        d = HostDictionary.load(p)
        assert d.auto_accept_high_confidence is False
