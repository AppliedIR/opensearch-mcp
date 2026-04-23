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
    propose_canonical,
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
        snapshot = (d.to_yaml(),)
        for _ in range(100):
            d.resolve("ADMIN01")
            d.resolve("unknown")
            d.resolve("")
        assert (d.to_yaml(),) == snapshot


class TestProposeCanonical:
    """Spec Test 2 — exact-strip 1.00, Levenshtein 0.85, alphabetical tie-break."""

    def test_uppercase_bare_match(self):
        d = _dict3()
        suggestion, conf = propose_canonical("ADMIN01", d)
        assert suggestion == "admin01"
        assert conf == 1.00

    def test_fqdn_strip_match(self):
        d = _dict3()
        suggestion, conf = propose_canonical("admin01.shieldbase.com", d)
        assert suggestion == "admin01"
        assert conf == 1.00

    def test_triage_suffix_strip(self):
        d = _dict3()
        suggestion, conf = propose_canonical("admin01-triage", d)
        assert suggestion == "admin01"
        assert conf == 1.00

    def test_triage_underscore_variant(self):
        d = _dict3()
        suggestion, conf = propose_canonical("admin01_triage", d)
        assert suggestion == "admin01"
        assert conf == 1.00

    def test_levenshtein_typo_wksn01(self):
        """SC-2 pin — wksn01 vs wkstn01 at ≈0.857 must pass 0.85 threshold."""
        d = _dict3()
        suggestion, conf = propose_canonical("wksn01", d)
        assert suggestion == "wkstn01"
        assert conf >= 0.85
        assert conf < 1.00  # not exact

    def test_no_close_match_returns_none(self):
        d = _dict3()
        suggestion, conf = propose_canonical("WIN-3BVS460J98U", d)
        assert suggestion is None
        assert conf == 0.0

    def test_empty_input_returns_none(self):
        d = _dict3()
        assert propose_canonical("", d) == (None, 0.0)
        assert propose_canonical(None, d) == (None, 0.0)

    def test_alphabetical_tie_break(self):
        """SC-3 pin — equidistant canonicals break alphabetically."""
        # Input differs by 1 char from each canonical (6/7 = 0.857 > 0.85
        # threshold) so both are candidates. wkstn01 and zkstn01 are both
        # distance 1 from xkstn01; alphabetical order → wkstn01 wins.
        d = HostDictionary(
            hosts={
                "zkstn01": {"aliases": ["zkstn01"]},
                "wkstn01": {"aliases": ["wkstn01"]},
            }
        )
        suggestion, conf = propose_canonical("xkstn01", d)
        assert suggestion == "wkstn01"  # alphabetically earlier of the two ties
        assert conf >= 0.85


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

    def test_roundtrip_via_to_yaml(self):
        """Construct with False, serialize, parse back, flag preserved."""
        d_before = HostDictionary(
            auto_accept_high_confidence=False,
            domains=["shieldbase.com"],
            hosts={"admin01": {"aliases": ["admin01"]}},
        )
        serialized = d_before.to_yaml()
        reloaded = yaml.safe_load(serialized)
        assert reloaded["auto_accept_high_confidence"] is False
        assert reloaded["version"] == 1

    def test_save_is_not_yet_implemented(self):
        """SC-8 stub — save() raises until Commit D fills it in."""
        d = HostDictionary()
        with pytest.raises(NotImplementedError, match="Commit D"):
            d.save()

    def test_add_alias_is_not_yet_implemented(self):
        d = HostDictionary()
        with pytest.raises(NotImplementedError, match="Commit D"):
            d.add_alias("foo", "bar")
