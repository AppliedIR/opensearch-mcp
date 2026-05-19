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


class TestSaveAtomic:
    """v1 Test 1 — save() writes via temp+rename; crash mid-write leaves prior file."""

    def test_save_writes_full_yaml(self, tmp_path):
        p = tmp_path / "host-dictionary.yaml"
        d = HostDictionary(
            domains=["shieldbase.com"],
            hosts={"admin01": {"aliases": ["admin01", "ADMIN01"]}},
            path=p,
        )
        d.save()
        assert p.exists()
        reloaded = HostDictionary.load(p)
        assert "admin01" in reloaded.hosts
        assert "ADMIN01" in reloaded.hosts["admin01"]["aliases"]

    def test_save_atomic_temp_rename(self, tmp_path):
        """The implementation writes to <path>.tmp then os.replace.

        Verify that .tmp file is gone after a successful save (os.replace
        removes the source name on POSIX).
        """
        p = tmp_path / "host-dictionary.yaml"
        d = HostDictionary(hosts={"x": {"aliases": ["x"]}}, path=p)
        d.save()
        assert not (tmp_path / "host-dictionary.yaml.tmp").exists()

    def test_save_partial_write_leaves_prior_state(self, tmp_path, monkeypatch):
        """If os.replace fails after tmp write, prior file is preserved."""
        p = tmp_path / "host-dictionary.yaml"
        # First successful save establishes a prior state on disk.
        HostDictionary(hosts={"prior": {"aliases": ["prior"]}}, path=p).save()
        before = p.read_text()

        # Now construct a new dict and simulate os.replace failure.
        d = HostDictionary(hosts={"new": {"aliases": ["new"]}}, path=p)
        import os

        real_replace = os.replace

        def fail_replace(src, dst):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", fail_replace)
        with pytest.raises(OSError):
            d.save()
        # Prior file content intact
        assert p.read_text() == before
        monkeypatch.setattr(os, "replace", real_replace)

    def test_save_without_path_raises(self):
        d = HostDictionary(hosts={"x": {"aliases": ["x"]}})
        with pytest.raises(ValueError, match="path"):
            d.save()

    def test_save_merge_unions_concurrent_adds(self, tmp_path):
        """WSL2 Test B2 — concurrent ADD-ONLY save with merge=True
        unions both processes' adds on disk. Without merge, the second
        save's changes clobber the first."""
        p = tmp_path / "host-dictionary.yaml"
        # Establish a base on disk.
        HostDictionary(
            hosts={"admin01": {"aliases": ["admin01"]}},
            path=p,
        ).save()

        # Simulate Process A: loads, adds OFFDEVS-TUHMGJE
        a = HostDictionary.load(p)
        a.add_canonical("OFFDEVS-TUHMGJE")

        # Simulate Process B: also loads, adds host-B
        b = HostDictionary.load(p)
        b.add_canonical("host-B")

        # Both save with merge=True (preflight semantics)
        a.save(merge=True)
        b.save(merge=True)

        # On disk, both adds survive — last save unioned with first.
        reloaded = HostDictionary.load(p)
        assert "OFFDEVS-TUHMGJE" in reloaded.hosts, (
            "Process A's add was clobbered by Process B's save — merge-on-save is broken"
        )
        assert "host-B" in reloaded.hosts
        assert "admin01" in reloaded.hosts

    def test_save_replace_mode_preserves_deletions(self, tmp_path):
        """case_host_fix deletes a canonical when collapsing into another.
        `merge=False` (default) preserves that deletion — merge=True
        would un-delete it from disk."""
        p = tmp_path / "host-dictionary.yaml"
        HostDictionary(
            hosts={
                "admin01": {"aliases": ["admin01"]},
                "wkstn01": {"aliases": ["wkstn01"]},
            },
            path=p,
        ).save()

        d = HostDictionary.load(p)
        del d.hosts["wkstn01"]
        d._rebuild_alias_map()
        d.save()  # default merge=False

        reloaded = HostDictionary.load(p)
        assert "wkstn01" not in reloaded.hosts, (
            "default save() must preserve deletions; merge=False is the right default"
        )


class TestAddAlias:
    """v1 Test 2 — add_alias adds raw to existing canonical's alias list."""

    def test_add_alias_to_existing_canonical(self):
        d = _dict3()
        d.add_alias("admin01-triage", "admin01")
        assert "admin01-triage" in d.hosts["admin01"]["aliases"]
        # Lookup map rebuilt — new alias resolves.
        assert d.resolve("admin01-triage") == "admin01"

    def test_add_alias_idempotent(self):
        d = _dict3()
        d.add_alias("admin01-triage", "admin01")
        d.add_alias("admin01-triage", "admin01")
        # No duplicate
        assert d.hosts["admin01"]["aliases"].count("admin01-triage") == 1

    def test_add_alias_unknown_canonical_raises(self):
        d = _dict3()
        with pytest.raises(ValueError, match="not in dictionary"):
            d.add_alias("foo", "bar-canonical-that-doesnt-exist")


class TestAddCanonical:
    """v1 Test 3 — add_canonical creates a new canonical entry."""

    def test_add_canonical_creates_entry(self):
        d = _dict3()
        d.add_canonical("WIN-3BVS460J98U")
        assert "WIN-3BVS460J98U" in d.hosts
        assert d.hosts["WIN-3BVS460J98U"]["aliases"] == ["WIN-3BVS460J98U"]
        # Self-resolves immediately after add.
        assert d.resolve("WIN-3BVS460J98U") == "WIN-3BVS460J98U"

    def test_add_canonical_idempotent(self):
        d = _dict3()
        d.add_canonical("admin01")  # Already exists.
        # Untouched.
        assert d.hosts["admin01"]["aliases"] == [
            "admin01",
            "ADMIN01",
            "admin01.shieldbase.com",
        ]
