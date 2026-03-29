"""Tests for reduced Event ID loader."""

from __future__ import annotations

from opensearch_mcp.reduced import load_reduced_ids


class TestLoadReducedIds:
    def test_returns_set_of_ints(self):
        ids = load_reduced_ids()
        assert isinstance(ids, set)
        assert all(isinstance(i, int) for i in ids)

    def test_contains_key_authentication_ids(self):
        ids = load_reduced_ids()
        assert 4624 in ids  # successful logon
        assert 4625 in ids  # failed logon
        assert 4672 in ids  # special privileges

    def test_contains_key_sysmon_ids(self):
        ids = load_reduced_ids()
        assert 1 in ids  # process create
        assert 3 in ids  # network connection
        assert 22 in ids  # DNS query

    def test_contains_key_persistence_ids(self):
        ids = load_reduced_ids()
        assert 7045 in ids  # service installed
        assert 4698 in ids  # scheduled task created

    def test_contains_key_execution_ids(self):
        ids = load_reduced_ids()
        assert 4688 in ids  # process creation
        assert 4104 in ids  # PowerShell script block

    def test_does_not_contain_4663(self):
        """4663 (file object access) is intentionally excluded — too noisy."""
        ids = load_reduced_ids()
        assert 4663 not in ids

    def test_reasonable_count(self):
        """Reduced mode should have a meaningful but bounded set of IDs."""
        ids = load_reduced_ids()
        assert 50 < len(ids) < 200

    def test_caching(self):
        """Second call returns same object (cached)."""
        ids1 = load_reduced_ids()
        ids2 = load_reduced_ids()
        assert ids1 is ids2
