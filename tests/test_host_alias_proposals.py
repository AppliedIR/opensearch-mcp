"""A near-match never aliases two different hosts.

Host names one character apart are usually siblings (wkstn01 / wkstn02),
and FQDNs share a domain that hides how different their labels are, so a
fuzzy match aliases only dotless names with the same digits. Exact matches
after stripping a domain or a -triage suffix are unchanged. All names here
are synthetic.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opensearch_mcp import ingest_cli
from opensearch_mcp.host_dictionary import HostDictionary, propose_canonical


def _propose(canonical: str, raw: str, domains: list[str] | None = None):
    host_dict = HostDictionary(domains=domains)
    host_dict.add_canonical(canonical)
    return propose_canonical(raw, host_dict)


@pytest.mark.parametrize(
    "canonical, raw",
    [
        ("badhost", "badhost2"),
        ("lab1-pc01", "lab2-pc01"),  # the digits differ before the end
        ("host01.corp.example", "host02.corp.example"),
        ("dc01.corp.example", "dev01.corp.example"),
    ],
)
def test_a_different_host_one_edit_away_is_not_proposed(canonical, raw):
    assert _propose(canonical, raw) == (None, 0.0)


@pytest.mark.parametrize(
    "raw, domains", [("wksn01", None), ("wksn01.corp2.local", ["corp2.local"])]
)
def test_a_typo_with_the_same_digits_is_still_proposed(raw, domains):
    # the second is compared without its domain, whose digit doesn't count
    canonical, score = _propose("wkstn01", raw, domains)
    assert canonical == "wkstn01" and 0.85 <= score < 1.0


def test_an_exact_match_after_stripping_the_domain_is_unchanged():
    # the domain's own digit doesn't count against the host
    assert _propose("dev01", "dev01.corp2.local", domains=["corp2.local"]) == ("dev01", 1.0)


# --- Through the ingest preflight: one call per ingest, as idx_ingest runs it ---


@pytest.fixture
def case(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-a"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-a\n")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
    monkeypatch.setattr(ingest_cli, "_ensure_host_id_keyword_mapping", lambda case_id: {})
    return tmp_path


def _ingest(case, hostname):
    scan_root = case / "evidence" / hostname
    scan_root.mkdir(parents=True)
    report, host_dict = ingest_cli._preflight_host_discovery(
        "case-a", scan_root, [MagicMock(hostname=hostname)]
    )
    (decision,) = [d for d in report["decisions_applied"] if d["raw"] == hostname]
    return decision, host_dict


@pytest.mark.parametrize(
    "first, second",
    [("wkstn01", "wkstn02"), ("dc01.corp.example", "dev01.corp.example")],
)
def test_a_second_host_ingested_later_keeps_its_own_id(case, first, second):
    _ingest(case, first)
    decision, host_dict = _ingest(case, second)
    assert decision["decision"] == "auto_new_canonical"
    assert host_dict.resolve(second) == second
    assert host_dict.resolve(first) == first
    assert set(host_dict.hosts) == {first, second}


def test_a_triage_copy_of_a_host_is_still_aliased_to_it(case):
    _ingest(case, "wkstn01")
    decision, host_dict = _ingest(case, "wkstn01-triage")
    assert (decision["decision"], decision["confidence"]) == ("auto_alias", 1.0)
    assert host_dict.resolve("wkstn01-triage") == "wkstn01"
