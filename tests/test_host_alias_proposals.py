"""A near-match never makes two different hosts one machine.

Host names one character apart are usually siblings (wkstn01 / wkstn02),
and FQDNs share a domain that hides how different their labels are. A near
spelling is only a hint for the examiner, computed once when the name is
first scanned, and only between names with the same digits. Names that are
equal once a domain or a collection token is set aside are proposed as one
machine. Runs through the names scan, as every ingest does. All names here
are synthetic.
"""

from __future__ import annotations

import uuid

import pytest
from sift_common import host_identity as hi
from sift_common import host_proposal as hp

from opensearch_mcp import names_scan
from opensearch_mcp import write_context as wc


@pytest.fixture
def case():
    return wc.case_dir_for(f"alias-{uuid.uuid4().hex[:8]}")


def scan(case, name, where=""):
    """One ingest of a host folder named `name`."""
    unit = names_scan.Unit(locator=where or f"evidence/{name}", source="host folder")
    unit.add(name, "folder name", "folder")
    names_scan.record(case, [unit])
    return unit.key


def hints(case, name):
    return [h["near"] for h in hi.load(case).hints if h["raw"] == name]


def group(case, name):
    (g,) = [g for g in hp.propose(hi.load(case)) if any(p[1] == name for p in g.pairs)]
    return {p[1] for p in g.pairs}, g


@pytest.mark.parametrize(
    "first, second",
    [
        ("badhost", "badhost2"),
        ("lab1-pc01", "lab2-pc01"),  # the digits differ before the end
        ("host01.corp.example", "host02.corp.example"),
        ("dc01.corp.example", "dev01.corp.example"),
        ("ws01.lab", "ws01lab"),  # a dot in either name, in either direction
        ("ws01lab", "ws01.lab"),
        ("workstation-1203", "workstation-1230"),  # the same digits, in another order
    ],
)
def test_a_different_host_with_a_close_name_is_neither_hinted_nor_grouped(case, first, second):
    scan(case, first)
    scan(case, second)
    assert hints(case, second) == []
    assert group(case, second)[0] == {second}


@pytest.mark.parametrize("second", ["wksn01", "wksn01.corp2.local"])
def test_a_typo_with_the_same_digits_is_hinted(case, second):
    # the second is compared without its domain, whose digit doesn't count
    scan(case, "wkstn01")
    scan(case, second)
    assert hints(case, second) == ["wkstn01"]


def test_a_name_equal_once_its_domain_is_set_aside_is_proposed_as_one_machine(case):
    # the domain's own digit doesn't count against the host
    scan(case, "dev01")
    scan(case, "dev01.corp2.local")
    names, g = group(case, "dev01")
    assert names == {"dev01", "dev01.corp2.local"} and g.tier != hp.CERTAIN


@pytest.mark.parametrize(
    "first, second",
    [("wkstn01", "wkstn02"), ("dc01.corp.example", "dev01.corp.example")],
)
def test_a_second_host_ingested_later_keeps_its_own_machine(case, first, second):
    scan(case, first)
    scan(case, second)
    assert group(case, first)[0] == {first} and group(case, second)[0] == {second}


def test_a_triage_copy_of_a_host_is_proposed_with_it(case):
    scan(case, "wkstn01")
    scan(case, "wkstn01-triage")
    assert group(case, "wkstn01")[0] == {"wkstn01", "wkstn01-triage"}


NEAR_SPELLINGS = [("SQLPRODA01", "SQLPRODB01"), ("web-a01", "web-b01"), ("wkstn01", "wksn01")]


@pytest.mark.parametrize("first, second", NEAR_SPELLINGS)
def test_a_near_spelling_is_its_own_machine_with_a_note(case, first, second):
    scan(case, first)
    scan(case, second)
    names, g = group(case, second)
    assert names == {second}
    assert f"{hp.FLAG_NEAR}: {first.lower()}" in g.flags


@pytest.mark.parametrize("first, second", NEAR_SPELLINGS[:1])
def test_a_near_spelling_is_hinted_once_however_often_it_is_scanned(case, first, second):
    scan(case, first)
    scan(case, second)
    scan(case, second, where=f"evidence/{second}-earlier")
    assert len(hi.load(case).hints) == 1


def test_a_scan_confirms_a_unit_the_examiners_host_list_names(case):
    hp.upload_host_list(case, "WKS21\n", "ex1")
    unit = names_scan.Unit(locator="evidence/WKS21", source="host folder")
    unit.add("WKS21", "folder name", "folder")
    unit.add("WKS21", "SYSTEM ComputerName", "artifact")
    names_scan.record(case, [unit])
    m = hi.load(case).machine_of_pair(unit.key, "WKS21")
    assert m is not None and m.state == hi.CONFIRMED
