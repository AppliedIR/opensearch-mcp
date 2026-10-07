"""Enrichment stamps the outcome lookup_ioc gives, and computes no verdict.

`lookup_ioc` used to answer with OpenCTI's top full-text hit, which could be
an unrelated indicator sharing a word with the IOC, or an observable: on a
real case every SUSPICIOUS verdict was one of the two, including the case's
own domain controller and SRV records. Exactness is now the providers'
contract (each answers only records whose value is the IOC), so enrichment
takes `outcome` as given: those answers come back NO_MATCH and are stamped
NO_MATCH, and no `threat_intel.verdict` is written. The shapes below are those
answers, with the case's names replaced by synthetic ones and the unrelated
indicators' by reserved ones.
"""

from __future__ import annotations

import hashlib

import pytest
from _intel_case import intel_case
from _intel_gateway import FakeGateway, found, not_found

from opensearch_mcp import threat_intel

# queried IOC -> (the unrelated indicator answered, its confidence)
UNRELATED = {
    "settings-win.data.microsoft.com": ("http://settings-update.invalid:7567/settings", 75),
    "dc01.corp-a.test": ("worker-unrelated.invalid", 70),
    "_kerberos._tcp.dc._msdcs.corp-a.test": ("0756.invalid", 70),
    "_ldap._tcp.dc._msdcs.corp-a.test": ("0756.invalid", 70),
    "_ldap._tcp.site-a._sites.corp-a.test": ("0756.invalid", 70),
    "notepad-plus-plus.org": ("plus-bonus.invalid", 70),
}
OBSERVED = "login.live.com"  # an observable of exactly this value, confidence 0
OWN = "update-check.invalid"  # has its own indicator
MD5 = hashlib.md5(b"own indicator").hexdigest()


def _answer(ioc: str) -> dict:
    if ioc in UNRELATED:
        name, confidence = UNRELATED[ioc]
        return found(ioc, confidence, name=name)
    if ioc == OBSERVED:
        return found(ioc, 0, entity_type="observable")
    if ioc == OWN:
        return found(ioc, 90)
    return not_found(ioc)


@pytest.fixture
def quick(monkeypatch, tmp_path):
    monkeypatch.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
    monkeypatch.setattr(threat_intel.time, "sleep", lambda s: None)
    monkeypatch.setattr(threat_intel, "_coverage_path_for_run", lambda run: tmp_path / "c.json")
    return monkeypatch


def _lookup(monkeypatch, ioc_type: str, value: str, answer) -> tuple[dict, dict]:
    FakeGateway(answer).install(monkeypatch)
    results = threat_intel.batch_lookup({ioc_type: {value}})
    return results[value], results["_intel_coverage"]


class TestTheOutcomeIsTheBackends:
    @pytest.mark.parametrize("ioc", sorted(UNRELATED))
    def test_an_unrelated_indicator(self, quick, ioc):
        """Confirmed — the IOC has no indicator of its own — and no verdict."""
        intel, coverage = _lookup(quick, "domain", ioc, _answer)
        assert intel["confirmed"] is True
        assert intel["entry"]["outcome"] == "NO_MATCH"
        assert "verdict" not in intel["entry"]
        assert ioc in coverage["enriched"]

    @pytest.mark.parametrize("confidence", [0, 90])
    def test_an_observable_of_exactly_this_value(self, quick, confidence):
        answer = lambda ioc: found(ioc, confidence, entity_type="observable")  # noqa: E731
        intel, _ = _lookup(quick, "domain", OBSERVED, answer)
        assert intel["entry"]["outcome"] == "NO_MATCH"

    def test_an_indicator_whose_name_holds_the_ioc(self, quick):
        """A URL indicator on this host is a different IOC."""
        answer = lambda ioc: found(ioc, 90, name=f"http://{ioc}/payload")  # noqa: E731
        intel, _ = _lookup(quick, "ip", "8.8.4.4", answer)
        assert intel["entry"]["outcome"] == "NO_MATCH"

    @pytest.mark.parametrize(
        "ioc_type, value, name",
        [
            ("ip", "8.8.8.8", "8.8.8.8"),
            ("domain", OWN, OWN.upper()),
            ("hash", MD5, MD5.upper()),
        ],
        ids=["ip", "domain in another case", "hash in another case"],
    )
    def test_the_iocs_own_indicator(self, quick, ioc_type, value, name):
        intel, _ = _lookup(quick, ioc_type, value, lambda ioc: found(ioc, 90, name=name))
        assert intel["entry"]["outcome"] == "MATCH"
        assert intel["entry"]["opencti"]["matches"][0]["confidence"] == 90

    def test_ssdeep_case_carries_meaning(self, quick):
        value = "3:AbC+/x:AbC"
        intel, _ = _lookup(quick, "hash", value, lambda ioc: found(ioc, 90, name=value.lower()))
        assert intel["entry"]["outcome"] == "NO_MATCH"


@pytest.fixture(scope="module")
def os_client():
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
        return client
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")


@pytest.mark.integration
class TestThroughEnrichCase:
    def test_only_the_iocs_own_indicator_is_stamped_and_the_run_completes(self, os_client, quick):
        names = [*UNRELATED, OBSERVED, OWN]
        docs = {
            "winevt-dns": [
                {"winlog": {"event_data": {"QueryName": name}}, "n": i}
                for i, name in enumerate(names)
            ]
        }
        FakeGateway(_answer).install(quick)
        with intel_case(os_client, docs, prefix="pytest-match") as case_id:
            summary = threat_intel.enrich_case(os_client, case_id)
            os_client.indices.refresh(index=f"case-{case_id}-*")
            hits = os_client.search(index=f"case-{case_id}-*", body={"size": 20})["hits"]["hits"]
        assert (summary["status"], summary["iocs_looked_up"], summary["matched"]) == (
            "complete",
            len(names),
            1,
        )
        assert summary["not_found"] == len(names) - 1
        outcomes = {
            h["_source"]["winlog"]["event_data"]["QueryName"]: [
                e["outcome"] for e in h["_source"]["threat_intel.iocs"]
            ]
            for h in hits
        }
        assert outcomes == {name: ["MATCH" if name == OWN else "NO_MATCH"] for name in names}
        assert not any("threat_intel.verdict" in h["_source"] for h in hits)
