"""No verdict is silently lost on a document carrying several IOCs.

Each IOC is stamped by its own update-by-query and the last one's fields
stand, so the order decides which verdict a document keeps — and without a
refresh between requests a later one met a stale version and skipped the
document. Measured on copies of real pslist, Sysmon and ProcsWMI documents,
the old stamping lost MALICIOUS on 123-289 of 1,124. Stamps now go in
ascending rank, each refreshing, and conflicts are counted.

Values are derived.
"""

from __future__ import annotations

import hashlib
import itertools
from unittest.mock import MagicMock

import pytest
from _intel_case import intel_case
from _intel_gateway import FakeGateway, found, not_found

from opensearch_mcp import threat_intel


def _h(algo: str, text: str) -> str:
    return hashlib.new(algo, text.encode()).hexdigest()


MAL = _h("md5", "malicious")  # MALICIOUS, confidence 90
SUS = _h("sha1", "suspicious")  # SUSPICIOUS, confidence 50
NF = _h("sha256", "not found")
SYS_MAL = _h("md5", "sysmon malicious").upper()
SYS_NF = _h("sha256", "sysmon not found").upper()


def _intel(value: str, verdict: str | None) -> dict:
    intel = {
        "threat_intel.ioc_type": "hash",
        "threat_intel.ioc_value": value,
        "threat_intel.source": "opencti",
    }
    if verdict:
        intel["threat_intel.verdict"] = verdict
        intel["threat_intel.confidence"] = 90 if verdict == "MALICIOUS" else 50
    else:
        intel["threat_intel.checked"] = True
    return intel


RESULTS = {
    MAL: _intel(MAL, "MALICIOUS"),
    SUS: _intel(SUS, "SUSPICIOUS"),
    NF: _intel(NF, None),
    SYS_MAL.lower(): _intel(SYS_MAL.lower(), "MALICIOUS"),
    SYS_NF.lower(): _intel(SYS_NF.lower(), None),
}
ORIGINS = {
    MAL: {("Hash.MD5", MAL)},
    SUS: {("Hash.SHA1", SUS)},
    NF: {("Hash.SHA256", NF)},
    SYS_MAL.lower(): {("winlog.event_data.Hashes", f"MD5={SYS_MAL},SHA256={SYS_NF}")},
    SYS_NF.lower(): {("winlog.event_data.Hashes", f"MD5={SYS_MAL},SHA256={SYS_NF}")},
}
DOCS = {
    "json-pslist": [{"Pid": 1, "Hash": {"MD5": MAL, "SHA1": SUS, "SHA256": NF}}],
    "json-pslistsus": [{"Pid": 2, "Hash": {"SHA1": SUS, "SHA256": NF}}],
    "winevt-sysmon": [{"winlog": {"event_data": {"Hashes": f"MD5={SYS_MAL},SHA256={SYS_NF}"}}}],
}
# document -> (verdict it must end with, the IOC it must name)
EXPECTED = {
    "json-pslist": ("MALICIOUS", MAL),
    "json-pslistsus": ("SUSPICIOUS", SUS),
    "winevt-sysmon": ("MALICIOUS", SYS_MAL.lower()),
}


class TestTheOrderAndTheRefresh:
    def test_ascending_rank_each_refreshing_and_conflicts_summed(self):
        client = MagicMock()
        client.update_by_query.side_effect = [
            {"updated": 1, "version_conflicts": 0},
            {"updated": 1, "version_conflicts": 2},
            {"updated": 1, "version_conflicts": 1},
        ]
        results = {v: RESULTS[v] for v in (MAL, NF, SUS)}  # worst order in
        updated, conflicts, failed = threat_intel.stamp_documents(
            client, "case-x-*", results, ORIGINS
        )

        stamped = [
            c.kwargs["body"]["script"]["params"]["threat_intel_ioc_value"]
            for c in client.update_by_query.call_args_list
        ]
        assert stamped == [NF, SUS, MAL]
        assert all(c.kwargs["refresh"] is True for c in client.update_by_query.call_args_list)
        assert (updated, conflicts, failed) == (3, 3, 0)


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


def _outcome(client, case_id: str) -> dict:
    client.indices.refresh(index=f"case-{case_id}-*")
    out = {}
    for name in DOCS:
        source = client.search(index=f"case-{case_id}-{name}")["hits"]["hits"][0]["_source"]
        out[name] = (source.get("threat_intel.verdict"), source.get("threat_intel.ioc_value"))
    return out


@pytest.mark.integration
class TestMultiIOCDocumentsKeepTheirVerdict:
    @pytest.mark.parametrize("order", list(itertools.permutations([MAL, SUS, NF])))
    def test_every_order_ends_on_the_highest_verdict_naming_its_ioc(self, os_client, order):
        """All six orders the three pslist IOCs can arrive in."""
        results = {value: RESULTS[value] for value in order}
        results.update({v: RESULTS[v] for v in (SYS_NF.lower(), SYS_MAL.lower())})
        with intel_case(os_client, DOCS, prefix="pytest-verdict") as case_id:
            updated, conflicts, failed = threat_intel.stamp_documents(
                os_client, f"case-{case_id}-*", results, ORIGINS
            )
            assert (conflicts, failed) == (0, 0)
            assert _outcome(os_client, case_id) == EXPECTED

    def test_through_the_pipeline(self, os_client, monkeypatch, tmp_path):
        monkeypatch.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
        monkeypatch.setattr(
            threat_intel, "_coverage_path_for_run", lambda run: tmp_path / "c.json"
        )

        def answer(ioc: str) -> dict:
            if ioc in (MAL, SYS_MAL.lower()):
                return found(ioc, 90)
            if ioc == SUS:
                return found(ioc, 50)
            return not_found(ioc)

        FakeGateway(answer).install(monkeypatch)
        with intel_case(os_client, DOCS, prefix="pytest-verdict") as case_id:
            summary = threat_intel.enrich_case(os_client, case_id)
            assert summary["version_conflicts"] == 0
            assert _outcome(os_client, case_id) == EXPECTED
