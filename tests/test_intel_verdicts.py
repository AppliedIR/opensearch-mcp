"""No answer is silently lost on a document carrying several IOCs.

Each IOC was stamped by its own update-by-query into one set of
`threat_intel.*` fields, so the last stamp's fields stood: a document kept one
IOC's verdict and lost the others' (the order and a refresh decided which;
measured on copies of real pslist, Sysmon and ProcsWMI documents, 123-289 of
1,124 lost theirs). Each IOC now has its own entry in `threat_intel.iocs`, a
stamp touches only its own IOC's entry, and every order ends with one entry
per IOC. Each request still refreshes, and conflicts are counted.

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


MAL = _h("md5", "matched")
SUS = _h("sha1", "matched too")
NF = _h("sha256", "not found")
SYS_MAL = _h("md5", "sysmon matched").upper()
SYS_NF = _h("sha256", "sysmon not found").upper()


def _result(value: str, outcome: str) -> dict:
    return {
        "ioc_type": "hash",
        "confirmed": True,
        "entry": {
            "ioc_type": "hash",
            "ioc_value": value,
            "outcome": outcome,
            "checked_at": "2026-10-07T12:00:00+00:00",
        },
    }


RESULTS = {
    MAL: _result(MAL, "MATCH"),
    SUS: _result(SUS, "MATCH"),
    NF: _result(NF, "NO_MATCH"),
    SYS_MAL.lower(): _result(SYS_MAL.lower(), "MATCH"),
    SYS_NF.lower(): _result(SYS_NF.lower(), "NO_MATCH"),
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
# document -> {IOC: outcome}, one entry each
EXPECTED = {
    "json-pslist": {MAL: "MATCH", SUS: "MATCH", NF: "NO_MATCH"},
    "json-pslistsus": {SUS: "MATCH", NF: "NO_MATCH"},
    "winevt-sysmon": {SYS_MAL.lower(): "MATCH", SYS_NF.lower(): "NO_MATCH"},
}


class TestEachRequestRefreshes:
    def test_every_ioc_stamped_each_refreshing_and_conflicts_summed(self):
        client = MagicMock()
        client.update_by_query.side_effect = [
            {"updated": 1, "version_conflicts": 0},
            {"updated": 1, "version_conflicts": 2},
            {"updated": 1, "version_conflicts": 1},
        ]
        results = {v: RESULTS[v] for v in (MAL, NF, SUS)}
        updated, conflicts, failed = threat_intel.stamp_documents(
            client, "case-x-*", results, ORIGINS
        )

        stamped = [
            c.kwargs["body"]["script"]["params"]["entry"]["ioc_value"]
            for c in client.update_by_query.call_args_list
        ]
        assert sorted(stamped) == sorted([MAL, NF, SUS])
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
        entries = source.get("threat_intel.iocs", [])
        assert "threat_intel.verdict" not in source, source
        out[name] = {e["ioc_value"]: e["outcome"] for e in entries}
        assert len(entries) == len(out[name]), entries  # one entry per IOC
    return out


@pytest.mark.integration
class TestMultiIOCDocumentsKeepEveryAnswer:
    @pytest.mark.parametrize("order", list(itertools.permutations([MAL, SUS, NF])))
    def test_every_order_ends_with_one_entry_per_ioc(self, os_client, order):
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
            if ioc in (MAL, SUS, SYS_MAL.lower()):
                return found(ioc, 90)
            return not_found(ioc)

        FakeGateway(answer).install(monkeypatch)
        with intel_case(os_client, DOCS, prefix="pytest-verdict") as case_id:
            summary = threat_intel.enrich_case(os_client, case_id)
            assert summary["version_conflicts"] == 0
            assert _outcome(os_client, case_id) == EXPECTED
