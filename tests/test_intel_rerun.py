"""A second enrichment run doesn't lower a verdict an earlier run stamped.

Extraction skips documents already checked, but stamping matches every
document carrying the IOC, so a second run whose lookup graded an IOC lower
(or didn't find it) rewrote documents the first run had stamped MALICIOUS,
and reported the run complete. Without force a stamp now never replaces a
higher verdict; force still does. Lookups go through the real gateway client
against a mocked endpoint; the stamping runs on the cluster. Values are
derived.
"""

from __future__ import annotations

import hashlib

import pytest
from _intel_case import intel_case
from _intel_gateway import FakeGateway, found, not_found
from test_intel_completion import os_client, quick  # noqa: F401

from opensearch_mcp import threat_intel

R = hashlib.md5(b"rerun-malicious").hexdigest()
H = hashlib.sha1(b"rerun-shared").hexdigest()
X = hashlib.sha256(b"rerun-new").hexdigest()
FIRST = {"json-pslist": [{"Pid": 1, "Hash": {"MD5": R, "SHA1": H}}]}

MALICIOUS = lambda ioc: found(ioc, 90)  # noqa: E731
SUSPICIOUS = lambda ioc: found(ioc, 50)  # noqa: E731


def _doc(client, case_id: str, pid: int) -> tuple:
    hits = client.search(
        index=f"case-{case_id}-json-pslist", body={"query": {"term": {"Pid": pid}}}
    )["hits"]["hits"]
    (source,) = [h["_source"] for h in hits]
    return source.get("threat_intel.verdict"), source.get("threat_intel.ioc_value")


def _rerun(client, quick, tmp_path, first: dict, second: dict, force: bool = False):  # noqa: F811
    """Run 1 on the first document; add a second carrying H and a new IOC;
    run 2. Returns (run 2 status, document 1 after, document 2 after)."""
    # Two runs, each with its own coverage: one map would resume the first.
    quick.setattr(threat_intel, "_coverage_path_for_run", lambda run: tmp_path / f"{run}.json")
    gateway = FakeGateway(lambda ioc: first[ioc]).install(quick)
    with intel_case(client, FIRST, prefix="pytest-rerun") as case_id:
        quick.setenv("VHIR_INGEST_RUN_ID", "rerun-1")
        threat_intel.enrich_case(client, case_id)
        assert _doc(client, case_id, 1) == ("MALICIOUS", R)
        client.index(
            index=f"case-{case_id}-json-pslist",
            body={"Pid": 2, "Hash": {"SHA1": H, "SHA256": X}},
            refresh=True,
        )
        gateway.answer = lambda ioc: second[ioc]
        quick.setenv("VHIR_INGEST_RUN_ID", "rerun-2")
        status = threat_intel.enrich_case(client, case_id, force=force)["status"]
        return status, _doc(client, case_id, 1), _doc(client, case_id, 2)


@pytest.mark.integration
class TestASecondRunKeepsTheHigherVerdict:
    def test_the_shared_ioc_graded_suspicious(self, os_client, quick, tmp_path):  # noqa: F811
        status, first, second = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MALICIOUS(R), H: SUSPICIOUS(H)},
            {H: SUSPICIOUS(H), X: not_found(X)},
        )
        assert status == "complete"
        assert first == ("MALICIOUS", R)
        assert second == ("SUSPICIOUS", H)

    def test_the_shared_ioc_not_found(self, os_client, quick, tmp_path):  # noqa: F811
        """The verdict survived this one before; its IOC was rewritten."""
        status, first, _ = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MALICIOUS(R), H: not_found(H)},
            {H: not_found(H), X: not_found(X)},
        )
        assert status == "complete"
        assert first == ("MALICIOUS", R)

    def test_a_higher_grade_still_lands(self, os_client, quick, tmp_path):  # noqa: F811
        _, first, second = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MALICIOUS(R), H: SUSPICIOUS(H)},
            {H: MALICIOUS(H), X: not_found(X)},
        )
        assert first[0] == "MALICIOUS"
        assert second == ("MALICIOUS", H)

    def test_force_still_replaces_it(self, os_client, quick, tmp_path):  # noqa: F811
        _, first, _ = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MALICIOUS(R), H: SUSPICIOUS(H)},
            {R: SUSPICIOUS(R), H: SUSPICIOUS(H), X: not_found(X)},
            force=True,
        )
        assert first[0] == "SUSPICIOUS"
