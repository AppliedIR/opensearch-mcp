"""A second enrichment run never loses an answer an earlier run stamped.

Extraction skips documents already checked, but stamping matches every
document carrying the IOC, so a second run whose lookup graded an IOC lower
(or didn't find it) used to rewrite the one stamp of documents the first run
had stamped. Each IOC now has its own entry: a run replaces only the entries
of the IOCs it looked up (force included), and an answer it couldn't get
marks that IOC's entry UNAVAILABLE while keeping the earlier records. Lookups
go through the real gateway client against a mocked endpoint; the stamping
runs on the cluster. Values are derived.
"""

from __future__ import annotations

import hashlib

import pytest
from _intel_case import intel_case
from _intel_gateway import FakeGateway, found, not_found, unconfirmed
from test_intel_completion import os_client, quick  # noqa: F401

from opensearch_mcp import threat_intel

R = hashlib.md5(b"rerun-malicious").hexdigest()
H = hashlib.sha1(b"rerun-shared").hexdigest()
X = hashlib.sha256(b"rerun-new").hexdigest()
FIRST = {"json-pslist": [{"Pid": 1, "Hash": {"MD5": R, "SHA1": H}}]}

MATCH = lambda ioc: found(ioc, 90)  # noqa: E731


def _doc(client, case_id: str, pid: int) -> dict:
    """{IOC: (outcome, records kept, checked_at)} for the document."""
    hits = client.search(
        index=f"case-{case_id}-json-pslist", body={"query": {"term": {"Pid": pid}}}
    )["hits"]["hits"]
    (source,) = [h["_source"] for h in hits]
    assert "threat_intel.verdict" not in source
    return {
        e["ioc_value"]: (
            e["outcome"],
            len((e.get("opencti") or {}).get("matches") or []),
            e["checked_at"],
        )
        for e in source.get("threat_intel.iocs", [])
    }


def _rerun(client, quick, tmp_path, first: dict, second: dict, force: bool = False):  # noqa: F811
    """Run 1 on the first document; add a second carrying H and a new IOC;
    run 2. Returns (run 2 status, document 1 after run 1, after run 2,
    document 2 after)."""
    # Two runs, each with its own coverage: one map would resume the first.
    quick.setattr(threat_intel, "_coverage_path_for_run", lambda run: tmp_path / f"{run}.json")
    gateway = FakeGateway(lambda ioc: first[ioc]).install(quick)
    with intel_case(client, FIRST, prefix="pytest-rerun") as case_id:
        quick.setenv("VHIR_INGEST_RUN_ID", "rerun-1")
        threat_intel.enrich_case(client, case_id)
        before = _doc(client, case_id, 1)
        client.index(
            index=f"case-{case_id}-json-pslist",
            body={"Pid": 2, "Hash": {"SHA1": H, "SHA256": X}},
            refresh=True,
        )
        gateway.answer = lambda ioc: second[ioc]
        quick.setenv("VHIR_INGEST_RUN_ID", "rerun-2")
        try:
            status = threat_intel.enrich_case(client, case_id, force=force)["status"]
        except threat_intel.IntelEnrichmentHalted as e:
            status = (e.summary or {}).get("status", "halted")
        return status, before, _doc(client, case_id, 1), _doc(client, case_id, 2)


@pytest.mark.integration
class TestASecondRunKeepsEarlierAnswers:
    def test_a_run_replaces_only_the_iocs_it_looked_up(self, os_client, quick, tmp_path):  # noqa: F811
        status, before, first, second = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MATCH(R), H: MATCH(H)},
            {H: not_found(H), X: not_found(X)},
        )
        assert status == "complete"
        assert first[R] == before[R]  # not looked up again: unchanged
        assert first[H][0] == "NO_MATCH"
        assert {k: v[0] for k, v in second.items()} == {H: "NO_MATCH", X: "NO_MATCH"}

    def test_force_replaces_each_iocs_own_entry(self, os_client, quick, tmp_path):  # noqa: F811
        _, before, first, _ = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MATCH(R), H: MATCH(H)},
            {R: not_found(R), H: MATCH(H), X: not_found(X)},
            force=True,
        )
        assert before[R][0] == "MATCH" and first[R][0] == "NO_MATCH"
        assert first[H][0] == "MATCH"

    def test_an_answer_it_couldnt_get_keeps_the_earlier_records(
        self,
        os_client,  # noqa: F811
        quick,  # noqa: F811
        tmp_path,
    ):
        status, before, first, _ = _rerun(
            os_client,
            quick,
            tmp_path,
            {R: MATCH(R), H: MATCH(H)},
            {R: unconfirmed(R), H: MATCH(H), X: not_found(X)},
            force=True,
        )
        assert status == "incomplete"
        outcome, records, checked_at = first[R]
        # OpenCTI's earlier record is kept, and the outcome is recomputed from it
        assert (outcome, records) == ("MATCH", 1)
        assert checked_at > before[R][2]
