"""An enrichment run reports `complete` only when it is.

Before, a run with no gateway, with every lookup failing, or with the rate
limit exhausted ended `complete, 0 malicious` — which reads as clean. Now it
is complete only when every extracted IOC got a confirmed lookup and every
stamp landed; otherwise it raises IntelEnrichmentHalted naming what is
missing, and the CLI records that as a failed run with the reason.

One row per cause, so fixing any single cause leaves the others failing.
Lookups go through the real gateway client against a mocked HTTP endpoint
answering in opencti-mcp's response shapes. Values are derived.
"""

from __future__ import annotations

import argparse
import hashlib

import pytest
from _intel_case import intel_case
from _intel_gateway import (
    FakeGateway,
    errored,
    found,
    not_found,
    rate_limited,
    text_reply,
    unconfirmed,
)

from opensearch_mcp import threat_intel

MAL = hashlib.md5(b"malicious").hexdigest()
CLEAN = hashlib.md5(b"clean").hexdigest()
DOCS = {
    "json-pslist": [
        {"Pid": 1, "Hash": {"MD5": MAL}},
        {"Pid": 2, "Hash": {"MD5": CLEAN}},
    ],
}

# cause -> (lookup answer, the words the reason must carry)
CAUSES = {
    "gateway down": (None, "gateway not configured"),
    "every call raising": (lambda ioc: ConnectionRefusedError("ECONNREFUSED"), "exception 2"),
    "every call an error payload": (errored, "error 2"),
    "rate limit exhausted": (lambda ioc: rate_limited(), "rate_limit_exhausted 2"),
    "an unconfirmed not-found": (unconfirmed, "unconfirmed 2"),
    "a plain-text reply": (text_reply, "unconfirmed 2"),
}


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


@pytest.fixture
def quick(monkeypatch, tmp_path):
    """No pacing or backoff waits; coverage in the test's own directory."""
    monkeypatch.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
    monkeypatch.setenv("VHIR_INTEL_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setattr(threat_intel.time, "sleep", lambda s: None)
    monkeypatch.setattr(threat_intel, "_coverage_path_for_run", lambda run: tmp_path / "c.json")
    return monkeypatch


def _gateway(monkeypatch, cause: str) -> FakeGateway | None:
    answer, _ = CAUSES[cause]
    if answer is None:
        return FakeGateway(not_found).install(monkeypatch, available=False)
    return FakeGateway(answer).install(monkeypatch)


@pytest.mark.integration
class TestEachCauseIsNotComplete:
    @pytest.mark.parametrize("cause", sorted(CAUSES))
    def test_enrich_case_raises_with_its_reason(self, os_client, quick, cause):
        _gateway(quick, cause)
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:
            with pytest.raises(threat_intel.IntelEnrichmentHalted, match=CAUSES[cause][1]):
                threat_intel.enrich_case(os_client, case_id)

    @pytest.mark.parametrize("cause", sorted(CAUSES))
    def test_the_run_status_reads_failed_with_the_reason(self, os_client, quick, cause, tmp_path):
        """Through the CLI and the status file, as idx_ingest_status shows it."""
        from opensearch_mcp import ingest_cli, ingest_status
        from opensearch_mcp.server import idx_ingest_status

        _gateway(quick, cause)
        quick.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
        quick.setenv("VHIR_INGEST_RUN_ID", f"run-{cause.replace(' ', '-')}")
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:
            quick.setattr(ingest_cli, "_resolve_case_id", lambda _c: case_id)
            args = argparse.Namespace(case=case_id, force=False, dry_run=False)
            with pytest.raises(threat_intel.IntelEnrichmentHalted):
                ingest_cli.cmd_enrich_intel(args)
            (status,) = idx_ingest_status(case_id=case_id)["ingests"]
        assert status["status"] == "failed", status
        assert status["halt_reason"] == "IntelEnrichmentHalted"
        assert CAUSES[cause][1] in status["message"]


@pytest.mark.integration
class TestStampsThatDidNotLand:
    def _found_all(self, monkeypatch):
        FakeGateway(lambda ioc: found(ioc, 90) if ioc == MAL else not_found(ioc)).install(
            monkeypatch
        )

    def test_a_version_conflict(self, os_client, quick):
        self._found_all(quick)
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:
            real = os_client.update_by_query

            def conflicting(**kw):
                result = real(**kw)
                return {**result, "version_conflicts": 1}

            quick.setattr(os_client, "update_by_query", conflicting)
            with pytest.raises(threat_intel.IntelEnrichmentHalted, match="version conflict"):
                threat_intel.enrich_case(os_client, case_id)

    def test_a_failed_stamp_request(self, os_client, quick):
        self._found_all(quick)
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:

            def failing(**kw):
                raise ConnectionError("node left")

            quick.setattr(os_client, "update_by_query", failing)
            with pytest.raises(threat_intel.IntelEnrichmentHalted, match="stamp requests failed"):
                threat_intel.enrich_case(os_client, case_id)


class TestWhatCountsAsConfirmed:
    """Confirmed only when the reply has `found` and no note or error."""

    @pytest.mark.parametrize(
        "answer, confirmed",
        [
            (lambda ioc: found(ioc, 90), True),
            (not_found, True),
            (unconfirmed, False),
            (errored, False),
            (text_reply, False),
            (lambda ioc: {"found": False, "ioc": ioc, "error": ""}, False),
            (lambda ioc: "[]", False),  # JSON, but not an object
        ],
        ids=["found", "not found", "note", "error", "text", "empty error", "json list"],
    )
    def test_reply(self, quick, answer, confirmed):
        FakeGateway(answer).install(quick)
        results = threat_intel.batch_lookup({"hash": {MAL}})
        coverage = results.pop("_intel_coverage")
        assert (MAL in results, MAL in coverage["enriched"]) == (confirmed, confirmed)
        assert (MAL in coverage["skipped"]) == (not confirmed)


@pytest.mark.integration
class TestAPlainTextReply:
    def test_stamps_nothing_and_is_looked_up_again_next_run(self, os_client, quick, tmp_path):
        """A reply with no `found` key was read as a confirmed not-found: the
        run read complete, every document was stamped checked, and the next
        run skipped them. Each run here has its own run id, as each launch
        does."""
        quick.setattr(threat_intel, "_coverage_path_for_run", lambda run: tmp_path / f"{run}.json")
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:
            quick.setenv("VHIR_INGEST_RUN_ID", "run-1")
            FakeGateway(text_reply).install(quick)
            with pytest.raises(threat_intel.IntelEnrichmentHalted, match="Input validation error"):
                threat_intel.enrich_case(os_client, case_id)
            os_client.indices.refresh(index=f"case-{case_id}-*")
            stamped = {"exists": {"field": "threat_intel.checked"}}
            assert (
                os_client.count(index=f"case-{case_id}-*", body={"query": stamped})["count"] == 0
            )

            quick.setenv("VHIR_INGEST_RUN_ID", "run-2")
            gateway = FakeGateway(
                lambda ioc: found(ioc, 90) if ioc == MAL else not_found(ioc)
            ).install(quick)
            summary = threat_intel.enrich_case(os_client, case_id)
        assert sorted(gateway.asked) == sorted([MAL, CLEAN])
        assert (summary["status"], summary["iocs_looked_up"], summary["malicious"]) == (
            "complete",
            2,
            1,
        )


@pytest.mark.integration
class TestACompleteRun:
    def test_complete_counts_only_confirmed_lookups(self, os_client, quick):
        """`iocs_looked_up` counted the coverage map as a lookup: it read 1
        when nothing succeeded."""
        FakeGateway(lambda ioc: found(ioc, 90) if ioc == MAL else not_found(ioc)).install(quick)
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:
            summary = threat_intel.enrich_case(os_client, case_id)
        assert summary["status"] == "complete"
        assert (summary["iocs_extracted"], summary["iocs_looked_up"]) == (2, 2)
        assert summary["malicious"] == 1

    def test_the_confirmed_verdicts_are_still_stamped_when_the_run_is_not_complete(
        self, os_client, quick
    ):
        """One lookup confirmed, one unconfirmed: the confirmed verdict is
        written, the unconfirmed IOC's document is left unstamped, and the
        run is not complete."""
        FakeGateway(lambda ioc: found(ioc, 90) if ioc == MAL else unconfirmed(ioc)).install(quick)
        with intel_case(os_client, DOCS, prefix="pytest-complete") as case_id:
            with pytest.raises(threat_intel.IntelEnrichmentHalted, match="unconfirmed 1"):
                threat_intel.enrich_case(os_client, case_id)
            os_client.indices.refresh(index=f"case-{case_id}-*")
            docs = {
                h["_source"]["Pid"]: h["_source"]
                for h in os_client.search(index=f"case-{case_id}-*")["hits"]["hits"]
            }
        assert docs[1].get("threat_intel.verdict") == "MALICIOUS"
        assert "threat_intel.checked" not in docs[2]
