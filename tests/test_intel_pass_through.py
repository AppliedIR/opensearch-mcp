"""Enrichment stamps each platform's answer per IOC, as the platform gave it.

lookup_ioc now answers with an aggregate `outcome` (MATCH, NO_MATCH,
UNAVAILABLE) and each provider's records verbatim. Enrichment used to turn
OpenCTI's top hit into a verdict (MALICIOUS at confidence >= 80, else
SUSPICIOUS) in one stamp per document; it now writes one entry per IOC in
`threat_intel.iocs`, decides on `outcome` and `providers` (so a MISP-only
match counts), counts a provider's UNAVAILABLE toward the circuit breaker per
provider, and under force clears an older release's one-IOC stamps. Values
are derived or synthetic; records are shaped like the adapters' output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest
from _intel_case import intel_case
from _intel_gateway import (
    FakeGateway,
    block,
    found,
    not_found,
    opencti_record,
    reply,
    unconfirmed,
)

from opensearch_mcp import threat_intel

MAPPINGS = Path(threat_intel.__file__).parent / "mappings"
REVOKED = hashlib.sha256(b"revoked indicator").hexdigest()
IP = "11.0.113.10"
MISP_ONLY = hashlib.md5(b"misp only").hexdigest()


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
    monkeypatch.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
    monkeypatch.setattr(threat_intel.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        threat_intel, "_coverage_path_for_run", lambda run: tmp_path / f"{run}.json"
    )
    return monkeypatch


def _sources(client, case_id: str) -> list[dict]:
    client.indices.refresh(index=f"case-{case_id}-*")
    hits = client.search(index=f"case-{case_id}-*", body={"size": 50})["hits"]["hits"]
    return [h["_source"] for h in hits]


def _answer(ioc: str) -> dict:
    if ioc == REVOKED:
        record = opencti_record(ioc, 100, ["malware"], revoked=True)
        record["valid_until"] = "2025-02-01T00:00:00Z"
        return reply(ioc, {"opencti": block("MATCH", [record])})
    if ioc == IP:
        records = [opencti_record(ioc, c) for c in (30, 50, 70)]
        return reply(ioc, {"opencti": block("MATCH", records)})
    if ioc == MISP_ONLY:
        attribute = {"uuid": "a1", "type": "md5", "value": ioc, "to_ids": True}
        return reply(
            ioc,
            {"opencti": block("NO_MATCH"), "misp": block("MATCH", [attribute], version="2.5.48")},
        )
    return not_found(ioc)


ENTRY_DOCS = {
    "json-filehash": [{"Hash": {"SHA256": REVOKED}}],
    "delim-netstat": [{"ForeignAddress": IP}],
    "json-misp": [{"Hash": {"MD5": MISP_ONLY}}],
}


@pytest.fixture(scope="module")
def stamped(os_client):
    """One case enriched once: its summary, and each document by its IOC."""
    mp = pytest.MonkeyPatch()
    try:
        import tempfile

        cov = Path(tempfile.mkdtemp()) / "c.json"
        mp.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
        mp.setattr(threat_intel, "_coverage_path_for_run", lambda run: cov)
        FakeGateway(_answer).install(mp)
        with intel_case(os_client, ENTRY_DOCS, prefix="pytest-pass") as case_id:
            summary = threat_intel.enrich_case(os_client, case_id)
            yield (
                summary,
                {s["threat_intel.iocs"][0]["ioc_value"]: s for s in _sources(os_client, case_id)},
            )
    finally:
        mp.undo()


@pytest.mark.integration
class TestWhatAnEntryHolds:
    def test_a_revoked_indicator_is_stamped_as_given(self, stamped):
        _, docs = stamped
        (entry,) = docs[REVOKED]["threat_intel.iocs"]
        assert entry["outcome"] == "MATCH"
        record = entry["opencti"]["matches"][0]
        assert (record["revoked"], record["valid_until"]) == (True, "2025-02-01T00:00:00Z")
        assert entry["opencti"]["version"] and entry["opencti"]["queried_at"]
        for key in ("verdict", "confidence", "labels"):
            assert f"threat_intel.{key}" not in docs[REVOKED]

    def test_every_record_is_kept(self, stamped):
        _, docs = stamped
        (entry,) = docs[IP]["threat_intel.iocs"]
        assert [r["confidence"] for r in entry["opencti"]["matches"]] == [30, 50, 70]

    def test_a_match_from_misp_alone_is_a_match(self, stamped):
        summary, docs = stamped
        (entry,) = docs[MISP_ONLY]["threat_intel.iocs"]
        assert entry["outcome"] == "MATCH"
        assert entry["misp"]["matches"][0]["to_ids"] is True
        assert entry["opencti"]["outcome"] == "NO_MATCH"
        assert summary["matched"] == 3

    def test_no_document_gets_a_verdict(self, stamped):
        _, docs = stamped
        assert not [d for d in docs.values() if "threat_intel.verdict" in d]


def test_two_ssdeeps_differing_only_in_case_are_two_entries(os_client, quick):
    """Entries are keyed on the exact lookup form: an SSDEEP's case carries
    meaning, so two that differ only in case are two IOCs."""
    a, b = "3:AbC+/x:AbC", "3:abc+/x:abc"
    FakeGateway(lambda ioc: found(ioc, 90) if ioc == a else not_found(ioc)).install(quick)
    results = threat_intel.batch_lookup({"hash": {a, b}})
    results.pop("_intel_coverage")
    origins = {a: {("Hash", a)}, b: {("Hash", b)}}
    with intel_case(os_client, {"delim-both": [{"x": 1}]}, prefix="pytest-ssdeep") as case_id:
        index = f"case-{case_id}-delim-both"
        os_client.index(index=index, id="d", body={"Hash": [a, b]}, refresh=True)
        threat_intel.stamp_documents(os_client, index, results, origins)
        os_client.indices.refresh(index=index)
        source = os_client.get(index=index, id="d")["_source"]
    entries = sorted((e["ioc_value"], e["outcome"]) for e in source["threat_intel.iocs"])
    assert entries == sorted([(a, "MATCH"), (b, "NO_MATCH")])


LEGACY = {
    "threat_intel.verdict": "MALICIOUS",
    "threat_intel.confidence": 100,
    "threat_intel.labels": ["malware"],
    "threat_intel.ioc_value": REVOKED,
    "threat_intel.ioc_type": "hash",
    "threat_intel.source": "opencti",
    "threat_intel.enriched_at": "2026-01-01T00:00:00+00:00",
    "threat_intel.checked": True,
}


@pytest.mark.integration
class TestForceAndOlderStamps:
    def _case(self, os_client, quick, force: bool, answer=not_found):
        evidence = {"feed": "vendor-x", "score": 7}  # the evidence's own object
        docs = {"json-old": [{"Hash": {"SHA256": REVOKED}, **LEGACY, "threat_intel": evidence}]}
        FakeGateway(answer).install(quick)
        with intel_case(os_client, docs, prefix="pytest-force") as case_id:
            try:
                summary = threat_intel.enrich_case(os_client, case_id, force=force)
            except threat_intel.IntelEnrichmentHalted as e:
                summary = e.summary or {}
            (source,) = _sources(os_client, case_id)
        return summary, source

    def test_a_forced_run_clears_an_older_stamp_and_stamps_the_answer(self, os_client, quick):
        summary, source = self._case(os_client, quick, force=True)
        assert not [k for k in LEGACY if k in source and k != "threat_intel.checked"]
        assert source["threat_intel.checked"] is True  # set again by the answer
        assert [e["outcome"] for e in source["threat_intel.iocs"]] == ["NO_MATCH"]
        assert summary["legacy_stamps_cleared"] == 1

    def test_the_evidence_s_own_threat_intel_object_is_kept(self, os_client, quick):
        _, source = self._case(os_client, quick, force=True)
        assert source["threat_intel"] == {"feed": "vendor-x", "score": 7}

    def test_an_unanswered_forced_run_leaves_the_document_unchecked(self, os_client, quick):
        _, source = self._case(os_client, quick, force=True, answer=unconfirmed)
        assert "threat_intel.checked" not in source
        assert [e["outcome"] for e in source["threat_intel.iocs"]] == ["UNAVAILABLE"]

    def test_anchor_a_run_without_force_leaves_an_older_stamp_alone(self, os_client, quick):
        docs = {"json-old": [{"Hash": {"SHA256": REVOKED}, **LEGACY}]}
        FakeGateway(not_found).install(quick)
        with intel_case(os_client, docs, prefix="pytest-force") as case_id:
            summary = threat_intel.enrich_case(os_client, case_id)
            (source,) = _sources(os_client, case_id)
        assert summary["status"] == "no_iocs"  # already checked: not extracted
        assert {k: source[k] for k in LEGACY} == LEGACY


class TestTheCircuitBreaker:
    @pytest.fixture
    def calls(self, quick):
        quick.setenv("VHIR_INTEL_BREAKER_THRESHOLD", "3")
        asked: list[str] = []

        def install(answer):
            def call_tool(tool, params, timeout=15):
                asked.append(params["ioc"])
                return answer(params["ioc"])

            quick.setattr("opensearch_mcp.gateway.gateway_available", lambda: True)
            quick.setattr("opensearch_mcp.gateway.call_tool", call_tool)
            return asked

        return install

    def test_a_provider_that_stays_unavailable_halts_the_run(self, calls):
        asked = calls(lambda ioc: json.loads(json.dumps(unconfirmed(ioc))))
        values = [f"{i}.0.113.1" for i in range(11, 21)]
        results = threat_intel.batch_lookup({"ip": set(values)})
        coverage = results.pop("_intel_coverage")
        assert len(asked) == 3  # the threshold, then the halt
        assert "circuit_breaker_halt" in coverage["skipped"].values()

    def test_one_provider_down_never_stops_another_s_answers(self, calls):
        def answer(ioc):
            return reply(
                ioc,
                {
                    "opencti": block("UNAVAILABLE", reason="can't reach OpenCTI"),
                    "misp": block("MATCH", [{"value": ioc}]),
                },
            )

        asked = calls(answer)
        values = {f"{i}.0.113.1" for i in range(11, 21)}
        results = threat_intel.batch_lookup({"ip": values})
        results.pop("_intel_coverage")
        assert len(asked) == 10
        assert {r["entry"]["outcome"] for r in results.values()} == {"MATCH"}

    def test_a_rate_limited_provider_is_waited_out_not_counted(self, calls, quick):
        state = {"n": 0}
        waits: list[float] = []
        quick.setattr(threat_intel.time, "sleep", waits.append)

        def answer(ioc):
            state["n"] += 1
            if state["n"] % 2:
                reason = "OpenCTI rate-limited the lookup: Too Many Requests (HTTP 429)"
                return reply(ioc, {"opencti": block("UNAVAILABLE", reason=reason)})
            return not_found(ioc)

        calls(answer)
        values = {f"{i}.0.113.1" for i in range(11, 21)}
        results = threat_intel.batch_lookup({"ip": values})
        coverage = results.pop("_intel_coverage")
        assert sorted(coverage["enriched"]) == sorted(values)
        assert len([w for w in waits if w >= 0.5]) == 10  # one wait per IOC


@pytest.mark.integration
def test_the_summary_counts_matched_unavailable_and_older_stamps(os_client, quick):
    from opensearch_mcp import server

    answers = {MISP_ONLY: _answer(MISP_ONLY), IP: unconfirmed(IP)}
    FakeGateway(lambda ioc: answers.get(ioc) or not_found(ioc)).install(quick)
    docs = {
        "json-misp": [{"Hash": {"MD5": MISP_ONLY}}],  # keyword-mapped outcome
        "winevt-net": [{"winlog": {"event_data": {"DestinationIp": IP}}}],  # text-mapped
        "winevt-match": [{"winlog": {"event_data": {"Hashes": f"MD5={MISP_ONLY.upper()}"}}}],
        "json-old": [{**LEGACY, "Note": "stamped by an older release"}],
    }
    with intel_case(os_client, docs, prefix="pytest-summary") as case_id:
        try:
            threat_intel.enrich_case(os_client, case_id)
        except threat_intel.IntelEnrichmentHalted:
            pass  # the IP couldn't be asked
        os_client.indices.refresh(index=f"case-{case_id}-*")
        counts = server._intel_counts(os_client, f"case-{case_id}-*")
    assert counts == {"checked": 3, "matched": 2, "unavailable": 1, "legacy": 1}


@pytest.mark.parametrize(
    "template",
    sorted(p.name for p in MAPPINGS.glob("*.json") if "threat_intel.verdict" in p.read_text()),
)
def test_each_template_maps_the_entry_fields_as_keyword(template):
    props = json.loads((MAPPINGS / template).read_text())["template"]["mappings"]["properties"]
    for field in ("outcome", "ioc_value", "ioc_type"):
        assert props[f"threat_intel.iocs.{field}"] == {"type": "keyword"}, (template, field)


def test_there_are_fourteen_such_templates():
    assert (
        len([p for p in MAPPINGS.glob("*.json") if "threat_intel.verdict" in p.read_text()]) == 14
    )


def test_the_cli_reports_matched_not_found_and_unavailable(quick, capsys, tmp_path):
    from opensearch_mcp import ingest_cli

    result = {
        "status": "complete",
        "iocs_extracted": 3,
        "iocs_looked_up": 3,
        "matched": 1,
        "not_found": 1,
        "unavailable": 1,
        "documents_updated": 4,
        "version_conflicts": 0,
    }
    quick.setattr(ingest_cli, "_resolve_case_id", lambda _c: "C-1")
    quick.setattr(ingest_cli, "get_client", lambda: object())
    quick.setattr(threat_intel, "enrich_case", lambda *a, **k: result)
    logged: list[dict] = []
    quick.setattr(
        ingest_cli,
        "AuditWriter",
        lambda **k: type("A", (), {"log": lambda self, **kw: logged.append(kw)})(),
    )
    ingest_cli.cmd_enrich_intel(argparse.Namespace(case="C-1", force=False, dry_run=False))
    out = capsys.readouterr().out
    assert "Matched: 1 IOC(s)" in out and "Not found: 1 IOC(s)" in out
    assert "Unavailable: 1 IOC(s)" in out
    assert "MALICIOUS" not in out and "SUSPICIOUS" not in out
    (record,) = logged
    assert record["result_summary"].startswith(
        "4 docs updated, 1 matched, 1 not found, 1 unavailable"
    )


@pytest.mark.integration
def test_a_document_never_answered_stays_unchecked_and_is_asked_again(os_client, quick):
    gateway = FakeGateway(unconfirmed).install(quick)
    docs = {"json-ps": [{"Hash": {"SHA256": REVOKED}}]}
    with intel_case(os_client, docs, prefix="pytest-unchecked") as case_id:
        for run in ("run-1", "run-2", "run-3"):
            quick.setenv("VHIR_INGEST_RUN_ID", run)
            with pytest.raises(threat_intel.IntelEnrichmentHalted):
                threat_intel.enrich_case(os_client, case_id)
        (source,) = _sources(os_client, case_id)
    assert gateway.asked == [REVOKED] * 3  # extracted again each run
    assert "threat_intel.checked" not in source
    assert [e["outcome"] for e in source["threat_intel.iocs"]] == ["UNAVAILABLE"]
