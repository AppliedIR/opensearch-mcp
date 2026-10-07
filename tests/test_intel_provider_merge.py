"""An outage never erases a platform's earlier answer.

A later document carrying an IOC that an earlier run checked is looked up
again, and the answer is stamped on every document carrying it. During an
OpenCTI outage that answer (MATCH from MISP) replaced the whole entry:
OpenCTI's earlier records became UNAVAILABLE, and the document stayed
checked, so OpenCTI was never asked again. Each provider's block is now
merged: a new UNAVAILABLE keeps the earlier answer, the outcome is
recomputed, and a document is checked only when every block on it is an
answer. The run says which provider didn't answer.

Also: an IOC only in an ECS `destination.ip` is looked up.

Runs against a cluster under this run's template names; the gateway is a
stand-in; values are derived.
"""

from __future__ import annotations

import hashlib
import itertools

import pytest
from _intel_case import intel_case
from _intel_gateway import FakeGateway, block, opencti_record, reply
from test_intel_verdicts import os_client  # noqa: F401

from opensearch_mcp import threat_intel

pytestmark = pytest.mark.integration

IOC = hashlib.md5(b"merged").hexdigest()
OTHER = hashlib.md5(b"answered before").hexdigest()
DEST_IP = "185.220.101.1"
DOWN = block("UNAVAILABLE", reason="can't reach OpenCTI")
_runs = itertools.count()


def _misp(outcome: str, value: str) -> dict:
    matches = [{"uuid": "a1", "type": "md5", "value": value}] if outcome == "MATCH" else []
    return block(outcome, matches, version="2.5.48")


def _opencti_match(value: str) -> dict:
    return block("MATCH", [opencti_record(value, c) for c in (30, 50, 70)])


def _run(client, case_id, monkeypatch, answer, force=False):
    """One enrichment run of its own; returns (summary or the halt's text, IOCs asked)."""
    gw = FakeGateway(answer).install(monkeypatch)
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", f"merge-{next(_runs)}")
    try:
        result = threat_intel.enrich_case(client, case_id, force=force)
    except threat_intel.IntelEnrichmentHalted as e:
        result = str(e)
    client.indices.refresh(index=f"case-{case_id}-*")
    return result, gw.asked


def _doc(client, case_id, index, doc_id="0"):
    return client.get(index=f"case-{case_id}-{index}", id=doc_id)["_source"]


def _entry(source, value=IOC):
    (entry,) = [e for e in source["threat_intel.iocs"] if e["ioc_value"] == value]
    return entry


@pytest.fixture
def quick(monkeypatch, tmp_path):
    monkeypatch.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
    monkeypatch.setattr(threat_intel.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        threat_intel, "_coverage_path_for_run", lambda run: tmp_path / f"{run}.json"
    )
    return monkeypatch


def _later_doc(client, case_id):
    client.index(index=f"case-{case_id}-json-later", id="0", body={"Hash": {"MD5": IOC}})
    client.indices.refresh(index=f"case-{case_id}-*")


def test_an_outage_keeps_opencti_s_earlier_records(os_client, quick):  # noqa: F811
    """The UAT's repro: an earlier MATCH, then an outage and a non-force run."""
    with intel_case(os_client, {"json-first": [{"Hash": {"MD5": IOC}}]}) as case_id:
        _run(
            os_client,
            case_id,
            quick,
            lambda i: reply(i, {"opencti": _opencti_match(i), "misp": _misp("NO_MATCH", i)}),
        )
        _later_doc(os_client, case_id)
        result, asked = _run(
            os_client,
            case_id,
            quick,
            lambda i: reply(i, {"opencti": DOWN, "misp": _misp("MATCH", i)}),
        )
        assert asked == [IOC]
        assert "OpenCTI: 1 not answered" in result
        first = _doc(os_client, case_id, "json-first")
        entry = _entry(first)
        assert (entry["opencti"]["outcome"], len(entry["opencti"]["matches"])) == ("MATCH", 3)
        assert entry["misp"]["outcome"] == "MATCH" and entry["outcome"] == "MATCH"
        assert first["threat_intel.checked"] is True  # both platforms' answers are on it
        later = _doc(os_client, case_id, "json-later")
        assert _entry(later)["opencti"]["outcome"] == "UNAVAILABLE"
        assert "threat_intel.checked" not in later  # asked again next time


def test_a_misp_only_answer_keeps_opencti_s_earlier_no_match(os_client, quick):  # noqa: F811
    with intel_case(os_client, {"json-first": [{"Hash": {"MD5": IOC}}]}) as case_id:
        _run(
            os_client,
            case_id,
            quick,
            lambda i: reply(i, {"opencti": block("NO_MATCH"), "misp": _misp("NO_MATCH", i)}),
        )
        _later_doc(os_client, case_id)
        _run(
            os_client,
            case_id,
            quick,
            lambda i: reply(i, {"opencti": DOWN, "misp": _misp("MATCH", i)}),
        )
        entry = _entry(_doc(os_client, case_id, "json-first"))
        assert entry["opencti"]["outcome"] == "NO_MATCH"
        assert (entry["misp"]["outcome"], entry["outcome"]) == ("MATCH", "MATCH")
        assert "reason" not in entry  # every block answered


def test_after_the_outage_only_the_unanswered_entries_are_asked_again(
    os_client,  # noqa: F811
    quick,
):
    docs = {"json-first": [{"Hash": {"MD5": OTHER}}], "json-second": [{"Hash": {"MD5": IOC}}]}
    with intel_case(os_client, docs) as case_id:

        def answer(i):
            return reply(i, {"opencti": block("NO_MATCH"), "misp": _misp("NO_MATCH", i)})

        _run(
            os_client,
            case_id,
            quick,
            lambda i: reply(
                i,
                {
                    # IOC: MISP matched while OpenCTI was down, a MATCH missing an answer
                    "opencti": block("NO_MATCH") if i == OTHER else DOWN,
                    "misp": _misp("NO_MATCH" if i == OTHER else "MATCH", i),
                },
            ),
        )
        assert "threat_intel.checked" not in _doc(os_client, case_id, "json-second")
        result, asked = _run(os_client, case_id, quick, answer)
        assert asked == [IOC]  # OTHER's entry already has both answers
        assert result["status"] == "complete"
        second = _doc(os_client, case_id, "json-second")
        assert _entry(second)["opencti"]["outcome"] == "NO_MATCH"
        assert _entry(second)["misp"]["outcome"] == "NO_MATCH"  # the new answer
        assert second["threat_intel.checked"] is True


def test_force_still_asks_again_for_everything(os_client, quick):  # noqa: F811
    docs = {"json-first": [{"Hash": {"MD5": OTHER}}], "json-second": [{"Hash": {"MD5": IOC}}]}
    with intel_case(os_client, docs) as case_id:

        def answered(i):
            return reply(i, {"opencti": block("NO_MATCH"), "misp": _misp("NO_MATCH", i)})

        _run(os_client, case_id, quick, answered)
        _, asked = _run(os_client, case_id, quick, answered)
        assert asked == []  # nothing is left unanswered
        _, asked = _run(os_client, case_id, quick, answered, force=True)
        assert sorted(asked) == sorted([IOC, OTHER])


def test_an_ioc_only_in_destination_ip_is_looked_up(os_client, quick):  # noqa: F811
    docs = {"json-conn": [{"destination": {"ip": DEST_IP}, "event": {"kind": "event"}}]}
    with intel_case(os_client, docs) as case_id:
        result, asked = _run(
            os_client, case_id, quick, lambda i: reply(i, {"opencti": _opencti_match(i)})
        )
        assert asked == [DEST_IP]
        assert result["matched"] == 1
        assert _entry(_doc(os_client, case_id, "json-conn"), DEST_IP)["outcome"] == "MATCH"
