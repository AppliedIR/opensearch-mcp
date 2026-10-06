"""Triage enrichment doesn't say "complete" when its verdict writes fail or when an
aggregation leaves values unread. OpenSearch and call_tool are stand-ins.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import server as srv
from opensearch_mcp import triage_remote as tr

GW = [
    "shimcache",
    "amcache",
    "evtx_proc",
    "tasks",
    "vol_dlls",
    "evtx_svc",
    "vol_svcs",
    "registry_svcs",
    "registry_run",
    "registry_activestub",
    "registry_netsh",
]
# entries whose values come from a terms aggregation (the 5,000-value cap)
AGG = [k for k in GW if k not in ("evtx_svc", "registry_svcs")]


class StubOS:
    def __init__(self, other=0, write_ok=True, fail_rule_writes=False):
        self.other = other
        self.write_ok = write_ok
        self.fail_rule_writes = fail_rule_writes
        self.indices = MagicMock()
        self.writes = 0

    def search(self, index, body, **kw):
        aggs = body.get("aggs", {})
        if aggs:
            name = next(iter(aggs))
            buckets = [{"key": "C:\\x\\a.dll", "doc_count": 1}]
            agg = {"buckets": buckets, "sum_other_doc_count": self.other}
            return {"hits": {"hits": []}, "aggregations": {name: agg}}
        if "event.code" in str(body):
            return {"hits": {"hits": [{"_source": {"winlog.event_data": {"ServiceName": "s"}}}]}}
        hits = [
            {"_source": {"KeyPath": "ROOT\\ControlSet001\\Services\\s", "ValueData": "C:\\a.exe"}}
        ]
        return {"hits": {"hits": hits}}

    def update_by_query(self, index, body, **kw):
        is_rule = "params" not in body["script"] or "prefix" in body["script"].get("params", {})
        is_rule = is_rule or "known" in body["script"].get("params", {})
        if (is_rule and self.fail_rule_writes) or (not is_rule and not self.write_ok):
            raise RuntimeError("cluster_block_exception")
        self.writes += 1
        return {"updated": 1}


def _verdict(name, args, timeout=60):
    return {"verdict": "SUSPICIOUS", "confidence": "medium", "reasons": ["r"]}


def _enrich(stub):
    with (
        patch.object(tr, "gateway_available", return_value=True),
        patch.object(tr, "call_tool", side_effect=_verdict),
    ):
        return tr.enrich_remote(stub, "c1")


@pytest.mark.parametrize("name", GW)
def test_a_lookup_whose_verdict_cannot_be_written_is_not_complete(name):
    res = _enrich(StubOS(write_ok=False))
    assert res[name]["status"] != "complete", res[name]
    assert res[name].get("write_failures", 0) >= 1, res[name]


@pytest.mark.parametrize("name", GW)
def test_written_verdicts_stay_complete(name):
    res = _enrich(StubOS())
    assert res[name]["status"] == "complete", res[name]
    assert "write_failures" not in res[name] and "unchecked_docs" not in res[name]


def test_every_persistence_rule_whose_write_fails_is_counted():
    res = tr._enrich_registry_persistence(StubOS(fail_rule_writes=True), "c1")
    assert res["status"] != "complete", res
    assert res["rules_failed"] == 15, res


def test_idx_enrich_triage_is_incomplete_when_persistence_writes_fail():
    with (
        patch.object(tr, "gateway_available", return_value=False),
        patch.object(srv, "_get_os", return_value=StubOS(fail_rule_writes=True)),
        patch.object(srv.audit, "log", return_value=None),
    ):
        resp = srv.idx_enrich_triage(case_id="c1")
    assert resp["status"] == "incomplete", resp
    assert "registry_persistence" in resp["failed_artifacts"], resp


@pytest.mark.parametrize("name", AGG)
def test_values_past_the_aggregation_cap_are_counted_not_complete(name):
    res = _enrich(StubOS(other=7))
    assert res[name]["status"] != "complete", res[name]
    assert res[name]["unchecked_docs"] == 7, res[name]
