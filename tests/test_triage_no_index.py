"""Triage enrichment says "skipped" with the reason when an artifact's index
doesn't exist, and "empty" only when it exists with nothing to check.

A wildcard matching no index answers 200 with no aggregations, which every
artifact read as `empty`: "no data", while the case's Velociraptor and Kansa
data sat in json-*/delim-* indices triage doesn't read. The stand-in answers
as OpenSearch 3.x does: no `aggregations` key by default, and a 404
`index_not_found_exception` with allow_no_indices=False.
"""

from __future__ import annotations

import fnmatch
import uuid
from unittest.mock import patch

import pytest
from opensearchpy.exceptions import NotFoundError

from opensearch_mcp import triage_remote as tr


class _OpenSearch:
    def __init__(self, existing):
        self.existing = existing

    def search(self, index, body, **kw):
        matched = [n for n in self.existing if fnmatch.fnmatch(n, index)]
        if not matched:
            if kw.get("allow_no_indices") is False:
                raise NotFoundError(404, "index_not_found_exception", f"no such index [{index}]")
            return {"hits": {"total": {"value": 0}, "hits": []}, "_shards": {"total": 0}}
        result = {"hits": {"total": {"value": 0}, "hits": []}, "_shards": {"total": len(matched)}}
        if body.get("aggs"):
            result["aggregations"] = {k: {"buckets": []} for k in body["aggs"]}
        return result


GATEWAY = [
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


def _enrich(existing):
    with (
        patch.object(tr, "gateway_available", return_value=True),
        patch.object(tr, "call_tool", side_effect=AssertionError("no lookup expected")),
    ):
        return tr.enrich_remote(_OpenSearch(existing), "c1")


def test_no_index_is_skipped_with_a_reason_not_empty():
    res = _enrich([])
    for name in GATEWAY:
        assert res[name]["status"] == "skipped", (name, res[name])
        assert res[name].get("reason"), (name, res[name])


def test_an_existing_index_with_nothing_to_check_is_empty():
    existing = [
        "case-c1-shimcache-h",
        "case-c1-amcache-h",
        "case-c1-evtx-h",
        "case-c1-tasks-h",
        "case-c1-vol-dlllist-h",
        "case-c1-vol-svcscan-h",
        "case-c1-registry-h",
    ]
    res = _enrich(existing)
    assert {name: res[name]["status"] for name in GATEWAY} == dict.fromkeys(GATEWAY, "empty")


def test_no_registry_index_skips_persistence_with_a_reason():
    res = _enrich([])["registry_persistence"]
    assert res["status"] == "skipped" and "index_not_found" in res["reason"], res


@pytest.mark.integration
def test_the_cluster_names_the_missing_registry_pattern():
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        client.cluster.health()
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")
    case = f"pytest-noreg-{uuid.uuid4().hex[:8]}"
    res = tr._enrich_registry_persistence(client, case)
    assert res["status"] == "skipped", res
    assert f"case-{case}-registry-*" in res["reason"], res


def test_a_registry_index_runs_persistence_as_before():
    """Its rules still run, and what they update is reported."""
    calls = []

    class _WithUpdates(_OpenSearch):
        def update_by_query(self, index, body, **kw):
            calls.append(index)
            return {"updated": 1}

    res = tr._enrich_registry_persistence(_WithUpdates(["case-c1-registry-h"]), "c1")
    assert calls and set(calls) == {"case-c1-registry-*"}, calls
    assert res == {"status": "complete", "enriched": len(calls)}, res
