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
from unittest.mock import patch

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
