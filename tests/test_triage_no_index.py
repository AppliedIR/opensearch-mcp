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
from sift_common import host_identity

from opensearch_mcp import triage_remote as tr
from opensearch_mcp import write_context as wc

CASE = f"triage-{uuid.uuid4().hex[:8]}"  # a case of this release: no pre-0.6.4 indices


def v2(artifact_type: str) -> str:
    return f"case-{host_identity.ensure_case_uuid(wc.case_dir_for(CASE), 2)[0]}-{artifact_type}-0"


class _OpenSearch:
    def __init__(self, existing):
        self.existing = existing

    def search(self, index, body, **kw):
        parts = [x.strip() for x in index.split(",") if x.strip()]
        keep = [x for x in parts if not x.startswith("-")]
        drop = [x[1:] for x in parts if x.startswith("-")]
        matched = [  # as OpenSearch resolves a comma list with `-` exclusions
            n
            for n in self.existing
            if any(fnmatch.fnmatch(n, k) for k in keep)
            and not any(fnmatch.fnmatch(n, d) for d in drop)
        ]
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
        return tr.enrich_remote(_OpenSearch(existing), CASE)


def test_no_index_is_skipped_with_a_reason_not_empty():
    res = _enrich([])
    for name in GATEWAY:
        assert res[name]["status"] == "skipped", (name, res[name])
        assert res[name].get("reason"), (name, res[name])


def test_an_existing_index_with_nothing_to_check_is_empty():
    existing = [
        v2("shimcache"),
        v2("amcache"),
        v2("evtx"),
        v2("tasks"),
        v2("vol-dlllist"),
        v2("vol-svcscan"),
        v2("registry"),
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
    c12 = host_identity.ensure_case_uuid(wc.case_dir_for(case), 2)[0]
    res = tr._enrich_registry_persistence(client, case)
    assert res["status"] == "skipped", res
    assert f"case-{c12}-registry-*" in res["reason"], res


def test_a_registry_index_runs_persistence_as_before():
    """Its rules still run, and what they update is reported."""
    calls = []

    class _WithUpdates(_OpenSearch):
        def update_by_query(self, index, body, **kw):
            calls.append(index)
            return {"updated": 1, "total": 1}  # each rule matched a row

    res = tr._enrich_registry_persistence(_WithUpdates([v2("registry")]), CASE)
    assert calls and set(calls) == {v2("registry")[:-1] + "*"}, calls
    assert res == {"status": "complete", "enriched": len(calls)}, res
