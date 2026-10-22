"""A search that matched no open index says so instead of "No results".

A mistyped case id, an artifact type never ingested, or a case whose only
index is closed matched nothing, so nothing was searched; the answer used to
be 0 hits, which reads as "looked, found nothing". Runs against a cluster.
"""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest

from opensearch_mcp import server as srv

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def scratch():
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    tag = f"pytest-tpl-{uuid.uuid4().hex[:8]}"
    created = _scratch_templates.install(client, tag)
    try:
        for case, host in (("a", "h1"), ("a", "h2"), ("b", "h1")):
            index = f"case-{tag}-{case}-evtx-{host}"
            client.index(
                index=index,
                body={"@timestamp": "2026-01-01T00:00:00Z", "event": {"code": "4624"}},
                refresh=True,
            )
        client.indices.close(index=f"case-{tag}-b-evtx-h1")  # case b: closed only
        yield client, tag
    finally:
        client.indices.delete(index=f"case-{tag}-*", ignore=[404])
        _scratch_templates.remove(client, created)


AUDITED = []


@pytest.fixture
def tools(scratch, monkeypatch):
    client, tag = scratch
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv, "_get_active_case", lambda: f"{tag}-a")
    AUDITED.clear()

    def log(**kw):
        AUDITED.append(kw)
        return f"aid-{len(AUDITED)}"

    monkeypatch.setattr(srv.audit, "log", log)
    return tag


# each query tool and what it needs beyond a query and a scope
TOOLS = {
    "idx_search": {},
    "idx_count": {},
    "idx_aggregate": {"field": "event.code"},
    "idx_field_values": {"field": "event.code"},
    "idx_timeline": {},
}


def _total(tool, result):
    """The documents a live answer counted, by where each tool reports them."""
    if tool == "idx_field_values":
        return sum(v["count"] for v in result["values"])
    key = {"idx_search": "total", "idx_count": "count"}.get(tool, "total_docs")
    return result[key]


def _no_index(result, pattern):
    return result == {
        "error": f"No open index matches {pattern!r}: nothing was searched. "
        "Check the case id or index pattern.",
        "audit_id": "aid-1",
    }


@pytest.mark.parametrize(
    "where",
    [
        lambda t: {"case_id": f"{t}-ax"},
        lambda t: {"index": f"case-{t}-a-json-*"},
        lambda t: {"index": f"case-{t}-a-delim-*,case-{t}-a-lnk-*"},
        lambda t: {"case_id": f"{t}-b"},
    ],
    ids=["mistyped case id", "type never ingested", "no part of a comma pattern", "closed only"],
)
@pytest.mark.parametrize("tool", TOOLS)
def test_a_pattern_matching_no_open_index_is_an_error(tools, where, tool):
    from opensearch_mcp.case_scope import case_read_scope

    kw = where(tools)
    result = getattr(srv, tool)(query="event.code:4624", **TOOLS[tool], **kw)
    pattern = kw.get("index") or case_read_scope(kw["case_id"], srv._get_os())
    assert _no_index(result, pattern), result
    (entry,) = AUDITED
    assert entry["tool"] == tool and entry["params"]["scope"] == pattern
    assert entry["params"]["index"] == kw.get("index", "")  # what was asked for
    assert entry["result_summary"] == "no open index matched"
    assert entry["params"].get("field") == TOOLS[tool].get("field")
    if tool == "idx_timeline":
        assert entry["params"]["interval"] == "1h"


@pytest.mark.parametrize("tool", TOOLS)
def test_a_case_with_no_hits_still_answers_zero(tools, tool):
    result = getattr(srv, tool)(query="event.code:9999", case_id=f"{tools}-a", **TOOLS[tool])
    assert "error" not in result, result
    assert _total(tool, result) == 0


def test_a_time_range_that_excludes_everything_still_answers_zero(tools):
    result = srv.idx_search(
        query="event.code:4624", case_id=f"{tools}-a", time_from="2030-01-01T00:00:00Z"
    )
    assert "error" not in result and result["total"] == 0, result


@pytest.mark.parametrize("tool", TOOLS)
def test_a_wildcard_across_indices_with_hits_answers_as_before(tools, tool):
    index = f"case-{tools}-a-evtx-*"
    result = getattr(srv, tool)(query="event.code:4624", index=index, **TOOLS[tool])
    assert "error" not in result, result
    assert _total(tool, result) == 2


@pytest.mark.parametrize("case", ["ax", "b"], ids=["mistyped case id", "closed only"])
def test_docs_per_key_with_no_open_index_counts_nothing(tools, case):
    counts, note = srv._docs_per_key(f"{tools}-{case}", ["k1"])
    assert (counts, note) == ({}, "no open index of the case: no documents counted")
