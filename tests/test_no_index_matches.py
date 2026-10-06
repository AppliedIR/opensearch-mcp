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
    AUDITED.clear()

    def log(**kw):
        AUDITED.append(kw)
        return f"aid-{len(AUDITED)}"

    monkeypatch.setattr(srv.audit, "log", log)
    return tag


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
@pytest.mark.parametrize("tool", ["idx_search", "idx_count"])
def test_a_pattern_matching_no_open_index_is_an_error(tools, where, tool):
    kw = where(tools)
    result = getattr(srv, tool)(query="event.code:4624", **kw)
    pattern = kw.get("index") or f"case-{kw['case_id']}-*"
    assert _no_index(result, pattern), result
    (entry,) = AUDITED
    assert entry["tool"] == tool and entry["params"]["index"] == pattern
    assert entry["result_summary"] == "no open index matched"


@pytest.mark.parametrize("tool", ["idx_search", "idx_count"])
def test_a_case_with_no_hits_still_answers_zero(tools, tool):
    result = getattr(srv, tool)(query="event.code:9999", case_id=f"{tools}-a")
    assert "error" not in result, result
    if tool == "idx_count":
        assert result["count"] == 0
    else:
        assert result["total"] == 0


def test_a_time_range_that_excludes_everything_still_answers_zero(tools):
    result = srv.idx_search(
        query="event.code:4624", case_id=f"{tools}-a", time_from="2030-01-01T00:00:00Z"
    )
    assert "error" not in result and result["total"] == 0, result


@pytest.mark.parametrize("tool", ["idx_search", "idx_count"])
def test_a_wildcard_across_indices_with_hits_answers_as_before(tools, tool):
    result = getattr(srv, tool)(query="event.code:4624", index=f"case-{tools}-a-evtx-*")
    assert "error" not in result, result
    assert (result["count"] if tool == "idx_count" else result["total"]) == 2
