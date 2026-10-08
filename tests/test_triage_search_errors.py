"""A triage search that fails is a failure, not a skip: only an index that
isn't there is skipped. The enrichment is real; the cluster client raises,
and the gateway is reachable. Values are synthetic."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from opensearchpy.exceptions import ConnectionError, NotFoundError, RequestError, TransportError
from test_hayabusa_outcomes import scan  # noqa: F401 (a fixture)

from opensearch_mcp import triage_remote


@pytest.fixture
def gateway(monkeypatch):
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)
    monkeypatch.setattr(triage_remote, "call_tool", lambda *a, **k: {"verdict": "EXPECTED"})


def _client(raises):
    c = MagicMock()
    for op in ("search", "count", "update_by_query"):
        getattr(c, op).side_effect = raises
    return c


ERRORS = {
    "connection": ConnectionError("N/A", "connection refused", None),
    "503": TransportError(503, "unavailable", "the cluster is busy"),
}


def _artifacts(results):
    """The artifacts' outcomes; `_cleared` is the step that clears retired stamps."""
    return {k: v for k, v in results.items() if isinstance(v, dict) and not k.startswith("_")}


@pytest.mark.parametrize("raises", ERRORS.values(), ids=ERRORS.keys())
def test_every_failed_search_fails_its_artifact(gateway, raises):
    results = triage_remote.enrich_remote(_client(raises), "c1")
    artifacts = _artifacts(results)
    assert artifacts["registry_persistence"]["status"] == "failed"
    assert all(v["status"] == "failed" for v in artifacts.values()), artifacts
    assert all(v["reason"].startswith("search failed: ") for v in artifacts.values())
    assert results["_cleared"]["status"] == "failed"  # the clear failed the same way


def test_an_index_that_isnt_there_is_still_a_skip(gateway):
    results = triage_remote.enrich_remote(
        _client(NotFoundError(404, "index_not_found_exception", "no such index")), "c1"
    )
    artifacts = _artifacts(results)
    assert artifacts and all(v["status"] == "skipped" for v in artifacts.values()), artifacts
    assert not any("search failed" in v.get("reason", "") for v in artifacts.values())
    assert results["_cleared"] == {"status": "complete", "cleared": 0}  # nothing to clear


def test_a_mapping_error_on_one_index_fails_that_artifact_in_the_tool(gateway, monkeypatch):
    """The tasks index took the evtx template: its search returns a 400."""
    from opensearch_mcp import server as srv

    bad = RequestError(400, "search_phase_execution_exception", "Text fields are not optimised")
    c = MagicMock()

    def search(index=None, **k):
        if "tasks" in str(index):
            raise bad
        raise NotFoundError(404, "index_not_found_exception", "no such index")

    c.search.side_effect = search
    c.count.side_effect = search
    c.update_by_query.side_effect = search
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    monkeypatch.setattr(srv.audit, "log", lambda **k: None)
    resp = srv.idx_enrich_triage(case_id="c1")
    assert resp["details"]["tasks"]["status"] == "failed"
    assert resp["details"]["tasks"]["reason"].startswith("search failed: RequestError(400")
    assert "tasks" in resp["failed_artifacts"]


def test_a_scan_whose_triage_searches_fail_says_so(gateway, scan, capsys):  # noqa: F811
    status = scan(triage=True, client=_client(ERRORS["connection"]))
    out = capsys.readouterr().out
    assert "Triage enrichment incomplete" in out
    (warning,) = [w for w in status.get("warnings", []) if w.startswith("triage:")]
    assert "registry_persistence" in warning and "search failed" in warning
