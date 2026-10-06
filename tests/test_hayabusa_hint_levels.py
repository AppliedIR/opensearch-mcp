"""The Hayabusa query the server suggests finds every top-severity spelling.

Hayabusa's CSV abbreviates Level: crit, high, med, low, info, and emer for an
alert on a configured critical system. With -b the levels are spelled in full.
Each suggestion is read where the server emits it and run through idx_search
against indexed rows of every spelling.
"""

from __future__ import annotations

import re
import uuid

import _scratch_templates
import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv

pytestmark = pytest.mark.integration

TOP = {"emer", "crit", "critical", "high"}
LOWER = {"med", "medium", "low", "info", "informational"}


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
        yield client, tag
    finally:
        client.indices.delete(index=f"case-{tag}-*", ignore=[404])
        _scratch_templates.remove(client, created)


def _suggestions(client, case, tmp_path, monkeypatch):
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv, "_get_active_case", lambda: case)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    real = client.transport.perform_request
    out = {}

    def no_plugin(*a, **k):
        if "_security_analytics" in str(a):
            raise RuntimeError("404 no detectors")
        return real(*a, **k)

    def no_findings(*a, **k):
        if "_security_analytics" in str(a):
            return {"total_findings": 0, "findings": []}
        return real(*a, **k)

    for name, fake in (("no sigma plugin", no_plugin), ("no sigma findings", no_findings)):
        monkeypatch.setattr(client.transport, "perform_request", fake)
        out[name] = srv.idx_list_detections()["suggestion"]
    monkeypatch.setattr(client.transport, "perform_request", real)
    hosts = [
        {"hostname": "hosta", "artifacts": [{"name": "evtx", "status": "complete", "indexed": 1}]},
        {"hostname": "hayabusa", "artifacts": [{"name": "hayabusa", "status": "complete"}]},
    ]
    ingest_status.write_status(case, 99999999, "r", "complete", hosts, {"indexed": 1}, "t0")
    (status,) = srv.idx_ingest_status(case_id=case)["ingests"]
    out["ingest next step"] = next(s for s in status["next_steps"] if "Hayabusa" in s)
    return out


def test_the_suggested_query_finds_every_top_level_spelling(scratch, tmp_path, monkeypatch):
    client, tag = scratch
    case = f"{tag}-hb"  # case-{tag}-* is what the scratch templates cover
    index = f"case-{case}-hayabusa-hosta"
    for i, level in enumerate(sorted(TOP | LOWER)):
        client.index(
            index=index,
            id=str(i),
            body={"Timestamp": "2024-01-01T00:00:00Z", "RuleTitle": f"r{i}", "Level": level},
        )
    client.indices.refresh(index=index)
    # The harness reaches the real mapping: Level is an exact-match keyword.
    assert client.indices.get_mapping(index=index)[index]["mappings"]["properties"]["Level"] == {
        "type": "keyword"
    }
    for where, text in _suggestions(client, case, tmp_path, monkeypatch).items():
        m = re.search(r"idx_search\(query='(.*?)', index='(.*?)'\)", text)
        assert m, (where, text)
        found = {
            d["Level"]
            for d in srv.idx_search(query=m.group(1), index=m.group(2), limit=200)["results"]
        }
        assert found == TOP, (where, m.group(1), sorted(found))
