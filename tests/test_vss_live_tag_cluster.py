"""Shadow-copy records against a cluster: the live volume's tag wins in
either order, a record only in shadow copies keeps the first copy's tag, a
second run changes nothing, and a case written with the stores' tags over the
live ones is repaired by ingesting it again. Templates are the tree's, under
this run's names. Values are synthetic."""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest

from opensearch_mcp import bulk
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost

pytestmark = pytest.mark.integration

# the records each volume holds: alpha everywhere, old1 in both copies, old2 in vss2 only
VOLUMES = {
    "live": ["alpha", "bravo"],
    "vss1": ["alpha", "old1"],
    "vss2": ["alpha", "old1", "old2"],
}
TAGS = {"alpha": "live", "bravo": "live", "old1": "vss1", "old2": "vss2"}


@pytest.fixture(scope="module")
def client():
    try:
        from opensearch_mcp.client import get_client

        c = get_client()
        if c.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    return c


@pytest.fixture
def case(client):
    cid = f"vss-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    c12 = wc.case_identity(d)[0]
    created = _scratch_templates.install(client, f"vt-{c12}", c12=c12)
    yield d
    client.indices.delete(index=f"case-{c12}-*", ignore=[404])
    _scratch_templates.remove(client, created)


def _write(client, case, vss_id, records, tag=None) -> tuple[int, int]:
    """One volume's records through the scan's write path; `tag` overrides
    the record's own tag (a case written before the fix)."""
    host = DiscoveredHost(
        hostname="WKS01", volume_root=case / vss_id, vss_id=vss_id, unit_locator="evidence/img.e01"
    )
    ctx = wc.host_context(case, case.name, host)
    with wc.writing(ctx):
        index = wc.index_name("amcache")
        docs = [
            {"_index": index, "_id": r, "_source": {"KeyName": r, "vhir.vss_id": tag or vss_id}}
            for r in records
        ]
        result = bulk.flush_bulk(client, docs)
    client.indices.refresh(index=index)
    return result


def _tags(client, case) -> dict:
    c12 = wc.case_identity(case)[0]
    res = client.search(index=f"case-{c12}-*", body={"query": {"match_all": {}}, "size": 100})
    return {h["_source"]["KeyName"]: h["_source"]["vhir.vss_id"] for h in res["hits"]["hits"]}


def _scan(client, case, order=("live", "vss1", "vss2")) -> dict:
    return {v: _write(client, case, v, VOLUMES[v]) for v in order}


def test_the_live_tag_wins_and_a_copy_only_record_keeps_the_first_copys(client, case, capsys):
    bulk.reset_circuit_breaker()
    counts = _scan(client, case)
    assert _tags(client, case) == TAGS
    assert counts == {"live": (2, 0), "vss1": (1, 0), "vss2": (1, 0)}
    assert bulk.get_already_present() == 3  # alpha twice, old1 once
    assert "WARNING" not in capsys.readouterr().err


def test_a_copy_written_before_live_still_gives_way(client, case):
    _scan(client, case, order=("vss2", "vss1", "live"))
    assert _tags(client, case)["alpha"] == "live"


def test_a_second_run_changes_nothing(client, case, capsys):
    _scan(client, case)
    bulk.reset_circuit_breaker()
    counts = _scan(client, case)
    assert _tags(client, case) == TAGS
    assert counts == {"live": (2, 0), "vss1": (0, 0), "vss2": (0, 0)}
    assert bulk.get_already_present() == 5
    assert "WARNING" not in capsys.readouterr().err


def test_a_case_written_with_the_copies_tags_is_repaired_by_ingesting_again(client, case):
    # as written before the fix: every volume overwrote, the last copy's tag stayed
    for v in ("live", "vss1", "vss2"):
        _write(client, case, "live", VOLUMES[v], tag=v)
    assert _tags(client, case)["alpha"] == "vss2"
    _scan(client, case)
    assert _tags(client, case) == {**TAGS, "old1": "vss2"}  # copy vs copy: the one stored stays


def test_a_create_on_a_stored_record_is_already_present_and_keeps_it(client, case, capsys):
    bulk.reset_circuit_breaker()
    assert _write(client, case, "live", ["e1"]) == (1, 0)
    assert _write(client, case, "vss2", ["e1"]) == (0, 0)
    assert bulk.get_already_present() == 1
    assert bulk.get_last_bulk_reason() == ""
    assert _write(client, case, "vss2", ["e2"]) == (1, 0)
    assert _tags(client, case) == {"e1": "live", "e2": "vss2"}
    assert "WARNING" not in capsys.readouterr().err
