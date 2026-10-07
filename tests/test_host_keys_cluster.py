"""Case identity and machine keys against a cluster: each case reads only its
own data, a renamed case folder keeps it, a case from before 0.7 is read
through its alias and its hosts carry over, and the summary counts machines.
Templates are the tree's, installed under this run's names. Values are
synthetic."""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest
from sift_common import host_identity

from opensearch_mcp import bulk
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc
from opensearch_mcp.case_scope import attach_legacy_alias, ensure_v1_imported

pytestmark = pytest.mark.integration


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
def cases(client, monkeypatch):
    """new(name, v1=False) -> (case dir, c12); cleans up every index and template."""
    made: list[tuple[str, dict]] = []
    tag = uuid.uuid4().hex[:8]
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)

    def new(name: str, v1: bool = False):
        cid = f"{name}-{tag}"
        d = wc.case_dir_for(cid)
        if v1:
            (d / "CASE.yaml").write_text(f"case_id: {cid}\n")
        else:
            u = uuid.uuid4().hex
            (d / "CASE.yaml").write_text(f"case_id: {cid}\ncase_uuid: {u}\nnaming_version: 2\n")
        c12 = wc.case_identity(d)[0]
        made.append((c12, _scratch_templates.install(client, f"hk-{c12}", c12=c12)))
        return d, c12

    new.tag = tag
    yield new
    for c12, created in made:
        client.indices.delete(index=f"case-{c12}-*", ignore=[404])
        client.indices.delete_alias(index="_all", name=f"vhir-legacy-{c12}", ignore=[404])
        _scratch_templates.remove(client, created)
    client.indices.delete(index=f"case-*-{tag}-*", ignore=[404])


def write(client, case_dir, locator, raw, docs: dict, artifact="evtx"):
    """docs: {parser id: source}. Returns the run's context."""
    ctx = wc.open_unit(case_dir, locator, raw, source="test")
    with wc.writing(ctx):
        index = wc.index_name(artifact)
        bulk.flush_bulk(
            client, [{"_index": index, "_id": k, "_source": dict(v)} for k, v in docs.items()]
        )
    client.indices.refresh(index=index)
    return ctx


def v1_index(client, name: str, docs: list[dict]):
    for n, d in enumerate(docs):
        client.index(index=name, id=str(n), body=d)
    client.indices.refresh(index=name)


def evtx(n, host=None, **extra):
    return {
        str(i): {"@timestamp": "2024-01-01T00:00:00Z", "event.code": "4624", **extra,
                 **({"host.name": host} if host else {})}
        for i in range(n)
    }  # fmt: skip


# -- A: identity and isolation


def test_each_case_counts_searches_and_summarises_only_its_own_data(client, cases, monkeypatch):
    acme, _ = cases("acme", v1=True)
    acme2, _ = cases(f"acme-{cases.tag}-2", v1=True)  # its id begins with acme's
    v2a, _ = cases("north")
    v2b, _ = cases("south")
    v1_index(
        client, f"case-{acme.name}-evtx-wks01", [{"host.name": "WKS01", "host.id": "WKS01"}] * 3
    )
    v1_index(
        client, f"case-{acme2.name}-evtx-wks09", [{"host.name": "WKS09", "host.id": "WKS09"}] * 5
    )
    write(client, v2a, "hosts/N1", "N1", evtx(7))
    write(client, v2b, "hosts/S1", "S1", evtx(11))
    for case, n in ((acme, 3), (acme2, 5), (v2a, 7), (v2b, 11)):
        monkeypatch.setattr(srv, "_get_active_case", lambda c=case.name: c)
        assert srv.idx_count(query="*")["count"] == n, case.name
        assert srv.idx_search(query="*", limit=50)["total"] == n, case.name
        assert srv.idx_case_summary()["total_docs"] == n, case.name


def test_a_renamed_case_folder_keeps_its_data(client, cases, monkeypatch):
    case, c12 = cases("rename")
    write(client, case, "hosts/WKS10", "WKS10", evtx(4))
    moved = case.rename(case.parent / f"{case.name}-renamed")
    monkeypatch.setattr(srv, "_get_active_case", lambda: moved.name)
    assert srv.idx_count(query="*")["count"] == 4


def test_a_pre_0_7_case_gets_its_alias_also_for_indices_made_later(client, cases):
    case, c12 = cases("legacy", v1=True)
    v1_index(client, f"case-{case.name}-evtx-wks10", [{"host.name": "WKS10"}])
    assert attach_legacy_alias(client, case.name)["attached"] == [f"case-{case.name}-evtx-wks10"]
    v1_index(
        client, f"case-{case.name}-registry-wks10", [{"host.name": "WKS10"}]
    )  # by an older release
    attach_legacy_alias(client, case.name)
    members = sorted(client.indices.get_alias(name=f"vhir-legacy-{c12}"))
    assert members == [f"case-{case.name}-evtx-wks10", f"case-{case.name}-registry-wks10"]


def test_a_restored_copy_attaches_no_alias(client, cases):
    case, c12 = cases("copy", v1=True)
    (case / "CASE.yaml").write_text(f"case_id: {case.name}\nlegacy_alias: none\n")
    v1_index(client, f"case-{case.name}-evtx-wks10", [{"host.name": "WKS10"}])
    assert attach_legacy_alias(client, case.name)["attached"] == []
    assert not client.indices.exists_alias(name=f"vhir-legacy-{c12}")


def test_indices_no_case_can_claim_are_listed(client, cases, monkeypatch):
    case, _ = cases("lister")
    orphan = f"case-gone-{cases.tag}-evtx-wks10"
    v1_index(client, orphan, [{"host.name": "WKS10"}])
    write(client, case, "hosts/WKS10", "WKS10", evtx(1))
    monkeypatch.setattr(srv, "_get_active_case", lambda: case.name)
    assert orphan in srv.idx_case_summary()["unattributed_indices"]


# -- B: storage


def test_two_machines_sharing_a_name_path_and_record_ids_are_both_stored(client, cases):
    case, c12 = cases("twins")
    write(client, case, "hosts/corp-a/DC01", "DC01", evtx(1000, host="DC01"))
    write(client, case, "hosts/corp-b/DC01", "DC01", evtx(1000, host="DC01"))
    assert client.count(index=f"case-{c12}-evtx-0")["count"] == 2000


def test_a_new_evtx_index_has_four_primaries_and_keyword_machine_fields(client, cases):
    case, c12 = cases("shards")
    write(client, case, "hosts/WKS10", "WKS10", evtx(1))
    index = f"case-{c12}-evtx-0"
    settings = client.indices.get_settings(index=index)[index]["settings"]["index"]
    assert settings["number_of_shards"] == "4"
    assert settings["default_pipeline"].endswith("winlog_data_normalize_v1")
    props = client.indices.get_mapping(index=index)[index]["mappings"]["properties"]

    def field(dotted):  # the mapping shows dotted names as objects
        node = {"properties": props}
        for part in dotted.split("."):
            node = node["properties"][part]
        return node

    for name in ("host.id", "vhir.host_key", "vhir.unit", "vhir.prev_ids"):
        assert field(name)["type"] == "keyword", name
    assert field("vhir.rid") == {"type": "keyword", "index": False}


def test_a_pre_0_7_host_ingested_again_says_it_adds_a_second_copy(client, cases):
    case, c12 = cases("second", v1=True)
    v1_index(client, f"case-{case.name}-evtx-wks01", [{"host.name": "WKS01", "host.id": "WKS01"}])
    wc.SECOND_COPY.clear()
    write(client, case, "hosts/WKS01", "WKS01", evtx(2))
    assert client.count(index=f"case-{c12}-evtx-0")["count"] == 2
    assert wc.second_copy_note("WKS01", "evtx") == wc.SECOND_COPY_NOTE
    out: dict = {}
    srv._existing_host_docs(client, case.name, "evtx", "WKS01", out)
    assert out["notes"] == [f"evtx: {wc.SECOND_COPY_NOTE}"]


# -- C: a pre-0.7 case's hosts carry over


def test_a_pre_0_7_machine_keeps_its_host_id_and_its_merge_is_flagged(client, cases):
    case, c12 = cases("carry", v1=True)
    (case / "host-dictionary.yaml").write_text(
        "version: 1\nhosts:\n  WKS01:\n    aliases: [WKS01, wks01.corp.example.test]\n"
    )
    v1_index(client, f"case-{case.name}-evtx-wks01", [
        {"host.name": "WKS01", "host.id": "WKS01"},
        {"host.name": "wks01.corp.example.test", "host.id": "WKS01"},
    ])  # fmt: skip
    write(client, case, "hosts/WKS01", "WKS01", evtx(1, host="WKS01"))  # imports first
    assert ensure_v1_imported(client, case) is False
    (machine,) = host_identity.load(case).machines.values()
    assert machine.canonical == "WKS01" and machine.state == host_identity.CONFIRMED
    assert host_identity.FLAG_V1_MERGED in machine.flags
    hit = client.search(index=f"case-{c12}-evtx-0")["hits"]["hits"][0]["_source"]
    assert hit["host.id"] == "WKS01" and hit["vhir.host_key"] in machine.keys


# -- G: the summary counts machines


def test_one_machine_under_two_names_is_one_host_in_the_summary(client, cases, monkeypatch):
    case, c12 = cases("summary")
    a = host_identity.unit_key("hosts/WKS01")
    b = host_identity.unit_key("hosts/wks01-fqdn")
    key = host_identity.new_machine_key()
    host_identity.append_observations(
        case, [{"kind": "unit", "unit": a}, {"kind": "unit", "unit": b}]
    )
    host_identity.append_decision(case, {"action": "confirm", "args": {"machines": [
        {"key": key, "canonical": "WKS01",
         "pairs": [[a, "WKS01"], [b, "wks01.corp.example.test"]]}]}},
        (case / host_identity.OBSERVATIONS).stat().st_size)  # fmt: skip
    write(client, case, "hosts/WKS01", "WKS01", evtx(2, host="WKS01"))
    write(client, case, "hosts/wks01-fqdn", "wks01.corp.example.test",
          {"t1": {"task.command": "x"}}, artifact="tasks")  # fmt: skip
    monkeypatch.setattr(srv, "_get_active_case", lambda: case.name)
    resp = srv.idx_case_summary()
    assert resp["hosts"] == ["WKS01"]
    assert resp["host_names"] == {"WKS01": ["WKS01", "wks01.corp.example.test"]}
    assert set(resp["artifacts"]) == {"evtx", "tasks"}
