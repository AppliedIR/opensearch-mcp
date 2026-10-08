"""Records are stored under their machine, in indices named from the case's
identity, and reads stay inside the case. No cluster: a stand-in client
records what would be sent. Names and values are synthetic."""

from __future__ import annotations

import argparse
import fnmatch
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sift_common import host_identity

from opensearch_mcp import bulk, ingest, ingest_cli, mappings
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc
from opensearch_mcp.case_scope import CaseScopeError, confine
from opensearch_mcp.parse_csv import _VOLATILE_KEYS, _doc_id
from opensearch_mcp.parse_plaso import _PLASO_VOLATILE_KEYS
from opensearch_mcp.paths import build_index_name, stem_type


def new_case(name: str | None = None) -> tuple[Path, str]:
    """A case with an identity: (its directory, its c12)."""
    name = name or f"case-{uuid.uuid4().hex[:6]}"
    d = wc.case_dir_for(name)
    u = uuid.uuid4().hex
    (d / "CASE.yaml").write_text(f"case_id: {name}\ncase_uuid: {u}\nnaming_version: 2\n")
    return d, u[:12]


class _Sent:
    """A cluster stand-in for flush_bulk: keeps every action, accepts all."""

    def __init__(self):
        self.actions: list[dict] = []
        self.indices = MagicMock()
        self.indices.exists.return_value = True
        self.indices.stats.return_value = {"indices": {}}

    def stored(self) -> dict:
        """_id -> source, as an index would hold them."""
        return {a["_id"]: a["_source"] for a in self.actions}


def _send(client, actions):
    with patch.object(bulk.helpers, "bulk", side_effect=lambda c, a, **k: (len(a), [])):
        client.actions.extend(actions)
        return bulk.flush_bulk(client, actions)


def write(client, case_dir, locator, raw, rids, artifact="evtx", **source):
    ctx = wc.open_unit(case_dir, locator, raw, source="test")
    with wc.writing(ctx):
        index = wc.index_name(artifact)
        _send(client, [{"_index": index, "_id": r, "_source": {**source}} for r in rids])
    return ctx


# -- storage


def test_two_machines_with_one_name_and_one_record_keep_both():
    case, c12 = new_case()
    client = _Sent()
    rids = [f"{c12}:Security.evtx:{n}" for n in range(500)]
    write(client, case, "hosts/site-a/DC01", "DC01", rids)
    write(client, case, "hosts/site-b/DC01", "DC01", rids)
    stored = client.stored()
    assert len(stored) == 1000
    assert {s["host.id"] for s in stored.values()} == {"DC01", "DC01 (2)"}
    assert len({s["vhir.host_key"] for s in stored.values()}) == 2
    assert {a["_index"] for a in client.actions} == {f"case-{c12}-evtx-0"}


def test_one_confirmed_machine_from_two_folders_is_stored_once():
    case, _ = new_case()
    a, b = (host_identity.unit_key(x) for x in ("hosts/a/DC01", "hosts/b/DC01"))
    key = host_identity.new_machine_key()
    host_identity.append_observations(
        case, [{"kind": "unit", "unit": a}, {"kind": "unit", "unit": b}]
    )
    host_identity.append_decision(
        case,
        {
            "action": "confirm",
            "args": {"machines": [{"key": key, "canonical": "DC01",
                                   "pairs": [[a, "DC01"], [b, "DC01"]]}]},
        },
        (case / host_identity.OBSERVATIONS).stat().st_size,
    )  # fmt: skip
    client = _Sent()
    rids = [f"Security.evtx:{n}" for n in range(300)]
    write(client, case, "hosts/a/DC01", "DC01", rids)
    write(client, case, "hosts/b/DC01", "DC01", rids)
    stored = client.stored()
    assert len(stored) == 300
    assert {s["vhir.host_key"] for s in stored.values()} == {key}


def test_every_record_carries_its_machine_unit_and_own_id():
    case, c12 = new_case()
    client = _Sent()
    ctx = write(client, case, "hosts/WKS01", "WKS01", ["r1"], **{"host.name": "WKS01"})
    (action,) = client.actions
    src = action["_source"]
    assert src["vhir.unit"] == ctx.unit and src["vhir.rid"] == "r1"
    assert action["_id"] == wc.doc_id(src["vhir.host_key"], "r1")
    assert src["host.id"] == "WKS01"


def test_a_record_with_no_host_name_gets_its_units_name():
    case, _ = new_case()
    client = _Sent()
    write(client, case, "hosts/WKS02", "WKS02", ["r1"])
    assert client.actions[0]["_source"]["host.name"] == "WKS02"


def test_each_row_of_a_multi_host_file_gets_its_own_machine():
    case, c12 = new_case()
    client = _Sent()
    ctx = wc.open_unit(case, "extractions/forwarded.csv", "WEC01", source="test")
    with wc.writing(ctx):
        index = wc.index_name("evtx")
        actions = [
            {"_index": index, "_id": str(n), "_source": {"host.name": h}}
            for n, h in enumerate(["SRV1", "SRV2", "SRV3"])
        ]
        _send(client, actions)
    assert [a["_source"]["host.id"] for a in client.actions] == ["SRV1", "SRV2", "SRV3"]
    assert len({a["_source"]["vhir.host_key"] for a in client.actions}) == 3


@pytest.mark.no_case_dirs
def test_a_write_to_a_case_index_with_no_run_open_is_refused():
    with pytest.raises(wc.NoWriteContext):
        bulk.flush_bulk(
            _Sent(), [{"_index": "case-0123456789ab-evtx-0", "_id": "x", "_source": {}}]
        )


@pytest.mark.no_case_dirs
def test_an_ingest_into_a_case_with_no_directory_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "none"))
    host = SimpleNamespace(hostname="H", volume_root=tmp_path, unit_locator="")
    with pytest.raises(wc.NoWriteContext, match="no case directory"):
        wc.host_context(None, "missing-case", host)


# -- ids that survive a rename and tell rebuilt machines apart


def test_a_renamed_machines_rows_keep_their_ids():
    case, _ = new_case()
    client = _Sent()
    ctx = write(client, case, "hosts/WKS01", "WKS01", ["row-1"])
    before = client.actions[0]["_id"]
    key = client.actions[0]["_source"]["vhir.host_key"]
    host_identity.append_decision(
        case, {"action": "rename", "args": {"machine": key, "canonical": "FIN-WS-01"}},
        (case / host_identity.OBSERVATIONS).stat().st_size, door="R",  # as a host rename
    )  # fmt: skip
    again = _Sent()
    ctx._resolved.clear()
    with wc.writing(ctx):
        _send(again, [{"_index": wc.index_name("evtx"), "_id": "row-1", "_source": {}}])
    assert again.actions[0]["_id"] == before
    assert again.actions[0]["_source"]["host.id"] == "FIN-WS-01"


@pytest.mark.parametrize("volatile", [_VOLATILE_KEYS, _PLASO_VOLATILE_KEYS], ids=["csv", "plaso"])
def test_a_content_hash_ignores_the_host_fields(volatile):
    row = {"Path": "C:\\x.exe", "LastModified": "2024-01-01"}
    one = _doc_id("case-0123456789ab-amcache-0", {**row, "host.id": "A", "host.name": "a"},
                  volatile_keys=volatile)  # fmt: skip
    two = _doc_id("case-0123456789ab-amcache-0", {**row, "host.id": "B", "host.name": "b"},
                  volatile_keys=volatile)  # fmt: skip
    assert one == two


def test_an_evtx_record_id_carries_its_time_created(mock_evtx_record):
    from opensearch_mcp import parse_evtx

    records = [
        mock_evtx_record(record_id=7, timestamp="2024-01-01T00:00:00Z"),
        mock_evtx_record(record_id=7, timestamp="2025-06-01T00:00:00Z"),  # a reinstall
        mock_evtx_record(record_id=7, timestamp="2024-01-01T00:00:00Z"),  # the same record
    ]
    parser = MagicMock()
    parser.records_json.return_value = iter(records)
    sent = []
    with (
        patch.object(parse_evtx, "PyEvtxParser", return_value=parser),
        patch.object(
            parse_evtx, "flush_bulk", side_effect=lambda c, a: sent.extend(a) or (len(a), 0)
        ),
    ):
        parse_evtx.parse_and_index(
            evtx_path=Path("/x/Security.evtx"), client=None, index_name="case-0123456789ab-evtx-0",
            source_file="Windows/System32/winevt/Logs/Security.evtx",
        )  # fmt: skip
    ids = [a["_id"] for a in sent]
    assert ids[0] != ids[1] and ids[0] == ids[2]


@pytest.mark.parametrize("module", ["parse_tasks", "parse_wer"])
def test_a_file_at_the_same_path_with_other_bytes_is_another_record(module, tmp_path):
    import importlib

    mod = importlib.import_module(f"opensearch_mcp.{module}")
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"first")
    b.write_bytes(b"second")
    assert mod._file_sha256(a) != mod._file_sha256(b)
    assert mod._file_sha256(a) == mod._file_sha256(a)


def test_two_memory_images_with_one_file_name_never_share_an_id():
    from opensearch_mcp.parse_memory import _vol3_doc_id

    case, _ = new_case()
    rec = {"PID": 4, "ImageFileName": "System", "Offset(V)": 1}
    ids = []
    for where in ("site-a/memory.raw", "site-b/memory.raw"):
        with wc.writing(wc.open_unit(case, where, "H", source="test")):
            ids.append(_vol3_doc_id("case-x-vol-pslist-0", "windows.pslist", rec, where))
    assert ids[0] != ids[1]


def test_a_renamed_case_folder_keeps_image_and_access_log_ids(tmp_path):
    first = tmp_path / "cases" / "acme"
    (first / "evidence").mkdir(parents=True)
    image = first / "evidence" / "disk.E01"
    before = (ingest_cli._image_id("disk", image, first),
              host_identity.unit_locator(first / "evidence" / "access.log", first))  # fmt: skip
    renamed = first.rename(tmp_path / "cases" / "acme-2024")
    after = (ingest_cli._image_id("disk", renamed / "evidence" / "disk.E01", renamed),
             host_identity.unit_locator(renamed / "evidence" / "access.log", renamed))  # fmt: skip
    assert before == after


def test_the_access_log_source_is_case_relative(tmp_path, monkeypatch):
    case, _ = new_case()
    log = case / "evidence" / "access.log"
    log.parent.mkdir()
    log.write_text('10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n')
    seen = {}

    def fake(f, client, index, hostname, **kw):
        seen["source_file"] = kw["source_file"]
        return 1, 0, 0

    for name in (
        "_preflight_shard_capacity",
        "_ensure_case_active",
    ):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "get_client", MagicMock())
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: case.name)
    with patch("opensearch_mcp.parse_accesslog.ingest_accesslog", side_effect=fake):
        ingest_cli.cmd_ingest_accesslog(argparse.Namespace(
            path=str(log), hostname="web01", case=None, time_from=None, time_to=None,
            index_suffix=None, batch_size=1000,
        ))  # fmt: skip
    assert seen["source_file"] == "evidence/access.log"


# -- names


def _winning_template(index: str) -> str:
    best = (-1, "")
    for name, filename in [*mappings._TEMPLATES_REGISTRY, ("evtx", "evtx_ecs_template.json")]:
        body = json.loads((mappings._MAPPINGS_DIR / filename).read_text())
        if any(fnmatch.fnmatchcase(index, p) for p in body["index_patterns"]):
            best = max(best, (body.get("priority", 0), name))
    return best[1]


@pytest.mark.parametrize(
    "prefix,stem,family",
    [("zeek", "ssh", "vhir-delimited"), ("delim", "evtx", "vhir-delimited"),
     ("json", "ssh", "vhir-json"), ("delim", "my-evtx-export", "vhir-delimited")],
)  # fmt: skip
def test_a_per_file_index_takes_its_own_familys_template(prefix, stem, family):
    index = build_index_name("0123456789ab", stem_type(prefix, stem))
    assert _winning_template(index) == family, index


def test_long_names_and_stems_stay_under_the_index_name_limit():
    case, c12 = new_case()
    client = _Sent()
    raw = "H" * 300
    ctx = wc.open_unit(case, "extractions/x.json", raw, source="test")
    with wc.writing(ctx):
        index = wc.index_name(stem_type("json", "s" * 300))
        _send(client, [{"_index": index, "_id": "1", "_source": {}}])
    assert len(index.encode()) <= 255 and raw.lower() not in index
    assert client.actions[0]["_source"]["host.name"] == raw


def test_two_units_never_share_a_hayabusa_staging_file(monkeypatch):
    case, _ = new_case()
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-1")
    one = wc.open_unit(case, "hosts/a/DC01", "DC01", source="test")
    two = wc.open_unit(case, "hosts/b/DC01", "DC01", source="test")
    stems = {ingest.hayabusa_staging_stem(one), ingest.hayabusa_staging_stem(two)}
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-2")
    stems.add(ingest.hayabusa_staging_stem(one))
    assert len(stems) == 3


def test_a_shard_near_its_document_limit_refuses_the_write():
    case, c12 = new_case()
    client = _Sent()
    client.indices.exists.return_value = False
    shard = {
        "routing": {"primary": True},
        "docs": {"count": 1_400_000_000, "deleted": 100_000_001},
    }
    client.indices.stats.return_value = {
        "indices": {f"case-{c12}-evtx-0": {"shards": {"0": [shard]}}}
    }
    with pytest.raises(wc.ShardHeadroom, match="_split"):
        write(client, case, "hosts/A", "A", ["1"])
    body = client.indices.create.call_args.kwargs["body"]
    assert body["settings"]["index"]["number_of_shards"] == 4


# -- reads stay inside the case


@pytest.mark.parametrize(
    "expression",
    ["case-*", "case-*-evtx-*", "case-ffffffffffff-*", "{own}evtx-0,case-other-evtx-wks10"],
)
def test_an_index_outside_the_active_case_is_refused(monkeypatch, expression):
    case, c12 = new_case()
    monkeypatch.setattr(srv, "_get_active_case", lambda: case.name)
    client = MagicMock()
    with patch.object(srv, "_get_os", return_value=client):
        resp = srv.idx_search(query="*", index=expression.format(own=f"case-{c12}-"))
    assert "outside case" in resp["error"], resp
    client.search.assert_not_called()


def test_the_cases_own_indices_are_accepted():
    case, c12 = new_case()
    assert confine(f"case-{c12}-evtx-0", case.name) == f"case-{c12}-evtx-0"


@pytest.mark.parametrize("tool", ["idx_search", "idx_count", "idx_aggregate", "idx_timeline"])
def test_with_no_active_case_reads_are_an_error(monkeypatch, tool):
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    client = MagicMock()
    kwargs = {"field": "host.id"} if tool == "idx_aggregate" else {}
    with patch.object(srv, "_get_os", return_value=client):
        resp = (
            getattr(srv, tool)(query="*", **kwargs)
            if tool != "idx_timeline"
            else srv.idx_timeline()
        )
    assert resp["error"].startswith("No active case"), resp
    client.search.assert_not_called()
    client.count.assert_not_called()


def test_a_scope_is_never_every_case():
    with pytest.raises(CaseScopeError):
        confine("", "")


# -- the AI's host correction is a suggestion


def test_case_host_fix_changes_no_document_and_records_a_suggestion(monkeypatch):
    case, _ = new_case()
    monkeypatch.setattr(srv, "_get_active_case", lambda: case.name)
    client = MagicMock()
    with patch.object(srv, "_get_os", return_value=client):
        resp = srv.case_host_fix("wksn01", "wkstn01")
    assert resp["status"] == "suggested" and resp["docs_updated"] == 0
    client.update_by_query.assert_not_called()
    state = host_identity.load(case)
    assert [(s["raw"], s["canonical"], s["origin"]) for s in state.suggestions] == [
        ("wksn01", "wkstn01", "ai")
    ]
    assert not state.machines


# -- the second-copy notice reaches the status


def test_the_notice_reaches_a_scans_artifact_and_its_status(monkeypatch):
    from opensearch_mcp.results import ArtifactResult, HostResult

    monkeypatch.setattr(
        wc, "SECOND_COPY", {(wc.current().c12, "WKS01", "evtx"): wc.SECOND_COPY_NOTE}
    )
    host = SimpleNamespace(hostname="WKS01")
    hr = HostResult(hostname="WKS01", volume_root="/x")
    hr.artifacts.append(ArtifactResult(artifact="evtx", index="case-0123456789ab-evtx-0"))
    status = [{"hostname": "WKS01", "artifacts": [{"name": "evtx"}]}]
    ingest._add_second_copy_notes(host, 0, hr, status)
    assert hr.artifacts[0].note == wc.SECOND_COPY_NOTE
    assert status[0]["artifacts"][0]["note"] == wc.SECOND_COPY_NOTE


def test_the_notice_reaches_a_background_runs_status(monkeypatch):
    monkeypatch.setattr(
        wc, "SECOND_COPY", {(wc.current().c12, "WKS01", "json-x"): wc.SECOND_COPY_NOTE}
    )
    written = {}
    monkeypatch.setattr(ingest_cli, "write_status", lambda **kw: written.update(kw))
    ingest_cli._write_bg_status("c", "r", "complete", "WKS01", "json", "t0")
    (art,) = written["hosts"][0]["artifacts"]
    assert wc.SECOND_COPY_NOTE in art["note"]


REMOVED_NOTE = "3 reserved identity fields removed from evidence"


def test_the_removal_count_reaches_a_scans_artifact_and_its_status(monkeypatch):
    from opensearch_mcp.results import ArtifactResult, HostResult

    monkeypatch.setattr(wc, "REMOVED", {(wc.current().c12, "WKS01", "evtx"): 3})
    host = SimpleNamespace(hostname="WKS01")
    hr = HostResult(hostname="WKS01", volume_root="/x")
    hr.artifacts.append(ArtifactResult(artifact="evtx", index="case-0123456789ab-evtx-0"))
    status = [{"hostname": "WKS01", "artifacts": [{"name": "evtx"}]}]
    ingest._add_second_copy_notes(host, 0, hr, status)
    assert hr.artifacts[0].note == REMOVED_NOTE
    assert status[0]["artifacts"][0]["note"] == REMOVED_NOTE


def test_the_removal_count_reaches_a_background_runs_status(monkeypatch):
    monkeypatch.setattr(wc, "REMOVED", {(wc.current().c12, "WKS01", "json-x"): 3})
    written = {}
    monkeypatch.setattr(ingest_cli, "write_status", lambda **kw: written.update(kw))
    ingest_cli._write_bg_status("c", "r", "complete", "WKS01", "json", "t0")
    (art,) = written["hosts"][0]["artifacts"]
    assert REMOVED_NOTE in art["note"]


@pytest.mark.no_case_dirs
def test_a_case_folder_without_its_case_yaml_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
    (tmp_path / "half-made").mkdir()  # a folder, but no CASE.yaml
    host = SimpleNamespace(hostname="WKS10", volume_root=tmp_path, unit_locator="")
    with pytest.raises(wc.NoWriteContext, match="no case directory"):
        wc.host_context(None, "half-made", host)


def test_a_scan_of_a_pre_0_7_host_says_it_adds_a_second_copy(tmp_path, monkeypatch):
    """Through the scan's own host loop, not only the helper."""
    from opensearch_mcp.discover import DiscoveredHost

    case, c12 = new_case()
    evtx_dir = tmp_path / "evtx"
    evtx_dir.mkdir()
    (evtx_dir / "Security.evtx").write_bytes(b"x" * 100_000)
    host = DiscoveredHost(hostname="WKS01", volume_root=tmp_path, evtx_dir=evtx_dir)
    monkeypatch.setattr(wc, "SECOND_COPY", {(c12, "WKS01", "evtx"): wc.SECOND_COPY_NOTE})
    with (
        patch.object(ingest, "parse_and_index", return_value=(5, 0, 0)),
        patch.object(ingest, "_safe_count", return_value=0),
        patch.object(ingest, "sha256_file", return_value="abcd"),
        patch.object(ingest, "_write_ingest_manifest"),
    ):
        result = ingest.ingest(
            hosts=[host], client=MagicMock(), audit=MagicMock(), case_id=case.name,
            include={"evtx"}, case_dir=case,
        )  # fmt: skip
    (ar,) = [a for a in result.hosts[0].artifacts if a.artifact == "evtx"]
    assert wc.SECOND_COPY_NOTE in ar.note


# -- a record can't choose its machine; a write mints the case's identity


def test_a_record_carrying_another_units_keys_is_restamped(tmp_path):
    case, _ = new_case()
    client = _Sent()
    forged = {
        "host.id": "DC01",
        "vhir.host_key": "0" * 16,
        "vhir.unit": "1" * 16,
        "vhir.rid": "x",
        "vhir": {"host_key": "2" * 16, "unit": "3" * 16, "prev_ids": ["y"]},
        "host": {"id": "DC09"},
    }
    ctx = wc.open_unit(case, "evidence/x.json", "WKS10", source="test")
    with wc.writing(ctx):
        _send(client, [{"_index": wc.index_name("json-x"), "_id": "r1", "_source": dict(forged)}])
    (action,) = client.actions
    src = action["_source"]
    assert src["vhir.unit"] == ctx.unit and src["vhir.host_key"] not in ("0" * 16, "2" * 16)
    assert "vhir" not in src and "host" not in src
    assert src["vhir.rid"] == "r1" and action["_id"] == wc.doc_id(src["vhir.host_key"], "r1")


def test_machine_fields_given_as_a_list_are_removed_before_the_stamp():
    case, _ = new_case()
    client = _Sent()
    forged = {
        "vhir": [{"host_key": "forged", "unit": "u", "rid": "r", "prev_ids": ["p"]}, {"note": 1}],
        "host": [{"id": "DC09"}],
    }
    ctx = wc.open_unit(case, "evidence/x.json", "WKS10", source="test")
    with wc.writing(ctx):
        _send(client, [{"_index": wc.index_name("json-x"), "_id": "r1", "_source": forged}])
    (action,) = client.actions
    src = action["_source"]
    assert src["vhir"] == [{"note": 1}] and "host" not in src
    assert src["vhir.host_key"] != "forged" and src["host.id"] != "DC09"
    assert action["_id"] == wc.doc_id(src["vhir.host_key"], "r1")


def _values(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _values(v)
    elif isinstance(node, list):
        for v in node:
            yield from _values(v)
    else:
        yield node


def test_machine_fields_at_any_depth_are_removed_and_counted():
    case, _ = new_case()
    client = _Sent()
    forged = {
        "vhir": {
            "a": [[{"host_key": "forged-1"}], [{"keep": 1}]],  # a list in a list
            "b": {"c": {"d": {"e": {"unit": "forged-2"}}}},  # depth 5
            "rid": "forged-3",
        },
        "host": [
            {"os": {"id": "forged-4", "name": "kept"}},
            [{"id": "forged-5"}],
        ],  # dict in list in dict
        "vhir.x.prev_ids": ["forged-6"],  # dotted, deeper than the stamp's own
        "host.name": "WKS10",  # evidence's own name: kept
    }
    ctx = wc.open_unit(case, "evidence/deep.json", "WKS10", source="test")
    with wc.writing(ctx):
        actions = [{"_index": wc.index_name("json-x"), "_id": "r1", "_source": forged}]
        _send(client, actions)
        _send(client, actions)  # a batch sent again removes nothing more
    src = client.actions[-1]["_source"]
    assert not {"forged-1", "forged-2", "forged-3", "forged-4", "forged-5", "forged-6"} & set(
        _values(src)
    )
    assert src["vhir"] == {"a": [[{"keep": 1}]]} and src["host"] == [{"os": {"name": "kept"}}]
    assert src["host.name"] == "WKS10"
    note = wc.removed_note("WKS10", "json-x", ctx.c12)
    assert note == "6 reserved identity fields removed from evidence"


def test_a_batch_sent_again_keeps_its_ids():
    case, _ = new_case()
    client = _Sent()
    ctx = wc.open_unit(case, "hosts/WKS11", "WKS11", source="test")
    actions = [{"_index": None, "_id": "r1", "_source": {}}]
    with wc.writing(ctx):
        actions[0]["_index"] = wc.index_name("evtx")
        _send(client, actions)
        first = actions[0]["_id"]
        _send(client, actions)
    assert actions[0]["_id"] == first and actions[0]["_source"]["vhir.rid"] == "r1"


def test_a_write_mints_the_case_identity_and_names_its_indices_by_it():
    import yaml

    d = wc.case_dir_for(f"noid-{uuid.uuid4().hex[:6]}")
    (d / "CASE.yaml").write_text(f"case_id: {d.name}\n")
    assert wc.case_identity(d)[0] == ""  # nothing derived from the case id
    client = _Sent()
    write(client, d, "hosts/WKS12", "WKS12", ["r1"])
    case_uuid = yaml.safe_load((d / "CASE.yaml").read_text())["case_uuid"]
    assert client.actions[0]["_index"] == f"case-{case_uuid.replace('-', '')[:12]}-evtx-0"


def test_a_failed_read_leaves_the_pre_0_7_import_to_run_again():
    from opensearch_mcp.case_scope import ensure_v1_imported

    d = wc.case_dir_for(f"v1fail-{uuid.uuid4().hex[:6]}")
    (d / "CASE.yaml").write_text(f"case_id: {d.name}\n")
    client = MagicMock()
    client.indices.get.return_value = {f"case-{d.name}-evtx-wks13": {}}
    client.indices.get_mapping.side_effect = ConnectionError("cluster unreachable")
    with pytest.raises(ConnectionError):
        ensure_v1_imported(client, d)
    assert not host_identity.load(d).v1_imported


def test_the_second_copy_notice_is_per_case():
    a, _ = new_case()
    b, _ = new_case()
    ca = wc.open_unit(a, "hosts/WKS14", "WKS14", source="test")
    cb = wc.open_unit(b, "hosts/WKS14", "WKS14", source="test")
    wc.SECOND_COPY[(ca.c12, "WKS14", "evtx")] = wc.SECOND_COPY_NOTE
    try:
        with wc.writing(cb):
            assert wc.second_copy_note("WKS14", "evtx") == ""
        with wc.writing(ca):
            assert wc.second_copy_note("WKS14", "evtx") == wc.SECOND_COPY_NOTE
    finally:
        wc.SECOND_COPY.clear()


def test_a_case_whose_indices_cant_be_listed_still_excludes_every_longer_case_id():
    from opensearch_mcp.case_scope import legacy_expression, scope_of

    case = wc.case_dir_for(f"lst-{uuid.uuid4().hex[:6]}")
    wc.case_dir_for(f"{case.name}-2")  # a longer id beside it

    class Down:
        class indices:  # noqa: N801
            @staticmethod
            def get(**kw):
                raise OSError("cluster unreachable")

    expr = legacy_expression(scope_of(case.name), client=Down())
    assert expr == f"case-{case.name}-*,-case-{case.name}-2-*"


def test_a_second_run_of_a_host_reports_only_its_own_removals():
    case, _ = new_case()
    for run in ("r1", "r2"):  # the same evidence, read again
        forged = {"vhir": {"host_key": "forged-a", "unit": "forged-b"}}
        client = _Sent()
        ctx = wc.open_unit(case, "evidence/again.json", "WKS12", source="test", run_id=run)
        with wc.writing(ctx):
            _send(client, [{"_index": wc.index_name("json-x"), "_id": "r1", "_source": forged}])
    assert wc.removed_note("WKS12", "json-x", ctx.c12) == (
        "2 reserved identity fields removed from evidence"
    )


@pytest.mark.parametrize(
    "partial",
    [
        {"timed_out": True, "_shards": {"failed": 0}},
        {"timed_out": False, "_shards": {"failed": 2}},
    ],
    ids=["timed out", "shards failed"],
)
def test_a_partial_read_leaves_the_pre_0_7_import_to_run_again(partial):
    from opensearch_mcp.case_scope import V1ReadIncomplete, ensure_v1_imported

    d = wc.case_dir_for(f"v1part-{uuid.uuid4().hex[:6]}")
    (d / "CASE.yaml").write_text(f"case_id: {d.name}\n")
    index = f"case-{d.name}-evtx-wks13"
    client = MagicMock()
    client.indices.get.return_value = {index: {}}
    props = {"host": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}}}
    client.indices.get_mapping.return_value = {index: {"mappings": {"properties": props}}}
    page = {"aggregations": {"p": {"buckets": [{"key": {"name": "WKS13", "id": "WKS13"}}]}}}
    client.search.return_value = {**page, **partial}
    with pytest.raises(V1ReadIncomplete, match="runs again next time"):
        ensure_v1_imported(client, d)
    assert not host_identity.load(d).v1_imported  # not finalised on partial pairs
    client.search.return_value = {**page, "timed_out": False, "_shards": {"failed": 0}}
    assert ensure_v1_imported(client, d) is True  # the next run imports it
    assert host_identity.load(d).v1_imported
