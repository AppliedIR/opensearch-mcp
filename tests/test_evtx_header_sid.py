"""An evtx record keeps the SID in its header as `winlog.user.identifier`.

normalize_event never read System/Security@UserID, so the SID the header
carries (often the account the provider ran as) was lost before mapping. It
is now kept, mapped `keyword` by the template, and an index made before the
field was mapped gets the same mapping when the templates are installed. A
record goes in with the SID only where it is mapped `keyword`: elsewhere (the
put refused, an index reopened since) it goes in without it, as before, and
the run says which index and why. The decision comes before the content hash,
so the stored hash covers exactly what is stored.

The clients are fakes; the records are synthetic.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from record_ids_cluster import make_case

from opensearch_mcp import ingest_status, mappings, ops
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest
from opensearch_mcp.ingest_cli import _rebuilt_status_host
from opensearch_mcp.normalize import normalize_event

SID = "S-1-5-21-2838623409-1327563992-2591358621-1220"
FIELD = "winlog.user.identifier"


def _record(security=..., event_data=None):
    system = {
        "EventID": 1040,
        "Channel": "Application",
        "Computer": "RD01",
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:30:00Z"}},
        "Provider": {"#attributes": {"Name": "MsiInstaller"}},
    }
    if security is not ...:
        system["Security"] = security
    return {"Event": {"System": system, "EventData": event_data}}


# --- normalize_event ----------------------------------------------------------


def test_the_header_sid_is_kept():
    doc = normalize_event(_record({"#attributes": {"UserID": SID}}))
    assert doc[FIELD] == SID


@pytest.mark.parametrize(
    "security",
    [..., None, {}, "S-1-5-18", {"#attributes": None}, {"#attributes": {}},
     {"#attributes": {"UserID": ""}}, {"#attributes": {"UserID": 18}}, {"#attributes": "x"}],
    ids=["absent", "null", "empty", "string", "attributes null", "no UserID", "empty UserID",
         "UserID not text", "attributes not an object"],
)  # fmt: skip
def test_no_header_shape_raises_and_a_missing_sid_writes_no_key(security):
    doc = normalize_event(_record(security))
    assert FIELD not in doc
    assert doc["event.code"] == 1040


def test_the_user_name_still_comes_from_the_event_data():
    doc = normalize_event(_record({"#attributes": {"UserID": SID}}, {"TargetUserName": "tdungan"}))
    assert (doc["user.name"], doc[FIELD]) == ("tdungan", SID)
    assert "user.name" not in normalize_event(_record({"#attributes": {"UserID": SID}}))


def test_the_template_maps_it_keyword_without_a_text_form():
    t = json.loads((Path(mappings.__file__).parent / "evtx_ecs_template.json").read_text())
    assert t["template"]["mappings"]["properties"][FIELD] == {"type": "keyword"}


# --- the install's forward map ----------------------------------------------


def _mapping(sid=None):
    props = {"event": {"properties": {"code": {"type": "integer"}}}}
    if sid:
        props["winlog"] = {"properties": {"user": {"properties": {"identifier": sid}}}}
    return {"mappings": {"properties": props}}


def _patch(indices, refuse=()):
    sent = []

    def put(index, body):
        sent.append((index, body))
        if index in refuse:
            raise RuntimeError("illegal_argument_exception: Limit of total fields [61] exceeded")

    c = MagicMock()
    c.indices.get_mapping.return_value = indices
    c.indices.put_mapping.side_effect = put
    with patch.object(mappings, "_low_event_data", return_value=({}, {})):
        return mappings.patch_evtx_indices(c), sent


def test_an_old_index_is_given_the_field_and_one_that_has_it_is_sent_nothing():
    result, sent = _patch({"case-a-evtx-0": _mapping(), "case-b-evtx-0": _mapping(
        {"type": "keyword"})})  # fmt: skip
    assert sent == [("case-a-evtx-0", {"properties": {"winlog": {"properties": {
        "user": {"properties": {"identifier": {"type": "keyword"}}}}}}})]  # fmt: skip
    assert result["patched"] == {"case-a-evtx-0": [FIELD]}
    assert result["unchanged"] == ["case-b-evtx-0"]


def test_a_refused_put_is_named_with_its_error():
    result, _ = _patch({"case-a-evtx-0": _mapping()}, refuse={"case-a-evtx-0"})
    assert result["patched"] == {}
    assert result["failed"] == [{"index": "case-a-evtx-0", "error": (
        "illegal_argument_exception: Limit of total fields [61] exceeded")}]  # fmt: skip


# --- the write: kept where mapped keyword, else dropped before the hash ---------


@pytest.fixture
def write(tmp_path, monkeypatch):
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPPED", {})
    monkeypatch.setattr(wc, "_prepared", set())
    monkeypatch.setattr(mappings, "_INSTALLED", {"status": "ok", "evtx_failed": []})
    calls = []
    monkeypatch.setattr(wc, "prepare_index", lambda c, i: calls.append(("prepare", i)))
    monkeypatch.setattr(wc, "note_second_copy", lambda *a: "")
    case = make_case(tmp_path / "cases", "sid")
    ctx = wc.open_unit(case, "evidence/RD01", "RD01", source="evidence folder")
    monkeypatch.setattr(wc, "_imported", {ctx.case_dir})
    index = f"case-{ctx.c12}-evtx-0"
    kinds: dict[str, object] = {}

    def field_mapping(index, fields):
        calls.append(("read", index))
        kind = kinds.get(index)
        if isinstance(kind, Exception):
            raise kind
        m = {fields: {"mapping": {"identifier": {"type": kind}}}} if kind else {}
        return {index: {"mappings": m}}

    client = MagicMock()
    client.indices.get_field_mapping.side_effect = field_mapping

    def run(*sids, kind="keyword"):
        kinds[index] = kind
        actions = [
            {"_index": index, "_id": f"r{n}", "_source": {"event.code": 1040, "host.name": "RD01",
                                                          **({FIELD: s} if s else {})}}
            for n, s in enumerate(sids)
        ]  # fmt: skip
        with wc.op("aud-1"), wc.writing(ctx):
            wc.stamp_or_refuse(actions, client)
        return [a["_source"] for a in actions]

    run.index, run.calls = index, calls
    wc.set_current(None)
    yield run
    wc.set_current(None)


def _hash_covers_what_is_stored(src):
    return wc.content_hash(src) == src["vhir.content_hash"]


def test_into_an_index_that_maps_it_the_sid_is_stored_under_the_hash(write):
    (src,) = write(SID)
    assert src[FIELD] == SID and _hash_covers_what_is_stored(src)
    without = {k: v for k, v in src.items() if k != FIELD}
    assert wc.content_hash(without) != src["vhir.content_hash"]
    assert write.calls == [("prepare", write.index), ("read", write.index)]
    assert wc.SID_DROPPED == {}


@pytest.mark.parametrize(
    "kind,why",
    [(None, "it isn't mapped"), ("text", "it is mapped text"),
     (RuntimeError("timed out"), "its mapping couldn't be read (timed out)")],
    ids=["not mapped", "mapped text", "read failed"],
)  # fmt: skip
def test_elsewhere_the_record_goes_without_it_and_the_hash_covers_what_is_stored(write, kind, why):
    srcs = write(SID, None, kind=kind)
    assert all(FIELD not in s and _hash_covers_what_is_stored(s) for s in srcs)
    want = f"{write.index}: records went in without {FIELD} (the record header's SID): {why}"
    assert wc.SID_DROPPED == {write.index: want}


def test_a_refused_put_is_the_reason_given(write, monkeypatch):
    err = "illegal_argument_exception: Limit of total fields [61] exceeded"
    monkeypatch.setitem(mappings._INSTALLED, "evtx_failed", [{"index": write.index,
                                                              "error": err}])  # fmt: skip
    (src,) = write(SID, kind=None)
    assert FIELD not in src and _hash_covers_what_is_stored(src)
    assert wc.SID_DROPPED[write.index].endswith(f": the mapping update was refused ({err})")


def test_the_mapping_is_read_after_the_index_is_prepared_and_kept_once_keyword(write):
    write(SID, kind=None)
    write(SID, kind="keyword")
    write(SID, kind="keyword")
    i = write.index
    assert write.calls == [("prepare", i), ("read", i), ("prepare", i), ("read", i),
                           ("prepare", i)]  # fmt: skip
    assert wc.SID_DROPPED == {}


def test_records_without_a_sid_dont_read_the_mapping(write):
    (src,) = write(None, kind=None)
    assert ("read", write.index) not in write.calls and _hash_covers_what_is_stored(src)


# --- the run says so ----------------------------------------------------------


def test_the_evtx_ingest_puts_the_dropped_sid_in_the_runs_status(tmp_path, monkeypatch, capsys):
    """Both routes (MCP and CLI): a warning in idx_ingest_status, and on
    stderr. A note from an earlier run in the process isn't repeated."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "Application.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    host.evtx_dir = evtx
    index = "case-c1-evtx-0"
    note = f"{index}: records went in without {FIELD} (the record header's SID): it isn't mapped"
    monkeypatch.setattr(wc, "SID_DROPPED", {index: "an earlier run's"})

    def parse_and_index(**kw):
        assert index not in wc.SID_DROPPED
        wc.SID_DROPPED[index] = note
        return (500, 0, 0)

    client = MagicMock()
    client.count.side_effect = Exception("no index")
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    with (
        patch("opensearch_mcp.write_context.index_name", return_value=index),
        patch("opensearch_mcp.mappings.evtx_limit_note", return_value=""),
        patch("opensearch_mcp.ingest.parse_and_index", side_effect=parse_and_index),
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
    ):
        ingest(hosts=[host], client=client, audit=audit, case_id="c1",
               reduced_log_names=None, status_pid=os.getpid(),
               status_run_id="run-evtx")  # fmt: skip
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert f"HOST1: {note}" in status.get("warnings", [])
    assert f"NOTE: {note}" in capsys.readouterr().err


def test_a_refused_put_is_in_the_runs_result_and_its_audit_entry(tmp_path, monkeypatch):
    """The result keeps the note (the status after hayabusa is rebuilt from
    it), and the file's ingest_evtx entry names the index and the error."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPPED", {})
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "Application.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    host.evtx_dir = evtx
    index = "case-c1-evtx-0"
    err = "illegal_argument_exception: Limit of total fields [248] has been exceeded"
    monkeypatch.setattr(mappings, "_INSTALLED", {"status": "ok", "evtx_failed": [
        {"index": index, "error": err}]})  # fmt: skip
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    client.indices.get_field_mapping.return_value = {index: {"mappings": {}}}

    def parse_and_index(**kw):
        action = {"_index": index, "_source": {FIELD: SID}}
        assert wc._sid_unmapped(client, [action], "case-") == {index}
        return (500, 0, 0)

    entries = []
    monkeypatch.setattr(ops, "later", lambda audit, aid, tool, summary, *a, **k: entries.append(
        (tool, summary)))  # fmt: skip
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    with (
        patch("opensearch_mcp.write_context.index_name", return_value=index),
        patch("opensearch_mcp.mappings.evtx_limit_note", return_value=""),
        patch("opensearch_mcp.ingest.parse_and_index", side_effect=parse_and_index),
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
    ):
        result = ingest(hosts=[host], client=client, audit=audit, case_id="c1",
                        reduced_log_names=None, status_pid=os.getpid(),
                        status_run_id="run-evtx")  # fmt: skip
    note = (f"{index}: records went in without {FIELD} (the record header's SID): "
            f"the mapping update was refused ({err})")  # fmt: skip
    (ar,) = [a for a in result.hosts[0].artifacts if a.artifact == "evtx"]
    assert ar.note == note
    assert _rebuilt_status_host(result.hosts[0])["artifacts"][0]["note"] == note
    assert [s for t, s in entries if t == "ingest_evtx"] == [f"500 indexed, 0 skipped; {note}"]
