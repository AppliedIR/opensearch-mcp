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


LIMIT = "illegal_argument_exception: Limit of total fields [61] exceeded"
SID_PUT = {"properties": {"winlog": {"properties": {
    "user": {"properties": {"identifier": {"type": "keyword"}}}}}}}  # fmt: skip


def _patch(indices, refuse=(), low=({}, {})):
    """patch_evtx_indices over `indices`; the SID put to one in `refuse` is
    refused at its field limit. `low` is what _low_event_data finds."""
    sent = []

    def put(index, body):
        sent.append((index, body))
        if index in refuse and body == SID_PUT:
            raise RuntimeError(LIMIT)

    c = MagicMock()
    c.indices.get_mapping.return_value = indices
    c.indices.put_mapping.side_effect = put
    with patch.object(mappings, "_low_event_data", return_value=low):
        return mappings.patch_evtx_indices(c), sent


def test_an_old_index_is_given_the_field_and_one_that_has_it_is_sent_nothing():
    result, sent = _patch({"case-a-evtx-0": _mapping(), "case-b-evtx-0": _mapping(
        {"type": "keyword"})})  # fmt: skip
    assert sent == [("case-a-evtx-0", SID_PUT)]
    assert result["patched"] == {"case-a-evtx-0": [FIELD]}
    assert result["unchanged"] == ["case-b-evtx-0"]


def test_a_refused_put_is_named_with_its_error_and_its_field():
    result, _ = _patch({"case-a-evtx-0": _mapping()}, refuse={"case-a-evtx-0"})
    assert result["patched"] == {}
    assert result["failed"] == [{"index": "case-a-evtx-0", "error": LIMIT, "field": FIELD}]


def test_a_refused_sid_put_never_costs_the_raise_which_goes_first_as_base_sent_it():
    """The event-data raise is its own put, the body base sent, before the
    SID's: the SID's refusal leaves it applied."""
    props = {"Payload": {"type": "keyword", "ignore_above": 8191}}
    low = ({"winlog.event_data.Payload"}, props)
    result, sent = _patch({"case-a-evtx-0": _mapping()}, refuse={"case-a-evtx-0"}, low=low)
    raise_put = {"properties": {"winlog": {"properties": {"event_data": {"properties": props}}}}}
    assert sent == [("case-a-evtx-0", raise_put), ("case-a-evtx-0", SID_PUT)]
    assert result["patched"] == {"case-a-evtx-0": ["winlog.event_data.Payload"]}
    assert result["failed"] == [{"index": "case-a-evtx-0", "error": LIMIT, "field": FIELD}]


# --- the write: kept where mapped keyword, else dropped before the hash ---------


@pytest.fixture
def write(request, tmp_path, monkeypatch):
    """stamp_or_refuse over a batch into one evtx index of a new case; each
    record is the native parser's (it carries the header marker) unless
    `header` says otherwise. The install has run ok, unless the row runs the
    real one (`@pytest.mark.template_install`)."""
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPS", [])
    monkeypatch.setattr(wc, "_prepared", set())
    if not request.node.get_closest_marker("template_install"):
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

    def run(*sids, kind="keyword", header=True, extra=None):
        kinds[index] = kind
        marks = header if isinstance(header, (list, tuple)) else [header] * len(sids)
        actions = [
            {"_index": index, "_id": f"r{n}", "_source": {"event.code": 1040, "host.name": "RD01",
                                                          **({FIELD: s} if s else {}),
                                                          **(extra or {})},
             **({wc.HEADER_SID_KEY: True} if marks[n] else {})}
            for n, s in enumerate(sids)
        ]  # fmt: skip
        with wc.op("aud-1"), wc.writing(ctx):
            wc.stamp_or_refuse(actions, client)
        run.sent = actions
        return [a["_source"] for a in actions]

    run.index, run.calls, run.unit = index, calls, ctx.unit
    wc.set_current(None)
    yield run
    wc.set_current(None)


def _hash_covers_what_is_stored(src):
    return wc.content_hash(src) == src["vhir.content_hash"]


def _note(index, why):
    return f"{index}: records went in without {FIELD} (the record header's SID): {why}"


def test_into_an_index_that_maps_it_the_sid_is_stored_under_the_hash(write):
    (src,) = write(SID)
    assert src[FIELD] == SID and _hash_covers_what_is_stored(src)
    without = {k: v for k, v in src.items() if k != FIELD}
    assert wc.content_hash(without) != src["vhir.content_hash"]
    assert write.calls == [("prepare", write.index), ("read", write.index)]
    assert wc.SID_DROPS == []
    assert all(wc.HEADER_SID_KEY not in a for a in write.sent)  # the marker is never sent


@pytest.mark.parametrize(
    "kind,why",
    [(None, "it isn't mapped"), ("text", "it is mapped text"),
     (RuntimeError("timed out"), "its mapping couldn't be read (timed out)")],
    ids=["not mapped", "mapped text", "read failed"],
)  # fmt: skip
def test_elsewhere_the_record_goes_without_it_and_the_hash_covers_what_is_stored(write, kind, why):
    srcs = write(SID, None, kind=kind)
    assert all(FIELD not in s and _hash_covers_what_is_stored(s) for s in srcs)
    assert wc.sid_note(write.index, write.unit) == _note(write.index, why)


def test_a_refused_put_is_the_reason_given(write, monkeypatch):
    refused = {"index": write.index, "error": LIMIT, "field": FIELD}
    monkeypatch.setitem(mappings._INSTALLED, "evtx_failed", [refused])
    (src,) = write(SID, kind=None)
    assert FIELD not in src and _hash_covers_what_is_stored(src)
    assert wc.sid_note(write.index, write.unit) == _note(
        write.index, f"the mapping update was refused ({LIMIT})")  # fmt: skip


def test_the_mapping_is_read_after_the_index_is_prepared_and_kept_once_keyword(write):
    write(SID, kind=None)
    write(SID, kind="keyword")
    write(SID, kind="keyword")
    i = write.index
    assert write.calls == [("prepare", i), ("read", i), ("prepare", i), ("read", i),
                           ("prepare", i)]  # fmt: skip
    # the first batch's drop stays named: a later keyword read doesn't erase it
    assert wc.sid_note(i, write.unit) == _note(i, "it isn't mapped")


def test_records_without_a_sid_dont_read_the_mapping(write):
    (src,) = write(None, kind=None)
    assert ("read", write.index) not in write.calls and _hash_covers_what_is_stored(src)


# --- only the native evtx parser's records carry the header SID ------------------


@pytest.mark.parametrize("extra", [None, {"vhir.parse_method": "pyevtx-rs"}],
                         ids=["plain", "names the native parser"])  # fmt: skip
def test_another_writers_field_is_kept_as_sent_and_the_mapping_isnt_read(write, extra):
    """A CSV or JSON record of that name, into the same evtx index (a column
    or key may name the native parser), keeps it, as at base."""
    srcs = write(SID, SID, kind=None, header=False, extra=extra)
    assert all(s[FIELD] == SID and _hash_covers_what_is_stored(s) for s in srcs)
    assert ("read", write.index) not in write.calls
    assert wc.SID_DROPS == [] and wc.sid_note(write.index, write.unit) == ""


def test_in_a_mixed_batch_only_the_parsers_records_go_without_it(write):
    srcs = write(SID, SID, kind=None, header=[True, False])
    assert FIELD not in srcs[0] and srcs[1][FIELD] == SID
    assert all(_hash_covers_what_is_stored(s) for s in srcs)
    assert all(wc.HEADER_SID_KEY not in a for a in write.sent)


# --- every drop of a run is named, with every cause ------------------------------


def test_every_cause_of_an_indexs_drops_is_named_in_the_order_they_happened(write):
    write(SID, kind=RuntimeError("timed out"))
    write(SID, kind=None)
    write(SID, kind=None)
    assert wc.sid_note(write.index, write.unit) == _note(
        write.index, "its mapping couldn't be read (timed out); then it isn't mapped")  # fmt: skip


def test_a_note_names_only_its_own_units_drops(write):
    write(SID, kind=None)
    assert wc.sid_note(write.index, "another-unit") == ""


# --- the note names the install's real cause -------------------------------------


@pytest.mark.parametrize(
    "installed,why",
    [({"status": "partial", "evtx_failed": [
        {"index": "case-*-evtx-*", "error": "ConnectionTimeout: read timed out"}]},
      "the install couldn't read the evtx mappings to add it (ConnectionTimeout: read timed out)"),
     ({"status": "error", "error": "Existing default_pipeline 'ops' already bound"},
      "the install's forward map didn't run (Existing default_pipeline 'ops' already bound)"),
     ({"status": "partial", "evtx_failed": [{"index": "{index}", "error": "illegal_argument"}]},
      "it isn't mapped")],
    ids=["mappings unread", "early return", "a refused raise isn't the SID's"],
)  # fmt: skip
def test_an_unmapped_index_names_the_installs_reason(write, monkeypatch, installed, why):
    for f in installed.get("evtx_failed", []):
        f["index"] = f["index"].format(index=write.index)
    monkeypatch.setattr(mappings, "_INSTALLED", installed)
    write(SID, kind=None)
    assert wc.sid_note(write.index, write.unit) == _note(write.index, why)


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
    note = _note(index, "it isn't mapped")
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPS", [])
    wc.SID_DROPS.append((wc.current().unit, index, "an earlier run's"))

    def parse_and_index(**kw):
        assert wc.SID_DROPS == []  # the run's own
        action = {"_index": index, "_source": {FIELD: SID}}
        assert wc._sid_unmapped(client, [action], "case-", [True], wc.current().unit) == {index}
        return (500, 0, 0)

    client = MagicMock()
    client.count.side_effect = Exception("no index")
    client.indices.get_field_mapping.return_value = {index: {"mappings": {}}}
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
    monkeypatch.setattr(wc, "SID_DROPS", [])
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "Application.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    host.evtx_dir = evtx
    index = "case-c1-evtx-0"
    err = "illegal_argument_exception: Limit of total fields [248] has been exceeded"
    monkeypatch.setattr(mappings, "_INSTALLED", {"status": "partial", "evtx_failed": [
        {"index": index, "error": err, "field": FIELD}]})  # fmt: skip
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    client.indices.get_field_mapping.return_value = {index: {"mappings": {}}}

    def parse_and_index(**kw):
        action = {"_index": index, "_source": {FIELD: SID}}
        assert wc._sid_unmapped(client, [action], "case-", [True], wc.current().unit) == {index}
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


def _two_files(tmp_path, monkeypatch, fails=None, cut_fails=False):
    """Two files of one host into one index: the first file parsed has its
    records go in without the SID (it isn't mapped), the second finds the field
    mapped. File `fails` fails after its flush; with `cut_fails`, file 0 fails
    in its truncation check, before its parse. Returns the files'
    ingest_evtx summaries."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPS", [])
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    for name in ("Application.evtx", "System.evtx"):
        (evtx / name).write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    host.evtx_dir = evtx
    index = "case-c1-evtx-0"
    kinds = iter([None, "keyword"])
    files = iter(range(2))
    client = MagicMock()
    client.count.side_effect = Exception("no index")

    def parse_and_index(**kw):
        n, kind = next(files), next(kinds)
        mapping = {FIELD: {"mapping": {"identifier": {"type": kind}}}} if kind else {}
        client.indices.get_field_mapping.return_value = {index: {"mappings": mapping}}
        action = {"_index": index, "_source": {FIELD: SID}}
        dropped = wc._sid_unmapped(client, [action], "case-", [True], wc.current().unit)
        if n == fails:
            raise OSError("the file broke after its first flush")
        return (500, 0, 0) if dropped else (7, 0, 0)

    cuts = iter(range(2))

    def evtx_truncation(path):
        if next(cuts) == 0 and cut_fails:
            raise OSError("the truncation check failed")
        return []

    entries = []
    monkeypatch.setattr(ops, "later", lambda audit, aid, tool, summary, *a, **k: entries.append(
        (tool, summary)))  # fmt: skip
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    with (
        patch("opensearch_mcp.write_context.index_name", return_value=index),
        patch("opensearch_mcp.mappings.evtx_limit_note", return_value=""),
        patch("opensearch_mcp.ingest.parse_and_index", side_effect=parse_and_index),
        patch("opensearch_mcp.ingest.evtx_truncation", side_effect=evtx_truncation),
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
    ):
        ingest(hosts=[host], client=client, audit=audit, case_id="c1",
               reduced_log_names=None, status_pid=os.getpid(),
               status_run_id="run-evtx")  # fmt: skip
    return [s for t, s in entries if t == "ingest_evtx"]


def test_a_file_that_fails_after_a_dropping_flush_names_the_drop_in_its_audit(
    tmp_path, monkeypatch
):
    note = _note("case-c1-evtx-0", "it isn't mapped")
    assert _two_files(tmp_path, monkeypatch, fails=0) == [
        f"FAILED: the file broke after its first flush; {note}",
        "7 indexed, 0 skipped",
    ]


def test_a_files_audit_names_only_the_drops_of_that_file(tmp_path, monkeypatch):
    note = _note("case-c1-evtx-0", "it isn't mapped")
    assert _two_files(tmp_path, monkeypatch) == [
        f"500 indexed, 0 skipped; {note}",
        "7 indexed, 0 skipped",
    ]


def test_a_file_that_fails_after_an_earlier_files_drop_names_no_drop_in_its_audit(
    tmp_path, monkeypatch
):
    note = _note("case-c1-evtx-0", "it isn't mapped")
    assert _two_files(tmp_path, monkeypatch, fails=1) == [
        f"500 indexed, 0 skipped; {note}",
        "FAILED: the file broke after its first flush",
    ]


def test_a_file_that_fails_before_its_parse_is_audited_and_the_next_file_runs(
    tmp_path, monkeypatch
):
    note = _note("case-c1-evtx-0", "it isn't mapped")
    assert _two_files(tmp_path, monkeypatch, cut_fails=True) == [
        "FAILED: the truncation check failed",
        f"500 indexed, 0 skipped; {note}",
    ]


# --- per process: the drop record and the install's account are a run's own -----

UUID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def acme(tmp_path, monkeypatch):
    d = tmp_path / "acme"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(f"case_id: acme\ncase_uuid: {UUID}\n")
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return d


def _ingest_one(case, client, name, sent):
    """One ingest() of HOST1's `name` alone: the real parser loop over three
    records whose header carries SID, and the real bulk path into `sent`."""
    from sift_common.audit import AuditWriter

    from opensearch_mcp import bulk

    evtx = case.parent / "HOST1" / "evtx"
    evtx.mkdir(parents=True, exist_ok=True)
    for old in evtx.iterdir():
        old.unlink()
    (evtx / name).write_bytes(b"\1" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=evtx.parent, evtx_dir=evtx)
    parser = MagicMock()
    parser.records_json.return_value = [
        {"event_record_id": n, "timestamp": f"2024-01-15T10:30:0{n}Z",
         "data": json.dumps(_record({"#attributes": {"UserID": SID}}))}
        for n in range(3)
    ]  # fmt: skip

    def bulk_into(client, actions, **kw):
        actions = list(actions)
        sent.extend(json.loads(json.dumps(a)) for a in actions)
        return len(actions), []

    with (
        patch("opensearch_mcp.parse_evtx.PyEvtxParser", return_value=parser),
        patch.object(bulk.helpers, "bulk", side_effect=bulk_into),
        patch("opensearch_mcp.ingest.evtx_truncation", return_value=[]),
        patch("opensearch_mcp.ingest._write_ingest_manifest"),
        patch("opensearch_mcp.ingest_status._STATUS_DIR", case / "status"),
        patch("opensearch_mcp.mappings.evtx_limit_note", return_value=""),
    ):
        result = ingest(hosts=[host], client=client,
                        audit=AuditWriter(mcp_name="opensearch-ingest-1"), case_id="acme",
                        include={"evtx"}, status_pid=os.getpid(),
                        status_run_id=f"run-{name}", case_dir=case)  # fmt: skip
    (ar,) = [a for a in result.hosts[0].artifacts if a.artifact == "evtx"]
    return ar


def _file_summaries(case, name):
    """The result summaries of the ingest_evtx entries about `name`'s step."""
    entries = []
    for f in sorted((case / "audit").glob("*.jsonl")):
        entries += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    steps = {
        e["audit_id"]
        for e in entries
        if e["tool"] == "ingest_evtx"
        and "about" not in e
        and any(str(i.get("path", "")).endswith(name) for i in e.get("inputs") or [])
    }
    out = []
    for e in entries:
        if e["tool"] == "ingest_evtx" and e.get("about") in steps:
            s = e["result_summary"]
            out.append(s["value"] if isinstance(s, dict) else s)
    return out


def test_a_clean_run_after_a_run_that_dropped_says_nothing_of_the_earlier_drop(acme, monkeypatch):
    """Two ingest() runs in one process, as two runs of one ingest child
    (the drop record and keyword cache start empty here, as a new child's
    do; nothing is reset between the runs). Run 1 can't read the mapping;
    run 2 reads it keyword and its records go in with the SID: its result,
    status note and file entry name no drop."""
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPS", [])
    monkeypatch.setattr(wc, "prepare_index", lambda client, index: None)
    monkeypatch.setattr(wc, "note_second_copy", lambda client, ctx, index: None)
    monkeypatch.setattr(wc, "_imported", {acme})
    answer = {"kind": RuntimeError("ConnectionTimeout: read timed out")}

    def field_mapping(index, fields):
        if isinstance(answer["kind"], Exception):
            raise answer["kind"]
        return {index: {"mappings": {fields: {"mapping": {"identifier": {"type": "keyword"}}}}}}

    client = MagicMock()
    client.count.side_effect = Exception("no index")
    client.indices.get_field_mapping.side_effect = field_mapping
    sent1, sent2 = [], []
    ar1 = _ingest_one(acme, client, "System.evtx", sent1)
    assert "its mapping couldn't be read (ConnectionTimeout: read timed out)" in ar1.note
    assert sent1 and all(FIELD not in a["_source"] for a in sent1)

    answer["kind"] = "keyword"
    ar2 = _ingest_one(acme, client, "Application.evtx", sent2)
    assert FIELD not in ar2.note, ar2.note
    assert (ar2.indexed, ar2.bulk_failed) == (3, 0)
    assert [a["_source"][FIELD] for a in sent2] == [SID] * 3
    assert _file_summaries(acme, "Application.evtx") == ["3 indexed, 0 skipped"]


class _FieldLimit:
    """test_evtx_long_fields' cluster: its evtx read fails while `unread` is
    set, and an index in `full` refuses the SID's put at its field limit."""

    def __init__(self, indices, full=()):
        from test_evtx_long_fields import _Cluster

        self.cluster = _Cluster(indices)
        self.full, self.unread = set(full), None
        real_get, real_put = self.cluster.get_mapping, self.cluster.put_mapping

        def get_mapping(index="", **kw):
            if self.unread and index == mappings._TEMPLATE_PATTERN:
                raise self.unread
            return real_get(index=index, **kw)

        def put_mapping(index, body):
            if index in self.full and body == SID_PUT:
                raise RuntimeError(LIMIT)
            return real_put(index, body)

        self.cluster.get_mapping, self.cluster.put_mapping = get_mapping, put_mapping

    def client(self):
        return self.cluster.client()


@pytest.mark.template_install
def test_a_new_childs_clean_install_names_its_own_refusal_not_an_earlier_read_error(
    acme, monkeypatch
):
    """In one process, each drop by an ingest() run. Install 1
    (ensure_installed_once) can't read the evtx mappings, and run 1's drop
    names that. A new ingest child then starts: its install record, drop
    record and keyword cache start empty (reset here as a new child's are).
    Its install reads cleanly and the SID's put is refused at the field
    limit: run 2's drop names the refusal, and not the earlier read error."""
    from test_evtx_long_fields import _index_064

    index = f"case-{UUID[:12]}-evtx-0"
    monkeypatch.setattr(mappings, "_INSTALLED", None)
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    monkeypatch.setattr(wc, "SID_DROPS", [])
    monkeypatch.setattr(wc, "prepare_index", lambda client, index: None)
    monkeypatch.setattr(wc, "note_second_copy", lambda client, ctx, index: None)
    monkeypatch.setattr(wc, "_imported", {acme})
    cluster = _FieldLimit({index: _index_064()}, full={index})

    def client():
        c = cluster.client()
        c.count.side_effect = Exception("no index")

        def field_mapping(index, fields):  # what the cluster holds for the SID
            m = cluster.cluster.state[index]["mappings"].get("properties", {})
            got = m.get("winlog", {}).get("properties", {}).get("user", {})
            got = got.get("properties", {}).get("identifier")
            return {index: {"mappings": {fields: {"mapping": {"identifier": got}}} if got else {}}}

        c.indices.get_field_mapping.side_effect = field_mapping
        return c

    cluster.unread = RuntimeError("ConnectionTimeout: read timed out")
    c1 = client()
    first = mappings.ensure_installed_once(c1)
    assert {"index": mappings._TEMPLATE_PATTERN,
            "error": "ConnectionTimeout: read timed out"} in first["evtx_failed"]  # fmt: skip
    sent1, sent2 = [], []
    ar1 = _ingest_one(acme, c1, "System.evtx", sent1)
    assert ar1.note == _note(index, (
        "the install couldn't read the evtx mappings to add it "
        "(ConnectionTimeout: read timed out)"))  # fmt: skip
    assert sent1 and all(FIELD not in a["_source"] for a in sent1)

    monkeypatch.setattr(mappings, "_INSTALLED", None)  # a new child
    monkeypatch.setattr(wc, "SID_DROPS", [])
    monkeypatch.setattr(wc, "_SID_KEYWORD", set())
    cluster.unread = None
    c2 = client()
    second = mappings.ensure_installed_once(c2)
    assert second["evtx_failed"] == [{"index": index, "error": LIMIT, "field": FIELD}]
    ar2 = _ingest_one(acme, c2, "Application.evtx", sent2)
    assert ar2.note == _note(index, f"the mapping update was refused ({LIMIT})")
    assert (ar2.indexed, ar2.bulk_failed) == (3, 0)
    assert sent2 and all(FIELD not in a["_source"] for a in sent2)
