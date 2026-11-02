"""A term with no field named searches an evtx index's declared fields.

OpenSearch's default for such a term is every field, and it fails past 1,024
of them: real event data reaches that. The evtx template now copies every
event-data value into one field, winlog.event_data_all, and names the fields
an unfielded term searches: every field it declares. An index made before
keeps its shape; a query that fails there names its fix.

- (a) The installed template: its fields, lenient, the dates rule before the
  strings rule; a field added to the template file is searched with no other
  edit.
- (b) What repairs a query too many fields or clauses failed, said by the
  error (every shard failed) and by the partial answer (some did). A search
  failure is a `Query error:` only when OpenSearch's status blames the query
  (400, 500, or too many buckets at any status); any other raises as it was.
  idx_search's docstring says a comparison needs a field.
- (c) idx_search sorts on _score and _doc as they are, not as fields.
- (d) The install raises an old index's own rule's limit and nothing else.
- (e) What parse_evtx writes, a batch sent again included: every key is a
  declared field or event data, and none is vhir.id_scheme. VHIR_TEST_EVTX
  (evtx paths, os.pathsep-separated) names real logs; synthetic records run
  always.

The clients are stand-ins; the failure bodies are OpenSearch 3.5.0's, measured.
"""

from __future__ import annotations

import copy
import json
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from opensearchpy.exceptions import RequestError, TransportError
from test_evtx_long_fields import _Cluster, _index_064, kw, rule
from test_partial_shard_answers import Cluster, failures, run, tools  # noqa: F401 (fixture)

from opensearch_mcp import bulk, mappings, parse_evtx
from opensearch_mcp import write_context as wc

TEMPLATE = Path(mappings.__file__).parent / "evtx_ecs_template.json"
ALL, DATES_ALL = "winlog.event_data_all", "winlog.event_data_dates_all"
DATE_FORMAT = "strict_date_optional_time||yyyy/MM/dd HH:mm:ss||yyyy/MM/dd||epoch_millis"
DATES_MAP = {"type": "date", "format": DATE_FORMAT, "ignore_malformed": True, "doc_values": False}
DATES, STRINGS = "winlog_event_data_dates", "winlog_event_data_strings"


def _paths(props: dict, prefix: str = "") -> list[str]:
    """Every field `props` maps, dotted, with its multi-fields."""
    out = []
    for name, m in props.items():
        if isinstance(m.get("properties"), dict):
            out += _paths(m["properties"], f"{prefix}{name}.")
        else:
            out += [prefix + name, *(f"{prefix}{name}.{f}" for f in m.get("fields") or {})]
    return out


def _installed(client=None) -> dict:
    """The vhir-evtx-ecs body the install PUTs."""
    client = client or _Cluster({}).client()
    mappings.ensure_winlog_pipeline(client)
    (body,) = [c.kwargs["body"] for c in client.indices.put_index_template.call_args_list
               if c.kwargs["name"] == "vhir-evtx-ecs"]  # fmt: skip
    return body["template"]


# --- (a) The installed template ----------------------------------------------


def test_an_unfielded_term_searches_every_declared_field_and_the_catch_all():
    tpl = _installed()
    listed = tpl["settings"]["index.query.default_field"]
    shipped = json.loads(TEMPLATE.read_text())["template"]["mappings"]["properties"]
    assert sorted(listed) == sorted(_paths({**shipped, **mappings.HOST_KEY_FIELDS}))
    assert len(listed) == len(set(listed))
    # index: false (vhir.rid), a multi-field, the catch-all; no stamp key evtx never gets
    assert {"vhir.rid", "process.command_line.keyword", ALL, DATES_ALL} <= set(listed)
    assert "vhir.id_scheme" not in listed
    assert tpl["settings"]["index.query_string.lenient"] is True
    assert tpl["mappings"]["properties"][ALL] == {**kw(8191), "doc_values": False}
    assert tpl["mappings"]["properties"][DATES_ALL] == DATES_MAP


def test_the_dates_rule_comes_before_the_strings_rule_and_both_copy():
    rules = _installed()["mappings"]["dynamic_templates"]
    assert [list(e)[0] for e in rules] == [DATES, STRINGS]
    dates, strings = rules[0][DATES], rules[1][STRINGS]
    assert dates["match_mapping_type"] == "date"
    assert dates["mapping"] == {"type": "date", "copy_to": [ALL, DATES_ALL]}
    assert strings["mapping"] == {**kw(8191), "copy_to": ALL}


def test_a_field_added_to_the_template_file_is_searched_with_no_other_edit(tmp_path, monkeypatch):
    body = json.loads(TEMPLATE.read_text())
    body["template"]["mappings"]["properties"]["winlog.new_field"] = {
        "type": "keyword", "fields": {"text": {"type": "text"}}}  # fmt: skip
    path = tmp_path / TEMPLATE.name
    path.write_text(json.dumps(body))
    monkeypatch.setattr(mappings, "_EVTX_TEMPLATE_FILE", path)
    listed = _installed()["settings"]["index.query.default_field"]
    assert {"winlog.new_field", "winlog.new_field.text"} <= set(listed)


# --- (b) Repairs: every shard failed (raise), some did (partial) ---------------

EVTX = "case-acac00000001-evtx-0"
EXPANSION = ("failed to create query: field expansion for [*] matches too many fields, "
             "limit: 1024, got: 3346")  # fmt: skip
# a field pattern the AI named, escaped (unescaped, `winlog.event_data.*:x` is a parse error)
PATTERN = ("failed to create query: field expansion for [winlog.event_data.*] matches too "
           "many fields, limit: 1024, got: 3305")  # fmt: skip
NESTED = "Query contains too many nested clauses; maxClauseCount is set to 1024"
EXPANDED = (
    "; a term with no field named, or a field pattern, expanded to more fields than that "
    "index allows: name one field (field:value; in evtx, winlog.event_data.<Name>:<value>)"
)
REPAIR = {
    "expansion": EXPANDED,
    "pattern": EXPANDED,
    "nested": (
        "; the query expanded past OpenSearch's clause limit: name the fields, or quote a "
        "path or URL (a /.../ is read as a regular expression)"
    ),
}
REASON = {"expansion": EXPANSION, "pattern": PATTERN, "nested": NESTED}
QUERY = {"expansion": "*mimikatz*", "pattern": r"winlog.event_data.\*:x", "nested": "*mimikatz*"}


def _all_failed(kind: str) -> TransportError:
    """The error each failure raises when every shard fails: a 400 whose root
    cause names the index (expansion, pattern), a 500 whose root cause doesn't
    (nested)."""
    if kind in ("expansion", "pattern"):
        cause = {"type": "query_shard_exception", "reason": REASON[kind], "index": EVTX}
        status, cls = 400, RequestError
    else:
        cause = {"type": "too_many_nested_clauses", "reason": NESTED}
        status, cls = 500, TransportError
    shard = {"shard": 0, "index": EVTX, "node": "n1", "reason": cause}
    info = {"error": {"root_cause": [cause], "type": "search_phase_execution_exception",
                      "reason": "all shards failed", "phase": "query", "grouped": True,
                      "failed_shards": [shard], "caused_by": {**cause, "caused_by": cause}},
            "status": status}  # fmt: skip
    return cls(status, "search_phase_execution_exception", info)


class _Failing(Cluster):
    def __init__(self, error):
        super().__init__({"total": 4, "successful": 4, "skipped": 0, "failed": 0})
        self.error = error

    def search(self, index=None, body=None, **kw):
        raise self.error

    count = search


@pytest.mark.parametrize("kind", list(REPAIR))
@pytest.mark.parametrize("tool", sorted(tools()))
def test_a_query_every_shard_failed_says_its_repair(run, tool, kind):  # noqa: F811
    with pytest.raises(ValueError) as e:
        run(_Failing(_all_failed(kind)), tool, **tools(QUERY[kind], index=EVTX)[tool])
    where = f" ({EVTX})" if kind != "nested" else ""  # the root cause's own index
    said = f"Query error: all shards failed: {REASON[kind]}{where} ({EVTX}{REPAIR[kind]})"
    assert str(e.value) == said
    assert "include_fields" not in str(e.value)


@pytest.mark.parametrize("kind", list(REPAIR))
@pytest.mark.parametrize("tool", sorted(tools()))
def test_a_query_some_shards_failed_says_its_repair(run, tool, kind):  # noqa: F811
    reason = REASON[kind]
    cls = "too_many_nested_clauses" if kind == "nested" else "query_shard_exception"
    shards = {"total": 5, "successful": 1, "skipped": 0, "failed": 4,
              "failures": failures(EVTX, reason, cls)}  # fmt: skip
    reply = run(Cluster(shards), tool, **tools(QUERY[kind])[tool])
    assert reply["partial"] is True and reply["failed_indices"] == [EVTX]
    assert f"{EVTX}: {reason}{REPAIR[kind]}" in reply["partial_warning"]
    assert "include_fields" not in reply["partial_warning"]


def test_another_server_error_is_raised_as_it_was(run):  # noqa: F811
    error = TransportError(503, "unavailable_shards_exception", {})
    with pytest.raises(TransportError):
        run(_Failing(error), "idx_search", query="x", index=EVTX)


BUCKETS = ("Trying to create too many buckets. Must be less than or equal to: [65535] but "
           "was [70000]. This limit can be set by changing the [search.max_buckets] cluster "
           "level setting.")  # fmt: skip
INTERVAL = "; use a larger interval or a shorter time window (time_from/time_to)"
WINDOW = ("Result window is too large, from + size must be less than or equal to: [10000] "
          "but was [20010]. See the scroll api for a more efficient way to request large data "
          "sets. This limit can be set by changing the [index.max_result_window] index level "
          "parameter.")  # fmt: skip
BREAKER = ("[parent] Data too large, data for [<http_request>] would be [1031798784/984mb], "
           "which is larger than the limit of [1020054732/972.7mb]")  # fmt: skip


STATE = {"type": "illegal_state_exception", "reason": "unexpected state"}


def _search_failed(status: int, *causes: dict, caused_by: dict | None = None, reason=None):
    """A search_phase_execution_exception at `status`: its root causes, a
    failed shard for each, and its caused_by (the first cause unless given)."""
    shards = [{"shard": 0, "index": EVTX, "node": "n1", "reason": c} for c in causes]
    error = {"root_cause": list(causes), "type": "search_phase_execution_exception",
             "reason": "all shards failed" if reason is None else reason, "phase": "query",
             "grouped": True, "failed_shards": shards}  # fmt: skip
    if caused_by or causes:
        error["caused_by"] = caused_by or causes[0]
    cls = RequestError if status == 400 else TransportError
    return cls(status, "search_phase_execution_exception", {"error": error, "status": status})


# OpenSearch's status says whose fault a failed search is: the query's (400, 500,
# or too many buckets, which it answers as a 503), or the cluster's (no shard, a breaker)
@pytest.mark.parametrize(
    "error, said",
    [
        (_search_failed(400, {"type": "illegal_argument_exception", "reason": WINDOW}),
         f"Query error: all shards failed: {WINDOW}"),
        (_search_failed(500, {"type": "illegal_state_exception", "reason": "unexpected state"}),
         "Query error: all shards failed: unexpected state"),
        # no top-level reason: the root cause's alone, with its index
        (_search_failed(500, {**STATE, "index": EVTX}, reason=""),
         f"Query error: unexpected state ({EVTX})"),
        (_search_failed(503, caused_by={"type": "too_many_buckets_exception", "reason": BUCKETS,
                                        "max_buckets": 65535}, reason=""),
         f"Query error: {BUCKETS}{INTERVAL}"),
        (_search_failed(503), None),  # no shard available
        (_search_failed(429, {"type": "circuit_breaking_exception", "reason": BREAKER,
                              "bytes_wanted": 1031798784, "bytes_limit": 1020054732,
                              "durability": "TRANSIENT"}), None),
        (_search_failed(502), None),
        (_search_failed(504), None),
        # a 500 that isn't a failed search phase is the cluster's
        (TransportError(500, "illegal_state_exception",
                        {"error": {"root_cause": [STATE], "type": "illegal_state_exception",
                                   "reason": "unexpected state"}, "status": 500}), None),
    ],
    ids=["400", "500 another reason", "500 no top reason", "503 too many buckets",
         "503 no shard", "429 breaker", "502", "504", "500 not a search phase"],
)  # fmt: skip
@pytest.mark.parametrize("tool", ["idx_search", "idx_count", "idx_timeline"])
def test_the_status_decides_if_a_failed_search_is_a_query_error(run, tool, error, said):  # noqa: F811
    if said is None:  # as at base: the error itself, its status kept
        with pytest.raises(TransportError) as e:
            run(_Failing(error), tool, **tools(index=EVTX)[tool])
        assert e.value is error and e.value.status_code == error.status_code
        return
    with pytest.raises(ValueError) as e:
        run(_Failing(error), tool, **tools(index=EVTX)[tool])
    assert str(e.value) == said
    assert "clause limit" not in said  # no rule keyed on the nested-clause text


def test_idx_search_says_a_comparison_needs_a_field():
    from opensearch_mcp import server

    doc = " ".join(server.idx_search.__doc__.split())
    assert "A comparison (>, <, >=, <=) needs a field: '@timestamp:>2024-01-25'." in doc
    assert (
        "On evtx indices an unfielded one ('>2024-01-25') compares no dates: any hits come "
        "from other fields' text."
    ) in doc
    assert "matches nothing" not in doc


# --- (c) Sort keys -----------------------------------------------------------


class _Sorted(Cluster):
    def search(self, index=None, body=None, **kw):
        self.sent = body
        return super().search(index=index, body=body, **kw)


@pytest.mark.parametrize(
    "sort, sent",
    [
        ("_score:desc", {"_score": {"order": "desc"}}),
        ("_doc:asc", {"_doc": {"order": "asc"}}),
        ("@timestamp:asc", {"@timestamp": {"order": "asc", "unmapped_type": "date"}}),
        ("no.such.field", {"no.such.field": {"order": "desc", "unmapped_type": "date"}}),
    ],
)
def test_score_and_doc_sort_as_they_are_and_fields_as_fields(run, sort, sent):  # noqa: F811
    cluster = _Sorted({"total": 1, "successful": 1, "skipped": 0, "failed": 0}, total=1)
    run(cluster, "idx_search", query="x", index=EVTX, sort=sort)
    assert cluster.sent["sort"] == [sent]


# --- (d) The install's patch over old and new indices ------------------------

IDX = "case-9203c4a7e4d8-evtx-0"
SID = "winlog.user.identifier"
SID_PUT = {"properties": {"winlog": {"properties": {
    "user": {"properties": {"identifier": {"type": "keyword"}}}}}}}  # fmt: skip


def _after_upgrade(limit: int) -> dict:
    """An evtx index made by this template: the dates rule at [0], the strings
    rule (at `limit`) at [1], both copying to the catch-all."""
    index = _index_064()
    for f in ("Payload", "Details", "ContextInfo"):
        index["mappings"]["properties"]["winlog"]["properties"]["event_data"]["properties"][f] = {
            **kw(8191), "copy_to": ALL}  # fmt: skip
    ed = index["mappings"]["properties"]["winlog"]["properties"]["event_data"]["properties"]
    ed["Data"]["properties"]["#text"] = kw(8191)
    index["mappings"]["properties"]["winlog"]["properties"]["event_data_all"] = {
        **kw(8191), "doc_values": False}  # fmt: skip
    index["mappings"]["properties"]["winlog"]["properties"]["event_data_dates_all"] = DATES_MAP
    strings = rule(limit)
    strings[STRINGS]["mapping"]["copy_to"] = ALL
    dates = {DATES: {"path_match": "winlog.event_data.*", "match_mapping_type": "date",
                     "mapping": {"type": "date", "copy_to": [ALL, DATES_ALL]}}}  # fmt: skip
    index["mappings"]["dynamic_templates"] = [dates, strings]
    return index


def _current() -> dict:
    """An evtx index made by 0.6.5's template: every limit 8,191, no copy_to."""
    index = _index_064(Payload=kw(8191), Details=kw(8191), ContextInfo=kw(8191))
    ed = index["mappings"]["properties"]["winlog"]["properties"]["event_data"]["properties"]
    ed["Data"]["properties"]["#text"] = kw(8191)
    index["mappings"]["dynamic_templates"] = [rule(8191)]
    return index


@pytest.mark.parametrize(
    "index, rules",
    [
        (_index_064(), [rule(8191)]),  # its own rule, its limit raised: no copy_to, no dates
        (_current(), None),
        (_after_upgrade(8191), None),
        # its strings rule found by name at [1], the dates rule left as it is
        (_after_upgrade(1024), _after_upgrade(8191)["mappings"]["dynamic_templates"]),
    ],
    ids=["1024 index", "current index", "after the upgrade", "after the upgrade, rule lowered"],
)
def test_the_patch_raises_an_indexs_own_rule_then_maps_the_header_sid_and_nothing_else(
    index, rules
):
    cluster = _Cluster({IDX: copy.deepcopy(index)})
    client = cluster.client()
    result = mappings.patch_evtx_indices(client)
    # these indices predate the header SID, so its own put comes last, and only it
    *puts, sid = cluster.to(IDX)
    assert sid == SID_PUT
    if rules is None:
        assert puts == [] and result == {"patched": {IDX: [SID]}, "unchanged": [], "failed": []}
        return
    (put,) = puts
    assert put["dynamic_templates"] == rules
    if not any(DATES in e for e in index["mappings"]["dynamic_templates"]):
        assert ALL not in json.dumps(put) and "event_data_all" not in json.dumps(put)
        assert "event_data_dates_all" not in json.dumps(put)
    client.indices.put_settings.assert_not_called()
    assert result["patched"][IDX][-2:] == [STRINGS, SID]


# --- (e) What parse_evtx writes ------------------------------------------------

REAL = [Path(p) for p in os.environ.get("VHIR_TEST_EVTX", "").split(os.pathsep) if p]


def _keys(src: dict, prefix: str = ""):
    """The fields a record writes (an empty object writes none)."""
    for k, v in src.items():
        if isinstance(v, dict):
            yield from _keys(v, f"{prefix}{k}.")
        else:
            yield prefix + k


def _synthetic(n: int = 1) -> list[dict]:
    """pyevtx-rs records: event data with a date, a number, a nested object and
    a list; user data; a Data list."""
    system = {"EventID": 4688, "Channel": "Security", "Computer": "WKS7",
              "EventRecordID": n, "Provider": {"#attributes": {"Name": "Security-Auditing"}},
              "TimeCreated": {"#attributes": {"SystemTime": "2024-01-16T11:00:00Z"}}}  # fmt: skip
    events = [
        {
            "System": system,
            "EventData": {
                "NewProcessName": "C:\\w\\x.exe",
                "ProcessId": "0x1a4",
                "When": "2024-01-16T11:00:00Z",
                "Nested": {"A": {"B": 2}},
                "Many": ["a", "b"],
            },
        },  # fmt: skip
        {"System": {**system, "EventID": 4103}, "EventData": {"Data": ["one", "two"]}},
        {"System": {**system, "EventID": 2004}, "UserData": {"RuleChange": {"RuleId": "r1"}}},
    ]
    return [{"event_record_id": n + i, "data": json.dumps({"Event": e})}
            for i, e in enumerate(events)]  # fmt: skip


def _write(files, records=None):
    """parse_and_index over `files` (or `records`) in a new case, every bulk
    request captured, its first batch sent twice. Returns (key set, id_scheme
    seen, the first batch's _ids each time, records sent)."""
    name = f"unf-{uuid.uuid4().hex[:6]}"
    case = wc.case_dir_for(name)
    (case / "CASE.yaml").write_text(
        f"case_id: {name}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    client = MagicMock()
    client.indices.exists.return_value = True
    keys: set[str] = set()
    seen = {"id_scheme": 0, "sent": 0, "extra": set()}
    batches: list[list[str]] = []

    def capture(c, actions, **kw):
        actions = list(actions)
        for a in actions:
            keys.update(_keys(a["_source"]))
            seen["id_scheme"] += "vhir.id_scheme" in a["_source"]
            seen["extra"].update(set(a) - {"_index", "_id", "_op_type", "_source"})
        seen["sent"] += len(actions)
        batches.append([a["_id"] for a in actions])
        return len(actions), []

    real = bulk.flush_bulk

    def twice(client, actions, **kw):
        out = real(client, actions, **kw)
        if len(batches) == 1:  # the first batch, sent again as stamped
            real(client, actions, **kw)
        return out

    ctx = wc.open_unit(case, "hosts/WKS7", "WKS7", source="test")
    with (
        wc.writing(ctx),
        patch.object(bulk.helpers, "bulk", side_effect=capture),
        patch.object(parse_evtx, "flush_bulk", twice),
    ):
        index = wc.index_name("evtx")
        if records is not None:
            with patch.object(parse_evtx, "PyEvtxParser") as parser:
                parser.return_value.records_json.return_value = records
                parse_evtx.parse_and_index(Path("x.evtx"), client, index, source_file="x.evtx")
        for f in files:
            parse_evtx.parse_and_index(f, client, index, source_file=str(f))
    return keys, seen, batches


def _check(keys, seen, batches):
    tpl = mappings.with_host_key_fields(json.loads(TEMPLATE.read_text()))["template"]
    declared = set(_paths(tpl["mappings"]["properties"]))
    stray = sorted(k for k in keys if k not in declared and not k.startswith("winlog.event_data."))
    assert seen["sent"] and not stray, stray[:20]
    assert seen["id_scheme"] == 0 and seen["extra"] == set()
    assert len(batches) >= 2 and batches[1] == batches[0]  # sent again under the same ids


def test_what_parse_evtx_writes_is_declared_or_event_data_synthetic():
    _check(*_write([], records=_synthetic()))


@pytest.mark.skipif(not REAL or not all(p.is_file() for p in REAL), reason="VHIR_TEST_EVTX unset")
def test_what_parse_evtx_writes_is_declared_or_event_data_real():
    _check(*_write(REAL))
