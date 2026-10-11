"""Long evtx event-data values are indexed up to 8,191 characters, and an
index that can't take that limit says so.

A `winlog.event_data` string was mapped `keyword` with `ignore_above: 1024`:
a longer value (a 4103 Payload, a Sysmon 13 Details) was kept in `_source`
but not indexed, so a search on its field found nothing. The template now
gives 8,191; installing it raises the limits on the case's existing open
evtx indices, from their full mapping; and an evtx ingest into an index still
below the template's limits says so in the run's status.

The clients here are fakes: get_mapping honours `filter_path` and
`expand_wildcards`, and put_mapping changes the fake's state as OpenSearch
does (properties merged, dynamic_templates replaced). Values are synthetic.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status, mappings
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

TEMPLATE = Path(mappings.__file__).parent / "evtx_ecs_template.json"
RULE = "winlog_event_data_strings"
# The template as 0.6.4 shipped it, with both event-data limits set back to 1024
SHIPPED_064 = "3abf027226722ab8bd8561baf82e5d3469143deef4b1185e1ae1e09cc52348e7"


def kw(n):
    return {"type": "keyword", "ignore_above": n}


def rule(n):
    return {RULE: {"path_match": "winlog.event_data.*", "match_mapping_type": "string",
                   "mapping": kw(n)}}  # fmt: skip


def _template():
    return json.loads(TEMPLATE.read_text())["template"]["mappings"]


def _resolve(m, path):
    """A path's mapping as OpenSearch picks it: the explicit property, else
    the first dynamic rule whose path_match matches."""
    if path in m["properties"]:
        return m["properties"][path]
    for entry in m["dynamic_templates"]:
        (body,) = entry.values()
        if fnmatch.fnmatchcase(path, body.get("path_match", "*")):
            return body["mapping"]
    return None


# --- The template -------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "Payload",
        "Details",
        "ContextInfo",
        "QueryResults",
        "ImagePath",
        "Operation",
        "UserData.Param1",
        "Data.Foo",
    ],
)
def test_an_event_data_string_is_indexed_up_to_8191(field):
    m = _template()
    assert _resolve(m, f"winlog.event_data.{field}") == kw(8191)
    assert list(m["dynamic_templates"][0]) == [RULE]  # the rule, first, by its name


def test_the_other_limits_are_unchanged():
    m = _template()
    assert _resolve(m, "winlog.event_data.Data.#text") == kw(8191)
    p = m["properties"]
    assert p["winlog.event_data.ScriptBlockText"] == kw(32766)
    assert p["winlog.event_data.Data_raw"]["fields"]["keyword"] == kw(10000)
    assert p["winlog.event_data._pipeline_error"] == kw(512)
    assert p["process.command_line"]["fields"]["keyword"] == kw(2048)


def test_only_the_two_event_data_limits_changed():
    t = json.loads(TEMPLATE.read_text())
    m = t["template"]["mappings"]
    m["dynamic_templates"][0][RULE]["mapping"]["ignore_above"] = 1024
    m["properties"]["winlog.event_data.Data.#text"]["ignore_above"] = 1024
    canon = json.dumps(t, sort_keys=True).encode()
    assert hashlib.sha256(canon).hexdigest() == SHIPPED_064


# --- Installing raises the limits on existing indices -------------------------

IDX = "case-9203c4a7e4d8-evtx-0"


def _index_064(**extra):
    """An evtx index made under the 0.6.4 template: Payload, Details and
    ScriptBlockText as measured on OpenSearch 3.5.0, the rest as that
    template maps them."""
    ed = {
        "Payload": kw(1024), "Details": kw(1024), "ContextInfo": kw(1024),
        "ScriptBlockText": kw(32766),
        "Data_raw": {"type": "text", "fields": {"keyword": kw(10000)}},
        "Data": {"dynamic": "true", "properties": {"#text": kw(1024)}},
        **extra,
    }  # fmt: skip
    return {"mappings": {"dynamic_templates": [rule(1024)], "properties": {
        "event": {"properties": {"code": {"type": "integer"}}},
        "winlog": {"properties": {"event_data": {"properties": ed}}}}}}  # fmt: skip


def _merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict) and k != "fields":
            _merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


class _Cluster:
    """The indices, open or closed, and every put_mapping sent."""

    def __init__(self, indices: dict, closed=(), refuse=()):
        self.state = indices
        self.closed = set(closed)
        self.refuse = set(refuse)
        self.read_error = None
        self.calls: list[tuple[str, dict]] = []

    def get_mapping(self, index="", filter_path=None, expand_wildcards="open", **kw):
        if self.read_error:
            raise self.read_error
        if "*" not in index and "," not in index and index not in self.state:
            from opensearchpy.exceptions import NotFoundError

            raise NotFoundError(404, "index_not_found_exception", {})
        out = {
            k: copy.deepcopy(v)
            for k, v in self.state.items()
            if any(fnmatch.fnmatchcase(k, p) for p in index.split(","))
            and (expand_wildcards != "open" or k not in self.closed)
        }
        if filter_path == "*.mappings.dynamic_templates":
            return {
                k: {"mappings": {"dynamic_templates": v["mappings"].get("dynamic_templates", [])}}
                for k, v in out.items()
            }
        if filter_path:
            raise NotImplementedError(filter_path)
        return out

    def put_mapping(self, index, body):
        body = json.loads(json.dumps(body))
        self.calls.append((index, body))
        if index in self.refuse and "dynamic_templates" in body:  # the evtx patch
            raise RuntimeError("illegal_argument_exception")
        m = self.state[index]["mappings"]
        if "dynamic_templates" in body:
            m["dynamic_templates"] = body["dynamic_templates"]
        _merge(m.setdefault("properties", {}), body.get("properties", {}))
        return {"acknowledged": True}

    def client(self):
        def simulate(body):
            docs = []
            for d in body["docs"]:
                src = d["_source"]
                ed = src.get("winlog", {}).get("event_data") or src.get("winlog.event_data")
                data = ed.get("Data")
                out = {"Data_raw": str(data)}
                if isinstance(data, dict):
                    out["Data"] = data
                docs.append({"doc": {"_source": {"winlog.event_data": out}}})
            return {"docs": docs}

        c = MagicMock()
        c.indices.simulate_index_template.return_value = {}
        c.indices.get_mapping.side_effect = self.get_mapping
        c.indices.put_mapping.side_effect = self.put_mapping
        c.cat.indices.side_effect = lambda **k: [{"index": n} for n in self.state]
        c.ingest.simulate.side_effect = simulate
        return c

    def to(self, index):
        """put_mapping bodies sent to `index`, other than the stamp's fields."""
        return [
            b for i, b in self.calls
            if i == index and not (set(b) == {"properties"}
                                   and set(b["properties"]) <= set(mappings.STAMP_FIELDS))
        ]  # fmt: skip

    def limits(self, index):
        m = self.state[index]["mappings"]
        ed = m["properties"]["winlog"]["properties"]["event_data"]["properties"]
        got = {k: v.get("ignore_above") for k, v in ed.items() if v.get("type") == "keyword"}
        got["Data.#text"] = ed["Data"]["properties"]["#text"]["ignore_above"]
        got["Data_raw.keyword"] = ed["Data_raw"]["fields"]["keyword"]["ignore_above"]
        got["rule"] = m["dynamic_templates"][0][RULE]["mapping"]["ignore_above"]
        return got


def test_installing_raises_an_existing_indexs_limits_from_its_full_mapping():
    cluster = _Cluster({IDX: _index_064()})
    result = mappings.ensure_winlog_pipeline(cluster.client())
    assert cluster.to(IDX) == [{
        "dynamic_templates": [rule(8191)],
        "properties": {"winlog": {"properties": {"event_data": {"properties": {
            "ContextInfo": kw(8191), "Details": kw(8191), "Payload": kw(8191),
            "Data": {"properties": {"#text": kw(8191)}}}}}}},
    }]  # fmt: skip
    assert cluster.limits(IDX) == {
        "Payload": 8191, "Details": 8191, "ContextInfo": 8191, "ScriptBlockText": 32766,
        "Data.#text": 8191, "Data_raw.keyword": 10000, "rule": 8191,
    }  # fmt: skip
    assert result["status"] == "ok" and result["evtx_failed"] == []
    assert result["evtx_patched"] == {IDX: [
        "winlog.event_data.ContextInfo", "winlog.event_data.Data.#text",
        "winlog.event_data.Details", "winlog.event_data.Payload", RULE]}  # fmt: skip


def test_a_second_install_sends_the_patched_index_nothing():
    cluster = _Cluster({IDX: _index_064()})
    mappings.ensure_winlog_pipeline(cluster.client())
    cluster.calls.clear()
    result = mappings.ensure_winlog_pipeline(cluster.client())
    assert cluster.to(IDX) == [] and result["evtx_unchanged"] == [IDX]


def test_a_limit_is_never_lowered_and_other_types_are_left_alone():
    """A field already above the template's limit, an intended lower limit,
    and a field that isn't a keyword."""
    idx = _index_064(Hashes=kw(20000), _pipeline_error=kw(512), Count={"type": "long"},
                     Wild={"type": "wildcard", "ignore_above": 1024})  # fmt: skip
    cluster = _Cluster({IDX: idx})
    mappings.ensure_winlog_pipeline(cluster.client())
    limits = cluster.limits(IDX)
    assert limits["Hashes"] == 20000 and limits["_pipeline_error"] == 512
    ed = cluster.state[IDX]["mappings"]["properties"]["winlog"]["properties"]["event_data"]
    assert ed["properties"]["Count"] == {"type": "long"}
    assert ed["properties"]["Wild"] == {"type": "wildcard", "ignore_above": 1024}


def test_a_rule_already_above_the_templates_is_kept():
    idx = _index_064()
    idx["mappings"]["dynamic_templates"] = [rule(20000)]
    cluster = _Cluster({IDX: idx})
    mappings.ensure_winlog_pipeline(cluster.client())
    assert cluster.limits(IDX)["rule"] == 20000 and cluster.limits(IDX)["Payload"] == 8191


def test_a_refused_patch_is_reported_and_the_other_indices_are_patched():
    other = "case-9203c4a7e4d8-evtx-host2"
    cluster = _Cluster({IDX: _index_064(), other: _index_064()}, refuse={IDX})
    result = mappings.ensure_winlog_pipeline(cluster.client())
    assert result["status"] == "partial"
    assert [f["index"] for f in result["evtx_failed"]] == [IDX]
    assert list(result["evtx_patched"]) == [other] and cluster.limits(other)["rule"] == 8191


def test_a_closed_index_isnt_read_or_patched():
    cluster = _Cluster({IDX: _index_064()}, closed={IDX})
    mappings.ensure_winlog_pipeline(cluster.client())
    assert cluster.to(IDX) == [] and cluster.limits(IDX)["Payload"] == 1024


# --- An ingest into an index below the template's limits says so ---------------


def _note(index_body, name="case-x-evtx-0", read_error=None):
    fn = getattr(mappings, "evtx_limit_note", None)
    cluster = _Cluster({name: index_body} if index_body else {})
    cluster.read_error = read_error
    return fn(cluster.client(), name) if fn else None


def _say(index, fields, n=1024):
    return (
        f"{index}: winlog.event_data values longer than {n:,} characters in {fields} are "
        "stored but not indexed, so a search on those fields doesn't find them (the "
        "index's mapping predates 0.6.5 and wasn't updated)"
    )


def _idx(dyn, ed):
    return {"mappings": {"dynamic_templates": dyn, "properties": {
        "winlog": {"properties": {"event_data": {"properties": ed}}}}}}  # fmt: skip


DR = {"type": "text", "fields": {"keyword": kw(10000)}}


def test_an_index_made_by_064_is_named_with_its_low_fields():
    assert _note(_index_064(), "A") == _say(
        "A", "ContextInfo, Data.#text, Details, Payload, new fields"
    )


def test_a_patched_index_gives_no_note():
    patched = _idx([rule(8191)], {"Payload": kw(8191), "Details": kw(8191),
                                   "ScriptBlockText": kw(32766), "Data_raw": DR,
                                   "Data": {"properties": {"#text": kw(8191)}}})  # fmt: skip
    assert _note(patched) == ""


def test_a_field_still_low_under_a_raised_rule_is_named():
    assert _note(_idx([rule(8191)], {"Payload": kw(1024), "Details": kw(8191)}), "C") == (
        _say("C", "Payload")
    )


def test_the_lowest_limit_is_the_one_named():
    mixed = _idx([rule(8191)], {"Payload": kw(2048), "Details": kw(1024)})
    assert _note(mixed, "L") == _say("L", "Details, Payload", 1024)


def test_an_index_not_made_yet_gives_no_note():
    assert _note(None) == ""


@pytest.mark.parametrize("kind", ["forbidden", "timeout"])
def test_a_mapping_that_cant_be_read_is_said_so(kind):
    """Only a missing index means no note: a refusal or a timeout leaves the
    limits unknown, and the run says it couldn't check."""
    from opensearchpy.exceptions import AuthorizationException, ConnectionTimeout

    error = {
        "forbidden": AuthorizationException(403, "security_exception", {}),
        "timeout": ConnectionTimeout("TIMEOUT", "read timed out", None),
    }[kind]
    note = _note(_index_064(), "T", read_error=error)
    assert note == f"couldn't check T's event-data limits: {error}"


def test_the_templates_own_lower_limits_give_no_note():
    intended = _idx([rule(8191)], {"ScriptBlockText": kw(32766), "_pipeline_error": kw(512)})
    assert _note(intended) == ""


def test_more_than_ten_low_fields_are_cut_short():
    many = _idx([rule(8191)], {f"F{n:02d}": kw(1024) for n in range(12)})
    shown = ", ".join(f"F{n:02d}" for n in range(10)) + ", …"
    assert _note(many, "M") == _say("M", shown)


def test_the_evtx_ingest_puts_the_note_in_the_runs_status(tmp_path, monkeypatch, capsys):
    """The ingest both routes run (MCP and CLI): the note is in the evtx
    artifact's status, which idx_ingest_status shows as a warning, and on
    stderr."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    host.evtx_dir = evtx
    index = "case-c1-evtx-0"
    with patch("opensearch_mcp.write_context.index_name", return_value=index):
        client = _Cluster({index: _index_064()}).client()
        client.count.side_effect = Exception("no index")
        audit = MagicMock()
        audit._next_audit_id.return_value = "aid-1"
        with (
            patch("opensearch_mcp.ingest.parse_and_index", return_value=(500, 0, 0)),
            patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
        ):
            ingest(hosts=[host], client=client, audit=audit, case_id="c1",
                   reduced_log_names=None, status_pid=os.getpid(),
                   status_run_id="run-evtx")  # fmt: skip
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    want = _say(index, "ContextInfo, Data.#text, Details, Payload, new fields")
    assert f"HOST1: {want}" in status.get("warnings", [])
    assert want in capsys.readouterr().err
