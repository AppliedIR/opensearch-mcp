"""A record nested deeper than the surrogate walk can recurse, with a \\u escape that
sends it through the walk, is skipped and counted like a record that is not JSON;
every other record in the file is still sent. So is a record nested deeper than
normalize_event or the Data_raw text can recurse, without an escape. Unit test: the
reader and the bulk write are stubbed. Values are synthetic."""

import json
import sys

import pytest

from opensearch_mcp import parse_evtx

N, DEEP = 5, 3


def _nested(depth, escape=True):
    text = '"Jos\\u00e9"' if escape else '"rig"'  # a \u escape: the record takes the walk
    for _ in range(depth):
        text = '{"k": ' + text + "}"
    return text


def _depth():
    """The deepest nesting json.loads still parses here and the walk cannot recurse
    through: py3.12's json goes deeper than its recursion limit, py3.10's does not."""
    for depth in (5000, 700):
        try:
            json.loads(_nested(depth))
        except RecursionError:
            continue
        return depth
    pytest.fail("json.loads parses neither depth")


def _record(i, where=None, depth=None, escape=True):
    system = (
        '{"EventID": 4688, "Channel": "Security", "Computer": "RIG01", '
        f'"EventRecordID": {i}, '
        '"TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}}, '
        '"Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}'
    )
    event_data = '{"SubjectUserName": "rig", "NewProcessName": "C:\\\\a.exe"'
    deep = _nested(depth or _depth(), escape) if where else ""
    if where == "System":
        system += ', "Extra": ' + deep
    if where == "EventData":
        event_data += ', "Blob": ' + deep
    if where == "Data":  # an object-valued EventData.Data: _normalise_data writes Data_raw
        event_data += ', "Data": ' + deep
    data = '{"Event": {"System": ' + system + '}, "EventData": ' + event_data + "}}}"
    return {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


def _send(monkeypatch, records):
    sent = []
    monkeypatch.setattr(
        parse_evtx,
        "PyEvtxParser",
        lambda path: type("R", (), {"records_json": lambda self: records})(),
    )
    monkeypatch.setattr(
        parse_evtx, "flush_bulk", lambda client, actions: (sent.extend(actions) or len(actions), 0)
    )
    counts = parse_evtx.parse_and_index(
        evtx_path="rig.evtx", client=None, index_name="i", source_file="rig.evtx"
    )
    return counts, [a["_source"]["winlog.record_id"] for a in sent]


@pytest.mark.parametrize("where", ["System", "EventData"])
def test_a_record_too_deep_for_the_walk_is_skipped_and_the_rest_are_sent(monkeypatch, where):
    records = [_record(i, where) if i == DEEP else _record(i) for i in range(1, N + 1)]
    assert "\\u" in records[DEEP - 1]["data"]
    counts, ids = _send(monkeypatch, records)
    assert counts == (N - 1, 1, 0)
    assert ids == [str(i) for i in range(1, N + 1) if i != DEEP]


def _too_deep_for(where, step):
    """The shallowest depth (in steps of 100) json.loads still parses here and `step`
    cannot recurse through: the limits differ by Python version, so they are probed."""
    for depth in range(100, 20001, 100):
        try:
            data = json.loads(_record(DEEP, where, depth, escape=False)["data"])
        except RecursionError:
            break
        try:
            step(data)
        except RecursionError:
            return depth
    pytest.fail(f"no depth json.loads parses is too deep for {step.__name__} here")


def _normalise(data):
    parse_evtx._normalise_data(parse_evtx.normalize_event(data))


@pytest.mark.parametrize(
    "where, step",
    [
        pytest.param("Data", _normalise, id="Data_raw text"),
        pytest.param(
            "EventData",
            parse_evtx.normalize_event,
            id="normalize_event",
            marks=pytest.mark.skipif(
                sys.version_info < (3, 12),
                reason="json.loads stops before normalize_event does on this Python",
            ),
        ),
    ],
)
def test_a_record_too_deep_to_normalise_is_skipped_and_the_rest_are_sent(monkeypatch, where, step):
    depth = _too_deep_for(where, step)
    records = [
        _record(i, where, depth, escape=False) if i == DEEP else _record(i)
        for i in range(1, N + 1)
    ]
    assert "\\u" not in records[DEEP - 1]["data"]
    counts, ids = _send(monkeypatch, records)
    assert counts == (N - 1, 1, 0)
    assert ids == [str(i) for i in range(1, N + 1) if i != DEEP]
