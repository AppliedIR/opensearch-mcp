"""A record nested deeper than the surrogate walk can recurse, with a \\u escape that
sends it through the walk, is skipped and counted like a record that is not JSON;
every other record in the file is still sent. Unit test: the reader and the bulk
write are stubbed. Values are synthetic."""

import json

import pytest

from opensearch_mcp import parse_evtx

N, DEEP = 5, 3


def _nested(depth):
    text = '"Jos\\u00e9"'  # a \u escape: the record takes the walk
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


def _record(i, where=None):
    system = (
        '{"EventID": 4688, "Channel": "Security", "Computer": "RIG01", '
        f'"EventRecordID": {i}, '
        '"TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}}, '
        '"Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}'
    )
    event_data = '{"SubjectUserName": "rig", "NewProcessName": "C:\\\\a.exe"'
    if where == "System":
        system += ', "Extra": ' + _nested(_depth())
    if where == "EventData":
        event_data += ', "Blob": ' + _nested(_depth())
    data = '{"Event": {"System": ' + system + '}, "EventData": ' + event_data + "}}}"
    return {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


@pytest.mark.parametrize("where", ["System", "EventData"])
def test_a_record_too_deep_for_the_walk_is_skipped_and_the_rest_are_sent(monkeypatch, where):
    records = [_record(i, where) if i == DEEP else _record(i) for i in range(1, N + 1)]
    assert "\\u" in records[DEEP - 1]["data"]
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
    assert counts == (N - 1, 1, 0)
    ids = [a["_source"]["winlog.record_id"] for a in sent]
    assert ids == [str(i) for i in range(1, N + 1) if i != DEEP]
