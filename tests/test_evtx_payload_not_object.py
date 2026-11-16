"""A record whose EventData or UserData is not an object (text, a number, a
list, a boolean) costs no other record: every record of the file is sent, and
that record's raw value is kept in its event data. Unit test: the reader and
the bulk write are stubbed. Values are synthetic."""

import json

import pytest

from opensearch_mcp import parse_evtx
from opensearch_mcp.normalize import normalize_event

N, ODD = 5, 3  # the odd record is mid-file


def _records(source, raw):
    for i in range(1, N + 1):
        system = {
            "EventID": 4688,
            "Channel": "Security",
            "Computer": "RIG01",
            "EventRecordID": i,
            "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        }
        payload = {source: raw} if i == ODD else {"EventData": {"SubjectUserName": "rig"}}
        data = json.dumps({"Event": {"System": system, **payload}})
        yield {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


@pytest.mark.parametrize("source", ["EventData", "UserData"])
@pytest.mark.parametrize("raw", ["text", 7, ["a", "b"], True], ids=["str", "int", "list", "bool"])
def test_a_payload_that_is_not_an_object_costs_no_other_record(monkeypatch, source, raw):
    sent = []
    records = list(_records(source, raw))
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
    assert counts == (N, 0, 0)
    docs = {a["_source"]["winlog.record_id"]: a["_source"] for a in sent}
    assert sorted(docs) == [str(i) for i in range(1, N + 1)]
    assert docs[str(ODD)]["winlog.event_data"] == raw
    assert docs[str(N)]["winlog.event_data"] == {"SubjectUserName": "rig"}


H = {
    "event.code": 4688,
    "winlog.event_id": 4688,
    "winlog.channel": "Security",
    "winlog.provider_name": "",
}
LEVEL = {"event.kind": "event", "log.level": "information"}


@pytest.mark.parametrize(
    "payload, want",  # the docs the code made before the guard, key order included
    [
        (
            {"EventData": {"TargetUserName": "u"}},
            {
                **H,
                "user.name": "u",
                **LEVEL,
                "related.user": ["u"],
                "winlog.event_data": {"TargetUserName": "u"},
            },
        ),
        (
            {"UserData": {"W": {"#attributes": {}, "User": "u"}}},
            {
                **H,
                "user.name": "u",
                **LEVEL,
                "winlog.user_data": {"User": "u", "xml_name": "W"},
                "related.user": ["u"],
                "winlog.event_data": {"User": "u"},
            },
        ),
        ({"UserData": {"W": "s"}}, {**H, **LEVEL, "winlog.event_data": {"W": "s"}}),
    ],
    ids=["event_data_object", "user_data_wrapped", "user_data_inner_not_object"],
)
def test_an_object_payload_is_normalised_as_before(payload, want):
    system = {"EventID": 4688, "Channel": "Security"}
    doc = normalize_event({"Event": {"System": system, **payload}})
    assert json.dumps(doc) == json.dumps(want)
