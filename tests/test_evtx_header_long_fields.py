"""A record-header number no long field holds (System Version, Execution
ProcessID or ThreadID) costs no other record: every record of the file is
sent, and that record's header field is left unwritten (the header value is
not in the event data). Unit test: the reader is stubbed, and the bulk write
is stubbed with opensearch-py's own serialiser, which a 4,000-digit integer
stops. Values are synthetic."""

import json

import pytest
from opensearchpy.serializer import JSONSerializer

from opensearch_mcp import parse_evtx

N, ODD = 5, 3  # the crafted record is mid-file
FIELD = {"Version": "winlog.version", "ProcessID": "winlog.process.pid",
         "ThreadID": "winlog.process.thread.id"}  # fmt: skip
NORMAL = {"winlog.version": 2, "winlog.process.pid": 4, "winlog.process.thread.id": 8}


def _records(key, value):
    for i in range(1, N + 1):
        system = {
            "EventID": 4688,
            "Channel": "Security",
            "Computer": "RIG01",
            "EventRecordID": i,
            "Version": 2,
            "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
            "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 8}},
        }
        if i == ODD and key:
            (system if key == "Version" else system["Execution"]["#attributes"])[key] = value
        data = json.dumps({"Event": {"System": system, "EventData": {"SubjectUserName": "rig"}}})
        yield {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


def _sent(monkeypatch, key=None, value=None):
    sent = []
    records = list(_records(key, value))
    monkeypatch.setattr(
        parse_evtx,
        "PyEvtxParser",
        lambda path: type("R", (), {"records_json": lambda self: records})(),
    )

    def flush(client, actions):
        for action in actions:
            JSONSerializer().dumps(action["_source"])
            sent.append(action["_source"])
        return len(actions), 0

    monkeypatch.setattr(parse_evtx, "flush_bulk", flush)
    counts = parse_evtx.parse_and_index(
        evtx_path="rig.evtx", client=None, index_name="i", source_file="rig.evtx"
    )
    return counts, {doc["winlog.record_id"]: doc for doc in sent}


def test_the_header_numbers_of_ordinary_records_are_written(monkeypatch):
    counts, docs = _sent(monkeypatch)
    assert counts == (N, 0, 0) and sorted(docs) == [str(i) for i in range(1, N + 1)]
    assert all(NORMAL.items() <= doc.items() for doc in docs.values())


@pytest.mark.parametrize("key", list(FIELD))
@pytest.mark.parametrize(
    "value",
    ["0x" + "F" * 4000, "0x" + "F" * 17, "99999999999999999999"],
    ids=["hex_4000_digits", "hex_past_int64", "decimal_past_int64"],
)
def test_a_header_number_no_long_field_holds_costs_no_other_record(monkeypatch, key, value):
    counts, docs = _sent(monkeypatch, key, value)
    assert counts == (N, 0, 0) and sorted(docs) == [str(i) for i in range(1, N + 1)]
    odd = docs[str(ODD)]
    assert FIELD[key] not in odd
    assert {k: v for k, v in NORMAL.items() if k != FIELD[key]}.items() <= odd.items()
    assert all(NORMAL.items() <= docs[str(i)].items() for i in range(1, N + 1) if i != ODD)
