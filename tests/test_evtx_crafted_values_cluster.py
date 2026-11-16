"""Against a cluster, through the tree's evtx parser, pipeline and bulk writer:
one crafted value mid-file costs no other record. A number no long field
holds leaves its ECS field unwritten, its raw text kept in the event data; a
lone surrogate is stored as visible text (backslashreplace), never dropped.
The reader is stubbed with records in its records_json shape. Values are
synthetic."""

from __future__ import annotations

import json

import pytest
from test_host_keys_cluster import cases, client  # noqa: F401

from opensearch_mcp import parse_evtx
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.integration

N, CRAFTED = 1500, 1200  # the crafted record is in the second bulk flush


def _record(i, field=None, value=None):
    system = {
        "EventID": 4688,
        "Channel": "Security",
        "Computer": "RIG01",
        "EventRecordID": i,
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
    }
    event_data = {
        "SubjectUserName": "rig",
        "NewProcessId": "0x1a4",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "ProcessId": "0x1a4",
    }
    (system if field == "EventRecordID" else event_data).update({field: value} if field else {})
    data = json.dumps({"Event": {"System": system, "EventData": event_data}})  # \u escapes
    return {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


@pytest.mark.parametrize(
    "row",  # (field, value, the record's stored record_id, event data it keeps)
    [
        ("NewProcessId", "0x" + "F" * 17, str(CRAFTED), {"NewProcessId": "0x" + "F" * 17}),
        ("NewProcessId", "0x" + "F" * 4000, str(CRAFTED), {"NewProcessId": "0x" + "F" * 4000}),
        ("EventRecordID", "a\ud800b", "a\\ud800b", {}),
        ("NewProcessName", "a\ud800b", str(CRAFTED), {"NewProcessName": "a\\ud800b"}),
    ],
    ids=["hex_past_int64", "hex_4000_digits", "surrogate_record_id", "surrogate_event_data"],
)
def test_one_crafted_value_costs_no_other_record(client, cases, monkeypatch, row):  # noqa: F811
    field, value, record_id, stored = row
    case, _ = cases("cv")
    records = [_record(i, field, value) if i == CRAFTED else _record(i) for i in range(1, N + 1)]
    reader = type("Reader", (), {"records_json": lambda self: records})
    monkeypatch.setattr(parse_evtx, "PyEvtxParser", lambda path: reader())
    with wc.writing(wc.open_unit(case, "hosts/RIG01", "RIG01", source="test")):
        index = wc.index_name("evtx")
        counts = parse_evtx.parse_and_index(
            evtx_path="rig.evtx", client=client, index_name=index, source_file="rig.evtx"
        )
    client.indices.refresh(index=index)
    assert counts == (N, 0, 0)
    assert client.count(index=index)["count"] == N
    query = {"query": {"term": {"winlog.record_id": record_id}}}
    hits = client.search(index=index, body=query)["hits"]["hits"]
    assert len(hits) == 1
    doc = hits[0]["_source"]
    assert "process.pid" not in doc if field == "NewProcessId" else doc["process.pid"] == 0x1A4
    assert stored.items() <= doc["winlog.event_data"].items()
