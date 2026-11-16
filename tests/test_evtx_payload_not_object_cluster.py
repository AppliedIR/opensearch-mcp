"""Against a cluster, through the tree's evtx parser, pipeline and bulk writer:
a record whose EventData or UserData is not an object costs no other record.
That record is either stored or rejected alone and counted as a bulk failure;
every other record of the file is held. The reader is stubbed with records in
its records_json shape. Values are synthetic."""

from __future__ import annotations

import json

import pytest
from test_host_keys_cluster import cases, client  # noqa: F401

from opensearch_mcp import parse_evtx
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.integration

N, ODD = 1500, 1200  # the odd record is in the second bulk flush


def _record(i, source=None, raw=None):
    system = {
        "EventID": 4688,
        "Channel": "Security",
        "Computer": "RIG01",
        "EventRecordID": i,
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
    }
    payload = {source: raw} if source else {"EventData": {"SubjectUserName": "rig"}}
    data = json.dumps({"Event": {"System": system, **payload}})
    return {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


@pytest.mark.parametrize("source", ["EventData", "UserData"])
@pytest.mark.parametrize("raw", ["text", 7, ["a", "b"], True], ids=["str", "int", "list", "bool"])
def test_a_non_object_payload_costs_no_other_record(client, cases, monkeypatch, source, raw):  # noqa: F811
    case, _ = cases("po")
    records = [_record(i, source, raw) if i == ODD else _record(i) for i in range(1, N + 1)]
    reader = type("Reader", (), {"records_json": lambda self: records})
    monkeypatch.setattr(parse_evtx, "PyEvtxParser", lambda path: reader())
    with wc.writing(wc.open_unit(case, "hosts/RIG01", "RIG01", source="test")):
        index = wc.index_name("evtx")
        indexed, skipped, failed = parse_evtx.parse_and_index(
            evtx_path="rig.evtx", client=client, index_name=index, source_file="rig.evtx"
        )
    client.indices.refresh(index=index)
    kind = f"{source} {type(raw).__name__}"
    print(f"MEASURED {kind}: indexed {indexed}, skipped {skipped}, bulk_failed {failed}")
    assert skipped == 0 and indexed + failed == N and failed <= 1
    assert client.count(index=index)["count"] == indexed
    others = {"query": {"bool": {"must_not": {"term": {"winlog.record_id": str(ODD)}}}}}
    assert client.count(index=index, body=others)["count"] == N - 1
