"""The lone-surrogate walk at the evtx load point changes nothing else: records
whose text carries ordinary non-ASCII as \\u escapes (accents, CJK, a pair that
joins to one emoji) are sent byte for byte as the path without the walk sends
them. Unit test: the reader and the bulk write are stubbed. Values are synthetic."""

import json

from opensearch_mcp import parse_evtx

VALUES = ["Jos\u00e9 M\u00fcller", "\u7ba1\u7406\u8005", "\U0001f600 report.docx", "plain"]


def _records():
    for i, value in enumerate(VALUES, 1):
        system = {
            "EventID": 4688,
            "Channel": "Security",
            "Computer": "RIG01",
            "EventRecordID": i,
            "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        }
        event_data = {"SubjectUserName": value, "NewProcessName": f"C:\\{value}\\a.exe"}
        data = json.dumps({"Event": {"System": system, "EventData": event_data}})
        yield {"data": data, "event_record_id": i, "timestamp": "2024-01-15T10:00:00Z"}


def _sent(monkeypatch):
    sent = []
    monkeypatch.setattr(
        parse_evtx,
        "PyEvtxParser",
        lambda path: type("R", (), {"records_json": lambda self: list(_records())})(),
    )
    monkeypatch.setattr(
        parse_evtx, "flush_bulk", lambda client, actions: (sent.extend(actions) or len(actions), 0)
    )
    parse_evtx.parse_and_index(
        evtx_path="rig.evtx", client=None, index_name="i", source_file="rig.evtx"
    )
    return json.dumps(sent, ensure_ascii=False).encode("utf-8"), sent


def test_ordinary_non_ascii_is_sent_byte_identical(monkeypatch):
    assert all("\\u" in r["data"] for r in list(_records())[:3])  # these take the walk
    walked, sent = _sent(monkeypatch)
    monkeypatch.setattr(parse_evtx, "_visible_surrogates", lambda v: v, raising=False)
    unwalked, _ = _sent(monkeypatch)
    assert walked == unwalked
    assert [a["_source"]["winlog.event_data"]["SubjectUserName"] for a in sent] == VALUES


def _strings(value):
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return [value] if isinstance(value, str) else []


def test_a_lone_surrogate_in_a_list_is_sent_as_visible_text(monkeypatch):
    """Unnamed <Data> values come as a list: the walk reaches into it."""
    system = {
        "EventID": 4688,
        "Channel": "Security",
        "Computer": "RIG01",
        "EventRecordID": 1,
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
    }
    event_data = {"Data": {"#text": ["a\ud800b", "c"]}}
    data = json.dumps({"Event": {"System": system, "EventData": event_data}})
    records = [{"data": data, "event_record_id": 1, "timestamp": "2024-01-15T10:00:00Z"}]
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
    assert counts == (1, 0, 0)
    json.dumps(sent, ensure_ascii=False).encode("utf-8")  # a raw lone surrogate can't be encoded
    strings = _strings(sent[0]["_source"]["winlog.event_data"])
    assert any("a\\ud800b" in s for s in strings) and not any("\ud800" in s for s in strings)
