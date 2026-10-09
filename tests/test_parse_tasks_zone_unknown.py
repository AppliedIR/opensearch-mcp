"""Scheduled tasks when the system's time zone is unknown.

A date with its own negative offset (2005-10-11T13:21:17-08:00) needs no time
zone, but was dropped with the true local times. And the local times were
dropped without a word: the status read complete and the audit "N indexed".
An explicit offset now converts to UTC either way; the local times are still
indexed without @timestamp, and their count reaches stderr, the artifact's
status note and the audit summary. Values are synthetic.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opensearch_mcp import ingest
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.parse_tasks import parse_tasks_dir
from opensearch_mcp.results import HostResult

_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
    "<RegistrationInfo><Date>{}</Date></RegistrationInfo></Task>"
)


def _tasks(tmp_path, dates):
    tasks = tmp_path / "Tasks"
    tasks.mkdir()
    for n, date in enumerate(dates):
        (tasks / f"T{n}").write_text(_XML.format(date))
    return tasks


def _capture():
    sent: list[dict] = []

    def capture(client, actions, **kw):
        sent.extend(actions)
        return len(actions), 0

    return patch("opensearch_mcp.parse_tasks.flush_bulk", side_effect=capture), sent


def _stamps(tmp_path, dates, zone):
    patcher, sent = _capture()
    notes: list[str] = []
    with patcher:
        parse_tasks_dir(_tasks(tmp_path, dates), None, "i", "h", zone, notes=notes)
    return [a["_source"].get("@timestamp") for a in sent], notes


@pytest.mark.parametrize(
    "date, expected",
    [
        ("2005-10-11T13:21:17-08:00", "2005-10-11T21:21:17Z"),
        ("2023-01-17T10:48:01.1234567-05:00", "2023-01-17T15:48:01.123456Z"),
        ("2023-01-17T10:48:01-0500", "2023-01-17T15:48:01Z"),
        ("2023-01-29T08:00:00+05:30", "2023-01-29T02:30:00Z"),
        ("2023-01-29T08:00:00+0530", "2023-01-29T02:30:00Z"),
        ("2023-01-17T10:48:01.5+01:00", "2023-01-17T09:48:01.500000Z"),
    ],
    ids=["-08:00", "fraction and -05:00", "-0500", "+05:30", "+0530", "fraction and +01:00"],
)
def test_a_date_with_its_own_offset_needs_no_time_zone(tmp_path, date, expected):
    stamps, notes = _stamps(tmp_path, [date], None)
    assert stamps == [expected]
    assert notes == []


class _Audit:
    def __init__(self):
        self.logged: list[dict] = []

    def _next_audit_id(self):
        return "opensearch-tester-20261007-001"

    def log(self, **kw):
        self.logged.append(kw)
        return kw.get("audit_id")  # written


def _custom_artifact(tmp_path, zone, dates, monkeypatch):
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)
    status = [{"artifacts": [{"name": "tasks", "status": "pending"}]}]
    host = DiscoveredHost(hostname="WKS01", volume_root=tmp_path, system_timezone=zone)
    result = HostResult(hostname="WKS01")
    audit = _Audit()
    patcher, sent = _capture()
    with patcher:
        ingest._ingest_custom_artifact(
            "tasks",
            _tasks(tmp_path, dates),
            None,
            audit,
            "C-1",
            host,
            0,
            result,
            status,
            lambda *a, **k: None,
            lambda: None,
        )
    # the artifact's outcome is its last entry; each task file's step comes first
    return sent, status[0]["artifacts"][0], audit.logged[-1], result.artifacts[0]


def test_local_dates_with_the_zone_unknown_are_counted_everywhere(tmp_path, monkeypatch, capsys):
    dates = ["2014-01-01T00:00:00", "2015-02-02T01:01:01", "2016-03-03T02:02:02"]
    dates.append("2005-10-11T13:21:17-08:00")
    sent, status, logged, artifact = _custom_artifact(tmp_path, None, dates, monkeypatch)
    assert len(sent) == 4  # every task is indexed
    expected = "3 task(s) indexed without @timestamp"
    for text in (capsys.readouterr().err, status["note"], logged["result_summary"]):
        assert expected in text and "time zone is unknown" in text, text
    assert artifact.note.startswith(expected)
    assert status["status"] == "complete"


def test_a_note_already_on_the_status_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)
    original = ingest._find_artifact_status

    def with_note(*a):
        entry = original(*a)
        entry["note"] = "an earlier note"
        return entry

    monkeypatch.setattr(ingest, "_find_artifact_status", with_note)
    _, status, _, _ = _custom_artifact(tmp_path, None, ["2014-01-01T00:00:00"], monkeypatch)
    assert status["note"].startswith("an earlier note; 1 task(s) indexed without")


def test_anchor_a_known_zone_converts_as_before_with_no_note(tmp_path, monkeypatch, capsys):
    dates = [
        "2014-01-01T00:00:00",
        "2005-06-23T13:48:00+05:30",
        "2024-03-04T05:06:07Z",
        "2023-01-17T10:48:01-05:00",
    ]
    sent, status, logged, artifact = _custom_artifact(
        tmp_path, "America/New_York", dates, monkeypatch
    )
    stamps = sorted(a["_source"]["@timestamp"] for a in sent)
    assert stamps == sorted(
        [
            "2014-01-01T05:00:00Z",
            "2005-06-23T08:18:00Z",  # its own offset, as a negative one is
            "2024-03-04T05:06:07Z",
            "2023-01-17T15:48:01Z",
        ]
    )
    assert "note" not in status and artifact.note == ""
    assert logged["result_summary"] == "4 indexed"
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("zone", [None, "America/New_York"], ids=["zone unknown", "zone known"])
def test_an_out_of_range_date_is_counted_and_the_rest_ingested(tmp_path, zone):
    stamps, notes = _stamps(
        tmp_path, ["9999-12-31T23:59:59-01:00", "2005-10-11T13:21:17-08:00"], zone
    )
    assert sorted(stamps, key=str) == sorted([None, "2005-10-11T21:21:17Z"], key=str)
    assert any("1 task(s)" in n and "out of range" in n for n in notes), notes


def test_a_positive_offset_wins_over_a_known_zone_as_a_negative_one_does(tmp_path):
    stamps, _ = _stamps(
        tmp_path, ["2023-01-29T08:00:00+05:30", "2005-10-11T13:21:17-08:00"], "America/New_York"
    )
    assert stamps == ["2023-01-29T02:30:00Z", "2005-10-11T21:21:17Z"]
