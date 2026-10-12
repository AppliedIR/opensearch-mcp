"""A Windows zone id resolves to its CLDR zone, a WER report is dated by its
EventTime, and a shimcachemem row by its "Last Modified".

Zones go through discovery and the transcript and task parsers, as an ingest
runs them; WER under two process zones, since a FILETIME is UTC. Record ids
are pinned to the 0.6.4 ones: only @timestamp moves. Values are synthetic.
"""

from __future__ import annotations

import os
import time

import pytest

from opensearch_mcp import discover, parse_memory, parse_tasks, parse_transcripts, parse_wer, paths

_TASK = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>{date}</Date><Author>CORP\\bob</Author></RegistrationInfo>
  <Actions Context="Author"><Exec><Command>C:\\x.exe</Command></Exec></Actions>
</Task>
"""
_TRANSCRIPT = (
    "**********************\nWindows PowerShell transcript start\nStart time: {start}\n"
    "Username: CORP\\bob\nMachine: HOST1 (Microsoft Windows NT 10.0.19045.0)\n"
    "Host Application: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
    "Process ID: 4242\n**********************\nPS C:\\> whoami\n"
)


def _host_times(tmp_path, monkeypatch, zone_id, local):
    """A Windows volume whose SYSTEM hive names `zone_id`: a transcript and a
    task at `local` (YYYYmmddHHMMSS), dated with discovery's zone."""
    vr = tmp_path / "C"
    (vr / "Windows/System32/config").mkdir(parents=True)
    (vr / "Windows/System32/config/SYSTEM").write_bytes(b"")
    tasks = vr / "Windows/System32/Tasks"
    tasks.mkdir()
    iso = f"{local[:4]}-{local[4:6]}-{local[6:8]}T{local[8:10]}:{local[10:12]}:{local[12:]}"
    (tasks / "T1").write_text(_TASK.format(date=iso), encoding="utf-16")
    docs = vr / "Users/bob/Documents"
    docs.mkdir(parents=True)
    (docs / f"PowerShell_transcript.HOST1.abc.{local}.txt").write_text(
        _TRANSCRIPT.format(start=local)
    )
    monkeypatch.setattr(parse_transcripts, "_read_transcript_config", lambda v: (None, zone_id))
    host = discover.make_host("HOST1", vr)
    sent: list = []
    capture = lambda client, actions, **kw: (sent.extend(actions), (len(actions), 0))[1]  # noqa: E731
    monkeypatch.setattr(parse_transcripts, "flush_bulk", capture)
    monkeypatch.setattr(parse_tasks, "flush_bulk", capture)
    notes: list[str] = []
    zone = host.system_timezone
    parse_transcripts.ingest_transcripts(
        vr, None, "case-x-transcripts-0", "HOST1", volume_root=vr, system_timezone=zone
    )
    parse_tasks.parse_tasks_dir(
        tasks, None, "case-x-tasks-0", "HOST1", system_timezone=zone, volume_root=vr, notes=notes
    )
    by_index = {a["_index"]: a for a in sent}
    tr, tk = by_index.get("case-x-transcripts-0"), by_index["case-x-tasks-0"]
    return (
        tr["_source"].get("@timestamp") if tr else "SKIPPED",
        tk["_source"].get("@timestamp", "UNDATED"),
        notes,
        (tr["_id"] if tr else None, tk["_id"]),
    )


@pytest.mark.parametrize(
    "zone_id, local, utc",
    [
        ("Russia Time Zone 3", "20240701120000", "2024-07-01T08:00:00Z"),  # +4
        ("Russia Time Zone 10", "20240701120000", "2024-07-01T01:00:00Z"),  # +11
        ("Russia Time Zone 11", "20240115120000", "2024-01-15T00:00:00Z"),  # +12
        ("Pakistan Standard Time", "20240701120000", "2024-07-01T07:00:00Z"),
        ("Cen. Australia Standard Time", "20240115120000", "2024-01-15T01:30:00Z"),  # DST
        ("Cen. Australia Standard Time", "20240701120000", "2024-07-01T02:30:00Z"),
        ("Jordan Standard Time", "20240115120000", "2024-01-15T09:00:00Z"),
        ("UTC+12", "20191215120000", "2019-12-15T00:00:00Z"),  # Fiji was +13 that day
        ("UTC+12", "20240701120000", "2024-07-01T00:00:00Z"),
        ("Central Asia Standard Time", "20240701120000", "2024-07-01T06:00:00Z"),  # +6
        ("Mountain Standard Time (Mexico)", "20240115120000", "2024-01-15T19:00:00Z"),  # -7
        ("Eastern Standard Time", "20240115120000", "2024-01-15T17:00:00Z"),
        ("Eastern Standard Time", "20240701120000", "2024-07-01T16:00:00Z"),
        ("W. Europe Standard Time", "20240701120000", "2024-07-01T10:00:00Z"),
    ],
)
def test_a_windows_zone_dates_transcripts_and_tasks_in_utc(
    tmp_path, monkeypatch, zone_id, local, utc
):
    tr, tk, notes, _ = _host_times(tmp_path, monkeypatch, zone_id, local)
    assert (tr, tk, notes) == (utc, utc, [])


def test_the_zone_changes_no_record_id(tmp_path, monkeypatch):
    *_, ids = _host_times(tmp_path, monkeypatch, "Russia Time Zone 3", "20240701120000")
    assert ids == ("c69fee840dc975e7c45c", "a451ce84e09fa7bd7fb8")  # as in 0.6.4


@pytest.mark.parametrize(
    "name, want",
    [
        ("Russia Time Zone 3", "Europe/Samara"),
        ("russia time zone 3", "Europe/Samara"),
        (" Russia Time Zone 3", "Europe/Samara"),
        ("Russia Time Zone 3 ", "Europe/Samara"),
        ("Russia Time Zone 3\x00", "Europe/Samara"),
        ("Russia Time Zone 3\x00\x00garbage", "Europe/Samara"),  # a registry value's NUL tail
        ("Eastern Standard Time\x00", "America/New_York"),
        ("UTC+12", "Etc/GMT-12"),
        ("Foo Zone 5", None),  # unknown, not read as a POSIX string
        ("Russia TZ 3 Standard Time", None),
        ("\x00", None),
        ("  ", None),
        ("America/New_York", "America/New_York"),
        ("EST5EDT", "EST5EDT"),
        ("Etc/GMT-12", "Etc/GMT-12"),
        ("UTC", "UTC"),
        (None, None),
    ],
)
def test_resolve_timezone(name, want):
    assert paths.resolve_timezone(name) == want


@pytest.fixture(params=["UTC", "America/New_York"])
def process_zone(request, monkeypatch):
    """The process's own zone mustn't reach a FILETIME's reading."""
    monkeypatch.setenv("TZ", request.param)
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _wer(tmp_path, monkeypatch, body):
    d = tmp_path / "WER/ReportArchive/AppCrash_evil.exe_x"
    d.mkdir(parents=True)
    f = d / "Report.wer"
    f.write_text(body, encoding="utf-16")
    os.utime(f, (1748736000, 1748736000))  # mtime 2025-06-01T00:00:00Z
    sent: list = []
    monkeypatch.setattr(
        parse_wer, "flush_bulk", lambda c, a, **k: (sent.extend(a), (len(a), 0))[1]
    )
    notes: list[str] = []
    parse_wer.parse_wer_dir(
        tmp_path / "WER", None, "case-x-wer-0", "HOST1", volume_root=tmp_path, notes=notes
    )
    (a,) = sent
    return a["_id"], a["_source"]["@timestamp"], notes


def test_a_wer_report_is_dated_by_its_eventtime(tmp_path, monkeypatch, process_zone):
    body = (
        "Version=1\nEventType=APPCRASH\nEventTime=133497031270000000\n"
        "Sig[0].Name=Application Name\nSig[0].Value=evil.exe\n"
    )
    _id, ts, notes = _wer(tmp_path, monkeypatch, body)
    assert _id == "4f96481de95dbc7050f8"  # as in 0.6.4: the path and the bytes
    assert (ts, notes) == ("2024-01-14T10:52:07+00:00", [])


@pytest.mark.parametrize(
    "line",
    [
        "",
        "EventTime=0\n",
        "EventTime=garbage\n",
        "EventTime=121178592000000000\n",  # 1985-01-01: before 1990
        "EventTime=157469184000000000\n",  # 2100-01-01: more than a day ahead
    ],
)
def test_a_wer_report_without_eventtime_keeps_its_mtime_and_says_so(
    tmp_path, monkeypatch, process_zone, line
):
    _, ts, notes = _wer(
        tmp_path, monkeypatch, f"Version=1\nEventType=APPCRASH\n{line}Sig[0].Value=evil.exe\n"
    )
    assert ts == "2025-06-01T00:00:00+00:00"
    assert notes == [
        "1 WER report(s) have no readable EventTime: @timestamp is the file's modified time"
    ]


def test_shimcachemem_last_modified_is_the_timestamp(monkeypatch):
    row = {  # a vol3 2.28 row, as its JSON renderer prints it
        "Order": 1, "Last Modified": "2023-05-18T08:03:25+00:00", "Last Update": None,
        "Exec Flag": None, "File Size": None, "File Path": "C:\\Windows\\evil.exe",
        "__children": [],
    }  # fmt: skip
    sent: list = []
    monkeypatch.setattr(
        parse_memory, "flush_bulk", lambda c, a, **k: (sent.extend(a), (len(a), 0))[1]
    )
    _, _, implausible = parse_memory._index_vol3_records(
        [row],
        None,
        "case-x-vol-shimcachemem-0",
        "windows.shimcachemem",
        "HOST1",
        "mem.raw",
        "aid",
        "v",
    )
    (a,) = sent
    assert a["_id"] == "cf659d010cc717e0af72"  # as in 0.6.4: the row's content, without @timestamp
    assert (a["_source"].get("@timestamp"), implausible) == ("2023-05-18T08:03:25+00:00", 0)
