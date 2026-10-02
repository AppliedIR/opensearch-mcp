"""Hayabusa alerts are indexed with their time.

Hayabusa writes local time as "2022-11-28 18:48:24.526 +00:00", which
@timestamp's date format rejects, and the batch didn't name the column, so
every alert went in without a time. These run the real batch, parser and
bulk path with a stand-in hayabusa that writes a CSV in its format; values
are synthetic.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from opensearchpy.serializer import JSONSerializer

from opensearch_mcp import ingest, parse_delimited

HEADER = '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details"\n'
ROWS = [
    ("2022-11-28 18:48:24.526", "Service Terminated", "low", 7023, 43995),
    ("2022-11-28 18:49:29.033", "Computer Uptime", "info", 6013, 44100),
    ("2022-11-28 18:50:01.000", "Logon", "info", 4624, 44120),
]


def _csv(offset: str, shift_hours: int) -> str:
    from datetime import datetime, timedelta

    lines = [HEADER]
    for ts, title, level, eid, rid in ROWS:
        local = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f") + timedelta(hours=shift_hours)
        stamp = local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + f" {offset}"
        lines.append(f'"{stamp}","{title}","{level}","HOST-A","Sys",{eid},{rid},"x"\n')
    return "".join(lines)


class _Client:
    """Accepts bulk requests and keeps what was sent."""

    transport = SimpleNamespace(serializer=JSONSerializer())

    def __init__(self):
        self.sent: list[tuple[str, dict]] = []
        self.indices = SimpleNamespace(get_settings=self._fail, simulate_index_template=self._fail)

    @staticmethod
    def _fail(**kw):
        raise RuntimeError("not modelled")

    def bulk(self, *a, body=None, **kw):
        lines = [x for x in body.split("\n") if x]
        items = []
        for meta, source in zip(lines[0::2], lines[1::2]):
            m = json.loads(meta)
            op = next(iter(m))
            self.sent.append((m[op]["_id"], json.loads(source)))
            items.append({op: {"_index": m[op]["_index"], "_id": m[op]["_id"], "status": 201}})
        return {"errors": False, "items": items, "took": 1}


@pytest.fixture
def hayabusa(tmp_path, monkeypatch):
    """A hayabusa on the PATH that writes the given CSV wherever -o points."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fixture = tmp_path / "alerts.csv"
    (bindir / "hayabusa").write_text(
        "#!/bin/sh\n"
        'out=""; prev=""\n'
        'for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done\n'
        f'cp "{fixture}" "$out"\n'
    )
    (bindir / "hayabusa").chmod(0o755)
    rules = tmp_path / "rules"
    (rules / "config").mkdir(parents=True)
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setenv("HAYABUSA_RULES_DIR", str(rules))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(ingest, "vhir_dir", lambda: tmp_path / "home" / ".vhir")

    def run(csv_text: str) -> list[tuple[str, dict]]:
        fixture.write_text(csv_text)
        client = _Client()
        host = SimpleNamespace(hostname="host-a", evtx_dir=str(evtx))
        result = ingest.run_hayabusa_batch([host], client, "rowcase")
        assert result == {"host-a": len(ROWS)}, result
        return client.sent

    return run


@pytest.mark.parametrize("offset,shift", [("+00:00", 0), ("-05:00", -5)], ids=["UTC", "UTC-5"])
def test_every_alert_has_its_time_in_utc(hayabusa, offset, shift):
    sent = hayabusa(_csv(offset, shift))
    times = sorted(doc["@timestamp"] for _, doc in sent)
    assert times == [
        "2022-11-28T18:48:24.526000+00:00",
        "2022-11-28T18:49:29.033000+00:00",
        "2022-11-28T18:50:01+00:00",
    ]
    assert all(doc["Timestamp"].endswith(offset) for _, doc in sent)  # raw kept


def test_a_rerun_overwrites_the_same_alerts():
    """@timestamp isn't part of a document's id, so a re-run of the same
    evidence repairs the alerts already indexed instead of duplicating them."""
    record = {"Timestamp": "2022-11-28 18:48:24.526 +00:00", "RuleTitle": "x"}
    before = parse_delimited._doc_id(
        "i", dict(record), volatile_keys=parse_delimited._DELIM_VOLATILE
    )
    after = parse_delimited._doc_id(
        "i",
        dict(record, **{"@timestamp": "2022-11-28T18:48:24.526000+00:00"}),
        volatile_keys=parse_delimited._DELIM_VOLATILE,
    )
    assert before == after


def test_other_time_strings_are_left_as_they_were(tmp_path):
    data = tmp_path / "events.csv"
    data.write_text("when,what\n2026-01-01T00:00:00Z,a\nnot a time,b\n")
    client = _Client()
    parse_delimited.ingest_delimited(data, client, "case-x-delim-h", "h", time_field="when")
    assert sorted(doc["@timestamp"] for _, doc in client.sent) == [
        "2026-01-01T00:00:00Z",
        "not a time",
    ]


def test_a_time_out_of_range_in_utc_keeps_its_raw_value(tmp_path):
    """9999-12-31 23:59:59 at -01:00 is past the year 9999 in UTC: that row
    keeps its text and the others are still converted, not the file aborted."""
    data = tmp_path / "alerts.csv"
    data.write_text(
        "Timestamp,RuleTitle\n"
        "2022-11-28 18:48:24.526 +00:00,a\n"
        "9999-12-31 23:59:59.999 -01:00,b\n"
        "2022-11-28 18:49:29.033 -05:00,c\n"
    )
    client = _Client()
    parse_delimited.ingest_delimited(
        data, client, "case-x-hayabusa-h", "h", time_field="Timestamp"
    )
    got = {doc["RuleTitle"]: doc["@timestamp"] for _, doc in client.sent}
    assert got == {
        "a": "2022-11-28T18:48:24.526000+00:00",
        "b": "9999-12-31 23:59:59.999 -01:00",
        "c": "2022-11-28T23:49:29.033000+00:00",
    }
