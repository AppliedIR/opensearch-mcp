"""Velociraptor's Timestamp becomes @timestamp, and a file with no time
field says so in the ingest status.

Auto-detection didn't know Velociraptor's `Timestamp` (an epoch float), so
those documents had no @timestamp, and a file with no recognised time column
(Kansa's `LastWriteTimeUtc`) was ingested without a word: both disappeared
from idx_timeline. The client stand-in keeps what bulk sends.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from opensearchpy.serializer import JSONSerializer

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status, parse_delimited, parse_json, paths
from opensearch_mcp import server as srv


class _Client:
    transport = SimpleNamespace(serializer=JSONSerializer())

    def __init__(self):
        self.sent: list[dict] = []
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
            self.sent.append(json.loads(source))
            items.append({op: {"_index": m[op]["_index"], "_id": m[op]["_id"], "status": 201}})
        return {"errors": False, "items": items, "took": 1}


@pytest.fixture(autouse=True)
def _fresh_list():
    """NO_TIME_FIELD lives for the process (one ingest per worker)."""
    missed = getattr(paths, "NO_TIME_FIELD", [])
    missed.clear()
    yield
    missed.clear()


def _json(tmp_path, records) -> list[dict]:
    data = tmp_path / "Netstat.json"
    data.write_text("".join(json.dumps(r) + "\n" for r in records))
    client = _Client()
    parse_json.ingest_json(data, client, "case-x-json-vr-h", "h")
    return client.sent


def test_a_velociraptor_epoch_timestamp_is_the_time(tmp_path):
    (doc,) = _json(tmp_path, [{"Timestamp": 1675036674.3242571, "Pid": 4}])
    assert doc["@timestamp"] == "2023-01-29T23:57:54.324257+00:00"


def test_a_microsecond_epoch_is_read_as_microseconds(tmp_path):
    """Velociraptor's own logs carry 16-digit microsecond epochs; read as
    milliseconds they'd be year 55041 and abort the file."""
    docs = _json(tmp_path, [{"Timestamp": 1675036674324257, "msg": "x"}] * 2)
    assert [d["@timestamp"][:19] for d in docs] == ["2023-01-29T23:57:54"] * 2


def test_a_file_with_no_time_field_says_so_in_the_status(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    data = tmp_path / "rd01-PrefetchListing.csv"
    data.write_text("FullName,LastWriteTimeUtc\nC:\\\\x.pf,2023-01-29T23:57:54Z\n")
    parse_delimited.ingest_delimited(data, _Client(), "case-c1-delim-h", "h")
    cli._write_bg_status("c1", "run-tf", "complete", "h", "delimited", "2026-10-02T00:00:00Z")
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    (warning,) = [w for w in status.get("warnings", []) if "No time field" in w]
    assert "rd01-PrefetchListing.csv" in warning and "time_field=" in warning


def test_a_detected_time_field_is_unchanged_and_quiet(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    data = tmp_path / "events.csv"
    data.write_text("timestamp,what\n2026-01-01T00:00:00Z,a\n")
    client = _Client()
    parse_delimited.ingest_delimited(data, client, "case-c1-delim-h", "h")
    assert client.sent[0]["@timestamp"] == "2026-01-01T00:00:00Z"
    cli._write_bg_status("c1", "run-tf2", "complete", "h", "delimited", "2026-10-02T00:00:00Z")
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert not [w for w in status.get("warnings", []) if "No time field" in w]
