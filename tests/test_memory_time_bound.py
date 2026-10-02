"""A memory record's time becomes @timestamp only when it's plausible.

vol3 reports load times like 0027 and 9905 for some DLLs, and each became an
event on the timeline. A time before 1990 or more than a day ahead is now
left out of @timestamp (the raw field is kept), and the ingest status says
how many. Values are synthetic, in vol3's form.
"""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from unittest import mock

import pytest
from opensearchpy.serializer import JSONSerializer

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import parse_memory as pm
from opensearch_mcp import server as srv

LOAD_TIMES = [
    "0027-09-01T06:05:39+00:00",
    "1601-01-01T00:03:08+00:00",
    "1970-01-01T00:00:00+00:00",
    "9905-04-20T07:14:58+00:00",
    "2024-03-01T12:00:00+00:00",
]


def _records():
    return [
        {"PID": 4, "Base": hex(0x1000 * (i + 1)), "Name": f"m{i}.dll", "LoadTime": t}
        for i, t in enumerate(LOAD_TIMES)
    ]


class _Client:
    transport = SimpleNamespace(serializer=JSONSerializer())

    def __init__(self):
        self.sent: list[dict] = []
        self.indices = SimpleNamespace(get_settings=self._no, simulate_index_template=self._no)

    @staticmethod
    def _no(**kw):
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


def test_only_a_plausible_time_becomes_the_timestamp():
    client = _Client()
    count, failed, implausible = pm._index_vol3_records(
        _records(), client, "case-x-vol-dlllist-h", "windows.dlllist", "h", "m.raw", "aid", "v"
    )
    assert (count, failed, implausible) == (5, 0, 4)
    stamped = {d["LoadTime"]: d.get("@timestamp") for d in client.sent}
    assert stamped == {t: (t if t.startswith("2024") else None) for t in LOAD_TIMES}


@pytest.mark.parametrize(
    "value,plausible",
    [
        ("1989-12-31T23:59:59+00:00", False),
        ("1990-01-01T00:00:00+00:00", True),
        ("2023-01-25T14:38:26+00:00", True),
        ("2023-01-25T14:38:26", True),  # no offset: read as UTC
        ("not a time", False),
    ],
)
def test_the_bound(value, plausible):
    assert pm._plausible_time(value) is plausible


def test_a_day_ahead_is_the_limit():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    assert pm._plausible_time((now + timedelta(hours=23)).isoformat())
    assert not pm._plausible_time((now + timedelta(days=2)).isoformat())


def test_the_ingest_status_says_how_many(tmp_path, monkeypatch):
    client = _Client()
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-time-bound")
    monkeypatch.setattr(cli, "get_client", lambda: client)
    for name in (
        "_preflight_shard_capacity",
        "_ensure_case_active",
        "_warn_if_mapping_upgrade_required",
    ):
        monkeypatch.setattr(cli, name, mock.MagicMock())
    audit = mock.MagicMock()
    audit.return_value._next_audit_id.return_value = "aid-1"
    monkeypatch.setattr(cli, "AuditWriter", audit)
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(pm, "_find_vol3", lambda: "true")
    monkeypatch.setattr(pm, "_register_memory_evidence", lambda *a, **k: None)
    monkeypatch.setattr(pm, "run_vol3_plugin", lambda *a, **k: _records())
    image = tmp_path / "m.raw"
    image.write_bytes(b"\0" * 64)
    args = argparse.Namespace(
        path=str(image),
        case="c1",
        hostname="h",
        tier=1,
        plugins="windows.dlllist",
        yes=True,
        timeout=10,
    )
    cli.cmd_ingest_memory(args)
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    (item,) = [i for i in status["checklist"] if i["artifact"] == "windows.dlllist"]
    assert item["detail"] == "5 docs submitted; 4 with an implausible time, @timestamp not set"
