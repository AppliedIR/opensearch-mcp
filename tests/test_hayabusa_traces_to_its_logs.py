"""Hayabusa detections trace to the logs they came from.

Each detection carries `vhir.ingest_audit_id`, the id of its host's
`ingest_hayabusa` audit entry, as every other parser's records carry theirs;
that entry records the run's id and the evtx files Hayabusa read. A finding
citing a search over detections then traces to those files.
"""

import hashlib
import os
from types import SimpleNamespace

import opensearch_mcp.ingest as ingest
import opensearch_mcp.parse_delimited as parse_delimited

from .test_hayabusa_stale_csv import hb  # noqa: F401


class _Audit:
    def __init__(self):
        self.entries = []

    def _next_audit_id(self, audit_dir=None):
        return "opensearch-ex-20261009-042"

    def log(self, **kw):
        self.entries.append(kw)
        return kw.get("audit_id")


def test_detections_carry_their_entry_which_names_the_evtx_read(hb, tmp_path, monkeypatch):  # noqa: F811
    evtx = tmp_path / "evtx"
    for name in ("Security.evtx", "System.EVTX", "notes.txt"):
        (evtx / name).write_text("x")
    stamped = []

    def ingest_delimited(path, client, index, hostname, **kw):
        stamped.append((kw.get("ingest_audit_id"), len(audit.entries), path))
        return len(path.read_text().splitlines()) - 1, 0, 0, 0

    monkeypatch.setattr(parse_delimited, "ingest_delimited", ingest_delimited)
    audit = _Audit()
    host = SimpleNamespace(hostname="HOST1", evtx_dir=evtx, volume_root=evtx)
    results = ingest.run_hayabusa_batch([host], None, "case1", audit=audit, run_id="run-9")
    assert results == {"HOST1": 2}
    ((aid, written_by_then, csv),) = stamped
    # the run's step, written before its detections: the evtx read, each with
    # its hash and place, and the CSV Hayabusa wrote, hashed
    (entry,) = [
        e for e in audit.entries
        if e["tool"] == "ingest_hayabusa" and "about" not in (e.get("extra") or {})
    ]  # fmt: skip
    assert entry["audit_id"] == aid == "opensearch-ex-20261009-042"
    assert entry in audit.entries[:written_by_then]
    assert entry["params"]["run_id"] == "run-9"
    assert entry["input_files"] == [str(evtx / "Security.evtx"), str(evtx / "System.EVTX")]
    inputs = entry["extra"]["inputs"]
    assert [i["sha256"] for i in inputs] == [hashlib.sha256(b"x").hexdigest()] * 2
    for i in inputs:
        real = os.path.realpath(i["path"])
        assert i["realpath"] == real and i["st_dev"] == os.stat(real).st_dev
        assert isinstance(i["mnt_id"], int)
    (out,) = entry["extra"]["outputs"]
    assert (
        out["path"] == str(csv) and out["sha256"] == hashlib.sha256(csv.read_bytes()).hexdigest()
    )
