"""idx_ingest_memory's start audit entry names the host.

The tool requires the hostname and passes it to the worker, but its start
entry left it out, so until the worker's completion entry a running memory
ingest wasn't a candidate for that host's queries in provenance grading.
"""

from __future__ import annotations

from unittest import mock

from opensearch_mcp import ingest_status, mappings, paths, shard_capacity
from opensearch_mcp import server as srv


def test_the_start_entry_carries_the_hostname(tmp_path, monkeypatch):
    vhir = tmp_path / "vhir"
    case = tmp_path / "cases" / "CASE-T"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-T\n")
    (vhir / "active_case").parent.mkdir(exist_ok=True)
    (vhir / "active_case").write_text(str(case))
    monkeypatch.setattr(paths, "vhir_dir", lambda: vhir)
    monkeypatch.setattr(srv, "_get_active_case", lambda: "CASE-T")
    monkeypatch.setattr(srv, "get_client", lambda: mock.MagicMock())
    monkeypatch.setattr(srv, "_spawn_ingest", lambda *a, **k: mock.MagicMock(pid=4242))
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    monkeypatch.setattr(mappings, "ensure_winlog_pipeline", lambda c: {"status": "ok"})
    monkeypatch.setattr(ingest_status, "write_status", lambda *a, **k: None)
    monkeypatch.setattr(ingest_status, "read_active_ingests", lambda *a, **k: [])
    logged = []
    monkeypatch.setattr(srv.audit, "log", lambda **kw: logged.append(kw) or "aid-1")
    image = tmp_path / "evidence" / "mem.img"
    image.parent.mkdir()
    image.write_bytes(b"\0" * 16)

    resp = srv.idx_ingest_memory(path=str(image), hostname="rd01", dry_run=False)

    assert resp["status"] == "started", resp
    (start,) = [e for e in logged if e["tool"] == "idx_ingest_memory"]
    assert start["params"]["hostname"] == "rd01"
    assert start["params"]["run_id"] and start["input_files"] == [str(image)]
