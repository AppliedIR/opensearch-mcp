"""The detection step's status write keeps the ingest's own diagnostics.

After an ingest, the Hayabusa step rewrote the status checklist without each
artifact's error and wrote the final record without the rejected-event count
or its reason, so idx_ingest_status lost them (25 rejected read as 0; "RECmd
missing" as "unknown error"). Runs cmd_ingest and reads idx_ingest_status,
with hayabusa absent and present; the cluster and the parsers are stand-ins.
"""

from __future__ import annotations

import argparse
import shutil
from unittest import mock

import pytest
from _helpers import make_windows_tree

from opensearch_mcp import bulk, ingest, ingest_status
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import server as srv

_which = shutil.which
_REASON = "mapper_parsing_exception: failed to parse field [x]"


@pytest.fixture
def scan(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "vhir" / "ingest-status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-diagnostics")
    for name in (
        "get_client",
        "_preflight_shard_capacity",
        "_ensure_case_active",
        "_warn_if_mapping_upgrade_required",
        "AuditWriter",
    ):
        monkeypatch.setattr(cli, name, mock.MagicMock(), raising=False)
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    root = tmp_path / "evidence" / "host-a"
    make_windows_tree(root)
    (root / "Windows/System32/winevt/Logs/Security.evtx").write_bytes(b"\0" * 70000)

    def parse_and_index(**kw):  # 100 indexed, 25 rejected
        bulk._tls.last_bulk_reason = _REASON
        return 100, 0, 25

    def run_and_ingest(**kw):
        raise RuntimeError("RECmd missing")

    monkeypatch.setattr(ingest, "parse_and_index", parse_and_index)
    monkeypatch.setattr(ingest, "run_and_ingest", run_and_ingest)
    monkeypatch.setattr(ingest, "_safe_count", lambda *a: 0)
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)

    def run(installed: bool) -> dict:
        def which(name, *a, **k):
            if name == "hayabusa":
                return "/usr/local/bin/hayabusa" if installed else None
            return _which(name, *a, **k)

        monkeypatch.setattr(shutil, "which", which)
        if installed:

            def run_hayabusa_batch(*a, **k):  # its own bulk writes set their reason
                bulk._tls.last_bulk_reason = "hayabusa: version_conflict_engine_exception"
                return {"host-a": 5}

            monkeypatch.setattr(ingest, "run_hayabusa_batch", run_hayabusa_batch)
        args = argparse.Namespace(
            path=str(root),
            case="c1",
            hostname="host-a",
            include="evtx,amcache",
            yes=True,
            skip_triage=True,
        )
        cli.cmd_ingest(args)
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status

    return run


@pytest.mark.parametrize("installed", [False, True], ids=["hayabusa absent", "hayabusa present"])
def test_diagnostics_survive(scan, installed):
    status = scan(installed)
    assert any(i["artifact"] == "hayabusa-detection" for i in status["checklist"]), status
    assert "host-a/amcache: RECmd missing" in status["errors"], status["errors"]
    assert status["bulk_failed"] == 25, status
    (warning,) = [w for w in status.get("warnings", []) if "rejected" in w]
    assert warning.startswith("25 events rejected"), warning
    assert _REASON[:40] in warning, warning  # the ingest's reason, not hayabusa's
    assert "version_conflict" not in warning, warning
