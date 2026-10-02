"""With hayabusa missing, an evtx ingest and the detections list say so.

The detection phase only ran when hayabusa was on the PATH, so without it
nothing was logged or written and the status read "Ingest complete"; with
its rules missing, the detection row read done with 0 alerts. And
idx_list_detections answered "0 Hayabusa alerts" the same way whether or not
anything could have produced one. Ingests run in-process with the cluster
stubbed; the evtx parsing and the hayabusa batch are real.
"""

from __future__ import annotations

import argparse
import shutil
from unittest import mock

import pytest
from _helpers import make_windows_tree

from opensearch_mcp import ingest, ingest_status
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import server as srv

_which = shutil.which


def _hayabusa(monkeypatch, installed: bool) -> None:
    def which(name, *a, **k):
        if name == "hayabusa":
            return "/usr/local/bin/hayabusa" if installed else None
        return _which(name, *a, **k)

    monkeypatch.setattr(shutil, "which", which)


@pytest.fixture
def evtx_ingest(tmp_path, monkeypatch):
    """Run an evtx ingest of one host and return idx_ingest_status's view."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "vhir" / "ingest-status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-hayabusa-absent")
    for name in (
        "get_client",
        "_preflight_shard_capacity",
        "_ensure_case_active",
        "_warn_if_mapping_upgrade_required",
        "AuditWriter",
    ):
        monkeypatch.setattr(cli, name, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    root = tmp_path / "evidence"
    make_windows_tree(root / "host-a")

    def run() -> dict:
        args = argparse.Namespace(
            path=str(root / "host-a"),
            case="c1",
            hostname="host-a",
            include="evtx",
            yes=True,
            skip_triage=True,
        )
        cli.cmd_ingest(args)
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status

    return run


class TestTheIngestStatus:
    def test_hayabusa_not_installed(self, evtx_ingest, monkeypatch):
        _hayabusa(monkeypatch, installed=False)
        status = evtx_ingest()
        assert status["message"] == "Ingest complete with 1 error(s)."
        (error,) = status["errors"]
        assert error.startswith("hayabusa/hayabusa-detection: detections skipped: hayabusa not")
        assert "Install hayabusa on the PATH" in error

    def test_hayabusa_rules_missing(self, evtx_ingest, monkeypatch):
        """Not done with 0 alerts."""
        _hayabusa(monkeypatch, installed=True)
        monkeypatch.setattr(ingest, "_resolve_hayabusa_rules_dir", lambda: None)
        status = evtx_ingest()
        assert status["message"] == "Ingest complete with 1 error(s)."
        assert status["errors"] == ["hayabusa/hayabusa-detection: host-a: rules_not_found"]

    def test_hayabusa_ran(self, evtx_ingest, monkeypatch):
        _hayabusa(monkeypatch, installed=True)
        monkeypatch.setattr(ingest, "run_hayabusa_batch", lambda *a, **k: {"host-a": 5})
        status = evtx_ingest()
        assert status["message"].startswith("Ingest complete. ")
        assert "errors" not in status


@pytest.fixture
def detections(monkeypatch):
    """idx_list_detections on a cluster with no Hayabusa alerts, with the
    Security Analytics plugin missing or present."""
    client = mock.MagicMock()
    client.count.return_value = {"count": 0}
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)

    def run(plugin: bool) -> str:
        if plugin:
            client.transport.perform_request.return_value = {"findings": []}
        else:
            client.transport.perform_request.side_effect = RuntimeError("404 security_analytics")
        return srv.idx_list_detections()["suggestion"]

    return run


class TestTheDetectionsList:
    @pytest.mark.parametrize("plugin", [False, True], ids=["no sigma plugin", "sigma plugin"])
    def test_hayabusa_not_installed(self, detections, monkeypatch, plugin):
        _hayabusa(monkeypatch, installed=False)
        assert "Hayabusa not installed" in detections(plugin)

    @pytest.mark.parametrize("plugin", [False, True], ids=["no sigma plugin", "sigma plugin"])
    def test_hayabusa_installed(self, detections, monkeypatch, plugin):
        _hayabusa(monkeypatch, installed=True)
        suggestion = detections(plugin)
        assert "Hayabusa runs during evtx ingest if installed." in suggestion
        assert "not installed" not in suggestion
