"""With hayabusa absent, the active case's zero says so, whatever other cases hold.

idx_list_detections counted every case's Hayabusa indices, so another
case's alerts hid the "not installed" text from a case that had none. The
cluster is a stand-in that counts by pattern over a fixed set of indices.
"""

from __future__ import annotations

import fnmatch
import shutil
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import server as srv

_which = shutil.which


def _cluster(monkeypatch, indices: dict, branch: str, installed: bool):
    def count(index, **kw):
        patterns = [p.strip() for p in index.split(",")]
        total = sum(
            n for name, n in indices.items() if any(fnmatch.fnmatchcase(name, p) for p in patterns)
        )
        return {"count": total}

    def which(name, *a, **k):
        if name == "hayabusa":
            return "/usr/local/bin/hayabusa" if installed else None
        return _which(name, *a, **k)

    client = MagicMock()
    client.count.side_effect = count
    if branch == "no sigma plugin":
        client.transport.perform_request.side_effect = RuntimeError("404 No detectors found")
    else:
        client.transport.perform_request.return_value = {"total_findings": 0, "findings": []}
    monkeypatch.setattr(srv, "_get_os", lambda: client)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
    monkeypatch.setattr(srv, "_get_active_case", lambda: "case-a")
    monkeypatch.setattr(shutil, "which", which)
    return srv.idx_list_detections()["suggestion"]


BRANCHES = ["no sigma plugin", "no sigma findings"]


@pytest.mark.parametrize("branch", BRANCHES)
def test_another_cases_alerts_dont_hide_the_absent_hayabusa(monkeypatch, branch):
    indices = {"case-case-b-hayabusa-host9": 372, "case-case-a-evtx-host1": 5000}
    suggestion = _cluster(monkeypatch, indices, branch, installed=False)
    assert srv._HAYABUSA_ABSENT in suggestion, suggestion
    assert "372" not in suggestion and "Hayabusa alerts available" not in suggestion


@pytest.mark.parametrize("branch", BRANCHES)
def test_the_active_cases_own_alerts_are_counted_and_pointed_to(monkeypatch, branch):
    indices = {
        "case-case-a-hayabusa-host1": 124,
        "case-case-b-hayabusa-host9": 372,
        "case-case-a-evtx-host1": 5000,
    }
    suggestion = _cluster(monkeypatch, indices, branch, installed=False)
    assert "124 Hayabusa alerts" in suggestion, suggestion
    assert "index='case-case-a-hayabusa-*'" in suggestion, suggestion
    assert "496" not in suggestion and srv._HAYABUSA_ABSENT not in suggestion
