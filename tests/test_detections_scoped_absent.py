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
import yaml
from sift_common import host_identity

from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc

_which = shutil.which


def c12(case: str) -> str:
    """The case's identity, as a case made by 0.7: another row may have
    made the same case id first, without a naming version."""
    d = wc.case_dir_for(case)
    meta = yaml.safe_load((d / "CASE.yaml").read_text()) or {}
    if meta.get("naming_version") != 2:
        meta["naming_version"] = 2
        (d / "CASE.yaml").write_text(yaml.safe_dump(meta))
    return host_identity.ensure_case_uuid(d, 2)[0]


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
    indices = {f"case-{c12('case-b')}-hayabusa-0": 372, f"case-{c12('case-a')}-evtx-0": 5000}
    suggestion = _cluster(monkeypatch, indices, branch, installed=False)
    assert srv._HAYABUSA_ABSENT in suggestion, suggestion
    assert "372 Hayabusa" not in suggestion and "Hayabusa alerts available" not in suggestion


@pytest.mark.parametrize("branch", BRANCHES)
def test_the_active_cases_own_alerts_are_counted_and_pointed_to(monkeypatch, branch):
    indices = {
        f"case-{c12('case-a')}-hayabusa-0": 124,
        f"case-{c12('case-b')}-hayabusa-0": 372,
        f"case-{c12('case-a')}-evtx-0": 5000,
    }
    suggestion = _cluster(monkeypatch, indices, branch, installed=False)
    assert "124 Hayabusa alerts" in suggestion, suggestion
    assert f"index='case-{c12('case-a')}-hayabusa-*'" in suggestion, suggestion
    assert "496 Hayabusa" not in suggestion and srv._HAYABUSA_ABSENT not in suggestion
