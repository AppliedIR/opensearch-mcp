"""Hayabusa's detections are a line of their own, never a host (SPEC-HC-018).

A scan of one machine with the hayabusa phase on reported "across 2
host(s)" and listed "hayabusa" in its checklist as if it were a machine.
The host count is the run's hosts; the detections still show, on one line
that names no host, and a failed Hayabusa reads as the detection's failure,
not a host's. Same stand-in Hayabusa and scan as test_hayabusa_outcomes.
"""

from __future__ import annotations

import shutil
from unittest.mock import MagicMock

import pytest
from test_hayabusa_outcomes import _row, scan  # noqa: F401

from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_status


def _detections(status):
    return [c for c in status["checklist"] if c["artifact"] == "hayabusa-detection"]


def test_one_machine_with_detections_is_one_host(scan):  # noqa: F811
    status = scan()
    assert "across 1 host(s)" in status["message"], status["message"]
    assert status["hosts_total"] == 1 and status["hosts_complete"] == 1
    assert not [c for c in status["checklist"] if c["host"] == "hayabusa"]
    assert len(_detections(status)) == 1 and _row(status)["status"] == "done"


def test_a_failed_hayabusa_leaves_the_machine_complete(scan):  # noqa: F811
    status = scan("error")
    assert _row(status)["status"] == "failed"
    assert status["hosts_total"] == 1 and status["hosts_complete"] == 1


def test_a_failed_hayabusa_is_the_detections_error_not_a_hosts(scan):  # noqa: F811
    status = scan("error")
    (error,) = status["errors"]
    assert not error.startswith("hayabusa/"), error
    assert "hayabusa-detection" in error and "DEV01" in error and "Failed to load rules" in error


def test_anchor_the_detections_still_lead_to_the_hayabusa_query(scan):  # noqa: F811
    status = scan()
    assert any("Query Hayabusa alerts" in s for s in status["next_steps"]), status["next_steps"]


def _hosts(status):
    return status["hosts_complete"], status["hosts_total"]


def _evtx_fails(monkeypatch):
    monkeypatch.setattr(ing, "parse_and_index", MagicMock(side_effect=RuntimeError("bad evtx")))


@pytest.mark.parametrize("mode", ["ok", "error"])
def test_a_failed_artifact_counts_as_without_hayabusa(scan, monkeypatch, mode):  # noqa: F811
    _evtx_fails(monkeypatch)
    twin = scan(no_hb=True)
    shutil.rmtree(ingest_status._STATUS_DIR)  # the same run id: a fresh status
    assert not _detections(twin) and twin["checklist"][0]["status"] == "failed", twin
    assert _hosts(scan(mode)) == _hosts(twin) == (1, 1)


@pytest.mark.parametrize("mode", ["ok", "error", "empty", "none"])
def test_every_hayabusa_outcome_leaves_complete_hosts_complete(scan, mode):  # noqa: F811
    assert _hosts(scan(mode)) == (1, 1)


def test_the_detections_line_names_no_host(scan):  # noqa: F811
    assert [c["host"] for c in _detections(scan())] == [""]
