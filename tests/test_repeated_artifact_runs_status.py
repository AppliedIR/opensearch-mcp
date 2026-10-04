"""One artifact that runs more than once on a host keeps every run in its status.

Jumplists, lnk, shellbags and timeline run once per user profile, and WER and
OpenSSH logs once per directory, but each host has one status entry per
artifact. Each run used to overwrite it: a failed run followed by a good one
read `done`, and the counts were the last run's. Everything here is synthetic:
the tool runs and the custom parser are stubs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _host(tmp_path, name, users=("alice", "bob")):
    root = tmp_path / name
    h = DiscoveredHost(hostname=name, volume_root=root)
    for u in users:
        recent = root / "Users" / u / "AppData/Roaming/Microsoft/Windows/Recent"
        recent.mkdir(parents=True)
        h.artifacts.append(("jumplists", recent))
    return h


def _wer_host(tmp_path, name="HOST1"):
    root = tmp_path / name
    h = DiscoveredHost(hostname=name, volume_root=root)
    for sub in ("ReportArchive", "ReportQueue"):
        d = root / "ProgramData/Microsoft/Windows/WER" / sub
        d.mkdir(parents=True)
        h.artifacts.append(("wer", d))
    return h


def _by_user(results):
    """A stub run: `results[user]` is (indexed, skipped, bulk_failed) or an exception."""

    def run(*args, **kwargs):
        path = kwargs.get("artifact_path") or args[1]
        r = results[next(p for p in Path(path).parts if p in results)]
        if isinstance(r, Exception):
            raise r
        return r

    return run


def _ingest(hosts, tools=None, custom=None):
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    stubs = [patch("opensearch_mcp.ingest.sha256_file", return_value="h")]
    if tools is not None:
        stubs.append(patch("opensearch_mcp.ingest.run_and_ingest", side_effect=tools))
    if custom is not None:
        stubs.append(patch("opensearch_mcp.ingest._run_custom_parser", side_effect=custom))
    for s in stubs:
        s.start()
    try:
        ingest(
            hosts=hosts,
            client=client,
            audit=audit,
            case_id="c1",
            status_pid=os.getpid(),
            status_run_id="run-repeat",
        )
    finally:
        for s in stubs:
            s.stop()
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status


def _row(status, artifact, host="HOST1"):
    (row,) = [c for c in status["checklist"] if c["host"] == host and c["artifact"] == artifact]
    return row


def _raw(artifact, host="HOST1"):
    (path,) = ingest_status._STATUS_DIR.glob("*.json")
    data = json.loads(path.read_text())
    (h,) = [h for h in data["hosts"] if h["hostname"] == host]
    (a,) = [a for a in h["artifacts"] if a["name"] == artifact]
    return a


def test_a_failed_run_before_a_good_one_still_reads_failed(tmp_path, status_dir):
    tools = _by_user({"alice": RuntimeError("JLECmd failed (exit 3): bad file"), "bob": (7, 0, 0)})
    status = _ingest([_host(tmp_path, "HOST1")], tools=tools)
    row = _row(status, "jumplists")
    assert row["status"] == "failed"
    assert "JLECmd failed (exit 3): bad file" in row["detail"]
    assert status["errors"] == ["HOST1/jumplists: JLECmd failed (exit 3): bad file"]
    assert _raw("jumplists")["indexed"] == 7
    assert status["total_indexed"] == 7


def test_a_failed_run_after_a_good_one_reads_failed(tmp_path, status_dir):
    tools = _by_user({"alice": (5, 0, 0), "bob": RuntimeError("JLECmd failed (exit 3): bad file")})
    status = _ingest([_host(tmp_path, "HOST1")], tools=tools)
    assert _row(status, "jumplists")["status"] == "failed"
    assert _raw("jumplists")["indexed"] == 5


def test_a_failure_with_an_empty_message_still_reads_failed(tmp_path, status_dir):
    # a bare `assert` in a parser raises AssertionError with no message
    tools = _by_user({"alice": AssertionError(), "bob": (7, 0, 0)})
    status = _ingest([_host(tmp_path, "HOST1")], tools=tools)
    assert _row(status, "jumplists")["status"] == "failed"


def test_two_good_runs_add_up(tmp_path, status_dir):
    status = _ingest(
        [_host(tmp_path, "HOST1")],
        tools=_by_user({"alice": (5, 0, 0), "bob": (7, 0, 0)}),
    )
    row = _row(status, "jumplists")
    assert row["status"] == "done"
    assert row["detail"].startswith("12 docs submitted")
    assert status["total_indexed"] == 12


def test_events_an_earlier_run_lost_still_warn(tmp_path, status_dir):
    status = _ingest(
        [_host(tmp_path, "HOST1")],
        tools=_by_user({"alice": (0, 0, 4), "bob": (7, 0, 0)}),
    )
    assert status["bulk_failed"] == 4
    assert any("4 events rejected" in w for w in status.get("warnings", []))


@pytest.mark.parametrize(
    "result, status_, detail",
    [((5, 0, 0), "done", "5 docs submitted"), (RuntimeError("boom"), "failed", "boom")],
)
def test_a_single_run_reads_as_before(tmp_path, status_dir, result, status_, detail):
    status = _ingest(
        [_host(tmp_path, "HOST1", users=("alice",))], tools=_by_user({"alice": result})
    )
    row = _row(status, "jumplists")
    assert (row["status"], row["detail"]) == (status_, detail)


def test_a_custom_artifact_keeps_a_failed_directory(tmp_path, status_dir):
    custom = _by_user({"ReportArchive": RuntimeError("parser fault"), "ReportQueue": (3, 0, 0)})
    status = _ingest([_wer_host(tmp_path)], custom=custom)
    row = _row(status, "wer")
    assert (row["status"], row["detail"]) == ("failed", "parser fault")
    assert _raw("wer")["indexed"] == 3


def test_a_custom_artifact_adds_up_its_directories(tmp_path, status_dir):
    custom = _by_user({"ReportArchive": (2, 0, 1), "ReportQueue": (3, 0, 0)})
    status = _ingest([_wer_host(tmp_path)], custom=custom)
    assert _row(status, "wer")["detail"].startswith("5 docs submitted")
    assert status["bulk_failed"] == 1


def test_the_failure_shows_while_a_later_host_runs(tmp_path, status_dir):
    seen = {}
    first = _by_user({"alice": RuntimeError("bad file"), "bob": (7, 0, 0), "carol": (3, 0, 0)})

    def run(*args, **kwargs):
        if kwargs["hostname"] == "HOST2":
            (live,) = srv.idx_ingest_status(case_id="c1")["ingests"]
            seen["row"] = _row(live, "jumplists", host="HOST1")
        return first(*args, **kwargs)

    hosts = [_host(tmp_path, "HOST1"), _host(tmp_path, "HOST2", users=("carol",))]
    _ingest(hosts, tools=run)
    assert seen["row"]["status"] == "failed"
    assert seen["row"]["detail"] == "bad file"
