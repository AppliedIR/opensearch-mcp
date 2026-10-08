"""An input file that can't be read fails its own artifact, not the whole scan.

The file's sha256 was taken before the per-artifact error handling, so a
PermissionError on one file ended the scan and left every later artifact
`pending`. Synthetic: the parsers are stubs and the hash raises for the files
named unreadable.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

FILES = {
    "amcache": "Windows/AppCompat/Programs/Amcache.hve",
    "shimcache": "Windows/System32/config/SYSTEM",
    "srum": "Windows/System32/sru/SRUDB.dat",
    "firewall": "Windows/System32/LogFiles/Firewall/pfirewall.log",
}
EVTX = ("Security.evtx", "System.evtx")


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _host(tmp_path):
    root = tmp_path / "HOST1"
    h = DiscoveredHost(hostname="HOST1", volume_root=root, evtx_dir=root / "evtx")
    h.evtx_dir.mkdir(parents=True)
    for name in EVTX:
        (h.evtx_dir / name).write_bytes(b"\0" * 70000)
    for artifact, rel in FILES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"x")
        h.artifacts.append((artifact, root / rel))
    return h


def _run(tmp_path, unreadable=()):
    def sha256(path):
        if Path(path).name in unreadable:
            raise PermissionError(13, "Permission denied", str(path))
        return f"h-{Path(path).name}"

    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.sha256_file", side_effect=sha256),
        patch("opensearch_mcp.ingest.evtx_truncation", return_value=[]),
        patch("opensearch_mcp.ingest.parse_and_index", return_value=(5, 0, 0)),
        patch("opensearch_mcp.ingest.run_and_ingest", return_value=(7, 0, 0)),
        patch("opensearch_mcp.parse_srum.parse_srum", return_value=(9, 0, "", "completed")),
        patch("opensearch_mcp.ingest._run_custom_parser", return_value=(3, 0, 0)),
    ):
        ingest(
            hosts=[_host(tmp_path)],
            client=client,
            audit=audit,
            case_id="c1",
            include={"amcache", "shimcache", "srum", "firewall"},
            status_pid=os.getpid(),
            status_run_id="run-unreadable",
        )
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    rows = {r["artifact"]: r for r in status["checklist"]}
    return rows, audit


def _hashes(audit, tool):
    return [
        c.kwargs.get("input_sha256s")
        for c in audit.log.call_args_list
        if c.kwargs.get("tool") == f"ingest_{tool}"
    ]


@pytest.mark.parametrize(
    "artifact, name",
    [
        ("amcache", "Amcache.hve"),
        ("shimcache", "SYSTEM"),
        ("srum", "SRUDB.dat"),
        ("firewall", "pfirewall.log"),
        ("evtx", "System.evtx"),
    ],
)
def test_an_unreadable_file_fails_only_its_artifact(tmp_path, status_dir, artifact, name):
    rows, _ = _run(tmp_path, unreadable={name})
    assert rows[artifact]["status"] == "failed"
    assert name in rows[artifact]["detail"] and "Permission denied" in rows[artifact]["detail"]
    others = {a: r["status"] for a, r in rows.items() if a != artifact}
    assert set(others.values()) == {"done"}, others
    control, _ = _run(tmp_path / "control")
    for other in others:  # each other artifact submits what it does with nothing unreadable
        assert rows[other]["detail"] == control[other]["detail"], other


def test_the_readable_evtx_beside_an_unreadable_one_is_indexed(tmp_path, status_dir):
    rows, audit = _run(tmp_path, unreadable={"System.evtx"})
    assert rows["evtx"]["status"] == "failed"
    # the failed file's entry carries no hash rather than an empty one
    assert sorted(map(tuple, _hashes(audit, "evtx"))) == [(), ("h-Security.evtx",)]


def test_readable_files_are_still_hashed_into_the_audit(tmp_path, status_dir):
    rows, audit = _run(tmp_path)
    assert {r["status"] for r in rows.values()} == {"done"}
    assert _hashes(audit, "amcache") == [["h-Amcache.hve"]]
    assert _hashes(audit, "srum") == [["h-SRUDB.dat"]]
    assert _hashes(audit, "firewall") == [["h-pfirewall.log"]]
    assert sorted(map(tuple, _hashes(audit, "evtx"))) == [("h-Security.evtx",), ("h-System.evtx",)]
