"""An ingest installs the current index templates before it spawns.

Templates install on the first verified connection (`_get_os()`), which no
ingest tool otherwise made: after a restart, an ingest started first created
its indices under the previous templates. Everything below is stubbed — no
template is written to a cluster.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from _helpers import make_windows_tree

from opensearch_mcp import ingest_status, mappings, paths, shard_capacity
from opensearch_mcp import server as srv


@pytest.fixture
def stubs(monkeypatch, tmp_path):
    """The order of template installs and process spawns, and the client."""
    seen: list[str] = []
    client = MagicMock()
    monkeypatch.setattr(srv, "_client", None)
    monkeypatch.setattr(srv, "_client_verified", False)
    monkeypatch.setattr(srv, "get_client", lambda: client)

    def install(_client):
        seen.append("install")
        return {"status": "ok"}

    def popen(cmd, **kwargs):
        seen.append("spawn")
        proc = MagicMock(pid=4242, returncode=None)
        proc.poll.return_value = None
        return proc

    monkeypatch.setattr(mappings, "ensure_winlog_pipeline", install)
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    case = tmp_path / "cases" / "CASE-T"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-T\n")
    (tmp_path / "vhir").mkdir()
    (tmp_path / "vhir" / "active_case").write_text(str(case))
    monkeypatch.setattr(srv, "_get_active_case", lambda: "CASE-T")
    monkeypatch.setattr(paths, "vhir_dir", lambda: tmp_path / "vhir")
    monkeypatch.setattr(ingest_status, "write_status", lambda *a, **k: None)
    monkeypatch.setattr(ingest_status, "read_active_ingests", lambda *a, **k: [])
    return SimpleNamespace(calls=seen, client=client, evidence=_evidence(tmp_path))


def _evidence(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir(exist_ok=True)
    (root / "a.csv").write_text("x,y\n1,2\n")
    (root / "mem.img").write_bytes(b"\0" * 16)
    make_windows_tree(root / "host-a")
    return root


INGESTS = {
    "idx_ingest_delimited": lambda root: srv.idx_ingest_delimited(
        path=str(root / "a.csv"), hostname="h", dry_run=False
    ),
    "idx_ingest_memory": lambda root: srv.idx_ingest_memory(
        path=str(root / "mem.img"), hostname="h", dry_run=False
    ),
    "idx_ingest": lambda root: srv.idx_ingest(
        path=str(root / "host-a"), hostname="h", dry_run=False
    ),
}


@pytest.mark.parametrize("tool", sorted(INGESTS))
def test_templates_install_before_the_spawn(stubs, tool):
    result = INGESTS[tool](stubs.evidence)
    assert result["status"] == "started", result
    assert stubs.calls == ["install", "spawn"]


@pytest.mark.parametrize("tool", sorted(INGESTS))
def test_a_cluster_that_is_down_does_not_stop_the_ingest(stubs, tool):
    """The ingest reports the cluster itself; the install is skipped."""
    stubs.client.cluster.health.side_effect = ConnectionError("cluster down")
    result = INGESTS[tool](stubs.evidence)
    assert result["status"] == "started", result
    assert stubs.calls == ["spawn"]


def test_a_second_ingest_does_not_reinstall(stubs):
    for _ in range(2):
        assert INGESTS["idx_ingest_delimited"](stubs.evidence)["status"] == "started"
    assert stubs.calls == ["install", "spawn", "spawn"]
