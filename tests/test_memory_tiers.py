"""A memory ingest accepts only the tiers the worker does.

The tool previewed 24 plugins for tier 4 and 8 for tier 0, and a real run
answered `started` before the worker exited on `invalid choice`, even with
plugins named, because the worker is always passed --tier. The tool, both
command lines and the worker now read one set of tiers.
"""

from __future__ import annotations

import argparse
from unittest import mock

import pytest

from opensearch_mcp import (
    ingest_cli,
    ingest_status,
    mappings,
    parse_memory,
    paths,
    shard_capacity,
    vhir_plugin,
)
from opensearch_mcp import server as srv


@pytest.fixture
def memory(tmp_path, monkeypatch):
    """idx_ingest_memory up to the spawn, which is recorded, not run."""
    case = tmp_path / "cases" / "CASE-T"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-T\n")
    (tmp_path / "vhir").mkdir()
    (tmp_path / "vhir" / "active_case").write_text(str(case))
    monkeypatch.setattr(paths, "vhir_dir", lambda: tmp_path / "vhir")
    monkeypatch.setattr(srv, "_get_active_case", lambda: "CASE-T")
    monkeypatch.setattr(srv, "get_client", lambda: mock.MagicMock())
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    monkeypatch.setattr(mappings, "ensure_winlog_pipeline", lambda c: {"status": "ok"})
    monkeypatch.setattr(ingest_status, "write_status", lambda *a, **k: None)
    monkeypatch.setattr(ingest_status, "read_active_ingests", lambda *a, **k: [])
    spawned: list = []
    monkeypatch.setattr(
        srv, "_spawn_ingest", lambda cmd, *a: spawned.append(cmd) or mock.MagicMock(pid=4242)
    )
    image = tmp_path / "evidence" / "mem.img"
    image.parent.mkdir()
    image.write_bytes(b"\0" * 16)

    def call(**kw):
        return srv.idx_ingest_memory(path=str(image), hostname="h", **kw)

    return call, spawned


@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize(
    "kw",
    [{"tier": 4}, {"tier": 0}, {"tier": 4, "plugins": ["windows.pslist"]}],
    ids=["tier 4", "tier 0", "tier 4 with plugins"],
)
def test_a_tier_the_worker_refuses_is_an_error(memory, kw, dry_run):
    call, spawned = memory
    resp = call(dry_run=dry_run, **kw)
    assert "[1, 2, 3]" in resp.get("error", ""), resp
    assert "plugins" not in resp and "status" not in resp
    assert spawned == []


@pytest.mark.parametrize("tier,count", [(1, 8), (2, 17), (3, 24)])
def test_the_tiers_are_unchanged(memory, tier, count):
    call, spawned = memory
    assert call(tier=tier, dry_run=True)["plugin_count"] == count
    assert call(tier=tier, dry_run=False)["status"] == "started"
    assert len(spawned) == 1


def test_one_set_of_tiers():
    pm = parse_memory
    assert pm.TIERS == {1: pm.TIER_1, 2: pm.TIER_2, 3: pm.TIER_3}


def test_the_command_line_refuses_the_same_tiers(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv", ["opensearch-ingest", "memory", "m.img", "--hostname", "h", "--tier", "4"]
    )
    with pytest.raises(SystemExit) as exit_:
        ingest_cli.main()
    assert exit_.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_the_vhir_command_refuses_the_same_tiers(capsys):
    parser = argparse.ArgumentParser()
    vhir_plugin.register(parser.add_subparsers(dest="cmd"), set())
    with pytest.raises(SystemExit):
        parser.parse_args(["ingest-memory", "m.img", "--hostname", "h", "--tier", "4"])
    assert "invalid choice" in capsys.readouterr().err
    assert (
        parser.parse_args(["ingest-memory", "m.img", "--hostname", "h", "--tier", "3"]).tier == 3
    )
