"""Whose host names: every name a run's records give counts as the run's
input does, so an AI-written or AI-registered file never confirms or joins a
machine; and what the names scan keeps about a unit reaches the host log.
Values are synthetic."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from unittest import mock

import pytest
from _helpers import make_windows_tree
from sift_common import host_identity as hi

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status, names_scan
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost


def case():
    return wc.case_dir_for(f"orig-{uuid.uuid4().hex[:8]}")


# -- the folders the AI writes, and what the AI registered


@pytest.mark.parametrize("folder", ["extractions", "work", "reports", ".outputs", "DELETE"])
def test_a_file_in_a_folder_the_ai_writes_is_the_ais(folder):
    d = case()
    f = d / folder / "x.csv"
    f.parent.mkdir(parents=True)
    f.write_text("Computer\nWKS01\n")
    assert names_scan.file_origin(d, f) == names_scan.AI_WRITTEN


def test_a_file_directly_in_the_case_folder_is_the_ais_and_evidence_isnt():
    d = case()
    (d / "x.csv").write_text("Computer\nWKS01\n")
    (d / "evidence").mkdir(exist_ok=True)
    (d / "evidence" / "y.csv").write_text("Computer\nWKS01\n")
    assert names_scan.file_origin(d, d / "x.csv") == names_scan.AI_WRITTEN
    assert names_scan.file_origin(d, d / "evidence" / "y.csv") == names_scan.ARTIFACT


def test_a_link_the_ai_left_to_evidence_is_still_the_ais():
    d = case()
    (d / "evidence").mkdir(exist_ok=True)
    real = d / "evidence" / "y.csv"
    real.write_text("Computer\nWKS01\n")
    (d / "work").mkdir()
    (d / "work" / "y.csv").symlink_to(real)
    assert names_scan.file_origin(d, d / "work" / "y.csv") == names_scan.AI_WRITTEN


def test_a_looping_link_is_never_taken_for_evidence():
    d = case()
    (d / "evidence").mkdir(exist_ok=True)
    loop = d / "evidence" / "loop.csv"
    loop.symlink_to(loop)
    assert names_scan.file_origin(d, loop) == names_scan.AI_WRITTEN


def _register(d, path, via=None):
    """An entry as vhir's register_evidence_data writes it (case-mcp passes
    registered_via="mcp")."""
    entry = {"path": str(path.resolve()), "sha256": "0" * 64, "description": "",
             "registered_at": "2026-10-07T00:00:00Z", "registered_by": "ex1"}  # fmt: skip
    if via:
        entry["registered_via"] = via
    reg = d / "evidence.json"
    files = json.loads(reg.read_text())["files"] if reg.exists() else []
    reg.write_text(json.dumps({"files": [*files, entry]}))


def test_evidence_the_ai_registered_is_the_ais_wherever_it_is(tmp_path):
    d = case()
    outside = tmp_path / "share" / "x.csv"  # registered through a link in the case
    outside.parent.mkdir()
    outside.write_text("Computer\nWKS01\n")
    (d / "evidence").mkdir(exist_ok=True)
    (d / "evidence" / "x.csv").symlink_to(outside)
    _register(d, d / "evidence" / "x.csv", via="mcp")
    assert names_scan.file_origin(d, outside) == names_scan.AI_WRITTEN
    assert names_scan.file_origin(d, d / "evidence" / "x.csv") == names_scan.AI_WRITTEN


def test_evidence_the_examiner_registered_stays_evidence():
    d = case()
    (d / "evidence").mkdir(exist_ok=True)
    f = d / "evidence" / "y.csv"
    f.write_text("Computer\nWKS01\n")
    _register(d, f)
    assert names_scan.file_origin(d, f) == names_scan.ARTIFACT


def test_a_folder_the_ai_wrote_gives_the_ais_names_from_its_hives(monkeypatch):
    monkeypatch.setattr(
        names_scan, "registry_names", lambda root: ([("WKS02", "SYSTEM ComputerName")], {})
    )
    d = case()
    folder = d / "work" / "WKS02"
    make_windows_tree(folder)
    host = DiscoveredHost(hostname="WKS02", volume_root=folder)
    unit = names_scan.host_folder_unit(host, d)
    hive = [n for n in unit.names if n.origin != names_scan.FOLDER]
    assert hive and {n.origin for n in hive} == {names_scan.AI_WRITTEN}


# -- the ingest path: the run's input decides


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    (tmp_path / "audit").mkdir()
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setattr(cli, "get_client", lambda: mock.MagicMock())
    for n in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter"):
        monkeypatch.setattr(cli, n, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "stored_counts", lambda *a, **k: {})
    from opensearch_mcp import bulk

    monkeypatch.setattr(bulk, "_flush_with_retry", lambda client, actions, **k: (len(actions), 0))
    written: list[dict] = []

    def stamp_or_refuse(actions, client=None):
        wc.stamp(wc.current(), actions)
        written.extend(a["_source"] for a in actions)

    monkeypatch.setattr(wc, "stamp_or_refuse", stamp_or_refuse)
    return written


def test_an_ai_written_csv_naming_a_confirmed_host_isnt_stored_under_it(run, monkeypatch):
    d = case()
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: d.name)
    u = hi.unit_key("evidence/WKS01")
    key = hi.new_machine_key()
    hi.append_observations(d, [{"kind": "unit", "unit": u, "locator": "evidence/WKS01"}])
    hi.append_decision(d, {"action": "confirm", "args": {"machines": [
        {"key": key, "canonical": "WKS01", "pairs": [[u, "WKS01"]]}]}},
        hi.load(d).obs_offset)  # fmt: skip
    f = d / "work" / "rows.csv"
    f.parent.mkdir()
    f.write_text("when,Computer\n2026-01-01T00:00:00Z,WKS01\n")
    cli.cmd_ingest_delimited(argparse.Namespace(
        path=str(f), case=None, hostname="rows", time_field="when"))  # fmt: skip
    assert run and {w["host.name"] for w in run} == {"WKS01"}
    assert key not in {w["vhir.host_key"] for w in run}
    monkeypatch.setattr(srv, "_get_active_case", lambda: d.name)
    resp = {"results": [{} for _ in run]}
    srv._annotate_hosts(resp, d.name, hits=[{"_source": w} for w in run])
    assert all(doc.get("host_unconfirmed") for doc in resp["results"])


# -- what the scan keeps about a unit


def test_files_the_scan_couldnt_read_reach_the_host_log_and_the_screen(capsys):
    d = case()
    host = d / "evidence" / "WKS30"
    host.mkdir(parents=True)
    (host / "deep.json").write_text("[" * 100_000 + "]" * 100_000)
    (host / "rows.csv").write_text("Computer,x\nWKS30,1\n")
    h = DiscoveredHost(hostname="WKS30", volume_root=host)
    cli._record_scan(d.name, host, [h], [])
    (unit,) = hi.load(d).units.values()
    assert unit["names_not_sampled"] == "evidence/WKS30/deep.json: nested too deeply to read"
    assert "evidence/WKS30/deep.json: nested too deeply to read" in capsys.readouterr().out


def test_lvm_volumes_sharing_an_offset_stay_two_units_named_alike_in_both():
    d = case()
    image = d / "evidence" / "lvm.raw"
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"\0")
    leaves = [
        {"selector": {"volumes": "lvm1"}, "offset": 0, "fs": "ext4", "os": "linux"},
        {"selector": {"volumes": "lvm2"}, "offset": 0, "fs": "ext4", "os": "linux"},
    ]
    dry = [u.locator for u in names_scan.image_candidates(image, leaves, d)]
    assert len(set(dry)) == 2
    run = []
    for label in ("lvm1", "lvm2"):
        h = DiscoveredHost(hostname=f"L-{label}", volume_root=image)
        h.image_path, h.volume_label, h.volume_offset = image, label, 0
        cli._set_units([h], d.name, image, None, None, "folder")
        run.append(h.unit_locator)
    assert run == dry


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes here")
def test_a_pipe_named_like_a_csv_is_never_read(tmp_path):
    os.mkfifo(tmp_path / "events.csv")
    (tmp_path / "rows.csv").write_text("Computer\nWKS01\n")
    files, _ = names_scan._row_files(tmp_path)
    assert [f.name for f in files] == ["rows.csv"]


def test_a_dying_worker_never_fails_a_run_whose_name_only_holds_its_pid(tmp_path, monkeypatch):
    import atexit

    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(atexit, "register", lambda f: f)  # not this test process's exit
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    me = os.getpid()
    other = me + 1 if me + 1 != 777 else me + 2
    # another run's file: its case id holds this process's pid
    ingest_status.write_status(f"INC-{me}", other, "r1", "running", [], {}, "t0")
    cli._install_terminal_status_guards()
    try:
        raise RuntimeError("worker crashed")
    except RuntimeError:
        sys.excepthook(*sys.exc_info())
    (f,) = (tmp_path / "status").glob("*.json")
    assert json.loads(f.read_text())["status"] == "running"
