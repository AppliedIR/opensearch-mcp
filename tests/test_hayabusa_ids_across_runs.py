"""An image or archive ingested again keeps its Hayabusa detections' ids.

A detection's id hashed its `EvtxFile`, the path Hayabusa read the log
from: for an image or archive that's under the run's own temp directory,
which every run makes anew, so every re-ingest added a full second copy.
The id now hashes that path relative to the run's directory. A folder's
ids are as they always were, and logs that differ only in name or volume
keep their own detections.
"""

from __future__ import annotations

import argparse
import inspect
import shutil
import zipfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.ingest as ingest
import opensearch_mcp.parse_delimited as parse_delimited
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import write_context as wc
from opensearch_mcp.parse_csv import _doc_id

# Writes one detection per .evtx file under -d, with the path as Hayabusa gives it
STUB = """#!/bin/sh
out=""; dir=""; prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"; [ "$prev" = "-d" ] && dir="$a"; prev="$a"
done
echo "Timestamp,RuleTitle,Level,Computer,Channel,EventID,EvtxFile" > "$out"
for f in $(find "$dir" -name '*.evtx' | sort); do
  echo "2026-02-01 00:00:00.000 +00:00,Log cleared,high,WKS10,Security,1102,$f" >> "$out"
done
"""
LOGS = "kape/C/Windows/System32/winevt/Logs"
# A release before the run directory was passed still runs these rows, as itself
_params = inspect.signature(ingest.run_hayabusa_batch).parameters


@pytest.fixture
def hayabusa(tmp_path, monkeypatch):
    """run(evtx_dir, run_tmpdir) -> the parser ids of one Hayabusa run's detections."""
    stub = tmp_path / "hayabusa"
    stub.write_text(STUB)
    stub.chmod(0o755)
    rules = tmp_path / "rules"
    (rules / "config").mkdir(parents=True)
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda n, *a, **k: str(stub) if n == "hayabusa" else real_which(n)
    )
    monkeypatch.setattr(ingest, "vhir_dir", lambda: tmp_path / "vhir")
    monkeypatch.setattr(ingest, "_resolve_hayabusa_rules_dir", lambda: rules)
    sent: list[dict] = []

    def flush_bulk(client, actions, **kw):
        sent.extend(dict(a) for a in actions)
        n = len(actions)
        actions.clear()
        return n, 0

    monkeypatch.setattr(parse_delimited, "flush_bulk", flush_bulk)

    def run(evtx_dir, run_tmpdir, run_id):
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", run_id)
        sent.clear()
        host = SimpleNamespace(hostname="WKS10", evtx_dir=evtx_dir, volume_root=evtx_dir)
        kw = {"run_tmpdir": run_tmpdir} if "run_tmpdir" in _params else {}
        ingest.run_hayabusa_batch([host], MagicMock(), "hbids", **kw)
        return {a["_source"]["EvtxFile"].rsplit("/", 1)[-1]: a["_id"] for a in sent}

    return run


def _logs(root, *names):
    logs = root / LOGS
    logs.mkdir(parents=True)
    for name in names:
        (logs / name).write_bytes(b"\0")
    return logs


def test_the_same_archive_ingested_in_two_runs_keeps_its_detection_ids(hayabusa, tmp_path):
    runs = tmp_path / "case" / "tmp"
    first = hayabusa(_logs(runs / "ingest-1", "Security.evtx"), runs / "ingest-1", "r1")
    second = hayabusa(_logs(runs / "ingest-2", "Security.evtx"), runs / "ingest-2", "r2")
    assert first == second and len(first) == 1


def test_a_renamed_copy_of_a_log_keeps_its_own_detections(hayabusa, tmp_path):
    run = tmp_path / "case" / "tmp" / "ingest-1"
    logs = _logs(run, "Security.evtx", "Archive-Security-2026-10-01.evtx")
    ids = hayabusa(logs, run, "r1")
    assert len(set(ids.values())) == 2


def test_live_and_shadow_copy_detections_stay_apart(hayabusa, tmp_path):
    run = tmp_path / "case" / "tmp" / "ingest-1"
    live = hayabusa(_logs(run / "vol1", "Security.evtx"), run, "r1")
    shadow = hayabusa(_logs(run / "vss1", "Security.evtx"), run, "r2")
    assert live["Security.evtx"] != shadow["Security.evtx"]


def test_a_folders_detection_ids_are_as_before(hayabusa, tmp_path):
    folder = tmp_path / "evidence" / "WKS10"
    logs = _logs(folder, "Security.evtx")
    ids = hayabusa(logs, None, "r1")
    row = {
        "Timestamp": "2026-02-01 00:00:00.000 +00:00",
        "RuleTitle": "Log cleared",
        "Level": "high",
        "Computer": "WKS10",
        "Channel": "Security",
        "EventID": "1102",
        "EvtxFile": str(logs / "Security.evtx"),
    }
    with wc.writing(wc.open_unit(wc.case_dir_for("hbids"), "x", "WKS10", source="test")):
        index = wc.index_name("hayabusa")
    expected = _doc_id(
        index, {**row, "@timestamp": "x"}, volatile_keys=parse_delimited._DELIM_VOLATILE
    )
    assert ids["Security.evtx"] == expected


def test_an_archive_scan_gives_hayabusa_its_run_directory(tmp_path, monkeypatch):
    archive = tmp_path / "kape.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(f"{LOGS}/Security.evtx", b"\0" * 70000)
    seen = {}

    def found(root, *a, **k):
        from opensearch_mcp.discover import DiscoveredHost

        host = DiscoveredHost(hostname="WKS10", volume_root=root / "kape")
        host.evtx_dir = root / LOGS
        return [host]

    def batch(hosts, client, case_id, **kw):
        seen.update(kw, evtx=hosts[0].evtx_dir)
        return {}

    monkeypatch.setattr(cli, "discover", found)
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "hbids")
    monkeypatch.setattr(ingest, "parse_and_index", MagicMock(return_value=(5, 0, 0)))
    monkeypatch.setattr(ingest, "sha256_file", lambda p: "h")
    monkeypatch.setattr(ingest, "run_hayabusa_batch", batch)
    monkeypatch.setattr(shutil, "which", lambda n, *a, **k: "/x/hayabusa")
    args = argparse.Namespace(
        path=str(archive), case="hbids", yes=True, hostname="WKS10", all_logs=False,
        no_hayabusa=False, skip_triage=True,
    )  # fmt: skip
    cli.cmd_scan(args)
    assert seen.get("run_tmpdir") is not None
    assert seen["evtx"].is_relative_to(seen["run_tmpdir"])
