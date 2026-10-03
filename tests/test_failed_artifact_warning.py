"""A failed artifact's partly written index is flagged in idx_case_summary.

An artifact that fails after its first bulk flush leaves those documents in
its index, and the summary listed the index like any other. Now the summary
warns for each (host, artifact) whose most recent ingest failed, from the
case audit log (the ingest status files are swept after 24 hours). These rows
use the audit and status files of a run whose registry artifact failed with
1,000 documents written; the cluster rows that force a failure through a real
scan are in test_ingest_integration.py.
"""

import asyncio
import json
import os
import shutil
import time
from pathlib import Path

import pytest

from opensearch_mcp import ingest_status, server

FIXTURES = Path(__file__).parent / "fixtures" / "failed_artifact"
CID = "case-a"
INDICES = {  # what the case held
    f"case-{CID}-shimcache-dev01": 1694,
    f"case-{CID}-registry-dev01": 1000,
    f"case-{CID}-mft-dev01": 252626,
}
REGISTRY_WARNING = (
    f"case-{CID}-registry-dev01 (1,000 docs) may be incomplete: the most recent"
    " ingest of registry on dev01 failed (FAILED: line contains NUL)"
)


class _Cat:
    def indices(self, index, format="json", **kw):
        return [{"index": n, "docs.count": str(d)} for n, d in INDICES.items()]


class _Client:
    cat = _Cat()

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            return {"aggregations": {"hosts": {"buckets": [{"key": "dev01"}]}}}
        return {"aggregations": {"min_ts": {}, "max_ts": {}}}

    def count(self, index, body):
        return {"count": 0}


@pytest.fixture
def case(tmp_path, monkeypatch):
    """The case with the run's audit log; its status file in the status dir."""
    case_dir = tmp_path / "cases" / CID
    (case_dir / "audit").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {CID}\n")
    shutil.copy(FIXTURES / "opensearch-ingest-4294.jsonl", case_dir / "audit")
    status_dir = tmp_path / "ingest-status"
    status_dir.mkdir()
    shutil.copy(FIXTURES / f"{CID}-4294.json", status_dir)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", status_dir)
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
    monkeypatch.setattr(server, "_get_os", lambda: _Client())
    return case_dir


def incomplete(cid=CID):
    resp = server.idx_case_summary(case_id=cid)
    return [w for w in resp.get("warnings", []) if "may be incomplete" in w]


def test_the_runs_failed_registry_is_flagged(case):
    # the status file records no count for the failed artifact; the index's own is used
    status = json.loads((FIXTURES / f"{CID}-4294.json").read_text())
    (registry,) = [a for a in status["hosts"][0]["artifacts"] if a["name"] == "registry"]
    assert registry == {"name": "registry", "status": "failed", "error": "line contains NUL"}
    assert incomplete() == [REGISTRY_WARNING]  # shimcache and mft succeeded: no warning


def test_the_warning_outlives_the_status_file(case):
    status_file = ingest_status._STATUS_DIR / f"{CID}-4294.json"
    old = time.time() - 25 * 3600
    os.utime(status_file, (old, old))
    ingest_status.cleanup_old()
    assert not status_file.exists()
    assert incomplete() == [REGISTRY_WARNING]


def test_a_failed_plaso_artifact_is_flagged_under_its_own_name(case, monkeypatch):
    entry = {
        "ts": "2026-10-03T20:25:00+00:00",
        "tool": "ingest_prefetch",
        "case_id": CID,
        "params": {"hostname": "dev01", "tool": "prefetch", "run_id": "r2"},
        "result_summary": {"value": "FAILED: psort exited 1"},
    }
    with open(case / "audit" / "opensearch-ingest-4295.jsonl", "w") as f:
        f.write(json.dumps(entry) + "\n")
    monkeypatch.setitem(INDICES, f"case-{CID}-prefetch-dev01", 40)
    assert incomplete() == [
        f"case-{CID}-prefetch-dev01 (40 docs) may be incomplete: the most recent"
        " ingest of prefetch on dev01 failed (FAILED: psort exited 1)",
        REGISTRY_WARNING,
    ]


def _append(case, *entries):
    with open(case / "audit" / "opensearch-ingest-4296.jsonl", "a") as f:
        for ts, tool, params, result in entries:
            entry = {"ts": ts, "tool": tool, "case_id": CID, "params": params}
            f.write(json.dumps({**entry, "result_summary": {"value": result}}) + "\n")


def test_a_custom_parser_success_clears_its_failure(case, monkeypatch):
    # a custom parser's success entry records no params.tool, only its own name
    monkeypatch.setitem(INDICES, f"case-{CID}-tasks-dev01", 12)
    _append(
        case,
        (
            "2026-10-03T21:00:00+00:00",
            "ingest_tasks",
            {"hostname": "dev01", "tool": "tasks"},
            "FAILED: bad XML",
        ),
        (
            "2026-10-03T21:05:00+00:00",
            "ingest_tasks",
            {"hostname": "dev01", "path": "/x/Tasks"},
            "12 indexed",
        ),
    )
    assert incomplete() == [REGISTRY_WARNING]


def test_a_hostnames_case_doesnt_split_its_index(case):
    # DEV01 and dev01 write one index: the later success there clears it
    later = ("2026-10-03T21:00:00+00:00", "ingest_registry")
    _append(case, (*later, {"hostname": "DEV01", "tool": "registry"}, "1500 indexed"))
    assert incomplete() == []


def test_one_index_gets_one_warning_whatever_the_hostnames_case(case):
    later = ("2026-10-03T21:00:00+00:00", "ingest_registry")
    _append(case, (*later, {"hostname": "DEV01", "tool": "registry"}, "FAILED: line contains NUL"))
    assert incomplete() == [REGISTRY_WARNING.replace("on dev01", "on DEV01")]


def test_a_failure_that_left_no_index_isnt_flagged(case):
    _append(
        case,
        (
            "2026-10-03T21:00:00+00:00",
            "ingest_amcache",
            {"hostname": "dev01", "tool": "amcache"},
            "FAILED: no hive",
        ),
    )
    assert incomplete() == [REGISTRY_WARNING]  # no case-a-amcache-dev01 index


def test_another_cases_audit_entries_dont_count(case):
    log = case / "audit" / "opensearch-ingest-4294.jsonl"
    log.write_text(log.read_text().replace(f'"case_id": "{CID}"', '"case_id": "other"'))
    assert incomplete() == []


def test_entries_without_a_case_id_count_only_in_the_cases_own_log(case, tmp_path, monkeypatch):
    log = case / "audit" / "opensearch-ingest-4294.jsonl"
    log.write_text(log.read_text().replace(f'"case_id": "{CID}"', '"case_id": ""'))
    assert incomplete() == [REGISTRY_WARNING]  # a CLI run with no active case
    other = tmp_path / "cases" / "other"
    shutil.copytree(case, other)
    monkeypatch.setenv("VHIR_CASE_DIR", str(other))
    assert incomplete() == []  # another case's log says nothing about this one


def test_the_include_docstring_names_tier_1_and_event_logs():
    doc = " ".join(server.idx_ingest.__doc__.split())
    assert (
        'include: These artifact types (e.g., ["mft", "usn"]), plus the tier-1'
        " defaults and any event logs found." in doc
    )


def test_the_helper_isnt_a_tool_and_the_summary_still_is():
    names = {t.name for t in asyncio.run(server.server.list_tools())}
    assert "idx_case_summary" in names
    assert not [n for n in names if n.startswith("_")]
