"""An artifact that runs once per user profile is flagged when any profile failed.

Jumplists, lnk, shellbags and timeline run once per profile, and WER once per
directory, into one index per host. The summary's warning must come from the
whole most recent run of that index, not from its last entry. All entries are
synthetic and shaped like the ingest worker's own (params, input_files).
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from opensearch_mcp import server

CID = "case-b"
JL1 = f"case-{CID}-jumplists-host1"
JL2 = f"case-{CID}-jumplists-host2"
WER1 = f"case-{CID}-wer-host1"
INDICES = {JL1: 7, JL2: 4, WER1: 3}
T0 = datetime(2026, 10, 3, 21, 0, tzinfo=timezone.utc)
BAD = "FAILED: JLECmd failed (exit 3): bad file"


class _Cat:
    def indices(self, index, format="json", **kw):
        return [{"index": n, "docs.count": str(d)} for n, d in INDICES.items()]


class _Client:
    cat = _Cat()

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            buckets = [{"key": "host1"}, {"key": "host2"}]
            return {"aggregations": {"hosts": {"buckets": buckets}}}
        return {"aggregations": {"min_ts": {}, "max_ts": {}}}

    def count(self, index, body):
        return {"count": 0}


@pytest.fixture
def case(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / CID
    (case_dir / "audit").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {CID}\n")
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
    monkeypatch.setattr(server, "_get_os", lambda: _Client())
    return case_dir


def _entry(tool, host, path, run_id, ts, result):
    """One entry as the worker writes it: a success records the file (an EZ tool)
    or the path (a custom parser); a failure records only host, tool and run."""
    if result.startswith("FAILED"):
        params = {"hostname": host, "tool": tool, "run_id": run_id}
    elif tool == "wer":
        params = {"hostname": host, "path": path, "run_id": run_id, "bulk_failed": 0}
    else:
        params = {"hostname": host, "tool": tool, "file": path, "run_id": run_id, "bulk_failed": 0}
    if run_id is None:
        params.pop("run_id")
    return {
        "ts": ts.isoformat(),
        "tool": f"ingest_{tool}",
        "case_id": CID,
        "params": params,
        "result_summary": {"value": result},
        "input_files": [path],
    }


def run(case, log, run_id, minute, results, tool="jumplists", host="HOST1", root="/evidence"):
    """A run of `tool` on `host`, one entry per profile, in profile order."""
    with open(case / "audit" / f"opensearch-ingest-{log}.jsonl", "a") as f:
        for i, (profile, result) in enumerate(results):
            sub = "AppData/Local/Microsoft/Windows/WER" if tool == "wer" else "Recent"
            path = f"{root}/{host}/Users/{profile}/{sub}"
            ts = T0 + timedelta(minutes=minute, seconds=i)
            f.write(json.dumps(_entry(tool, host, path, run_id, ts, result)) + "\n")


def flagged():
    resp = server.idx_case_summary(case_id=CID)
    return [w.split(" ")[0] for w in resp.get("warnings", []) if "may be incomplete" in w]


@pytest.mark.parametrize("tool, index", [("jumplists", JL1), ("wer", WER1)])
def test_a_failed_profile_before_a_good_one_is_flagged(case, tool, index):
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")], tool=tool)
    assert flagged() == [index]


def test_a_failed_profile_after_a_good_one_is_flagged(case):
    run(case, 100, "r1", 0, [("alice", "7 indexed"), ("bob", BAD)])
    assert flagged() == [JL1]


def test_the_warning_names_the_failure(case):
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")])
    (w,) = [w for w in server.idx_case_summary(case_id=CID)["warnings"] if "incomplete" in w]
    assert w == (
        f"{JL1} (7 docs) may be incomplete: the most recent ingest of jumplists on HOST1"
        f" failed ({BAD})"
    )


def test_two_failed_profiles_give_one_warning(case):
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", BAD), ("carol", "7 indexed")])
    assert flagged() == [JL1]


def test_a_reingest_that_fixes_the_profile_clears_it(case):
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")])
    run(case, 101, "r2", 10, [("alice", "2 indexed"), ("bob", "7 indexed")])
    assert flagged() == []


def test_a_reingest_from_a_new_extraction_dir_that_fixes_it_clears_it(case):
    # an archive or image is extracted to a new ingest-<time>-<pid> dir every run
    old, new = "/c/tmp/ingest-20261003T210000-100", "/c/tmp/ingest-20261003T211000-101"
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")], root=old)
    run(case, 101, "r2", 10, [("alice", "2 indexed"), ("bob", "7 indexed")], root=new)
    assert flagged() == []


def test_a_reingest_that_still_fails_keeps_it(case):
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")])
    run(case, 101, "r2", 10, [("alice", BAD), ("bob", "7 indexed")])
    assert flagged() == [JL1]


def test_a_later_run_of_another_host_doesnt_clear_it(case):
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")])
    run(case, 100, "r1", 1, [("carol", "4 indexed")], host="HOST2")
    assert flagged() == [JL1]


@pytest.mark.parametrize(
    "newer, older, expected",
    [
        (
            [("alice", "2 indexed"), ("bob", "7 indexed")],
            [("alice", BAD), ("bob", "7 indexed")],
            [],
        ),
        (
            [("alice", BAD), ("bob", "7 indexed")],
            [("alice", "2 indexed"), ("bob", "7 indexed")],
            [JL1],
        ),
    ],
    ids=["newer-run-good", "newer-run-failed"],
)
def test_the_newest_run_decides_whatever_the_log_file_order(case, newer, older, expected):
    # each worker writes its own opensearch-ingest-<pid>.jsonl; pids don't sort by time
    run(case, 100, "r2", 10, newer)
    run(case, 900, "r1", 0, older)
    assert flagged() == expected


def test_two_runs_in_one_log_file(case):
    # a reused pid appends a second run to the same file
    run(case, 100, "r1", 0, [("alice", BAD), ("bob", "7 indexed")])
    run(case, 100, "r2", 10, [("alice", "2 indexed"), ("bob", "7 indexed")])
    assert flagged() == []


def test_entries_without_a_run_id_keep_the_latest_entry(case):
    # entries written before run ids were recorded: each counts as its own run
    run(case, 100, None, 0, [("alice", BAD)])
    run(case, 100, None, 10, [("alice", "2 indexed"), ("bob", "7 indexed")])
    assert flagged() == []
