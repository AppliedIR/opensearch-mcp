"""Two status lines say what is there. The investigation-hints pointer names
only the artifact types the case holds (it named MFT, USN and evtx for any
case), and a live ingest's elapsed time counts from when it started (its
status writes don't pass elapsed_seconds, so it read 0m). Fake client and
status files in tmp_path; values are synthetic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sift_common import host_identity

from opensearch_mcp import ingest_status, server
from opensearch_mcp import write_context as wc

TAIL = " indexed — call suggest_tools for investigation patterns"
INDICES: dict[str, list[tuple[str, int]]] = {}


def idx(case: str, artifact_type: str) -> str:
    return f"case-{host_identity.ensure_case_uuid(wc.case_dir_for(case), 2)[0]}-{artifact_type}-0"


class _Cat:
    def indices(self, index, format="json", **kw):
        return [{"index": n, "docs.count": str(d)} for entries in INDICES.values()
                for n, d in entries if n.startswith(index.removesuffix("*"))]  # fmt: skip


class _Client:
    cat = _Cat()

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            return {"aggregations": {"hosts": {"buckets": [{"key": "host1"}]}}}
        return {"aggregations": {"timed": {"min_ts": {}, "max_ts": {}}}}

    def count(self, index, body):
        return {"count": 0}


@pytest.fixture
def fake_os(monkeypatch):
    INDICES.clear()
    monkeypatch.setattr(server, "_get_os", lambda: _Client())


def pointer(case: str, types: list[str]) -> list[str]:
    INDICES[case] = [(idx(case, t), 100 * (i + 1)) for i, t in enumerate(types)]
    for _ in range(4):  # every hint given (the 500-character budget spreads them)
        got = server.idx_case_summary(case_id=case).get("investigation_hints")
        if got and len(got) == 1 and got[0].endswith(TAIL):
            return got
    raise AssertionError(got)


# -- the pointer names what the case holds


@pytest.mark.parametrize("case, types, named", [
    ("p1", ["mft"], "MFT"),
    ("p2", ["usn"], "USN"),
    ("p3", ["evtx"], "evtx"),
    ("p4", ["mft", "evtx"], "MFT/evtx"),
    ("p5", ["usn", "evtx"], "USN/evtx"),
    ("p6", ["mft", "usn"], "MFT/USN"),
    ("p7", ["prefetch", "mft"], "MFT"),             # Prefetch gives a hint only beside MFT
    ("p8", ["delim-usnjournal", "evtx"], "USN/evtx"),
])  # fmt: skip
def test_the_pointer_names_only_the_types_the_case_holds(fake_os, case, types, named):
    assert pointer(case, types) == [named + TAIL]


def test_a_case_with_all_three_keeps_the_pointer_as_it_was(fake_os):
    assert pointer("all", ["mft", "usn", "evtx"]) == ["MFT/USN/evtx" + TAIL]


def test_a_case_with_none_of_them_gets_no_hint(fake_os):
    INDICES["n"] = [(idx("n", "json"), 10), (idx("n", "prefetch"), 10)]
    for _ in range(2):
        assert "investigation_hints" not in server.idx_case_summary(case_id="n")


# -- a live run's elapsed counts from when it started


@pytest.fixture
def status(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)

    def write(state: str, started: str, elapsed: float = 0.0) -> dict:
        done = int(state == "complete")
        totals = {"indexed": 9, "hosts_total": 1, "hosts_complete": done,
                  "artifacts_total": 1, "artifacts_complete": done}  # fmt: skip
        ingest_status.write_status(
            case_id="c1", pid=4242, run_id="r1", status=state, hosts=[], totals=totals,
            started=started, elapsed_seconds=elapsed)  # fmt: skip
        (s,) = server.idx_ingest_status(case_id="c1")["ingests"]
        return s

    return write


def ago(minutes: float, tz=timezone.utc) -> str:
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return (t if tz else t.replace(tzinfo=None)).isoformat()


@pytest.mark.parametrize("state", ["running", "starting", ingest_status.AWAITING])
def test_a_live_run_counts_from_when_it_started(status, state):
    assert status(state, ago(7.5))["elapsed"] == "7m"


def test_a_live_run_with_no_zone_on_its_start_reads_it_as_utc(status):
    assert status("running", ago(12.2, tz=None))["elapsed"] == "12m"


def test_a_live_run_in_another_zone_counts_the_same(status):
    t = datetime.now(timezone(timedelta(hours=9))) - timedelta(minutes=3.5)
    assert status("running", t.isoformat())["elapsed"] == "3m"


def test_a_live_run_keeps_a_larger_elapsed_it_wrote(status):
    assert status("running", ago(1), elapsed=600)["elapsed"] == "10m"


@pytest.mark.parametrize("started", ["", "not a time", "2026-13-45T00:00:00", ago(-30)])
def test_a_live_run_whose_start_cant_be_counted_shows_what_it_wrote(status, started):
    assert status("running", started, elapsed=125)["elapsed"] == "2m"


@pytest.mark.parametrize("state", ["complete", "failed", ingest_status.CANCELLED])
def test_a_finished_run_shows_the_elapsed_it_wrote(status, state):
    s = status(state, ago(600), elapsed=125)
    assert s["elapsed"] == "2m", s
    if state == "complete":
        assert " in 2m." in s["message"], s


def test_a_finished_run_that_wrote_no_elapsed_reads_0m_as_before(status):
    assert status("complete", ago(600))["elapsed"] == "0m"


@pytest.mark.parametrize("ing, want", [
    ({"status": "running", "started": None}, 0),
    ({"status": "running"}, 0),
    ({"status": "complete", "started": "x", "elapsed_seconds": 3}, 3),
    ({}, 0),
])  # fmt: skip
def test_elapsed_seed_shapes(ing, want):
    assert server._elapsed_seconds(ing) == want
