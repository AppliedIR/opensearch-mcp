"""Triage enrichment doesn't say "complete" when its verdict writes fail or when an
aggregation leaves values unread. OpenSearch and call_tool are stand-ins.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from opensearchpy.exceptions import ConnectionTimeout

from opensearch_mcp import server as srv
from opensearch_mcp import triage_remote as tr

GW = [
    "shimcache",
    "amcache",
    "evtx_proc",
    "tasks",
    "vol_dlls",
    "evtx_svc",
    "vol_svcs",
    "registry_svcs",
    "registry_run",
    "registry_activestub",
    "registry_netsh",
]
# entries whose values come from a terms aggregation (the 5,000-value cap);
# the three service sources read every doc
AGG = [k for k in GW if k not in ("evtx_svc", "vol_svcs", "registry_svcs")]


class StubOS:
    def __init__(self, other=0, write_ok=True, fail_rule_writes=False):
        self.other = other
        self.write_ok = write_ok
        self.fail_rule_writes = fail_rule_writes
        self.indices = MagicMock()
        self.writes = 0

    def search(self, index, body, **kw):
        aggs = body.get("aggs", {})
        if "svcscan" in index:
            hit = {"_id": "v1", "_source": {"Name": "s", "Binary (Registry)": "C:\\a.exe"}}
            return {"hits": {"hits": [hit]}}
        if aggs:
            name = next(iter(aggs))
            buckets = [{"key": "C:\\x\\a.dll", "doc_count": 1}]
            agg = {"buckets": buckets, "sum_other_doc_count": self.other}
            return {"hits": {"hits": []}, "aggregations": {name: agg}}
        if "event.code" in str(body):
            hit = {"_id": "e1", "_source": {"winlog.event_data": {"ServiceName": "s"}}}
            return {"hits": {"hits": [hit]}}
        hits = [
            {
                "_id": "r1",
                "_source": {
                    "KeyPath": "ROOT\\ControlSet001\\Services\\s",
                    "ValueData": "C:\\a.exe",
                },
            }
        ]
        return {"hits": {"hits": hits}}

    def update_by_query(self, index, body, **kw):
        is_rule = "params" not in body["script"] or "prefix" in body["script"].get("params", {})
        is_rule = is_rule or "known" in body["script"].get("params", {})
        if (is_rule and self.fail_rule_writes) or (not is_rule and not self.write_ok):
            raise RuntimeError("cluster_block_exception")
        self.writes += 1
        return {"updated": 1}


def _verdict(name, args, timeout=60):
    return {"verdict": "SUSPICIOUS", "confidence": "medium", "reasons": ["r"]}


def _enrich(stub):
    with (
        patch.object(tr, "gateway_available", return_value=True),
        patch.object(tr, "call_tool", side_effect=_verdict),
    ):
        return tr.enrich_remote(stub, "c1")


@pytest.mark.parametrize("name", GW)
def test_a_lookup_whose_verdict_cannot_be_written_is_not_complete(name):
    res = _enrich(StubOS(write_ok=False))
    assert res[name]["status"] != "complete", res[name]
    assert res[name].get("write_failures", 0) >= 1, res[name]
    assert "re-run idx_enrich_triage" in res[name]["reason"], res[name]


@pytest.mark.parametrize("name", GW)
def test_written_verdicts_stay_complete(name):
    res = _enrich(StubOS())
    assert res[name]["status"] == "complete", res[name]
    assert "write_failures" not in res[name] and "unchecked_docs" not in res[name]


def test_every_persistence_rule_whose_write_fails_is_counted():
    res = tr._enrich_registry_persistence(StubOS(fail_rule_writes=True), "c1")
    assert res["status"] != "complete", res
    assert res["rules_failed"] == 15, res


def test_idx_enrich_triage_is_incomplete_when_persistence_writes_fail():
    with (
        patch.object(tr, "gateway_available", return_value=False),
        patch.object(srv, "_get_os", return_value=StubOS(fail_rule_writes=True)),
        patch.object(srv.audit, "log", return_value=None),
    ):
        resp = srv.idx_enrich_triage(case_id="c1")
    assert resp["status"] == "incomplete", resp
    assert "registry_persistence" in resp["failed_artifacts"], resp


@pytest.mark.parametrize("name", AGG)
def test_values_past_the_aggregation_cap_are_counted_not_complete(name):
    res = _enrich(StubOS(other=7))
    assert res[name]["status"] != "complete", res[name]
    assert res[name]["unchecked_docs"] == 7, res[name]


class ChunkedStub:
    """1,200 distinct paths, stamped in chunks of 500; the chunks in `fail` can't be written."""

    def __init__(self, other=0, fail=(2,)):
        self.other = other
        self.fail = fail
        self.indices = MagicMock()
        self.calls = 0

    def search(self, index, body, **kw):
        buckets = [{"key": f"C:\\x\\f{i}.dll", "doc_count": 1} for i in range(1200)]
        agg = {"buckets": buckets, "sum_other_doc_count": self.other}
        return {"hits": {"hits": []}, "aggregations": {"paths": agg}}

    def update_by_query(self, index, body, **kw):
        self.calls += 1
        if self.calls in self.fail:
            raise RuntimeError("cluster_block_exception")
        return {"updated": len(body["query"]["terms"]["FullPath.keyword"])}


def _amcache(stub):
    with patch.object(tr, "call_tool", side_effect=_verdict):
        return tr._enrich_file_artifact(
            stub, "c1", "case-c1-amcache-*", "FullPath.keyword", "amcache"
        )


def test_only_the_chunks_that_could_not_be_written_are_counted():
    res = _amcache(ChunkedStub(fail=(2,)))
    assert res["status"] == "failed", res
    assert res["write_failures"] == 500, res  # the second chunk's paths, not all 1,200
    assert res["enriched"] == 700, res


def test_write_failures_and_values_past_the_cap_are_both_reported():
    res = _amcache(ChunkedStub(other=7, fail=(3,)))
    assert res["status"] == "failed", res
    assert res["write_failures"] == 200 and res["unchecked_docs"] == 7, res
    assert "could not be written" in res["reason"] and "past the first 5000" in res["reason"]


def test_the_values_of_every_failed_chunk_add_up():
    res = _amcache(ChunkedStub(fail=(1, 3)))
    assert res["write_failures"] == 700, res  # 500 + 200
    assert res["enriched"] == 500, res


class FakeClock:
    """time for triage_remote: sleep moves the clock, nothing waits."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, s):
        self.now += s


class TaskStub:
    """A cluster whose writes take `takes` seconds: a write the caller waits on
    times out at the client's 10 s, as opensearch-py's does; one sent as a task
    finishes then. `ends` says how chunk n's task ends: "ok", "error" or "failures"."""

    def __init__(self, clock, takes=15.0, ends=None, n_paths=1200):
        self.clock = clock
        self.takes = takes
        self.ends = ends or {}
        self.n_paths = n_paths
        self.indices = MagicMock()
        self.tasks = MagicMock()
        self.tasks.get.side_effect = self._task
        self.submits = []
        self.running = {}

    def search(self, index, body, **kw):
        buckets = [{"key": f"C:\\x\\f{i}.dll", "doc_count": 1} for i in range(self.n_paths)]
        return {"hits": {"hits": []}, "aggregations": {"paths": {"buckets": buckets}}}

    def update_by_query(self, index, body, **kw):
        self.submits.append(kw)
        n = len(self.submits)
        terms = (
            body["query"]["terms"]
            if "terms" in body["query"]
            else (body["query"]["bool"]["filter"][0]["terms"])
        )
        count = len(next(iter(terms.values())))
        if kw.get("wait_for_completion", True) and self.takes > 10:
            raise ConnectionTimeout("TIMEOUT", "Read timed out. (read timeout=10)", None)
        self.running[f"n:{n}"] = (self.clock.now + self.takes, self.ends.get(n, "ok"), count)
        return {"task": f"n:{n}"}

    def _task(self, task_id, **kw):
        done_at, end, count = self.running[task_id]
        if self.clock.now < done_at:
            return {"completed": False}
        if end == "error":
            return {"completed": True, "error": {"reason": "cluster_block_exception"}}
        failures = [{"cause": "x"}] if end == "failures" else []
        return {"completed": True, "response": {"updated": count, "failures": failures}}


def _amcache_slow(stub, clock):
    with (
        patch.object(tr, "call_tool", side_effect=_verdict),
        patch.object(tr, "time", clock),
    ):
        return tr._enrich_file_artifact(
            stub, "c1", "case-c1-amcache-*", "FullPath.keyword", "amcache"
        )


def test_a_write_the_cluster_finishes_after_the_read_timeout_is_complete():
    clock = FakeClock()
    stub = TaskStub(clock, takes=15.0)
    res = _amcache_slow(stub, clock)
    assert res["status"] == "complete", res
    assert res["enriched"] == 1200 and "write_failures" not in res, res
    assert clock.now >= 15, clock.now  # it waited for the tasks


def test_each_write_is_sent_as_a_throttled_task():
    clock = FakeClock()
    stub = TaskStub(clock, takes=1.0)
    _amcache_slow(stub, clock)
    assert len(stub.submits) == 3, stub.submits  # 1,200 paths in chunks of 500
    for kw in stub.submits:
        assert kw["wait_for_completion"] is False, kw
        assert kw["requests_per_second"] == 1000 and kw["conflicts"] == "proceed", kw


@pytest.mark.parametrize("end", ["error", "failures"])
def test_a_task_that_fails_names_the_verdict_its_count_and_the_rerun(end):
    clock = FakeClock()
    res = _amcache_slow(TaskStub(clock, ends={2: end}), clock)
    assert res["status"] == "failed", res
    assert res["write_failures"] == 500 and res["enriched"] == 700, res
    assert (
        "500 verdicts could not be written to the index (SUSPICIOUS 500); "
        "re-run idx_enrich_triage to write them"
    ) in res["reason"], res


def test_failed_writes_are_named_by_each_verdict():
    clock = FakeClock()
    verdicts = {
        "C:\\a.exe": {"verdict": "EXPECTED", "confidence": "high"},
        "C:\\b.exe": {"verdict": "SUSPICIOUS", "confidence": "low"},
        "C:\\c.exe": {"verdict": "SUSPICIOUS", "confidence": "low"},
    }
    unwritten = {}
    stub = TaskStub(clock, ends={1: "error", 2: "error"})
    with patch.object(tr, "time", clock):
        updated, failed = tr._batch_stamp_verdicts(
            stub, "case-c1-*", "Path.keyword", verdicts, "*", unwritten
        )
    assert (updated, failed) == (0, 3) and unwritten == {"EXPECTED": 1, "SUSPICIOUS": 2}
    res = tr._loop_result(0, True, failed, 0, unwritten)
    assert "(EXPECTED 1, SUSPICIOUS 2)" in res["reason"], res


def _by_hash(paths):
    a = {"verdict": "EXPECTED", "confidence": "high"}
    b = {"verdict": "SUSPICIOUS", "confidence": "low", "reasons": ["r"]}
    return {f"C:\\x\\f{i}.dll": ({"h1": a, "h2": b} if i % 2 else {"h1": a}) for i in range(paths)}


def test_a_hash_stamp_the_cluster_finishes_after_the_read_timeout_is_counted():
    clock = FakeClock()
    stub = TaskStub(clock, takes=15.0)
    with patch.object(tr, "time", clock):
        updated, failed = tr._stamp_by_hash(
            stub, "case-c1-*", "FullPath.keyword", "SHA1.keyword", _by_hash(600)
        )
    assert (updated, failed) == (600, 0)
    assert all(kw["wait_for_completion"] is False for kw in stub.submits)
    assert all(kw["requests_per_second"] == 1000 for kw in stub.submits)


def test_a_failed_hash_stamp_names_each_paths_verdicts():
    clock = FakeClock()
    unwritten = {}
    stub = TaskStub(clock, ends={2: "failures"})
    with patch.object(tr, "time", clock):
        updated, failed = tr._stamp_by_hash(
            stub, "case-c1-*", "FullPath.keyword", "SHA1.keyword", _by_hash(600), unwritten
        )
    # the second chunk: paths 500-599, half with one hash, half with two verdicts
    assert (updated, failed) == (500, 100)
    assert unwritten == {"EXPECTED": 50, "EXPECTED/SUSPICIOUS": 50}, unwritten


def test_a_write_still_running_at_the_wait_limit_is_not_written():
    clock = FakeClock()
    stub = TaskStub(clock, takes=tr._CLEAR_WAIT + 60)
    res = _amcache_slow(stub, clock)
    assert res["status"] == "failed" and res["write_failures"] == 1200, res


def test_a_failed_write_is_counted_when_the_caller_keeps_no_tally():
    clock = FakeClock()
    verdicts = {"C:\\a.exe": {"verdict": "EXPECTED", "confidence": "high"}}
    with patch.object(tr, "time", clock):
        plain = tr._batch_stamp_verdicts(
            TaskStub(clock, ends={1: "error"}), "case-c1-*", "Path.keyword", verdicts
        )
        hashed = tr._stamp_by_hash(
            TaskStub(clock, ends={1: "error"}),
            "case-c1-*",
            "FullPath.keyword",
            "SHA1.keyword",
            _by_hash(3),
        )
    assert plain == (0, 1) and hashed == (0, 3)


class HashStub(TaskStub):
    """Amcache: 600 paths, the odd ones with a second SHA1."""

    def search(self, index, body, **kw):
        def bucket(i):
            hashes = [{"key": "a" * 40}] + ([{"key": "b" * 40}] if i % 2 else [])
            return {"key": f"C:\\x\\f{i}.dll", "hashes": {"buckets": hashes}}

        buckets = [bucket(i) for i in range(600)]
        return {"hits": {"hits": []}, "aggregations": {"paths": {"buckets": buckets}}}


def _by_sha1(name, args, timeout=60):
    bad = args.get("hash") == "b" * 40
    return {"verdict": "SUSPICIOUS" if bad else "EXPECTED", "confidence": "low", "reasons": []}


def test_a_failed_amcache_hash_write_names_each_paths_verdicts():
    clock = FakeClock()
    with (
        patch.object(tr, "call_tool", side_effect=_by_sha1),
        patch.object(tr, "time", clock),
    ):
        res = tr._enrich_file_artifact(
            HashStub(clock, ends={2: "error"}),
            "c1",
            "case-c1-amcache-*",
            "FullPath.keyword",
            "amcache",
            hash_field="SHA1.keyword",
        )
    assert res["status"] == "failed" and res["enriched"] == 500, res
    assert (
        "100 verdicts could not be written to the index (EXPECTED 50, EXPECTED/SUSPICIOUS 50)"
    ) in res["reason"], res
