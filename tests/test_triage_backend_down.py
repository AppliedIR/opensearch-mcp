"""Triage enrichment doesn't say "complete" when its triage calls fail.

With the windows-triage backend down every call_tool raises; each gateway
loop stopped after its consecutive-failure limit and still returned
`complete, enriched 0`, which reads as "the baseline found nothing".
OpenSearch and call_tool are stand-ins; nothing reaches a cluster or gateway.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opensearch_mcp import server as srv
from opensearch_mcp import triage_remote as tr

# Every artifact enrich_remote sends through the gateway.
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
N = 5  # values per artifact


class StubOS:
    """Answers each artifact's aggregation or search with N values."""

    def __init__(self, n=N):
        self.n = n
        self.indices = MagicMock()

    def search(self, index, body, **kw):
        aggs = body.get("aggs", {})
        if aggs:
            name = next(iter(aggs))
            values = [f"C:\\Windows\\x{i}.dll" for i in range(self.n)]
            buckets = [{"key": v} for v in values]
            return {"hits": {"hits": []}, "aggregations": {name: {"buckets": buckets}}}
        if "event.code" in str(body):  # evtx 7045
            hits = [
                {"_source": {"winlog.event_data": {"ServiceName": f"svc{i}"}}}
                for i in range(self.n)
            ]
        else:  # registry Services ImagePath
            hits = [
                {
                    "_source": {
                        "KeyPath": f"HKLM\\SYSTEM\\Services\\svc{i}",
                        "ValueData": "C:\\a.exe",
                    }
                }
                for i in range(self.n)
            ]
        return {"hits": {"hits": hits}}

    def update_by_query(self, index, body, **kw):
        return {"updated": 2}


def _down(name, args, timeout=60):
    raise RuntimeError(f"Tool not found: {name}")  # the gateway's 404 for a down backend


def _ok(name, args, timeout=60):
    return {"verdict": "EXPECTED", "confidence": "high", "reasons": []}


def _enrich(call_tool, n=N):
    with (
        patch.object(tr, "gateway_available", return_value=True),
        patch.object(tr, "call_tool", side_effect=call_tool),
    ):
        return tr.enrich_remote(StubOS(n), "c1")


def _tool(call_tool):
    with (
        patch.object(tr, "gateway_available", return_value=True),
        patch.object(tr, "call_tool", side_effect=call_tool),
        patch.object(srv, "_get_os", return_value=StubOS()),
        patch.object(srv.audit, "log", return_value=None),
    ):
        return srv.idx_enrich_triage(case_id="c1")


def test_every_artifact_fails_with_the_reason_when_the_backend_is_down():
    res = _enrich(_down)
    for name in GW:
        assert res[name]["status"] == "failed", (name, res[name])
        assert "windows-triage backend or gateway unavailable" in res[name]["reason"]
        assert res[name]["enriched"] == 0 and res[name]["checked"] == N


def test_idx_enrich_triage_says_incomplete_and_names_the_artifacts():
    resp = _tool(_down)
    assert resp["status"] == "incomplete", resp
    assert sorted(resp["failed_artifacts"]) == sorted(GW)


def test_a_working_backend_is_complete_with_the_same_counts():
    res = _enrich(_ok)
    for name in GW:
        assert res[name]["status"] == "complete" and "reason" not in res[name]
    got = {k: (res[k]["checked"], res[k]["enriched"]) for k in GW}
    # File artifacts stamp one update per verdict group (2); the others, 2 per value.
    assert got == {k: (N, 2) for k in GW[:5]} | {k: (N, 2 * N) for k in GW[5:]}
    resp = _tool(_ok)
    assert resp["status"] == "complete" and "failed_artifacts" not in resp


def test_one_transient_failure_among_successes_stays_complete():
    calls = {"n": 0}

    def flaky(name, args, timeout=60):
        calls["n"] += 1
        if calls["n"] % N == 2:  # one failure per artifact
            raise TimeoutError("timed out")
        return _ok(name, args)

    res = _enrich(flaky)
    assert {res[k]["status"] for k in GW} == {"complete"}, res


def test_a_backend_lost_mid_run_fails_after_stamping_what_it_got():
    """Each artifact's first value is answered, then every call fails: the
    partial verdicts are still stamped, and the status says it stopped."""

    def dies(name, args, timeout=60):
        if "x0." in str(args):  # each file artifact's first value
            return _ok(name, args)
        raise RuntimeError(f"Tool not found: {name}")

    res = _enrich(dies)
    for name in GW[:5]:  # file artifacts: one verdict stamped (2 updates)
        assert res[name]["status"] == "failed", (name, res[name])
        assert res[name]["enriched"] == 2, (name, res[name])


def _tool_small(call_tool, n):
    with (
        patch.object(tr, "gateway_available", return_value=True),
        patch.object(tr, "call_tool", side_effect=call_tool),
        patch.object(srv, "_get_os", return_value=StubOS(n)),
        patch.object(srv.audit, "log", return_value=None),
    ):
        return srv.idx_enrich_triage(case_id="c1")


def test_an_artifact_shorter_than_the_stop_fails_when_every_call_failed():
    """Two values never reach the three-in-a-row stop; both failing is still
    a failure, not `complete, enriched 0`."""
    res = _enrich(_down, n=2)
    for name in GW:
        assert res[name]["status"] == "failed", (name, res[name])
        assert "windows-triage backend or gateway unavailable" in res[name]["reason"]
    resp = _tool_small(_down, n=2)
    assert resp["status"] == "incomplete" and "amcache" in resp["failed_artifacts"], resp


def test_one_answer_then_one_failure_is_not_failed():
    """The loop ends on a failure, so only the answer before it keeps the
    artifact `complete`."""
    calls = {"n": 0}

    def every_other(name, args, timeout=60):
        calls["n"] += 1
        if calls["n"] % 2 == 0:  # each artifact's second call
            raise TimeoutError("timed out")
        return _ok(name, args)

    res = _enrich(every_other, n=2)
    assert {res[k]["status"] for k in GW} == {"complete"}, res
