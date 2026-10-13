"""A check_file reply with no verdict is a failed call, however many lookups
a value needs.

windows-triage answers its own errors ({"error": "database_error"},
{"error": "validation_error", ...}) as normal content, and the gateway passes
them on: such a reply answers nothing. A value sent as one lookup (a plain
path, a NetSh DLL) fails as a timed-out lookup does, so a step whose every
lookup comes back that way is `failed`, not `complete` with nothing enriched.
Shimcache's paths and Amcache's path-and-hash lookups follow the same rule.

OpenSearch is test_triage_command_lines' stand-in, or for Amcache's per-hash
aggregation a client that returns one; values are synthetic.
"""

from __future__ import annotations

import pytest
from test_triage_command_lines import NETSH, RUN, UNKNOWN, _reg, triage  # noqa: F401

from opensearch_mcp import triage_remote as tr

PLAIN = "C:\\Users\\Public\\svchost.exe"
DLL = "C:\\Users\\Public\\nh.dll"
NO_VERDICT = {
    "error": {"error": "backend error"},
    "empty": {},
    "text": {"text": "Input validation"},
    "validation_error": {
        "error": "validation_error",
        "message": "path contains a NUL byte",
        "audit_id": "wintriage-x-20261012-001",
    },  # fmt: skip
}
DATABASE_ERROR = {"error": "database_error", "message": "A database error occurred."}


@pytest.mark.parametrize("value", [PLAIN, DLL], ids=["plain path", "netsh dll"])
@pytest.mark.parametrize("reply", NO_VERDICT.values(), ids=NO_VERDICT.keys())
def test_one_lookup_with_no_verdict_is_a_failed_call(monkeypatch, value, reply):
    assert tr._sends(value) == [value]  # one lookup
    monkeypatch.setattr(tr, "call_tool", lambda name, args, timeout=None: dict(reply))
    state = {"failures": 0, "ok": False}
    assert tr._ask_all([value], state) is None
    assert state == {"failures": 1, "ok": False}


def test_one_lookup_with_a_verdict_is_answered(monkeypatch):
    monkeypatch.setattr(tr, "call_tool", lambda name, args, timeout=None: dict(UNKNOWN))
    state = {"failures": 0, "ok": False}
    assert tr._ask_all([PLAIN], state)["verdict"] == "UNKNOWN"
    assert state == {"failures": 0, "ok": True}


@pytest.mark.parametrize("reply", NO_VERDICT.values(), ids=NO_VERDICT.keys())
def test_run_and_netsh_values_answered_with_no_verdict_fail_the_step(triage, reply):  # noqa: F811
    old = {"triage.verdict": "SUSPICIOUS"}
    docs = [{**_reg(f"r{i}", RUN, f"C:\\Users\\Public\\r{i}.exe"), **old} for i in range(3)]
    docs += [{**_reg(f"n{i}", NETSH, f"C:\\Users\\Public\\n{i}.dll"), **old} for i in range(3)]
    table = {d["ValueData"]: reply for d in docs}
    results, sent, stamps = triage({"case-cmdline-registry-h1": docs}, table)
    assert sent == set(table)
    for step in ("registry_run", "registry_netsh"):
        assert results[step]["status"] == "failed", results[step]
    assert set(stamps.values()) == {("SUSPICIOUS", False)}  # nothing written


def test_run_values_with_a_verdict_complete_the_step(triage):  # noqa: F811
    docs = [_reg(f"r{i}", RUN, f"C:\\Users\\Public\\r{i}.exe") for i in range(3)]
    results, _, stamps = triage({"case-cmdline-registry-h1": docs}, {})
    assert results["registry_run"]["status"] == "complete", results["registry_run"]
    assert set(stamps.values()) == {("UNKNOWN", False)}


def test_shimcache_paths_answered_with_a_database_error_fail_the_step(triage):  # noqa: F811
    docs = [{"_id": f"s{i}", "Path": f"C:\\Users\\Public\\s{i}.exe"} for i in range(3)]
    table = {d["Path"]: DATABASE_ERROR for d in docs}
    results, sent, _ = triage({"case-cmdline-shimcache-h1": docs}, table)
    assert sent == set(table)
    assert results["shimcache"]["status"] == "failed", results["shimcache"]
    assert "consecutive gateway call failures" in results["shimcache"]["reason"]


class _Amcache:
    """Answers triage's path-and-hash aggregation; any write is a failure here."""

    def search(self, index=None, body=None, **kw):
        assert "hashes" in body["aggs"]["paths"]["aggs"], body
        buckets = [
            {"key": f"C:\\Users\\Public\\a{i}.exe", "doc_count": 1,
             "hashes": {"buckets": [{"key": f"{i}" * 40, "doc_count": 1,
                                     "sizes": {"buckets": [{"key": "1000"}]}}],
                        "sum_other_doc_count": 0}}
            for i in range(1, 4)
        ]  # fmt: skip
        return {"aggregations": {"paths": {"buckets": buckets, "sum_other_doc_count": 0}}}

    def update_by_query(self, **kw):
        raise AssertionError("nothing to write")


def test_amcache_hashes_answered_with_a_database_error_fail_the_step(monkeypatch):
    sent = []

    def call_tool(name, args, timeout=None):
        sent.append((args["path"], args.get("hash")))
        return dict(DATABASE_ERROR)

    monkeypatch.setattr(tr, "call_tool", call_tool)
    result = tr._enrich_file_artifact(
        _Amcache(), "x", "case-x-amcache-*", "FullPath.keyword", "amcache",
        hash_field="SHA1.keyword",
    )  # fmt: skip
    assert len(sent) == 3 and all(h for _, h in sent)  # each with its hash
    assert result["status"] == "failed", result
    assert "consecutive gateway call failures" in result["reason"]
