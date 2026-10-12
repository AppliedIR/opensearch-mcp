"""A re-run whose answer is no longer a LOLBin removes the earlier
`triage.lolbin`; one that still is keeps it.

LOLBAS changes upstream: an entry removed or renamed there no longer makes
check_file answer is_lolbin, and the next triage run must not leave the old
flag beside its new verdict. Each writer is covered: Run keys, Active Setup
StubPath, NetSh, the batch writer (Shimcache) and the per-hash writer
(Amcache), the last through StampingClient's rewrite of its painless script.

Runs against a cluster under this run's template names (test_triage_default_install's
rig). windows-triage is a stand-in whose answer for each path the test sets;
values are synthetic.
"""

from __future__ import annotations

import uuid

import pytest
from test_triage_default_install import (  # noqa: F401
    AMCACHE,
    REGISTRY,
    S32,
    Case,
    _reg,
    kv,
    scratch,
)

from opensearch_mcp import triage_remote

pytestmark = pytest.mark.integration

RUNDLL32, CMD, IFMON = S32 + "rundll32.exe", S32 + "cmd.exe", "ifmon.dll"
SHA1 = "1" * 40
LOLBIN = {"verdict": "EXPECTED_LOLBIN", "confidence": "high", "reasons": ["lolbin"],
          "is_lolbin": True}  # fmt: skip
NOT_LOLBIN = {"verdict": "EXPECTED", "confidence": "high", "reasons": ["path"],
              "is_lolbin": False}  # fmt: skip


@pytest.fixture
def rerun(scratch, tmp_path, monkeypatch):  # noqa: F811
    """A case holding one entry for each writer, and a run that answers every
    check_file with `answer`."""
    client, tag = scratch
    answer = {"now": LOLBIN}
    monkeypatch.setattr(triage_remote, "call_tool",
                        lambda tool, args, timeout=None: dict(answer["now"]))  # fmt: skip
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)
    case = Case(client, tag, f"lolbin-{uuid.uuid4().hex[:6]}", tmp_path)
    case.csv("registry", REGISTRY, [
        _reg("ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "A", RUNDLL32, "Run"),
        _reg("ROOT\\Microsoft\\NetSh", "ifmon", IFMON, "NetSh"),
    ])  # fmt: skip
    case.doc("registry", "as1", {"KeyPath": "ROOT\\Microsoft\\Active Setup\\Installed "
             "Components\\{1}", "ValueName": "StubPath", "ValueData": CMD})  # fmt: skip
    case.csv("shimcache", "Path,Executed", [f"{RUNDLL32},True"])
    case.csv("amcache", AMCACHE, [f"{RUNDLL32},{SHA1},1000,amc"])

    def run(now):
        answer["now"] = now
        result = triage_remote.enrich_remote(client, case.id)
        client.indices.refresh(index=f"case-{case.id}-*")
        return result

    return case, run


WRITERS = {  # step: (index kind, the entry's query)
    "registry_run": ("registry", kv("ValueName.keyword", "A")),
    "registry_activestub": ("registry", kv("_id", "as1")),
    "registry_netsh": ("registry", kv("ValueName.keyword", "ifmon")),
    "shimcache": ("shimcache", {"match_all": {}}),
    "amcache": ("amcache", kv("Name.keyword", "amc")),
}


@pytest.mark.parametrize("step", WRITERS)
def test_a_re_run_that_isnt_a_lolbin_removes_the_flag(rerun, step):
    case, run = rerun
    kind, query = WRITERS[step]
    first = run(LOLBIN)
    assert first[step]["status"] == "complete", first[step]
    assert case.one(kind, query)["lolbin"] is True
    second = run(NOT_LOLBIN)
    assert second[step]["status"] == "complete", second[step]
    stamp = case.one(kind, query)
    assert "lolbin" not in stamp, stamp
    assert stamp["verdict"] in ("EXPECTED", "UNKNOWN") and stamp["reason"]


@pytest.mark.parametrize("step", WRITERS)
def test_a_re_run_still_a_lolbin_keeps_the_flag(rerun, step):
    case, run = rerun
    kind, query = WRITERS[step]
    run(LOLBIN)
    again = dict(LOLBIN, reasons=["lolbin, again"])
    second = run(again)
    assert second[step]["status"] == "complete", second[step]
    stamp = case.one(kind, query)
    assert stamp["lolbin"] is True and "lolbin, again" in stamp["reason"], stamp
