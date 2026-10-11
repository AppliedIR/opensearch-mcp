"""Triage checks the executable a scheduled task or Run key starts, reads every
Run-key variant, and says when a Run value is too long to read.

check_file gets the executable a command line starts (a quoted path, the
shortest prefix ending in an executable extension before a space, a RunOnceEx
"||cmd" or "file|Function") and, as before, the value itself; each document
gets the worse answer. Tasks count the values sent (`checked`) and those that
name no executable (`not_checked`). RunOnce, RunOnceEx, RunServices and
RunServicesOnce are read beside Run; Explorer\\RunMRU is not. A Run value over
256 characters has no keyword term, so it can't be read: it is counted
(`too_long`) and fails the step.

OpenSearch is a stand-in that runs the queries triage sends, with `.keyword`
dropping values over 256 characters as `ignore_above` does; check_file answers
by exact string, so what was sent shows in each stamp.
"""

from __future__ import annotations

import fnmatch
import re

import pytest

from opensearch_mcp import triage_remote as tr

SUSP = {"verdict": "SUSPICIOUS", "confidence": "high", "reasons": ["masquerade"]}
LOLBIN = {"verdict": "EXPECTED_LOLBIN", "confidence": "high", "reasons": ["lolbin"],
          "is_lolbin": True}  # fmt: skip
UNKNOWN = {"verdict": "UNKNOWN", "confidence": "low", "reasons": ["Not in baseline"]}


def _field(doc, name):
    if name.endswith(".keyword"):
        v = doc.get(name[: -len(".keyword")])
        return None if isinstance(v, str) and len(v) > 256 else v  # ignore_above 256
    return doc.get(name)


def _wildcard(pattern):
    out = re.sub(r"\\(.)|(\*)|(.)", lambda m: re.escape(m[1]) if m[1] is not None
                 else ".*" if m[2] else re.escape(m[3]), pattern)  # fmt: skip
    return re.compile(out + r"\Z", re.S)


def _match(q, doc) -> bool:
    ((kind, body),) = q.items()
    if kind == "match_all":
        return True
    if kind == "bool":
        must = [*body.get("must", []), *body.get("filter", [])]
        should, msm = body.get("should", []), body.get("minimum_should_match", 0 if must else 1)
        return (all(_match(c, doc) for c in must)
                and not any(_match(c, doc) for c in body.get("must_not", []))
                and (not should or not msm
                     or sum(_match(c, doc) for c in should) >= msm))  # fmt: skip
    ((f, v),) = body.items() if kind != "exists" else [(body["field"], None)]
    if kind == "term":
        return _field(doc, f) == v
    if kind == "terms":
        return _field(doc, f) in v
    if kind == "wildcard":
        return isinstance(_field(doc, f), str) and bool(_wildcard(v).match(_field(doc, f)))
    if kind == "exists":
        return _field(doc, f) is not None
    if kind == "query_string":
        return v == "*"
    raise AssertionError(f"query not modelled: {q}")


class Cluster:
    def __init__(self, indices):
        self.store = indices

        class Indices:
            def refresh(self, **kw):
                return {}

        self.indices = Indices()

    def _docs(self, index):
        names = [n for n in self.store for p in str(index).split(",")
                 if p and not p.startswith("-") and fnmatch.fnmatchcase(n, p)]  # fmt: skip
        return [d for n in dict.fromkeys(names) for d in self.store[n]]

    def search(self, index=None, body=None, **kw):
        hits = [d for d in self._docs(index) if _match(body.get("query", {"match_all": {}}), d)]
        out = {"hits": {"total": {"value": len(hits)}, "hits": []}}
        for name, agg in (body.get("aggs") or {}).items():
            counts: dict = {}
            for d in hits:
                if (v := _field(d, agg["terms"]["field"])) is not None:
                    counts[v] = counts.get(v, 0) + 1
            buckets = [{"key": k, "doc_count": n} for k, n in counts.items()]
            out.setdefault("aggregations", {})[name] = {
                "buckets": buckets,
                "sum_other_doc_count": 0,
            }
        return out

    def update_by_query(self, index=None, body=None, **kw):
        src, params = body["script"]["source"], body["script"].get("params") or {}
        hits = [d for d in self._docs(index) if _match(body["query"], d)]
        if "params.verdict" in src:
            for d in hits:
                d["triage.verdict"] = params["verdict"]
                d["triage.lolbin"] = d.get("triage.lolbin") or "triage.lolbin'] = true" in src
        return {"updated": len(hits) if "params.verdict" in src else 0, "total": len(hits)}


@pytest.fixture
def triage(monkeypatch):
    """Run triage over `indices` with a check_file that answers by exact string;
    returns the step results, what check_file got and each doc's stamp."""

    def run(indices, table):
        sent = []

        def call_tool(name, args, timeout=None):
            if name != "check_file":
                return {}
            sent.append(args["path"])
            answer = table.get(args["path"], UNKNOWN)
            if isinstance(answer, Exception):
                raise answer
            return dict(answer)

        monkeypatch.setattr(tr, "call_tool", call_tool)
        monkeypatch.setattr(tr, "gateway_available", lambda: True)
        cluster = Cluster(indices)
        results = tr.enrich_remote(cluster, "cmdline")
        stamps = {d["_id"]: (d.get("triage.verdict"), bool(d.get("triage.lolbin")))
                  for docs in indices.values() for d in docs}  # fmt: skip
        return results, set(sent), stamps

    return run


TASKS = {
    "t1": "%windir%\\Temp\\svchost.exe",
    "t2": "powershell.exe",
    "t3": '"C:\\Users\\Public\\svchost.exe"',
    "t4": "C:\\Program Files\\Vendor App\\upd.exe",
    "t5": '"C:\\Program Files\\Vendor App\\upd.exe"',
    "t6": "C:\\Windows\\System32\\rundll32.exe",
    "t7": "UpdaterTask",
    "t8": "C:\\Windows\\System32\\cmd.exe /c C:\\Users\\Public\\evil.bat",
    "t9": "C:\\Users\\Public\\run.vbs /x",
    "t10": "\\\\fileserver\\share\\evil.exe /q",
    "t11": "\\??\\C:\\Users\\Public\\svchost.exe",
}
TASK_ANSWERS = {
    "%windir%\\Temp\\svchost.exe": SUSP, "powershell.exe": LOLBIN,
    "C:\\Users\\Public\\svchost.exe": SUSP, "C:\\Program Files\\Vendor App\\upd.exe": SUSP,
    "C:\\Windows\\System32\\rundll32.exe": LOLBIN, "C:\\Windows\\System32\\cmd.exe": LOLBIN,
    "C:\\Users\\Public\\run.vbs": SUSP, "\\\\fileserver\\share\\evil.exe": SUSP,
    "\\??\\C:\\Users\\Public\\svchost.exe": SUSP,
}  # fmt: skip


def test_a_task_is_checked_by_the_executable_it_starts_and_as_before(triage):
    docs = [{"_id": i, "task.command": v} for i, v in TASKS.items()]
    results, sent, stamps = triage({"case-cmdline-tasks-h1": docs}, TASK_ANSWERS)
    # the executables (a bare name is none), plus each command sent before that differs
    assert sent == (set(TASK_ANSWERS) - {"powershell.exe"}) | {
        TASKS["t8"],
        TASKS["t9"],
        TASKS["t10"],
    }
    assert stamps == {
        "t1": ("SUSPICIOUS", False), "t2": (None, False), "t3": ("SUSPICIOUS", False),
        "t4": ("SUSPICIOUS", False), "t5": ("SUSPICIOUS", False), "t6": ("UNKNOWN", True),
        "t7": (None, False), "t8": ("UNKNOWN", True), "t9": ("SUSPICIOUS", False),
        "t10": ("SUSPICIOUS", False), "t11": ("SUSPICIOUS", False),
    }  # fmt: skip
    task = results["tasks"]
    assert (task["checked"], task["not_checked"], task["status"]) == (9, 2, "complete")


RUN = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"
IFEO = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe"
SETUP = "ROOT\\Microsoft\\Active Setup\\Installed Components\\"


def _reg(i, key, data):
    return {"_id": i, "KeyPath": key, "ValueName": i, "ValueData": data}


def test_a_run_key_or_stubpath_is_checked_by_its_executable_and_as_before(triage):
    svchost = "C:\\Users\\Public\\svchost.exe"
    values = [
        ("r1", RUN, f'"{svchost}" -k netsvcs'),
        ("r2", RUN, "C:\\Windows\\System32\\rundll32.exe "
                    "C:\\Users\\bob\\AppData\\Roaming\\x.dll,Start"),
        ("r3", RUN, "C:\\Program Files\\Vendor App\\agent.exe /background"),
        ("r4", RUN, "%ProgramFiles%\\Windows Defender\\MSASCuiL.exe"),
        ("r5", RUN, svchost),
        ("r6", IFEO, svchost),
        ("w1", RUN, f"C:\\Windows\\System32\\cmd.exe /c start {svchost}"),
        ("w2", RUN, f"C:\\Windows\\System32\\rundll32.exe {svchost}"),
        ("b4", RUN, f"cmd /c start {svchost}"),
        ("r7", RUN, "C:\\Users\\Public\\run.ps1 -x"),
        ("r8", RUN, "\\\\fileserver\\share\\evil.exe /q"),
        ("s1", SETUP + "{A}", '"C:\\ProgramData\\x\\svchost.exe" /install'),
        ("s2", SETUP + "{B}", "%SystemRoot%\\system32\\unregmp2.exe /FirstLogon /Shortcuts"),
    ]  # fmt: skip
    docs = [_reg(i, k, v) for i, k, v in values]
    for d in docs:
        if d["_id"].startswith("s"):
            d["ValueName"] = "StubPath"
    exes = {
        svchost: SUSP, "C:\\Windows\\System32\\rundll32.exe": LOLBIN,
        "C:\\Windows\\System32\\cmd.exe": LOLBIN, "C:\\Program Files\\Vendor App\\agent.exe": SUSP,
        "C:\\Users\\Public\\run.ps1": SUSP, "\\\\fileserver\\share\\evil.exe": SUSP,
        "C:\\ProgramData\\x\\svchost.exe": SUSP, "%SystemRoot%\\system32\\unregmp2.exe": LOLBIN,
    }  # fmt: skip
    # a LOLBin wrapper's whole line reads SUSPICIOUS (check_file reads its last path)
    wrappers = {v: SUSP for i, _, v in values if i in ("w1", "w2", "b4")}
    _, sent, stamps = triage({"case-cmdline-registry-h1": docs}, {**exes, **wrappers})
    assert sent == {v for i, _, v in values if i != "r6"} | set(exes)
    assert stamps == {
        "r1": ("SUSPICIOUS", False), "r2": ("UNKNOWN", True), "r3": ("SUSPICIOUS", False),
        "r4": ("UNKNOWN", False), "r5": ("SUSPICIOUS", False), "r6": (None, False),
        "w1": ("SUSPICIOUS", True), "w2": ("SUSPICIOUS", True), "b4": ("SUSPICIOUS", False),
        "r7": ("SUSPICIOUS", False), "r8": ("SUSPICIOUS", False),
        "s1": ("SUSPICIOUS", False), "s2": ("UNKNOWN", False),  # StubPath writes no LOLBin flag
    }  # fmt: skip


def test_every_run_key_variant_is_read_but_not_runmru(triage):
    cv = "ROOT\\Microsoft\\Windows\\CurrentVersion\\"
    keys = {
        "k1": (cv + "Run", "C:\\Users\\Public\\k1.exe"),
        "k2": ("ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
               "C:\\Users\\Public\\k2.exe"),
        "k3": (cv + "RunOnce", "C:\\Users\\Public\\k3.exe"),
        "k4": (cv + "RunOnce\\Setup", "C:\\Users\\Public\\k4.exe"),
        "k5": (cv + "RunOnceEx\\0001", "||C:\\Users\\Public\\k5.exe"),
        "k9": (cv + "RunOnceEx\\0002", "C:\\Users\\Public\\k9.dll|DllRegisterServer"),
        "k6": (cv + "RunServices", "C:\\Users\\Public\\k6.exe"),
        "k7": (cv + "RunServicesOnce", "C:\\Users\\Public\\k7.exe"),
        "k8": (cv + "Policies\\Explorer\\Run", "C:\\Users\\Public\\k8.exe"),
        "n1": (cv + "Explorer\\RunMRU", "C:\\Users\\Public\\n1.exe"),  # typed commands
    }  # fmt: skip
    docs = [_reg(i, k, v) for i, (k, v) in keys.items()]
    exe = {i: v for i, (_, v) in keys.items()}  # RunOnceEx's own formats name theirs:
    exe.update(k5="C:\\Users\\Public\\k5.exe", k9="C:\\Users\\Public\\k9.dll")
    # only the executables answer SUSPICIOUS: each doc's stamp shows its own was sent
    _, sent, stamps = triage({"case-cmdline-registry-h1": docs}, {e: SUSP for e in exe.values()})
    run = [i for i in keys if i != "n1"]
    assert sent == {keys[i][1] for i in run} | {exe[i] for i in run}
    assert all(stamps[i] == ("SUSPICIOUS", False) for i in run) and stamps["n1"] == (None, False)


@pytest.mark.parametrize("short", [True, False], ids=["beside a short value", "alone"])
def test_a_run_value_too_long_to_read_is_counted_and_fails_the_step(triage, short):
    long_value = "C:\\Users\\Public\\" + "x" * 295 + ".exe"
    assert len(long_value) > 256
    docs = [_reg("long", RUN, long_value)]
    if short:  # two docs hold it, so a count of total minus buckets would say 2
        docs += [_reg("s1", RUN, "C:\\Users\\Public\\short.exe"),
                 _reg("s2", RUN, "C:\\Users\\Public\\short.exe")]  # fmt: skip
    results, sent, _ = triage({"case-cmdline-registry-h1": docs}, {})
    run = results["registry_run"]
    assert run["status"] == "failed" and run["too_long"] == 1, run
    assert "256" in run["reason"] and long_value not in sent


def test_a_value_is_answered_only_when_every_lookup_for_it_answered(triage):
    """The executable answers, the whole line times out: as when the line's
    one lookup failed before, the step isn't complete and nothing is written
    over the document's earlier stamp."""
    line = "C:\\Windows\\System32\\cmd.exe /c start C:\\Users\\Public\\svchost.exe"
    doc = {**_reg("w1", RUN, line), "triage.verdict": "SUSPICIOUS"}
    table = {"C:\\Windows\\System32\\cmd.exe": LOLBIN, line: TimeoutError("timed out")}
    results, _, stamps = triage({"case-cmdline-registry-h1": [doc]}, table)
    assert results["registry_run"]["status"] == "failed", results["registry_run"]
    assert stamps["w1"] == ("SUSPICIOUS", False)
