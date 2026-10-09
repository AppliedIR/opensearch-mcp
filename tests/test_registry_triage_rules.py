"""Registry triage reads the values it needs and stops flagging Windows' own.

- The scan's one RECmd run uses Kroll's batch with the keys the rules read
  appended, under Kroll's file name; Kroll's own text is kept as it is.
- The persistence rules flag a value only when it is set and isn't one
  Windows writes: an empty value, Windows' print monitors, LSA package lists
  holding only quote characters besides the defaults, and BootExecute's
  `autocheck autochk` entries (switches, all volumes or one) aren't flagged.
- A rule that no longer flags a row removes its own earlier stamp, and
  leaves another step's stamp alone.
- Active Setup is read from the value RECmd writes (`ValueName` StubPath).
- The result names the rules that had no registry value to check, and an
  empty registry loop says why.

The cluster rows run against a cluster under this run's template names, with
windows-triage stood in; values are synthetic.
"""

from __future__ import annotations

import fnmatch
import time
import uuid
from pathlib import Path

import _scratch_templates
import pytest
import yaml

from opensearch_mcp import tools, triage_remote

# Kroll's file name and a few of its kinds of scalar (a capitalised boolean,
# a YAML-1.1 "yes", an octal-looking string) whose text must survive
KROLL = """Description: Kroll RECmd Batch File
Author: someone
Version: 1.22
Id: 00000000-0000-0000-0000-000000000000
Keys:
    -
        Description: Run
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\\Windows\\CurrentVersion\\Run
        Recursive: False
    -
        Description: odd scalars
        HiveType: SYSTEM
        Category: Test
        KeyPath: Select
        ValueName: yes
        Comment: 010
        Recursive: false

# More to come...
"""


def _scalars(text: str) -> list[str]:
    """Each scalar's text as written, in order."""
    out = []

    def walk(node):
        if isinstance(node, yaml.ScalarNode):
            out.append(node.value)
        elif isinstance(node, yaml.SequenceNode):
            for n in node.value:
                walk(n)
        elif isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                walk(k)
                walk(v)

    walk(yaml.compose(text))
    return out


def _keys_node_scalars(text: str) -> list[list[str]]:
    keys = next(v for k, v in yaml.compose(text).value if k.value == "Keys")
    return [_scalars(yaml.serialize(entry)) for entry in keys.value]


class TestTheCombinedBatch:
    @pytest.fixture
    def kroll(self, tmp_path, monkeypatch):
        path = tmp_path / "zt" / "Kroll_Batch.reb"
        path.parent.mkdir()
        path.write_text(KROLL, encoding="utf-8")
        monkeypatch.setattr(tools, "_RECMD_BATCH", str(path))
        return path

    def test_kroll_s_entries_then_the_triage_keys_under_kroll_s_name(self, kroll, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        cmd = tools._build_command(
            tools.TOOLS["registry"], "registry", tmp_path / "config" / "SYSTEM", str(out)
        )
        batch = Path(cmd[cmd.index("--bn") + 1])
        assert batch.name == "Kroll_Batch.reb" and batch.parent.parent == out
        text = batch.read_text(encoding="utf-8")
        triage = tools._TRIAGE_KEYS.read_text(encoding="utf-8")
        kroll_entries = _keys_node_scalars(KROLL)
        triage_entries = _keys_node_scalars(triage)
        assert len(triage_entries) == 18
        assert _keys_node_scalars(text) == kroll_entries + triage_entries
        assert text.startswith(KROLL.rstrip("\n"))  # Kroll's text, as written
        assert {"False", "yes", "010"} <= set(_scalars(text))  # not coerced on the way

    @pytest.mark.parametrize(
        "content",
        [None, "Keys: [unclosed\n", "Description: no keys\n", "- a list\n"],
        ids=["missing", "malformed", "no-keys", "not-a-mapping"],
    )
    def test_without_a_usable_kroll_batch_the_command_is_today_s(self, kroll, tmp_path, content):
        if content is None:
            kroll.rename(kroll.with_suffix(".gone"))
        else:
            kroll.write_text(content, encoding="utf-8")
        assert tools._registry_batch(str(tmp_path)) == str(kroll)


# The cluster rows

SM = "ROOT\\ControlSet001\\Control\\Session Manager"
LSA = "ROOT\\ControlSet001\\Control\\Lsa"
MON = "ROOT\\ControlSet001\\Control\\Print\\Monitors\\"
WIN = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
WINLOGON = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
IFEO = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe"
STUB = "ROOT\\Microsoft\\Active Setup\\Installed Components\\{a}"

# (key, value name, data) Windows writes: no stamp
WINDOWS = {
    "appinit-empty": (WIN, "AppInit_DLLs", ""),
    "ifeo-blank": (IFEO, "Debugger", " "),
    "ssp-quotes": (LSA, "Security Packages", '""'),
    "monitor-tcpmon": (MON + "Standard TCP/IP Port", "Driver", "tcpmon.dll"),
    "monitor-upper": (MON + "USB Monitor", "Driver", "USBMON.DLL"),
    "boot-default": (SM, "BootExecute", "autocheck autochk *"),
    "boot-switches": (SM, "BootExecute", "autocheck autochk /q /v *"),
    "boot-volume-switch": (SM, "BootExecute", "autocheck autochk /k:C *"),
    "boot-chkdsk-pending": (
        SM,
        "BootExecute",
        "autocheck autochk /p \\??\\C: autocheck autochk *",
    ),
}
# what an attacker writes: stays SUSPICIOUS, the reason naming it
ATTACKER = {
    "appinit-dll": (WIN, "AppInit_DLLs", "C:\\ProgramData\\x.dll", "AppInit_DLLs: "),
    "ifeo-cmd": (IFEO, "Debugger", "C:\\Windows\\System32\\cmd.exe", "IFEO debugger: "),
    "ssp-evil": (LSA, "Security Packages", '"" evilssp', "Non-default Security Packages: "),
    "np-mimilib": (
        LSA,
        "Notification Packages",
        "rassfm scecli mimilib",
        "Non-default Notification Packages: ",
    ),
    "monitor-evil": (MON + "Evil", "Driver", "evilmon.dll", "Print Monitor DLL: "),
    "monitor-path": (
        MON + "Local Port",
        "Driver",
        "C:\\Users\\Public\\localspl.dll",
        "Print Monitor DLL: ",
    ),
    "boot-trailing": (SM, "BootExecute", "autocheck autochk * evil.exe", "BootExecute: "),
    "boot-other-program": (SM, "BootExecute", "autocheck evilchk *", "BootExecute: "),
    "boot-not-a-switch": (SM, "BootExecute", "autocheck autochk evil.exe *", "BootExecute: "),
    "boot-second-entry": (
        SM,
        "BootExecute",
        "autocheck autochk * evilnt evilnt.exe *",
        "BootExecute: ",
    ),
    "shell-extra": (WINLOGON, "Shell", "explorer.exe, evil.exe", "Winlogon Shell: "),
}
# the stamp each Windows value got from a version that flagged it
OLD_STAMP = {
    "appinit-empty": "AppInit_DLLs: ",
    "ifeo-blank": "IFEO debugger:  ",
    "ssp-quotes": 'Non-default Security Packages: ""',
    "monitor-tcpmon": "Print Monitor DLL: tcpmon.dll",
    "monitor-upper": "Print Monitor DLL: USBMON.DLL",
    "boot-switches": "BootExecute: autocheck autochk /q /v *",
    "boot-volume-switch": "BootExecute: autocheck autochk /k:C *",
    "boot-chkdsk-pending": "BootExecute: autocheck autochk /p \\??\\C: autocheck autochk *",
}
ALL_RULES = [
    "IFEO debugger",
    "SilentProcessExit monitor",
    "AppInit_DLLs",
    "Winlogon mpnotify",
    "Print Monitor DLL",
    "cmd.exe AutoRun",
    "Explorer Load",
    "TS InitialProgram",
    "Authentication Packages",
    "Security Packages",
    "Notification Packages",
    "Winlogon Shell",
    "Winlogon Userinit",
    "BootExecute",
    "Screensaver",
]
WITHOUT_DATA = [  # the rules none of WINDOWS/ATTACKER/the extra rows below reach
    "SilentProcessExit monitor",
    "Winlogon mpnotify",
    "cmd.exe AutoRun",
    "Explorer Load",
    "TS InitialProgram",
    "Screensaver",
]


def _check_file(args):
    if args["path"].lower().startswith("c:\\users\\public"):
        return {"verdict": "SUSPICIOUS", "confidence": "high", "reasons": ["masquerade"]}
    return {"verdict": "EXPECTED", "confidence": "high", "reasons": ["path"]}


@pytest.fixture(scope="module")
def scratch():
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    tag = f"pytest-tpl-{uuid.uuid4().hex[:8]}"
    created = _scratch_templates.install(client, tag)
    try:
        yield client, tag
    finally:
        client.indices.delete(index=f"case-{tag}-*", ignore=[404])
        _scratch_templates.remove(client, created)


@pytest.fixture
def case(scratch, monkeypatch):
    client, tag = scratch
    looked_up: list = []

    def call_tool(tool, args, timeout=None):
        # A real lookup takes longer than the 1 s refresh interval, so the
        # rules' writes are visible to the lookup's stamp, as they are in a run
        if not looked_up:
            time.sleep(1.5)
        looked_up.append(args)
        return _check_file(args)

    monkeypatch.setattr(triage_remote, "call_tool", call_tool)
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)
    case_id = f"{tag}-{uuid.uuid4().hex[:6]}"
    index = f"case-{case_id}-registry-h1"

    class Case:
        id = case_id

        def add(self, doc_id, key, name, data, **stamp):
            body = {"KeyPath": key, "ValueName": name, "ValueData": data}
            body.update({f"triage.{k}": v for k, v in stamp.items()})
            client.index(index=index, id=doc_id, body=body)

        def triage(self):
            client.indices.refresh(index=index)
            result = triage_remote.enrich_remote(client, case_id)
            client.indices.refresh(index=index)
            return result

        def stamp(self, doc_id):
            src = client.get(index=index, id=doc_id)["_source"]
            return {k: v for k, v in src.items() if k.startswith("triage.")}

    return Case()


def _all(case):
    for doc_id, (key, name, data) in WINDOWS.items():
        case.add(doc_id, key, name, data)
    for doc_id, (key, name, data, _) in ATTACKER.items():
        case.add(doc_id, key, name, data)


@pytest.mark.integration
class TestTheRules:
    def test_windows_values_get_no_stamp(self, case):
        _all(case)
        case.triage()
        assert {d: case.stamp(d) for d in WINDOWS} == dict.fromkeys(WINDOWS, {})

    def test_attacker_values_stay_suspicious(self, case):
        _all(case)
        case.triage()
        for doc_id, (_, _, data, reason) in ATTACKER.items():
            stamp = case.stamp(doc_id)
            assert stamp.get("triage.verdict") == "SUSPICIOUS", (doc_id, stamp)
            assert stamp["triage.reason"].startswith(reason), (doc_id, stamp)
            assert stamp["triage.reason"].endswith(data.split()[-1]), (doc_id, stamp)

    def test_a_re_triage_removes_the_stamps_an_older_version_put_on_windows_values(self, case):
        for doc_id, (key, name, data) in WINDOWS.items():
            if doc_id in OLD_STAMP:
                case.add(
                    doc_id,
                    key,
                    name,
                    data,
                    verdict="SUSPICIOUS",
                    reason=OLD_STAMP[doc_id],
                    checked=True,
                )
        for doc_id, (key, name, data, _) in ATTACKER.items():
            case.add(doc_id, key, name, data)
        case.triage()
        assert {d: case.stamp(d) for d in OLD_STAMP} == dict.fromkeys(OLD_STAMP, {})
        assert all(case.stamp(d)["triage.verdict"] == "SUSPICIOUS" for d in ATTACKER)

    def test_another_step_s_stamp_on_a_row_a_rule_no_longer_flags_is_kept(self, case):
        kept = {"verdict": "SUSPICIOUS", "reason": "other step: kept", "checked": True}
        for doc_id, (key, name, data) in WINDOWS.items():
            case.add(doc_id, key, name, data, **kept)
        case.triage()
        want = {f"triage.{k}": v for k, v in kept.items()}
        assert {d: case.stamp(d) for d in WINDOWS} == dict.fromkeys(WINDOWS, want)

    def test_active_setup_reads_the_value_recmd_writes(self, case):
        case.add("stub", STUB, "StubPath", "C:\\Users\\Public\\stub.exe")
        case.add("other", STUB, "Version", "1,0,0,0")
        result = case.triage()
        assert case.stamp("stub").get("triage.verdict") == "SUSPICIOUS"
        assert case.stamp("other") == {}
        assert result["registry_activestub"]["status"] != "empty", result["registry_activestub"]


@pytest.mark.integration
class TestNoRuleDowngradesAnother:
    """A lookup's stamp lands only on the documents its loop selected."""

    def test_an_ifeo_verdict_survives_active_setup_naming_the_same_exe(self, case):
        exe = "C:\\Windows\\System32\\cmd.exe"  # check_file: EXPECTED → UNKNOWN (flags only)
        case.add("ifeo", IFEO, "Debugger", exe)
        case.add("stub", STUB, "StubPath", exe)
        case.add("uninstall", STUB, "UninstallString", exe)
        case.triage()
        assert case.stamp("ifeo")["triage.verdict"] == "SUSPICIOUS"
        assert case.stamp("ifeo")["triage.reason"].startswith("IFEO debugger: ")
        assert case.stamp("stub")["triage.verdict"] == "UNKNOWN"
        assert case.stamp("uninstall") == {}  # not a StubPath value

    def test_an_appinit_verdict_survives_a_netsh_helper_with_the_same_dll(self, case):
        dll = "C:\\ProgramData\\x.dll"
        case.add("appinit", WIN, "AppInit_DLLs", dll)
        case.add("netsh", "ROOT\\Microsoft\\NetSh", "helper", dll)
        case.triage()
        assert case.stamp("appinit")["triage.verdict"] == "SUSPICIOUS"
        assert case.stamp("netsh")["triage.verdict"] == "UNKNOWN"


@pytest.mark.integration
class TestRulesWithoutData:
    def test_the_rules_no_row_reached_are_named(self, case):
        _all(case)
        case.add("userinit", WINLOGON, "Userinit", "C:\\Windows\\system32\\userinit.exe,")
        case.add("np", LSA, "Notification Packages", "scecli")
        case.add("ap", LSA, "Authentication Packages", "msv1_0")
        rp = case.triage()["registry_persistence"]
        assert rp["rules_without_data"] == WITHOUT_DATA, rp
        assert rp["note"].startswith(f"{len(WITHOUT_DATA)} of 15 rules had no registry values")

    def test_one_unrelated_row_names_all_fifteen(self, case):
        case.add("x", "ROOT\\Select", "Current", "1")
        rp = case.triage()["registry_persistence"]
        assert rp["rules_without_data"] == ALL_RULES, rp
        assert rp["status"] == "complete"


# Stand-in rows (no cluster)


class _OpenSearch:
    def __init__(self, existing, fail_on=""):
        self.existing, self.fail_on = existing, fail_on

    def search(self, index, body, **kw):
        matched = [n for n in self.existing if fnmatch.fnmatch(n, index)]
        result = {"hits": {"total": {"value": 0}, "hits": []}, "_shards": {"total": len(matched)}}
        if body.get("aggs"):
            result["aggregations"] = {k: {"buckets": []} for k in body["aggs"]}
        return result

    def update_by_query(self, index, body, **kw):
        if self.fail_on and self.fail_on in str(body["query"]):
            raise RuntimeError("rule failed")
        return {"updated": 0, "total": 0}


def test_empty_registry_loops_say_why(monkeypatch):
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)
    monkeypatch.setattr(  # the database version only: no lookup
        triage_remote, "call_tool",
        lambda name, *a, **k: {} if name == "get_db_stats" else pytest.fail("no lookup"),
    )  # fmt: skip
    res = triage_remote.enrich_remote(_OpenSearch(["case-c1-registry-h"]), "c1")
    for name in ("registry_svcs", "registry_activestub", "registry_netsh"):
        assert res[name]["status"] == "empty", (name, res[name])
        assert res[name]["reason"].startswith("no registry values to check"), (name, res[name])


def test_a_failing_rule_is_counted_failed_not_without_data():
    client = _OpenSearch(["case-c1-registry-h"], fail_on="BootExecute")
    rp = triage_remote._enrich_registry_persistence(client, "c1")
    assert (rp["status"], rp["rules_failed"]) == ("failed", 1)
    assert rp["rules_without_data"] == [r for r in ALL_RULES if r != "BootExecute"]


def test_an_enrichment_run_is_a_step_and_every_triage_write_stamps_its_id(monkeypatch):
    import json
    import uuid

    from opensearch_mcp.write_context import case_dir_for

    monkeypatch.setattr(triage_remote, "gateway_available", lambda: False)
    cid = f"steps-{uuid.uuid4().hex[:8]}"  # a case of its own: its audit holds this run only
    audit = case_dir_for(cid) / "audit"
    calls = []

    class Recording(_OpenSearch):
        def update_by_query(self, index, body, **kw):
            written = sorted(audit.glob("*.jsonl"))
            entries = [json.loads(x) for f in written for x in f.read_text().splitlines()]
            calls.append((body, entries))
            return {"updated": 0, "total": 0}

    triage_remote.enrich_remote(Recording([f"case-{cid}-registry-h", f"case-{cid}-evtx-h"]), cid)
    (ref,) = [e for e in calls[0][1] if e["tool"] == "enrich_triage"]  # before the first write
    assert ref["reference"]["source"] and "opensearch-mcp" in ref["reference"]["source_version"]
    stamping = [b for b, _ in calls if "ctx._source['triage." in str(b["script"]["source"])]
    assert stamping  # the persistence rules stamp
    import re

    sets = re.compile(r"ctx\._source\['triage\.(?!op_id')\w+'\]\s*=(?!=)")
    for body in stamping:
        source = body["script"]["source"]
        assert body["script"]["params"]["op_id"] == ref["audit_id"]
        for m in sets.finditer(source):  # the id is set just before each triage field
            assert source[: m.start()].endswith("ctx._source['triage.op_id'] = params.op_id; ")
    clears = [b for b, _ in calls if b not in stamping]
    assert all("triage.op_id" in b["script"]["params"]["f"] for b in clears)  # cleared too
