"""Automatic triage stamps a verdict only where windows-triage could earn it.

- Services are checked with their executable and no OS filter, once per
  (name, executable), and each verdict goes only to the documents that
  carry that pair: an ImagePath value, a 7045 event, an svcscan row (its
  registry binary first). Other values of a service key get no stamp.
- Process-creation events carry their image's verdict; other events don't.
- Tasks, Run, Active Setup and NetSh entries only flag: an EXPECTED target
  file is written as UNKNOWN, with the LOLBin flag kept.
- Amcache entries are checked with their SHA1, unless Amcache recorded none
  or couldn't have hashed the whole file; a SHA1 that matches no reference
  build reads UNKNOWN.
- A re-run removes the stamps this version no longer writes.

Runs against a cluster under this run's template names. windows-triage is
a stand-in that answers from the arguments it gets; values are synthetic.
"""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest

from opensearch_mcp import triage_remote
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import build_index_name

pytestmark = pytest.mark.integration

S32 = "C:\\Windows\\System32\\"
DEFAULT_EXE = {  # service: its default executable, lower-cased
    "Spooler": S32.lower() + "spoolsv.exe",
    "SpoolerHelper": S32.lower() + "spoolhlp.exe",
    "BITS": S32.lower() + "svchost.exe -k netsvcs -p",
    "ACPI": "\\systemroot\\system32\\drivers\\acpi.sys",
}
SHA1_OK, SHA1_OTHER, SHA1_BAD = "1" * 40, "2" * 40, "3" * 40
REGISTRY = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
    "ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile"
)


def _reg(keypath, name, data, category="Services"):
    return (
        f"C:\\h\\SYSTEM,SYSTEM,x,{category},{keypath},{name},RegSz,{data},,,,"
        "False,False,2024-01-01 00:00:00.0000000,"
    )


def check_service(args):
    if "os_version" in args:
        return {"error": "os_version sent"}
    given = args.get("binary_path", "").lower()
    if not given:
        return {"verdict": "UNKNOWN", "confidence": "low", "reasons": ["no binary_path supplied"]}
    if given == DEFAULT_EXE.get(args["service_name"]):
        return {"verdict": "EXPECTED", "confidence": "high", "reasons": ["executable matches"]}
    return {"verdict": "SUSPICIOUS", "confidence": "medium", "reasons": ["executable differs"]}


def check_file(args):
    path, sha1 = args["path"].lower(), args.get("hash")
    if path.endswith("rundll32.exe") and path.startswith(S32.lower()):
        return {
            "verdict": "EXPECTED_LOLBIN",
            "confidence": "high",
            "reasons": ["lolbin"],
            "is_lolbin": True,
        }
    if path.startswith("c:\\users\\public"):
        return {"verdict": "SUSPICIOUS", "confidence": "high", "reasons": ["masquerade"]}
    if path.endswith("nosha1.exe") and sha1:
        return {
            "verdict": "EXPECTED",
            "confidence": "high",
            "reasons": ["Hash not compared: the baseline has no SHA1 for this path"],
        }
    if sha1 == SHA1_OK:
        return {
            "verdict": "EXPECTED",
            "confidence": "high",
            "reasons": ["Hash matches a baseline build of this file"],
        }
    if sha1 in (SHA1_OTHER, SHA1_BAD):
        findings = [{"type": "hash_mismatch", "severity": "critical"}]
        if sha1 == SHA1_BAD:
            findings.append({"type": "unicode_evasion", "severity": "critical"})
        return {
            "verdict": "SUSPICIOUS",
            "confidence": "high",
            "findings": findings,
            "reasons": ["Hash does not match baseline - possible trojanized binary"],
        }
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


class Case:
    def __init__(self, client, tag, name, tmp_path):
        self.client, self.id, self.tmp = client, f"{tag}-{name}", tmp_path

    def csv(self, kind, header, rows):
        index = build_index_name(self.id, kind, "h1")
        path = self.tmp / f"{kind}.csv"
        path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
        _, _, failed = ingest_csv(path, self.client, index, "h1")
        assert failed == 0

    def doc(self, kind, doc_id, body):
        self.client.index(index=build_index_name(self.id, kind, "h1"), id=doc_id, body=body)

    def stamp(self, kind, query):
        self.client.indices.refresh(index=f"case-{self.id}-*")
        r = self.client.search(
            index=f"case-{self.id}-{kind}-*", body={"query": query, "size": 10000}
        )
        return [
            {
                k.removeprefix("triage."): v
                for k, v in h["_source"].items()
                if k.startswith("triage.")
            }
            for h in r["hits"]["hits"]
        ]

    def one(self, kind, query):
        (s,) = self.stamp(kind, query)
        return s


@pytest.fixture
def triage(scratch, tmp_path, monkeypatch):
    client, tag = scratch
    calls: list = []
    down = {"now": False}

    def call_tool(tool, args, timeout=None):
        calls.append((tool, dict(args)))
        if down["now"]:
            raise RuntimeError("Tool not found")
        return check_service(args) if tool == "check_service" else check_file(args)

    monkeypatch.setattr(triage_remote, "call_tool", call_tool)
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)

    def new_case(name):
        return Case(client, tag, f"{name}-{uuid.uuid4().hex[:6]}", tmp_path)

    def run(case):
        calls.clear()
        result = triage_remote.enrich_remote(client, case.id)
        client.indices.refresh(index=f"case-{case.id}-*")
        return result

    return new_case, run, calls, down


def kv(field, value):
    return {"term": {field: value}}


# Services


def _services(case):
    case.csv(
        "registry",
        REGISTRY,
        [
            _reg("ROOT\\ControlSet001\\Services\\Spooler", "ImagePath", S32 + "spoolsv.exe"),
            _reg("ROOT\\ControlSet002\\Services\\Spooler", "ImagePath", "C:\\ProgramData\\x.exe"),
            _reg(
                "ROOT\\ControlSet001\\Services\\BITS",
                "ImagePath",
                S32 + "svchost.exe -k netsvcs -p",
            ),
            _reg(
                "ROOT\\ControlSet001\\Services\\SpoolerHelper",
                "ImagePath",
                "C:\\ProgramData\\h.exe",
            ),
            _reg("ROOT\\ControlSet001\\Services\\Spooler", "Start", "2"),
            _reg("ROOT\\ControlSet001\\Services\\Spooler\\Parameters", "ServiceDll", "C:\\x.dll"),
        ],
    )


def test_each_service_doc_gets_the_verdict_for_its_own_executable(triage):
    new_case, run, calls, _ = triage
    case = new_case("svc")
    _services(case)
    result = run(case)
    assert result["registry_svcs"]["status"] == "complete"
    svc_calls = [a for t, a in calls if t == "check_service"]
    assert svc_calls and all("binary_path" in a and "os_version" not in a for a in svc_calls)
    by_value = lambda path: case.one("registry", kv("ValueData.keyword", path))  # noqa: E731
    assert by_value(S32 + "spoolsv.exe")["verdict"] == "EXPECTED"
    assert by_value("C:\\ProgramData\\x.exe")["verdict"] == "SUSPICIOUS"  # ControlSet002
    assert by_value(S32 + "svchost.exe -k netsvcs -p")["verdict"] == "EXPECTED"
    assert by_value("C:\\ProgramData\\h.exe")["verdict"] == "SUSPICIOUS"  # SpoolerHelper's own
    assert case.one("registry", kv("ValueName.keyword", "Start")) == {}
    assert case.one("registry", kv("ValueName.keyword", "ServiceDll")) == {}


def test_a_7045_event_and_svcscan_rows_are_checked_with_their_executable(triage):
    new_case, run, _, _ = triage
    case = new_case("svcev")
    case.doc(
        "evtx",
        "e7045",
        {
            "event.code": "7045",
            "winlog.event_data": {"ServiceName": "Spooler", "ImagePath": "C:\\ProgramData\\x.exe"},
        },
    )
    case.doc("vol-svcscan", "s1", {"Name": "Spooler", "Binary": "C:\\ProgramData\\x.exe"})
    case.doc(
        "vol-svcscan",
        "s2",
        {
            "Name": "ACPI",
            "Binary": "\\Driver\\ACPI",
            "Binary (Registry)": "C:\\ProgramData\\evil.sys",
        },
    )
    # Not yet restarted: memory still shows the default, the registry the hijack.
    case.doc(
        "vol-svcscan",
        "s3",
        {
            "Name": "Spooler",
            "Binary": S32 + "spoolsv.exe",
            "Binary (Registry)": "C:\\ProgramData\\x.exe",
        },
    )
    run(case)
    assert case.one("evtx", kv("_id", "e7045"))["verdict"] == "SUSPICIOUS"
    for doc_id in ("s1", "s2", "s3"):
        assert case.one("vol-svcscan", kv("_id", doc_id))["verdict"] == "SUSPICIOUS", doc_id


def test_every_imagepath_doc_is_stamped_past_5000(triage):
    new_case, run, _, _ = triage
    case = new_case("many")
    rows = [
        _reg(f"ROOT\\ControlSet{i:04d}\\Services\\Spooler", "ImagePath", S32 + "spoolsv.exe")
        for i in range(5200)
    ]
    case.csv("registry", REGISTRY, rows)
    result = run(case)
    assert result["registry_svcs"]["status"] == "complete", result["registry_svcs"]
    stamps = case.stamp("registry", kv("ValueName.keyword", "ImagePath"))
    assert len(stamps) == 5200 and {s.get("verdict") for s in stamps} == {"EXPECTED"}


def test_a_windows_triage_that_refuses_the_call_is_a_failure(triage, monkeypatch):
    new_case, run, _, _ = triage
    case = new_case("old")
    _services(case)
    monkeypatch.setattr(
        triage_remote, "call_tool", lambda tool, args, timeout=None: {"text": "Input validation"}
    )
    result = run(case)
    assert result["registry_svcs"]["status"] == "failed"
    assert "returned no verdict" in result["registry_svcs"]["reason"]


# Events and persistence entries


def test_only_process_creation_events_carry_the_image_verdict(triage):
    new_case, run, _, _ = triage
    case = new_case("ev")
    for doc_id, code in (("p4688", "4688"), ("p1", "1"), ("n3", "3"), ("n25", "25")):
        case.doc("evtx", doc_id, {"event.code": code, "process.name": S32 + "rundll32.exe"})
    run(case)
    for doc_id in ("p4688", "p1"):
        assert case.one("evtx", kv("_id", doc_id))["verdict"] == "EXPECTED_LOLBIN"
    for doc_id in ("n3", "n25"):
        assert case.one("evtx", kv("_id", doc_id)) == {}


def test_persistence_entries_only_flag(triage):
    new_case, run, _, _ = triage
    case = new_case("pers")
    case.doc("tasks", "t1", {"task.command": S32 + "rundll32.exe"})
    case.doc("tasks", "t2", {"task.command": "C:\\Users\\Public\\svchost.exe"})
    case.csv(
        "registry",
        REGISTRY,
        [
            _reg(
                "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "A", S32 + "rundll32.exe", "Run"
            ),
            _reg(
                "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run",
                "B",
                "C:\\Users\\Public\\sethc.exe",
                "Run",
            ),
            _reg("ROOT\\Microsoft\\NetSh", "ifmon", "ifmon.dll", "NetSh"),
        ],
    )
    active_setup = "ROOT\\Microsoft\\Active Setup\\Installed Components\\{1}"
    case.doc("registry", "as1", {"KeyPath": active_setup, "StubPath": S32 + "cmd.exe"})
    run(case)
    t1 = case.one("tasks", kv("_id", "t1"))
    assert (t1["verdict"], t1["lolbin"]) == ("UNKNOWN", True)
    assert t1["reason"].endswith("The entry itself is not compared to a baseline")
    assert case.one("tasks", kv("_id", "t2"))["verdict"] == "SUSPICIOUS"
    run_a = case.one("registry", kv("ValueName.keyword", "A"))
    assert (run_a["verdict"], run_a["lolbin"]) == ("UNKNOWN", True)
    assert case.one("registry", kv("ValueName.keyword", "B"))["verdict"] == "SUSPICIOUS"
    assert case.one("registry", kv("ValueName.keyword", "ifmon"))["verdict"] == "UNKNOWN"
    assert case.one("registry", kv("_id", "as1"))["verdict"] == "UNKNOWN"


# Amcache


AMCACHE = "FullPath,SHA1,Size,Name"


def test_amcache_entries_are_checked_with_their_sha1(triage):
    new_case, run, calls, _ = triage
    case = new_case("amc")
    case.csv(
        "amcache",
        AMCACHE,
        [
            f"{S32}sethc.exe,{SHA1_OK},1000,match",
            f"{S32}sethc.exe,{SHA1_OTHER},1000,other build",
            f"{S32}sethc.exe,{SHA1_BAD},1000,mismatch and more",
            f"{S32}mrt.exe,{'4' * 40},148633544,too big to hash",
            f"{S32}nosha1.exe,{'5' * 40},1000,baseline has none",
            f"{S32}empty.exe,,1000,no sha1",
        ],
    )
    result = run(case)
    assert result["amcache"]["status"] == "complete"
    by = lambda name: case.one("amcache", kv("Name.keyword", name))  # noqa: E731
    assert by("match")["verdict"] == "EXPECTED"
    assert "Hash matches" in by("match")["reason"]
    other = by("other build")
    assert (other["verdict"], other["confidence"]) == ("UNKNOWN", "low")
    assert other["reason"] == (
        "hash differs from every reference build; may be a patch level not in the reference"
    )
    assert by("mismatch and more")["verdict"] == "SUSPICIOUS"
    big = by("too big to hash")
    assert big["verdict"] == "EXPECTED" and "first 30 MiB" in big["reason"]
    assert "no SHA1 for this path" in by("baseline has none")["reason"]
    empty = by("no sha1")
    assert empty["verdict"] == "EXPECTED" and "Amcache recorded no SHA1" in empty["reason"]
    sent = {(a["path"], a.get("hash")) for t, a in calls if t == "check_file"}
    assert (f"{S32}mrt.exe", None) in sent and (f"{S32}empty.exe", None) in sent


# Re-runs


def _stale(case):
    """Stamps an earlier version wrote that this one no longer does."""
    old = {"triage.verdict": "EXPECTED", "triage.checked": True, "triage.reason": "old"}
    case.doc("evtx", "logon", {"event.code": "4624", **old})
    case.doc("evtx", "net", {"event.code": "3", "process.name": S32 + "rundll32.exe", **old})
    case.csv(
        "registry",
        REGISTRY,
        [
            _reg("ROOT\\ControlSet001\\Services\\Spooler\\Parameters", "ServiceDll", "C:\\x.dll"),
            _reg("ROOT\\ControlSet001\\Services\\Spooler", "ImagePath", S32 + "spoolsv.exe"),
        ],
    )
    case.client.indices.refresh(index=f"case-{case.id}-*")
    case.client.update_by_query(
        index=f"case-{case.id}-registry-*",
        body={
            "query": {"match_all": {}},
            "script": {
                "source": "ctx._source['triage.verdict'] = 'EXPECTED'; "
                "ctx._source['triage.checked'] = true; ctx._source['triage.reason'] = 'old'",
                "lang": "painless",
            },
        },
        refresh=True,
    )


def test_a_re_run_removes_the_stamps_this_version_no_longer_writes(triage):
    new_case, run, _, _ = triage
    case = new_case("upg")
    _stale(case)
    result = run(case)
    assert result["_cleared"] == {"status": "complete", "cleared": 3}
    assert case.one("evtx", kv("_id", "logon")) == {}
    assert case.one("evtx", kv("_id", "net")) == {}
    assert case.one("registry", kv("ValueName.keyword", "ServiceDll")) == {}
    assert case.one("registry", kv("ValueName.keyword", "ImagePath"))["reason"] == (
        "executable matches"
    )


def test_with_the_gateway_down_only_retired_stamps_are_removed(triage):
    new_case, run, _, down = triage
    case = new_case("down")
    _stale(case)
    down["now"] = True
    run(case)
    assert case.one("evtx", kv("_id", "logon")) == {}
    assert case.one("registry", kv("ValueName.keyword", "ImagePath"))["reason"] == "old"


def test_two_runs_give_the_same_stamps(triage):
    new_case, run, _, _ = triage
    case = new_case("twice")
    _services(case)
    case.doc("evtx", "p1", {"event.code": "4688", "process.name": S32 + "rundll32.exe"})
    run(case)
    first = case.stamp("registry", {"match_all": {}}) + case.stamp("evtx", {"match_all": {}})
    result = run(case)
    second = case.stamp("registry", {"match_all": {}}) + case.stamp("evtx", {"match_all": {}})
    assert first == second
    assert result.get("_cleared", {}).get("cleared", 0) == 0  # the second run retires nothing


def test_a_large_clear_finishes_before_triage_goes_on(scratch):
    """At about 500k stamped docs a synchronous clear outlived the client's
    10 s timeout and was still running when the stamping began; it also
    reported the wrong count. The clear is now waited for."""
    from opensearchpy import helpers

    client, tag = scratch
    case_id = f"{tag}-big-{uuid.uuid4().hex[:6]}"
    index = build_index_name(case_id, "evtx", "h1")
    client.indices.create(index=index, body={"settings": {"refresh_interval": "-1"}})
    n = 520_000
    stamped = {"event.code": "4624", "triage.checked": True, "triage.verdict": "EXPECTED"}
    helpers.bulk(
        client,
        ({"_index": index, "_id": str(i), "_source": stamped} for i in range(n)),
        chunk_size=10_000,
        request_timeout=120,
    )
    client.indices.put_settings(index=index, body={"refresh_interval": "1s"})
    client.indices.refresh(index=index)
    result = triage_remote._clear_stamps(client, case_id)
    assert result == {"status": "complete", "cleared": n}
    client.indices.refresh(index=index)
    left = client.count(index=index, body={"query": {"exists": {"field": "triage.checked"}}})
    assert left["count"] == 0


def test_hashes_past_a_paths_first_100_are_reported_unchecked(triage):
    new_case, run, _, _ = triage
    case = new_case("manyhash")
    case.csv(
        "amcache",
        AMCACHE,
        [f"{S32}sethc.exe,{n:040x},1000,build {n}" for n in range(1, 103)],
    )
    result = run(case)["amcache"]
    assert result["status"] == "failed"
    assert result["unchecked_hash_docs"] == 2
    assert "2 documents hold hashes past a path's first 100" in result["reason"]
