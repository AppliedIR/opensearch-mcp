"""The Run-key verdict lands only on Run-key documents.

An IFEO Debugger and a Run key often hold the same payload path. The IFEO
persistence rule marks its document SUSPICIOUS; the Run-key check_file verdict
for the same value must not replace it. A real triage run spends seconds in
gateway calls between the two stamps, more than the 1 s refresh interval, so
the Run-key stamp sees the rule's write. The first check_file call here waits
1.5 s to stand in for that; without the wait the old update hits a version
conflict and skips the document, which hides the overwrite.
"""

from __future__ import annotations

import time
import uuid

import _scratch_templates
import pytest

from opensearch_mcp import triage_remote
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import build_index_name

pytestmark = pytest.mark.integration

IFEO = "ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe"
RUN = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"
PAYLOAD = "C:\\Users\\Public\\x.exe"
HEADER = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
    "ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile"
)


def _row(keypath, name, data):
    return (
        f"C:\\h\\SOFTWARE,SOFTWARE,x,Autoruns,{keypath},{name},RegSz,{data},,,,"
        "False,False,2024-01-01 00:00:00.0000000,"
    )


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
def triage(scratch, tmp_path, monkeypatch):
    """Ingest RECmd rows into a fresh case; run triage with a stubbed check_file."""
    client, tag = scratch
    answer = {}
    calls = []

    def check_file(tool, args, timeout=None):
        calls.append(args.get("path"))
        if len(calls) == 1:
            time.sleep(1.5)
        return answer.get(args.get("path"), {})

    monkeypatch.setattr(triage_remote, "call_tool", check_file)
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)

    def new_case(name, rows):
        case = f"{tag}-{name}"  # case-{tag}-* is what the scratch templates cover
        index = build_index_name(case, "registry", "h1")
        csv = tmp_path / f"{name}.csv"
        csv.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
        _, _, failed = ingest_csv(csv, client, index, "h1")
        assert failed == 0
        client.indices.refresh(index=index)
        return case

    def run(case, verdict):
        answer[PAYLOAD] = verdict
        calls.clear()
        triage_remote.enrich_remote(client, case)
        client.indices.refresh(index=f"case-{case}-*")

    def stamp(case, value_name):
        r = client.search(
            index=f"case-{case}-registry-*",
            body={"query": {"term": {"ValueName.keyword": value_name}}},
        )
        (hit,) = r["hits"]["hits"]
        return hit["_source"].get("triage.verdict"), hit["_source"].get("triage.reason")

    return client, new_case, run, stamp


UNKNOWN = {"verdict": "UNKNOWN", "confidence": "low", "reasons": ["Not in baseline"]}


def test_an_ifeo_verdict_survives_a_run_key_with_the_same_value(triage):
    _, new_case, run, stamp = triage
    case = new_case("ifeo", [_row(IFEO, "Debugger", PAYLOAD), _row(RUN, "Helper", PAYLOAD)])
    run(case, UNKNOWN)
    verdict, reason = stamp(case, "Debugger")
    assert verdict == "SUSPICIOUS"
    assert reason.startswith("IFEO debugger: ")


def test_the_run_key_document_gets_check_files_verdict(triage):
    _, new_case, run, stamp = triage
    case = new_case("runkey", [_row(IFEO, "Debugger", PAYLOAD), _row(RUN, "Helper", PAYLOAD)])
    run(case, UNKNOWN)
    assert stamp(case, "Helper") == ("UNKNOWN", "Not in baseline")


def test_a_re_triage_moves_a_run_key_off_suspicious(triage):
    _, new_case, run, stamp = triage
    case = new_case("retriage", [_row(RUN, "Helper", PAYLOAD)])
    run(case, {"verdict": "SUSPICIOUS", "confidence": "medium", "reasons": ["first"]})
    assert stamp(case, "Helper") == ("SUSPICIOUS", "first")
    run(case, {"verdict": "EXPECTED", "confidence": "high", "reasons": ["second"]})
    assert stamp(case, "Helper") == ("EXPECTED", "second")


def test_a_re_triage_repairs_an_overwritten_ifeo_verdict(triage):
    """A case triaged before this fix holds the Run key's verdict on its IFEO document."""
    client, new_case, run, stamp = triage
    case = new_case("repair", [_row(IFEO, "Debugger", PAYLOAD), _row(RUN, "Helper", PAYLOAD)])
    client.update_by_query(
        index=f"case-{case}-registry-*",
        body={
            "query": {"term": {"ValueName.keyword": "Debugger"}},
            "script": {
                "source": "ctx._source['triage.verdict'] = 'UNKNOWN'; "
                "ctx._source['triage.reason'] = 'Not in baseline'; "
                "ctx._source['triage.checked'] = true",
                "lang": "painless",
            },
        },
        refresh=True,
    )
    assert stamp(case, "Debugger") == ("UNKNOWN", "Not in baseline")
    run(case, UNKNOWN)
    verdict, reason = stamp(case, "Debugger")
    assert verdict == "SUSPICIOUS"
    assert reason.startswith("IFEO debugger: ")
