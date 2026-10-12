"""A Run value over 256 characters is counted, on a real mapping.

`ValueData.keyword` ignores values over 256 characters, so the Run-key
aggregation can't read them. Triage counts them (`too_long`) and fails the
step, from RECmd rows ingested as the real pipeline ingests them.
"""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest

from opensearch_mcp import triage_remote
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import legacy_index_name

pytestmark = pytest.mark.integration

RUN = "ROOT\\Microsoft\\Windows\\CurrentVersion\\Run"
HEADER = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
    "ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile"
)
LONG = "C:\\Users\\Public\\" + "x" * 295 + ".exe"


def _row(name, data):
    return (
        f"C:\\h\\SOFTWARE,SOFTWARE,x,Autoruns,{RUN},{name},RegSz,{data},,,,"
        "False,False,2024-01-01 00:00:00.0000000,"
    )


@pytest.fixture
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


def test_a_run_value_over_256_characters_is_counted_on_a_real_mapping(
    scratch, tmp_path, monkeypatch
):
    client, tag = scratch
    sent = []
    monkeypatch.setattr(triage_remote, "call_tool", lambda tool, args, timeout=None: (
        sent.append(args.get("path")) or {}) if tool == "check_file" else {})  # fmt: skip
    monkeypatch.setattr(triage_remote, "gateway_available", lambda: True)
    case = f"{tag}-long"
    index = legacy_index_name(case, "registry", "h1")
    rows = [_row("Long", LONG), _row("A", "C:\\x\\a.exe"), _row("B", "C:\\x\\a.exe")]
    csv = tmp_path / "run.csv"
    csv.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    _, _, failed = ingest_csv(csv, client, index, "h1")
    assert failed == 0
    client.indices.refresh(index=index)
    run = triage_remote.enrich_remote(client, case)["registry_run"]
    assert run["status"] == "failed" and run["too_long"] == 1, run
    assert "256" in run["reason"] and LONG not in sent
