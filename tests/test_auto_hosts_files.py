"""hostname='auto' gives each detected host only the files named for it.

The auto-hosts wrapper ran one sub-run per detected host on the same flat
directory, and each sub-run ingested every file there: every host's indices
held every host's rows. The ingest runs in-process against the cluster with
this run's own template copies; values are synthetic.
"""

from __future__ import annotations

import argparse
import copy
import json
import uuid
from pathlib import Path
from unittest import mock

import pytest

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp.server import _detect_hostnames_from_filenames

_MAPPINGS = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"


def test_the_per_file_rule_matches_the_detector(tmp_path):
    names = [
        "EvtxECmd-HOST1.csv",
        "hayabusa-case1-host2.csv",
        "wkstn09.shieldbase.com-Autorunsc.csv",
        "notes.csv",
        "a-b.csv",
    ]
    for name in names:
        d = tmp_path / name
        d.mkdir()
        (d / name).write_text("x\n")
        assert _detect_hostnames_from_filenames(d) == ({cli._filename_host(d / name)} - {""}), name


@pytest.fixture
def ingest(tmp_path, monkeypatch):
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        client.cluster.health()
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")
    case_id = f"pytest-ah-{uuid.uuid4().hex[:8]}"
    base = f"case-{case_id}"
    comp = json.loads((_MAPPINGS / "json_type_stability.json").read_text())
    client.cluster.put_component_template(name=f"{base}-comp", body=comp)
    body = copy.deepcopy(json.loads((_MAPPINGS / "delimited_template.json").read_text()))
    body["template"].pop("aliases", None)
    body["index_patterns"] = [f"{base}-*"]
    if body.get("composed_of"):
        body["composed_of"] = [f"{base}-comp"]
    body["priority"] = 900
    client.indices.put_index_template(name=f"{base}-delim", body=body)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    (tmp_path / "audit").mkdir()
    monkeypatch.setattr(cli, "get_client", lambda: client)
    for n in (
        "_preflight_shard_capacity",
        "_ensure_case_active",
        "_warn_if_mapping_upgrade_required",
    ):
        monkeypatch.setattr(cli, n, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: case_id)

    def run(files: dict) -> dict:
        """files: {name: rows}; returns {index suffix: sorted row tags}."""
        flat = tmp_path / "flat"
        flat.mkdir()
        for name, n in files.items():
            tag = Path(name).stem
            body = "".join(f"2026-01-01T00:00:{i:02d}Z,{tag}-{i}\n" for i in range(n))
            (flat / name).write_text("when,what\n" + body)
        hosts = ",".join(sorted(_detect_hostnames_from_filenames(flat)))
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", f"ah-{uuid.uuid4().hex[:6]}")
        args = argparse.Namespace(
            path=str(flat), case=case_id, hostname="", auto_hosts=hosts, time_field="when"
        )
        cli.cmd_ingest_delimited(args)
        client.indices.refresh(index=f"{base}-*")
        out = {}
        for idx in sorted(client.indices.get(index=f"{base}-*")):
            hits = client.search(index=idx, body={"size": 100, "_source": ["what"]})
            out[idx[len(base) + 1 :]] = sorted(h["_source"]["what"] for h in hits["hits"]["hits"])
        return out

    try:
        yield run
    finally:
        client.indices.delete(index=f"{base}-*", ignore=[404])
        client.indices.delete_index_template(name=f"{base}-delim", ignore=[404])
        client.cluster.delete_component_template(name=f"{base}-comp", ignore=[404])


@pytest.mark.integration
@pytest.mark.parametrize(
    "h1,h2",
    [
        ("EvtxECmd-HOST1.csv", "EvtxECmd-HOST2.csv"),
        ("hayabusa-c1-host1.csv", "hayabusa-c1-host2.csv"),
    ],
    ids=["Tool-HOST", "hayabusa-case-HOST"],
)
def test_each_host_gets_only_its_own_file(ingest, h1, h2):
    got = ingest({h1: 3, h2: 2})
    s1, s2 = Path(h1).stem.lower(), Path(h2).stem.lower()
    assert got == {
        f"delim-{s1}-host1": [f"{Path(h1).stem}-{i}" for i in range(3)],
        f"delim-{s2}-host2": [f"{Path(h2).stem}-{i}" for i in range(2)],
    }, got


@pytest.mark.integration
def test_a_file_with_no_host_in_its_name_is_skipped(ingest, capsys):
    got = ingest({"EvtxECmd-HOST1.csv": 2, "EvtxECmd-HOST2.csv": 2, "readme.csv": 1})
    assert set(got) == {"delim-evtxecmd-host1-host1", "delim-evtxecmd-host2-host2"}, got
    assert "Skipped 1 file(s) whose name gives none of the hosts" in capsys.readouterr().out


@pytest.mark.integration
def test_one_name_segment_for_every_file_ingests_each_once(ingest):
    """Kansa names every file HOST-Module.csv, so the 'host' is the module
    and all files go to it: each read once, as before (a separate issue)."""
    got = ingest({"rd01.x.com-Autorunsc.csv": 2, "rd02.x.com-Autorunsc.csv": 3})
    assert sum(len(v) for v in got.values()) == 5, got
