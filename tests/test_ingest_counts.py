"""An ingest's status says what the index stored, beside what was sent.

Two rows that key to one document were reported as two indexed, and a
timestamp the mapping couldn't parse was dropped with no error. After each
memory plugin and each delimited run the status now carries the documents
stored under the run's audit id and the fields the mapping ignored.

The workers run in-process against the cluster: Volatility is stubbed, the
indexing, counting and status are real. Templates are this run's copies of
the tree's, under its own names; values are synthetic.
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
from opensearch_mcp import parse_memory as pm
from opensearch_mcp import server as srv

pytestmark = pytest.mark.integration

_MAPPINGS = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"


@pytest.fixture(scope="module")
def os_client():
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
        return client
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")


@pytest.fixture
def case(os_client, tmp_path, monkeypatch):
    """A case whose vol and delim indices get this run's copies of the
    tree's templates; the workers' cluster-side checks are stubbed."""
    case_id = f"pytest-count-{uuid.uuid4().hex[:8]}"
    base = f"case-{case_id}"
    comp = json.loads((_MAPPINGS / "json_type_stability.json").read_text())
    os_client.cluster.put_component_template(name=f"{base}-comp", body=comp)
    for kind, filename in (("vol", "vol3_template.json"), ("delim", "delimited_template.json")):
        body = copy.deepcopy(json.loads((_MAPPINGS / filename).read_text()))
        body["template"].pop("aliases", None)
        body["index_patterns"] = [f"{base}-{kind}-*"]
        if body.get("composed_of"):
            body["composed_of"] = [f"{base}-comp"]
        body["priority"] = 900
        os_client.indices.put_index_template(name=f"{base}-{kind}", body=body)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    (tmp_path / "audit").mkdir()
    monkeypatch.setattr(cli, "get_client", lambda: os_client)
    for name in (
        "_preflight_shard_capacity",
        "_ensure_case_active",
        "_warn_if_mapping_upgrade_required",
    ):
        monkeypatch.setattr(cli, name, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: case_id)
    try:
        yield case_id
    finally:
        os_client.indices.delete(index=f"{base}-*", ignore=[404])
        for kind in ("vol", "delim"):
            os_client.indices.delete_index_template(name=f"{base}-{kind}", ignore=[404])
        os_client.cluster.delete_component_template(name=f"{base}-comp", ignore=[404])


def _detail(case_id: str, artifact: str) -> str:
    (status,) = srv.idx_ingest_status(case_id=case_id)["ingests"]
    (item,) = [i for i in status["checklist"] if i["artifact"] == artifact]
    return item["detail"]


SERVICE = {"Offset": "0x1", "Order": 7, "PID": 4, "Start": "SERVICE_AUTO_START", "Name": "svc-a"}


def _memory(case_id: str, tmp_path, monkeypatch, run: str, records=None) -> str:
    """svcscan returning 5 rows, 3 of them byte-identical."""
    if records is None:
        records = [dict(SERVICE), dict(SERVICE), dict(SERVICE)]
        records += [dict(SERVICE, Name="svc-b"), dict(SERVICE, Name="svc-c")]
    monkeypatch.setattr(pm, "_find_vol3", lambda: "true")
    monkeypatch.setattr(pm, "_register_memory_evidence", lambda *a, **k: None)
    monkeypatch.setattr(pm, "run_vol3_plugin", lambda *a, **k: copy.deepcopy(records))
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", run)
    image = tmp_path / "mem.raw"
    image.write_bytes(b"\0" * 64)
    args = argparse.Namespace(
        path=str(image),
        case=case_id,
        hostname="h1",
        tier=1,
        plugins="windows.svcscan",
        yes=True,
        timeout=10,
    )
    cli.cmd_ingest_memory(args)
    return _detail(case_id, "windows.svcscan")


def _delimited(case_id: str, tmp_path, monkeypatch, run: str) -> str:
    """Three rows, one whose time can't be parsed."""
    data = tmp_path / "events.csv"
    data.write_text(
        "when,what\n2026-01-01T00:00:00Z,a\n2026-01-01T00:00:01Z,b\nnot a time at all,c\n"
    )
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", run)
    args = argparse.Namespace(path=str(data), case=case_id, hostname="h1", time_field="when")
    cli.cmd_ingest_delimited(args)
    return _detail(case_id, "delimited")


class TestTheStatusSaysWhatWasStored:
    def test_identical_memory_rows(self, case, tmp_path, monkeypatch):
        assert _memory(case, tmp_path, monkeypatch, "count-1") == "5 docs submitted, 3 stored"

    def test_an_unparsed_time(self, case, tmp_path, monkeypatch):
        detail = _delimited(case, tmp_path, monkeypatch, "count-1")
        # The source column is a date in the mapping too, so it's ignored there as well.
        assert detail.startswith("3 docs submitted, 3 stored; 1 doc with unparsed fields (e.g. ")
        assert "@timestamp ×1" in detail, detail

    def test_the_unparsed_total_is_exact_and_the_names_are_examples(
        self, case, tmp_path, monkeypatch
    ):
        """The names come from a 20-document sample; one late document
        ignores a field the sample may never see."""
        rows = [f"not a time,a{i},2026-01-01T00:00:00Z" for i in range(30)]
        rows.append("2026-01-01T00:00:00Z,z,not a time either")
        data = tmp_path / "late.csv"
        data.write_text("when,what,mtime\n" + "\n".join(rows) + "\n")
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", "count-late")
        args = argparse.Namespace(path=str(data), case=case, hostname="h1", time_field="when")
        cli.cmd_ingest_delimited(args)
        detail = _detail(case, "delimited")
        assert detail.startswith(
            "31 docs submitted, 31 stored; 31 docs with unparsed fields (e.g. "
        )
        assert "@timestamp ×30" in detail, detail
        (status,) = srv.idx_ingest_status(case_id=case)["ingests"]
        assert "ignore_above" in status["counts_note"]

    def test_only_this_runs_documents_count(self, case, tmp_path, monkeypatch):
        """The index already holds 3 documents from an earlier run."""
        _memory(case, tmp_path, monkeypatch, "count-1")
        for f in ingest_status._STATUS_DIR.glob("*.json"):
            f.unlink()
        others = [dict(SERVICE, Name=f"svc-other-{i}") for i in range(2)]
        detail = _memory(case, tmp_path, monkeypatch, "count-2", records=others)
        assert detail == "2 docs submitted, 2 stored"

    def test_a_rerun_gives_the_same_numbers(self, case, tmp_path, monkeypatch):
        first = (
            _memory(case, tmp_path, monkeypatch, "count-1"),
            _delimited(case, tmp_path, monkeypatch, "count-2"),
        )
        for f in ingest_status._STATUS_DIR.glob("*.json"):
            f.unlink()
        again = (
            _memory(case, tmp_path, monkeypatch, "count-3"),
            _delimited(case, tmp_path, monkeypatch, "count-4"),
        )
        assert again == first


def test_counting_never_fails_the_ingest(capsys):
    from opensearch_mcp.ingest_counts import stored_counts

    client = mock.MagicMock()
    client.count.side_effect = RuntimeError("cluster gone")
    assert stored_counts(client, "case-x-vol-svcscan-h1", "aid") == {}
    assert "could not count" in capsys.readouterr().err


def test_an_answer_that_isnt_a_count_never_fails_the_ingest(capsys):
    from opensearch_mcp.ingest_counts import describe, stored_counts

    counts = stored_counts(mock.MagicMock(), "case-x-vol-svcscan-h1", "aid")
    assert counts == {} and describe(counts) == ""
    assert "could not count" in capsys.readouterr().err
