"""Rejections reach `idx_ingest_status`, not only stderr and the log.

The json and delimited ingests counted bulk rejections but never passed the
count to the status writer, so a partly rejected run read `complete,
bulk_failed: 0`, and a wholly rejected one read `failed` with `unknown
error`. Every row goes through the real path: the ingest command writes the
status file, and `idx_ingest_status` reads it back.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import uuid
from pathlib import Path

import pytest

_MAPPINGS_DIR = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"
_CASE = "rejection-status-case"
_DEEP = ".".join(f"k{i}" for i in range(21))  # past the default depth limit of 20


# ---------------------------------------------------------------------------
# Writer and outcome, no cluster
# ---------------------------------------------------------------------------


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    from opensearch_mcp import ingest_status

    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


class TestTheWriter:
    def test_the_count_and_the_error_reach_the_file(self, status_dir):
        from opensearch_mcp.ingest_cli import _write_bg_status

        _write_bg_status(
            "C",
            "run",
            "failed",
            "h1",
            "json",
            "2026-09-30T00:00:00Z",
            indexed=0,
            error="all_records_rejected: failed to parse field [f]",
            bulk_failed=78,
            bulk_failed_reason="failed to parse field [f]",
        )
        (path,) = status_dir.glob("*.json")
        data = json.loads(path.read_text())
        assert data["bulk_failed"] == 78
        assert data["bulk_failed_reason"] == "failed to parse field [f]"
        assert data["hosts"][0]["artifacts"][0]["error"].startswith("all_records_rejected: ")

    @pytest.mark.parametrize(
        "indexed,failed,expected",
        [(0, 78, "failed"), (1, 1, "complete"), (5, 0, "complete"), (0, 0, "complete")],
    )
    def test_only_a_run_whose_every_record_was_rejected_fails(self, indexed, failed, expected):
        from opensearch_mcp.ingest_cli import _terminal_status

        status, error = _terminal_status(indexed, failed, "why")
        assert status == expected
        assert error == ("all_records_rejected: why" if expected == "failed" else "")

    def test_a_transport_give_up_is_not_called_a_rejection(self):
        from opensearch_mcp.ingest_cli import _terminal_status

        status, error = _terminal_status(0, 2, "transport: ConnectionTimeout: read timed out")
        assert (status, error) == ("failed", "transport_failed: ConnectionTimeout: read timed out")


# ---------------------------------------------------------------------------
# Through the real status path, against the cluster
# ---------------------------------------------------------------------------


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


@pytest.fixture(scope="module")
def tag(os_client):
    """The shipped json / delimited composition under this run's names."""
    tag = f"pytest-rejstat-{uuid.uuid4().hex[:8]}"
    component = json.loads((_MAPPINGS_DIR / "json_type_stability.json").read_text())
    os_client.cluster.put_component_template(name=f"{tag}-comp", body=component)
    for kind, filename in (("json", "json_template.json"), ("delim", "delimited_template.json")):
        body = copy.deepcopy(json.loads((_MAPPINGS_DIR / filename).read_text()))
        body["template"].pop("aliases", None)
        body["index_patterns"] = [f"{tag}-{kind}-*"]
        body["composed_of"] = [f"{tag}-comp"]
        body["priority"] = 900
        os_client.indices.put_index_template(name=f"{tag}-{kind}", body=body)
    yield tag
    for name in os_client.indices.get(index=f"{tag}-*", expand_wildcards="all"):
        os_client.indices.delete(index=name, ignore=[404])
    for kind in ("json", "delim"):
        os_client.indices.delete_index_template(name=f"{tag}-{kind}", ignore=[404])
    os_client.cluster.delete_component_template(name=f"{tag}-comp", ignore=[404])


def _index_name(tag: str, run: str, suffix: str, host: str) -> str:
    kind = "json" if suffix.startswith("json") else "delim"
    return f"{tag}-{kind}-{run}-{suffix.split('-', 1)[1]}-{host}".lower()


@pytest.fixture
def ingest(tag, status_dir, monkeypatch):
    """The ingest commands with only case plumbing replaced: case lookup,
    audit, shard pre-flight, and index names under this run's templates."""
    from opensearch_mcp import ingest_cli, paths

    run = uuid.uuid4().hex[:6]

    class _Audit:
        def __init__(self, *a, **k):
            pass

        def _next_audit_id(self):
            return "rejection-status-aid"

        def log(self, **k):
            pass

    monkeypatch.setenv("VHIR_INGEST_RUN_ID", f"run-{run}")
    monkeypatch.setattr(ingest_cli, "AuditWriter", _Audit)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: _CASE)
    monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda _c: None)
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda _c: None)
    monkeypatch.setattr(ingest_cli, "_warn_if_mapping_upgrade_required", lambda _c: None)
    monkeypatch.setattr(ingest_cli, "_preflight_shard_capacity", lambda *a, **k: None)
    monkeypatch.setattr(
        paths, "build_index_name", lambda case, suffix, host: _index_name(tag, run, suffix, host)
    )

    class Ingest:
        name = staticmethod(lambda suffix, host="h1": _index_name(tag, run, suffix, host))

        @staticmethod
        def json(path: Path) -> None:
            ingest_cli.cmd_ingest_json(
                argparse.Namespace(
                    path=str(path), hostname="h1", case=None, time_field=None,
                    time_from=None, time_to=None, batch_size=1000, dry_run=False,
                    index_suffix=None,
                )
            )  # fmt: skip

        @staticmethod
        def delimited(path: Path, recursive: bool = False, auto_hosts: str = "") -> None:
            ingest_cli.cmd_ingest_delimited(
                argparse.Namespace(
                    path=str(path), hostname="" if recursive or auto_hosts else "h1",
                    recursive=recursive, auto_hosts=auto_hosts, case=None, time_field=None,
                    delimiter=None, format=None, time_from=None, time_to=None, batch_size=1000,
                    dry_run=False, index_suffix=None,
                )
            )  # fmt: skip

    return Ingest


def _status() -> dict:
    from opensearch_mcp.server import idx_ingest_status

    (ingest,) = idx_ingest_status(case_id=_CASE)["ingests"]
    return ingest


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> Path:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)
    return path


@pytest.mark.integration
class TestRejectionsReachTheStatus:
    def test_json_one_of_two_rejected(self, ingest, tmp_path):
        ingest.json(_write_jsonl(tmp_path / "partial.jsonl", [{"f": "s"}, {"f": {"a": 1}}]))
        s = _status()
        assert (s["status"], s["total_indexed"], s["bulk_failed"]) == ("complete", 1, 1)
        assert "[f]" in s["warnings"][0]

    def test_json_all_78_rejected_names_the_reason(self, ingest, tmp_path):
        records = [{_DEEP: "v", "n": i} for i in range(78)]
        ingest.json(_write_jsonl(tmp_path / "all.jsonl", records))
        s = _status()
        assert (s["status"], s["bulk_failed"]) == ("failed", 78)
        assert s["halt_reason"] == "all_records_rejected"
        assert "refused before sending" in s["message"]
        (item,) = s["checklist"]
        assert "unknown error" not in item["detail"]
        assert "refused before sending" in item["detail"]

    def test_a_depth_refusal_appears_with_its_record_and_field(self, ingest, tmp_path):
        ingest.json(_write_jsonl(tmp_path / "deep.jsonl", [{"x": "ok"}, {_DEEP: "v"}]))
        s = _status()
        assert (s["status"], s["total_indexed"], s["bulk_failed"]) == ("complete", 1, 1)
        assert "refused before sending" in s["warnings"][0] and "k0.k1" in s["warnings"][0]

    def test_delimited_partial_against_a_conflicting_mapping(self, ingest, os_client, tmp_path):
        path = _write_csv(tmp_path / "flags.csv", ["flag", "n"], [["true", "1"], ["maybe", "2"]])
        os_client.indices.create(
            index=ingest.name("delim-flags"),
            body={"mappings": {"properties": {"flag": {"type": "boolean"}}}},
        )
        ingest.delimited(path)
        s = _status()
        assert (s["status"], s["total_indexed"], s["bulk_failed"]) == ("complete", 1, 1)
        assert "[flag]" in s["warnings"][0]

    def test_delimited_all_78_rejected_names_the_reason(self, ingest, tmp_path):
        rows = [[f"a{i}", f"b{i}"] for i in range(78)]
        ingest.delimited(_write_csv(tmp_path / "proc.csv", ["proc", "proc.name"], rows))
        s = _status()
        assert (s["status"], s["bulk_failed"]) == ("failed", 78)
        assert s["halt_reason"] == "all_records_rejected"
        assert "[proc" in s["message"]
        assert "unknown error" not in s["checklist"][0]["detail"]

    def test_a_recursive_walk_reports_every_subdir(self, ingest, tmp_path):
        """Each subdir's own final write lands in the walk's one status
        file; the walk must end with the sum, not the last subdir's result
        and not `complete` / 0."""
        root = tmp_path / "walk"
        (root / "hosta").mkdir(parents=True)
        (root / "hostb").mkdir()
        rows = [[f"a{i}", f"b{i}"] for i in range(78)]
        _write_csv(root / "hosta" / "a.csv", ["proc", "proc.name"], rows)
        _write_csv(root / "hostb" / "b.csv", ["x", "y"], [["1", "2"], ["3", "4"]])
        ingest.delimited(root, recursive=True)
        s = _status()
        assert (s["status"], s["total_indexed"], s["bulk_failed"]) == ("complete", 2, 78)
        assert "[proc" in s["warnings"][0]

    def test_an_auto_hosts_run_reports_every_host(self, ingest, os_client, tmp_path):
        """The same shared status file as the recursive walk: one host's
        records all rejected, the other's all indexed."""
        root = tmp_path / "flat"
        root.mkdir()
        _write_csv(root / "flags.csv", ["flag", "n"], [["maybe", "1"], ["maybe", "2"]])
        os_client.indices.create(
            index=ingest.name("delim-flags", host="hosta"),
            body={"mappings": {"properties": {"flag": {"type": "boolean"}}}},
        )
        ingest.delimited(root, auto_hosts="hosta,hostb")
        s = _status()
        assert (s["status"], s["total_indexed"], s["bulk_failed"]) == ("complete", 2, 2)
        assert "[flag]" in s["warnings"][0]

    def test_auto_hosts_with_recursive_reports_the_walk(self, ingest, tmp_path):
        """The two flags together: each auto-host runs the recursive walk,
        whose sums must reach the auto-hosts total."""
        root = tmp_path / "walk"
        (root / "hosta").mkdir(parents=True)
        (root / "hostb").mkdir()
        rows = [[f"a{i}", f"b{i}"] for i in range(78)]
        _write_csv(root / "hosta" / "a.csv", ["proc", "proc.name"], rows)
        _write_csv(root / "hostb" / "b.csv", ["x", "y"], [["1", "2"], ["3", "4"]])
        ingest.delimited(root, recursive=True, auto_hosts="h1")
        s = _status()
        assert (s["status"], s["total_indexed"], s["bulk_failed"]) == ("complete", 2, 78)
        assert "[proc" in s["warnings"][0]

    def test_a_run_the_transport_gave_up_on_names_the_transport(
        self, ingest, tmp_path, monkeypatch
    ):
        """Every attempt times out: nothing reached OpenSearch, so the status
        must not say OpenSearch rejected the records."""
        from opensearchpy.exceptions import ConnectionTimeout

        from opensearch_mcp import bulk

        def timing_out(client, actions, **kw):
            raise ConnectionTimeout("TIMEOUT", "read timed out", Exception("read timed out"))

        monkeypatch.setattr(bulk.helpers, "bulk", timing_out)
        monkeypatch.setattr(bulk, "_MAX_RETRIES", 1)
        monkeypatch.setattr(bulk.time, "sleep", lambda _s: None)
        ingest.json(_write_jsonl(tmp_path / "outage.jsonl", [{"x": 1}, {"x": 2}]))
        s = _status()
        assert (s["status"], s["bulk_failed"]) == ("failed", 2)
        assert s["halt_reason"] == "transport_failed"
        assert "ConnectionTimeout" in s["message"]
        assert "all_records_rejected" not in s["message"]
