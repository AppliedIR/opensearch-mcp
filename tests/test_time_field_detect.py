"""Velociraptor's Timestamp becomes @timestamp, and a file with no time
field says so in the ingest status.

Auto-detection didn't know Velociraptor's `Timestamp` (an epoch float), so
those documents had no @timestamp, and a file with no recognised time column
(Kansa's `LastWriteTimeUtc`) was ingested without a word: both disappeared
from idx_timeline. The client stand-in keeps what bulk sends.
"""

from __future__ import annotations

import argparse
import copy
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from opensearchpy.serializer import JSONSerializer

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status, parse_delimited, parse_json, paths
from opensearch_mcp import server as srv


class _Client:
    transport = SimpleNamespace(serializer=JSONSerializer())

    def __init__(self):
        self.sent: list[dict] = []
        self.indices = SimpleNamespace(get_settings=self._fail, simulate_index_template=self._fail)

    @staticmethod
    def _fail(**kw):
        raise RuntimeError("not modelled")

    def bulk(self, *a, body=None, **kw):
        lines = [x for x in body.split("\n") if x]
        items = []
        for meta, source in zip(lines[0::2], lines[1::2]):
            m = json.loads(meta)
            op = next(iter(m))
            self.sent.append(json.loads(source))
            items.append({op: {"_index": m[op]["_index"], "_id": m[op]["_id"], "status": 201}})
        return {"errors": False, "items": items, "took": 1}


@pytest.fixture(autouse=True)
def _fresh_list():
    """NO_TIME_FIELD lives for the process (one ingest per worker)."""
    missed = getattr(paths, "NO_TIME_FIELD", [])
    missed.clear()
    yield
    missed.clear()


def _json(tmp_path, records) -> list[dict]:
    data = tmp_path / "Netstat.json"
    data.write_text("".join(json.dumps(r) + "\n" for r in records))
    client = _Client()
    parse_json.ingest_json(data, client, "case-x-json-vr-h", "h")
    return client.sent


def test_a_velociraptor_epoch_timestamp_is_the_time(tmp_path):
    (doc,) = _json(tmp_path, [{"Timestamp": 1675036674.3242571, "Pid": 4}])
    assert doc["@timestamp"] == "2023-01-29T23:57:54.324257+00:00"


def test_a_microsecond_epoch_is_read_as_microseconds(tmp_path):
    """Velociraptor's own logs carry 16-digit microsecond epochs; read as
    milliseconds they'd be year 55041 and abort the file."""
    docs = _json(tmp_path, [{"Timestamp": 1675036674324257, "msg": "x"}] * 2)
    assert [d["@timestamp"][:19] for d in docs] == ["2023-01-29T23:57:54"] * 2


def test_a_file_with_no_time_field_says_so_in_the_status(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    data = tmp_path / "rd01-PrefetchListing.csv"
    data.write_text("FullName,LastWriteTimeUtc\nC:\\\\x.pf,2023-01-29T23:57:54Z\n")
    parse_delimited.ingest_delimited(data, _Client(), "case-c1-delim-h", "h")
    cli._write_bg_status("c1", "run-tf", "complete", "h", "delimited", "2026-10-02T00:00:00Z")
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    (warning,) = [w for w in status.get("warnings", []) if "No time field" in w]
    assert "rd01-PrefetchListing.csv" in warning and "time_field=" in warning


def test_a_detected_time_field_is_unchanged_and_quiet(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    data = tmp_path / "events.csv"
    data.write_text("timestamp,what\n2026-01-01T00:00:00Z,a\n")
    client = _Client()
    parse_delimited.ingest_delimited(data, client, "case-c1-delim-h", "h")
    assert client.sent[0]["@timestamp"] == "2026-01-01T00:00:00Z"
    cli._write_bg_status("c1", "run-tf2", "complete", "h", "delimited", "2026-10-02T00:00:00Z")
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert not [w for w in status.get("warnings", []) if "No time field" in w]


def test_a_nanosecond_epoch_keeps_its_raw_value_and_the_file_goes_on(tmp_path):
    """Read as microseconds a nanosecond epoch is year 55049: no @timestamp
    from it, the value stays, and the rest of the file is still sent."""
    docs = _json(
        tmp_path,
        [{"Timestamp": 1675036674324257100, "n": 1}, {"Timestamp": 1675036674.5, "n": 2}],
    )
    by_n = {d["n"]: d for d in docs}
    assert "@timestamp" not in by_n[1] and by_n[1]["Timestamp"] == 1675036674324257100
    assert by_n[2]["@timestamp"].startswith("2023-01-29T23:57:54")


def test_a_csv_timestamp_column_is_not_taken_as_the_time(tmp_path, monkeypatch):
    """Only JSON reads `Timestamp` (Velociraptor's epoch number): in a CSV the
    value is a string, which OpenSearch would index as epoch millis, in 1970."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    data = tmp_path / "netstat.csv"
    data.write_text("Timestamp,Proto\n1675036674,TCP\n")
    client = _Client()
    parse_delimited.ingest_delimited(data, client, "case-c1-delim-h", "h")
    assert "@timestamp" not in client.sent[0]
    cli._write_bg_status("c1", "run-csv", "complete", "h", "delimited", "2026-10-02T00:00:00Z")
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert any("netstat.csv" in w for w in status.get("warnings", []))


# --- Through the ingest commands, against the cluster ---------------------

_MAPPINGS = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"


@pytest.fixture
def cluster_case(tmp_path, monkeypatch):
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        client.cluster.health()
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")
    case_id = f"pytest-tf-{uuid.uuid4().hex[:8]}"
    base = f"case-{case_id}"
    comp = json.loads((_MAPPINGS / "json_type_stability.json").read_text())
    client.cluster.put_component_template(name=f"{base}-comp", body=comp)
    for kind, filename in (("delim", "delimited_template.json"), ("json", "json_template.json")):
        body = copy.deepcopy(json.loads((_MAPPINGS / filename).read_text()))
        body["template"].pop("aliases", None)
        body["index_patterns"] = [f"{base}-{kind}-*"]
        if body.get("composed_of"):
            body["composed_of"] = [f"{base}-comp"]
        body["priority"] = 900
        client.indices.put_index_template(name=f"{base}-{kind}", body=body)
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
    try:
        yield case_id
    finally:
        client.indices.delete(index=f"{base}-*", ignore=[404])
        for kind in ("delim", "json"):
            client.indices.delete_index_template(name=f"{base}-{kind}", ignore=[404])
        client.cluster.delete_component_template(name=f"{base}-comp", ignore=[404])


@pytest.mark.integration
def test_a_walks_sub_runs_each_name_only_their_own_files(cluster_case, tmp_path, monkeypatch):
    """host1's file has no time column, host2's has one: host2's own status
    write names nothing, and the walk's final write names host1's file once."""
    top = tmp_path / "walk"
    (top / "host1").mkdir(parents=True)
    (top / "host2").mkdir()
    (top / "host1" / "procs.csv").write_text("Name,Pid\nx,4\n")
    (top / "host2" / "events.csv").write_text("timestamp,what\n2026-01-01T00:00:00Z,a\n")
    writes = []  # (host, status, the note written)
    real = cli.write_status

    def spy(*a, **kw):
        real(*a, **kw)
        (host,) = kw["hosts"]
        (art,) = host["artifacts"]
        writes.append((host["hostname"], kw["status"], art.get("note", "")))

    monkeypatch.setattr(cli, "write_status", spy)
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "tf-walk")
    args = argparse.Namespace(path=str(top), case=cluster_case, hostname="", recursive=True)
    cli.cmd_ingest_delimited(args)
    host2_final = [n for host, st, n in writes if host == "host2" and st != "running"]
    assert host2_final == [""], writes
    final_note = [n for host, st, n in writes if st != "running"][-1]
    assert final_note.startswith("No time field detected in 1 file(s), e.g. host1/procs.csv")


@pytest.mark.integration
def test_a_foreground_json_ingest_prints_the_note(cluster_case, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VHIR_INGEST_RUN_ID", raising=False)
    data = tmp_path / "Pslist.json"
    data.write_text(json.dumps({"Name": "x", "Pid": 4}) + "\n")
    args = argparse.Namespace(path=str(data), case=cluster_case, hostname="h1")
    cli.cmd_ingest_json(args)
    out = [line for line in capsys.readouterr().out.splitlines() if "No time field" in line]
    assert out and "Pslist.json" in out[0] and "time_field=" in out[0]


@pytest.mark.integration
def test_an_auto_hosts_run_names_a_file_once(cluster_case, tmp_path, monkeypatch):
    """Each auto host's sub-run reads the same flat directory here, so the
    file without a time column was counted once per host."""
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "procs-host1.csv").write_text("Name,Pid\nx,4\n")
    (flat / "events-host2.csv").write_text("timestamp,what\n2026-01-01T00:00:00Z,a\n")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "tf-auto")
    args = argparse.Namespace(
        path=str(flat), case=cluster_case, hostname="", auto_hosts="host1,host2"
    )
    cli.cmd_ingest_delimited(args)
    (status,) = srv.idx_ingest_status(case_id=cluster_case)["ingests"]
    (note,) = [w for w in status.get("warnings", []) if "No time field" in w]
    assert "No time field detected in 1 file(s), e.g. flat/procs-host1.csv" in note


@pytest.mark.integration
def test_the_same_file_name_under_two_hosts_is_two_files(cluster_case, tmp_path, monkeypatch):
    """A recursive Kansa walk has the same module files under every host."""
    top = tmp_path / "walk"
    for host in ("host1", "host2"):
        (top / host).mkdir(parents=True)
        (top / host / "procs.csv").write_text("Name,Pid\nx,4\n")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "tf-same-name")
    args = argparse.Namespace(path=str(top), case=cluster_case, hostname="", recursive=True)
    cli.cmd_ingest_delimited(args)
    (status,) = srv.idx_ingest_status(case_id=cluster_case)["ingests"]
    (note,) = [w for w in status.get("warnings", []) if "No time field" in w]
    assert "No time field detected in 2 file(s), e.g. host1/procs.csv" in note
