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


@pytest.mark.parametrize(
    "text", ["1675036674", "1675036674324", "1675036674324257"], ids=["s", "ms", "us"]
)
def test_an_epoch_written_as_digits_in_a_string_reads_like_the_number(tmp_path, text):
    """Read as is, @timestamp takes digit text as epoch milliseconds: seconds
    became 1970. Now the text takes the number's path, whatever its unit."""
    docs = _json(tmp_path, [{"Timestamp": text, "n": 1}, {"Timestamp": 1675036674, "n": 2}])
    for d in docs:
        assert d["@timestamp"].startswith("2023-01-29T23:57:54"), d


def test_more_digits_than_int_reads_keeps_the_raw_value(tmp_path):
    docs = _json(tmp_path, [{"Timestamp": "9" * 5000, "n": 1}, {"Timestamp": 1675036674, "n": 2}])
    by_n = {d["n"]: d for d in docs}
    assert "@timestamp" not in by_n[1] and by_n[1]["Timestamp"] == "9" * 5000
    assert by_n[2]["@timestamp"].startswith("2023-01-29T23:57:54")


def test_an_integer_too_big_for_a_float_keeps_its_raw_value(tmp_path):
    docs = _json(tmp_path, [{"Timestamp": 10**400, "n": 1}, {"Timestamp": 1675036674, "n": 2}])
    by_n = {d["n"]: d for d in docs}
    assert "@timestamp" not in by_n[1]
    assert by_n[2]["@timestamp"].startswith("2023-01-29T23:57:54")


def test_zero_as_text_is_skipped_like_the_number(tmp_path):
    docs = _json(tmp_path, [{"Timestamp": "0", "n": 1}, {"Timestamp": 0, "n": 2}])
    assert all("@timestamp" not in d for d in docs), docs


def test_a_negative_epoch_as_text_reads_like_the_number(tmp_path):
    docs = _json(tmp_path, [{"Timestamp": "-86400", "n": 1}, {"Timestamp": -86400, "n": 2}])
    assert [d["@timestamp"][:10] for d in docs] == ["1969-12-31", "1969-12-31"]


@pytest.mark.parametrize("text", ["1675036674.5", "1675036674324.5"], ids=["s", "ms"])
def test_a_fractional_epoch_as_text_reads_like_the_number(tmp_path, text):
    """Copied as is, @timestamp took "1675036674.5" as epoch millis: 1970-01-20."""
    docs = _json(tmp_path, [{"Timestamp": text, "n": 1}, {"Timestamp": 1675036674, "n": 2}])
    for d in docs:
        assert d["@timestamp"].startswith("2023-01-29T23:57:54"), d
    want = "54.5" if text == "1675036674.5" else "54.3245"  # the fraction is kept
    assert docs[0]["@timestamp"].startswith(f"2023-01-29T23:57:{want}")


def test_zero_with_a_fraction_as_text_is_skipped(tmp_path):
    (doc,) = _json(tmp_path, [{"Timestamp": "0.0"}])
    assert "@timestamp" not in doc


@pytest.mark.integration
def test_a_digit_date_is_counted_in_the_status_and_not_found_in_1970(
    cluster_case, tmp_path, monkeypatch
):
    """Through the CLI and a cluster: the run's note counts them, and a time
    search over 1970-1977 (where OpenSearch put them) finds nothing."""
    data = tmp_path / "events.csv"
    data.write_text("date,what\n202301292357,a\n20230129,b\n2023-01-29T23:57:00Z,c\n")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "digit-dates")
    args = argparse.Namespace(path=str(data), case=cluster_case, hostname="h1", time_field="date")
    cli.cmd_ingest_delimited(args)
    (status,) = srv.idx_ingest_status(case_id=cluster_case)["ingests"]
    (note,) = [w for w in status.get("warnings", []) if "not understood" in w]
    assert "2 values in date not understood; not used as the timestamp" in note
    client = cli.get_client()
    index = f"case-{cluster_case}-delim-*"
    client.indices.refresh(index=index)
    early = {"range": {"@timestamp": {"gte": "1970-01-01", "lt": "1977-01-01"}}}
    assert client.count(index=index, body={"query": early})["count"] == 0
    assert client.count(index=index)["count"] == 3


@pytest.mark.integration
@pytest.mark.parametrize("walk", ["recursive", "auto-hosts"])
def test_both_walks_carry_the_digit_date_count(cluster_case, tmp_path, monkeypatch, walk):
    """Each host's sub-run counts its own file; the walk's final status sums them."""
    top = tmp_path / "walk"
    if walk == "recursive":
        for host, value in (("host1", "20230129"), ("host2", "202301292357")):
            (top / host).mkdir(parents=True)
            (top / host / "events.csv").write_text(f"date,what\n{value},a\n")
        args = argparse.Namespace(
            path=str(top), case=cluster_case, hostname="", recursive=True, time_field="date"
        )
    else:
        top.mkdir()
        (top / "events-host1.csv").write_text("date,what\n20230129,a\n")
        (top / "events-host2.csv").write_text("date,what\n202301292357,b\n")
        args = argparse.Namespace(
            path=str(top),
            case=cluster_case,
            hostname="",
            auto_hosts="host1,host2",
            time_field="date",
        )
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", f"digit-{walk}")
    cli.cmd_ingest_delimited(args)
    (status,) = srv.idx_ingest_status(case_id=cluster_case)["ingests"]
    (note,) = [w for w in status.get("warnings", []) if "not understood" in w]
    assert "2 values in date not understood; not used as the timestamp" in note


# JSON digit-text dates. The JSON path read any digit text as a number, and a
# number by size, so "20230129" became seconds (1970-08-23) and "202301292357"
# year 8380, with no note. Digit text now follows the delimited path's rule:
# an integer part of 9-10, 13 or 16 digits (leading zeros aside) converts; any
# other width gets no @timestamp, stays in its own field and is counted. Zero
# is no time and isn't counted; signed text and JSON numbers read as before.


@pytest.fixture
def fresh_notes():
    paths.NO_TIME_FIELD.clear()
    paths.TIME_NOT_UNDERSTOOD.clear()
    yield
    paths.NO_TIME_FIELD.clear()
    paths.TIME_NOT_UNDERSTOOD.clear()


def _json_ingest(tmp_path, records, time_field=None):
    data = tmp_path / "events.json"
    data.write_text("".join(json.dumps(r) + "\n" for r in records))
    client = _Client()
    parse_json.ingest_json(data, client, "case-x-json-ev-h", "h", time_field=time_field)
    return data, client.sent


def _counted(data) -> int:
    return sum(n for f, _, n in paths.TIME_NOT_UNDERSTOOD if f == str(data.absolute()))


@pytest.mark.parametrize(
    "value",
    ["20230129", "202301292357", "999999999999", "167503667412345", " 20230129 "],
    ids=["yyyymmdd", "yyyymmddHHMM", "12 digits", "15 digits", "spaced"],
)
def test_json_digit_text_of_no_epoch_width_gets_no_timestamp_and_is_counted(
    tmp_path, fresh_notes, value
):
    data, (doc,) = _json_ingest(tmp_path, [{"Timestamp": value, "n": 1}])
    assert "@timestamp" not in doc, doc
    assert doc["Timestamp"] == value  # its own field, as given
    assert _counted(data) == 1
    assert paths.no_time_field_note() == (
        "1 values in Timestamp not understood; not used as the timestamp"
    )


@pytest.mark.parametrize(
    "field, time_field", [("date", None), ("when", "when")], ids=["auto-detected", "chosen"]
)
def test_json_digit_dates_in_any_time_field(tmp_path, fresh_notes, field, time_field):
    data, docs = _json_ingest(
        tmp_path, [{field: "20230129", "m": "a"}, {field: "20230130", "m": "b"}], time_field
    )
    assert all("@timestamp" not in d for d in docs), docs
    assert _counted(data) == 2


@pytest.mark.integration
def test_a_background_json_run_counts_digit_dates_and_files_none_in_1970(
    cluster_case, tmp_path, monkeypatch
):
    data = tmp_path / "dated.jsonl"
    data.write_text(
        '{"date": "20230129", "m": "a"}\n'
        '{"date": "202301292357", "m": "b"}\n'
        '{"date": "2023-01-29T23:57:00Z", "m": "c"}\n'
    )
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "json-digit-dates")
    cli.cmd_ingest_json(argparse.Namespace(path=str(data), case=cluster_case, hostname="h1"))
    (status,) = srv.idx_ingest_status(case_id=cluster_case)["ingests"]
    (note,) = [w for w in status.get("warnings", []) if "not understood" in w]
    assert "2 values in date not understood; not used as the timestamp" in note
    client = cli.get_client()
    index = f"case-{cluster_case}-json-*"
    client.indices.refresh(index=index)
    early = {"range": {"@timestamp": {"lt": "1977-01-01"}}}
    late = {"range": {"@timestamp": {"gt": "2100-01-01"}}}
    assert client.count(index=index, body={"query": early})["count"] == 0
    assert client.count(index=index, body={"query": late})["count"] == 0
    assert client.count(index=index)["count"] == 3  # nothing dropped


@pytest.mark.integration
def test_a_foreground_json_run_prints_the_digit_date_note(
    cluster_case, tmp_path, monkeypatch, capsys
):
    monkeypatch.delenv("VHIR_INGEST_RUN_ID", raising=False)
    data = tmp_path / "dated.jsonl"
    data.write_text('{"date": "20230129", "m": "a"}\n')
    cli.cmd_ingest_json(argparse.Namespace(path=str(data), case=cluster_case, hostname="h1"))
    out = capsys.readouterr().out
    assert "1 values in date not understood; not used as the timestamp" in out


@pytest.mark.parametrize(
    "value, want",
    [
        ("0001675036674", "2023-01-29T23:57:54"),
        ("0001675036674324", "2023-01-29T23:57:54.324"),
    ],
    ids=["seconds", "milliseconds"],
)
def test_leading_zeros_don_t_count_toward_the_width(tmp_path, fresh_notes, value, want):
    """In both paths: 0001675036674 is ten digits of seconds, not thirteen of ms."""
    data, (doc,) = _json_ingest(tmp_path, [{"Timestamp": value}])
    assert doc["@timestamp"].startswith(want), doc
    assert _counted(data) == 0
    assert parse_delimited._epoch_text(value).startswith(want)


@pytest.mark.parametrize("path", ["json", "delimited"])
def test_all_zero_digits_are_no_time_and_not_counted(tmp_path, fresh_notes, monkeypatch, path):
    if path == "json":
        data, (doc,) = _json_ingest(tmp_path, [{"Timestamp": "00000000"}])
    else:
        sent: list[dict] = []

        def capture(client, actions, **kw):
            sent.extend(actions)
            return len(actions), 0

        monkeypatch.setattr(parse_delimited, "flush_bulk", capture)
        data = tmp_path / "events.csv"
        data.write_text("Timestamp,n\n00000000,1\n")
        parse_delimited.ingest_delimited(
            data, None, "case-x-delim-ev-h", "h", time_field="Timestamp"
        )
        (doc,) = [a["_source"] for a in sent]
    assert "@timestamp" not in doc
    assert paths.TIME_NOT_UNDERSTOOD == []


@pytest.mark.parametrize(
    "value, want",
    [
        ("1675036674", "2023-01-29T23:57:54"),
        ("1675036674324", "2023-01-29T23:57:54.324"),
        ("1675036674324257", "2023-01-29T23:57:54.324257"),
        ("1675036674.5", "2023-01-29T23:57:54.5"),
        ("999999999", "2001-09-09T01:46:39"),
        (1675036674, "2023-01-29T23:57:54"),
        (1675036674.5, "2023-01-29T23:57:54.5"),
        (1675036674324, "2023-01-29T23:57:54.324"),
        ("2023-01-29T23:57:54Z", "2023-01-29T23:57:54Z"),
    ],
)
def test_anchor_json_epochs_and_iso_times_are_unchanged(tmp_path, fresh_notes, value, want):
    data, (doc,) = _json_ingest(tmp_path, [{"Timestamp": value}])
    assert doc["@timestamp"].startswith(want), doc
    assert _counted(data) == 0


@pytest.mark.parametrize("value", ["0", 0, "0.0"])
def test_anchor_json_zero_is_skipped_and_not_counted(tmp_path, fresh_notes, value):
    data, (doc,) = _json_ingest(tmp_path, [{"Timestamp": value}])
    assert "@timestamp" not in doc
    assert _counted(data) == 0


@pytest.mark.parametrize("value", ["-86400", -86400])
def test_anchor_a_negative_json_epoch_reads_as_before(tmp_path, fresh_notes, value):
    data, (doc,) = _json_ingest(tmp_path, [{"Timestamp": value}])
    assert doc["@timestamp"].startswith("1969-12-31")
    assert _counted(data) == 0
