"""EZ-tool dates, the gaps after they were first read as dates.

- A date range on an EZ date field of an index made before 0.6.5 matches none
  of its records: the query tools say so, naming the index.
- The csv template types every EZ date column measured in the tools' real
  output, not only each tool's time field.
- A scan names the values each artifact's index couldn't parse, as the other
  routes do; a blank date cell is left out of its record, so it isn't one.
- `csv --tool evtxecmd` sets each record's @timestamp from TimeCreated, which
  the evtx index's windows, counts and timeline read.
- `--from`/`--to` read an EZ time as UTC, with or without its 7th fraction
  digit, on every Python the product runs on.

The cluster here is a stand-in that keeps what was sent and marks a value of
a template date field that isn't an EZ or ISO time as ignored, as a real
cluster does (measured on OpenSearch 3.5.0; the real cluster is test's leg).
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.server as srv
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import mappings as mp
from opensearch_mcp import parse_csv as pc

FORMAT = (
    "strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSSSSSS||yyyy-MM-dd HH:mm:ss||epoch_millis"
)
# The values a real cluster parses with FORMAT (an EZ time, with or without
# the fraction, or ISO); any other non-empty value goes to _ignored
_PARSES = re.compile(
    r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?)?$"
)


class Cluster:
    """Keeps every record sent; answers stored_counts' queries."""

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.indices = MagicMock()

    def flush(self, client, actions):
        for a in actions:
            self.docs[a["_id"]] = a["_source"]
        return len(actions), 0

    def _ignored(self, doc) -> list[str]:
        dates = mp.csv_date_fields()
        return sorted(k for k, v in doc.items() if k in dates and not _PARSES.match(str(v)))

    def _match(self, doc, q) -> bool:
        if "term" in q:
            ((field, value),) = q["term"].items()
            return value in self._ignored(doc) if field == "_ignored" else doc.get(field) == value
        if "terms" in q:
            ((field, values),) = q["terms"].items()
            return doc.get(field) in values
        if "exists" in q:
            return bool(self._ignored(doc))
        return all(self._match(doc, f) for f in q["bool"]["filter"])

    def count(self, index=None, body=None):
        return {"count": sum(self._match(d, body["query"]) for d in self.docs.values())}

    def search(self, index=None, body=None):
        hits = [{"_ignored": self._ignored(d)} for d in self.docs.values()
                if self._match(d, body["query"])][: body.get("size", 10)]  # fmt: skip
        return {"hits": {"hits": hits}}


def _csv(path: Path, cols: list[str], rows: list[list[str]]) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)
    return path


# --- a range on an EZ date field of an index made before 0.6.5 -----------------

OLD, NEW = "case-0640c0ffee01-mft-0", "case-0650c0ffee02-mft-0"
RANGE = "Created0x10:[2023-01-21 TO 2023-01-21||+1d]"
STALE = (
    f"{OLD} was made before 0.6.5; its EZ date fields aren't read as dates, so date ranges "
    "on them miss its records: delete the index and re-ingest, then re-run "
    "idx_enrich_triage/intel"
)


@pytest.fixture
def two_indices(monkeypatch):
    """A 0.6.4-made mft index (its EZ dates mapped without the format) and a
    fresh one, both empty of matches; the client records what was asked."""
    c = MagicMock()
    old = {"Created0x10": {"type": "date"}, "Created0x30": {"type": "text"}}
    new = {"Created0x10": {"type": "date", "format": FORMAT}}
    maps = {OLD: old, NEW: new}
    c.indices.get_mapping.side_effect = lambda index=None, **k: {
        i: {"mappings": {"properties": p}} for i, p in maps.items()
        if index in (i, "case-*")}  # fmt: skip
    c.search.return_value = {"hits": {"total": {"value": 0}, "hits": []},
                             "aggregations": {"timeline": {"buckets": []}}}  # fmt: skip
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: "aid-1")
    return c


QUERIES = {
    "idx_search": lambda index: srv.idx_search(query=RANGE, index=index),
    "idx_count": lambda index: srv.idx_count(query=RANGE, index=index),
    "idx_timeline": lambda index: srv.idx_timeline(
        query="*", index=index, interval="1d", time_field="Created0x10"
    ),  # fmt: skip
}


@pytest.mark.parametrize("tool", sorted(QUERIES))
def test_a_range_on_an_ez_date_of_an_index_made_before_0_6_5_says_so(two_indices, tool):
    r = QUERIES[tool]("case-*")
    assert r["hint"].startswith(STALE), r
    assert NEW not in r["hint"]


@pytest.mark.parametrize("tool", sorted(QUERIES))
def test_a_fresh_index_gives_no_such_hint(two_indices, tool):
    assert "made before 0.6.5" not in QUERIES[tool](NEW).get("hint", "")


def test_a_query_naming_no_ez_date_never_reads_the_mappings(two_indices):
    srv.idx_count(query="FileName:evil.exe", index="case-*")
    srv.idx_search(query="Created0x10_note:x", index="case-*")  # not the field itself
    two_indices.indices.get_mapping.assert_not_called()


# --- every measured EZ date column is typed ------------------------------------

# Measured in the real tools' output (MFTECmd, AmcacheParser, SBECmd, LECmd,
# JLECmd): every value of each is an EZ time
MEASURED = [
    "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10",
    "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30", "KeyLastWriteTimestamp",
    "LinkDate", "InstallDate", "DriverLastWriteTime", "DriverTimeStamp", "CreatedOn",
    "ModifiedOn", "AccessedOn", "LastWriteTime", "FirstInteracted", "SourceCreated",
    "SourceModified", "SourceAccessed", "TargetCreated", "TargetAccessed", "TrackerCreatedOn",
    "CreationTime",
]  # fmt: skip


def test_every_measured_ez_date_column_is_typed_with_the_format():
    props = json.loads((mp._MAPPINGS_DIR / "csv_template.json").read_text())["template"][
        "mappings"]["properties"]  # fmt: skip
    assert {f: props.get(f) for f in MEASURED} == dict.fromkeys(
        MEASURED, {"type": "date", "format": FORMAT, "ignore_malformed": True}
    )
    assert "Date" not in props  # a generic name: any csv with a Date column would lose it


# --- a scan names the values its artifact's index couldn't parse ----------------

SHIM = ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed",
        "Duplicate", "SourceFile"]  # fmt: skip


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """`run(rows)`: a scan of one host's shimcache through the real
    run_and_ingest and parse_csv, AppCompatCacheParser writing `rows`, into
    the stand-in cluster; returns (the status's shimcache checklist line,
    what the scan printed)."""
    from opensearch_mcp import ingest as ing
    from opensearch_mcp import ingest_status, tools
    from opensearch_mcp.discover import DiscoveredHost

    case = f"ez-{uuid.uuid4().hex[:6]}"
    cases = tmp_path / "cases"
    (cases / case).mkdir(parents=True)
    (cases / case / "CASE.yaml").write_text(
        f"case_id: {case}\ncase_uuid: {uuid.uuid4()}\nnaming_version: 2\n"
    )
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-ez")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    for name in ("_preflight_shard_capacity", "_ensure_case_active"):
        monkeypatch.setattr(cli, name, MagicMock())
    (tmp_path / "audit").mkdir()
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: case)
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    cluster = Cluster()
    monkeypatch.setattr(pc, "flush_bulk", cluster.flush)

    def run(rows):
        def run_tool(cmd, label):
            out = Path(cmd[cmd.index("--csv") + 1])
            _csv(out / "20260102030405_AppCompatCache.csv", SHIM, rows)
            return "", ""

        monkeypatch.setattr(tools, "_run_tool", run_tool)
        root = tmp_path / "M" / "dev01"
        root.mkdir(parents=True, exist_ok=True)
        (root / "SYSTEM").write_bytes(b"regf")
        host = DiscoveredHost(hostname="dev01", volume_root=root)
        host.artifacts.append(("shimcache", root / "SYSTEM"))
        monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])
        monkeypatch.setattr(cli, "get_client", lambda *a, **k: cluster)
        args = argparse.Namespace(
            path=str(tmp_path), case=case, yes=True, all_logs=False, hostname="dev01",
            no_hayabusa=True, skip_triage=True)  # fmt: skip
        out = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(" ".join(map(str, a))))
        cli.cmd_scan(args)
        (status,) = srv.idx_ingest_status(case_id=case)["ingests"]
        (line,) = [c for c in status["checklist"] if c["artifact"] == "shimcache"]
        return line, out

    return run


def _row(n, when):
    return ["1", str(n), f"C:\\Tools\\{n}.exe", when, "NA", "False", "SYSTEM"]


def test_a_scan_names_a_date_its_index_couldnt_parse(scan):
    line, out = scan([_row(0, "2024-02-16 14:32:07"), _row(1, "2024-02-16 15:00:00"),
                      _row(2, "N/A")])  # fmt: skip
    said = "; 1 doc with unparsed fields (e.g. LastModifiedTimeUTC ×1)"
    assert line["detail"] == "3 new, 3 stored" + said, line
    assert any(said in o for o in out), out


def test_a_blank_date_cell_isnt_an_unparsed_value(scan):
    line, _ = scan([_row(0, "2024-02-16 14:32:07"), _row(1, ""), _row(2, "N/A")])
    assert line["detail"] == "3 new, 3 stored; 1 doc with unparsed fields (e.g. " \
        "LastModifiedTimeUTC ×1)", line  # fmt: skip


def _sent(tmp_path, monkeypatch, cols, rows, index="case-x-shimcache-0", **kw):
    """ingest_csv over `rows`: (what it returned, the actions it sent)."""
    sent = []
    monkeypatch.setattr(pc, "flush_bulk", lambda c, a: (sent.extend(a), (len(a), 0))[1])
    got = pc.ingest_csv(csv_path=_csv(tmp_path / "t.csv", cols, rows), client=MagicMock(),
                        index_name=index, hostname="H1", **kw)  # fmt: skip
    return got, sent


# The id 65b3dbe gave the blank row: leaving the blank key out comes after it
BLANK_ID = "46cdea0127859653a913"


def test_a_blank_date_is_left_out_of_the_record_and_keeps_its_id(tmp_path, monkeypatch):
    _, sent = _sent(tmp_path, monkeypatch, SHIM, [_row(1, ""), _row(2, "N/A")])
    blank, na = (a["_source"] for a in sent)
    assert "LastModifiedTimeUTC" not in blank and na["LastModifiedTimeUTC"] == "N/A"
    assert sent[0]["_id"] == BLANK_ID


# --- csv --tool evtxecmd: @timestamp from TimeCreated ---------------------------

EVTX = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Computer"]


def _cmd_csv(tmp_path, monkeypatch, tool, cols, rows) -> list[dict]:
    """`opensearch-ingest csv --tool <tool>` over `rows`: the records sent."""
    sent = []
    monkeypatch.setattr(pc, "flush_bulk", lambda c, a: (sent.extend(a), (len(a), 0))[1])
    path = _csv(tmp_path / f"{tool}.csv", cols, rows)
    monkeypatch.setattr(cli, "get_client", lambda *a, **k: MagicMock())
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "_open_unit"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(cli, "_file_entry", lambda *a, **k: ("aid-1", ""))
    monkeypatch.setattr(cli, "_file_outcome", MagicMock())
    monkeypatch.setattr(cli, "_run_writer", MagicMock())
    args = argparse.Namespace(tool_name=tool, csv_path=str(path), hostname="WKS1", case="c1")
    cli.cmd_csv(args)
    return [a["_source"] for a in sent]


def test_evtxecmd_rows_get_their_timestamp_from_time_created(tmp_path, monkeypatch):
    sent = _cmd_csv(tmp_path, monkeypatch, "evtxecmd", EVTX, [
        ["1", "101", "2023-01-21 13:00:59.3935272", "4624", "WKS1"],
        ["2", "102", "2023-01-21 18:04:01", "4625", "WKS1"]])  # fmt: skip
    assert [s["@timestamp"] for s in sent] == [
        "2023-01-21T13:00:59.393527+00:00", "2023-01-21T18:04:01+00:00"]  # fmt: skip


def test_another_tools_rows_get_no_timestamp(tmp_path, monkeypatch):
    sent = _cmd_csv(tmp_path, monkeypatch, "shimcache", SHIM, [_row(0, "2024-02-16 14:32:07")])
    assert "@timestamp" not in sent[0]


# --- --from/--to on EZ times ---------------------------------------------------

FROM = datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_an_unzoned_ez_time_is_filtered_as_utc(tmp_path, monkeypatch):
    rows = [_row(0, "2024-02-16 14:32:07"), _row(1, "2023-01-21 13:00:59"),
            _row(2, "2024-01-15T14:32:07.123Z")]  # fmt: skip
    (count, skipped, _), sent = _sent(
        tmp_path, monkeypatch, SHIM, rows, time_field="LastModifiedTimeUTC", time_from=FROM
    )
    assert (count, skipped) == (2, 1)
    assert [a["_source"]["CacheEntryPosition"] for a in sent] == ["0", "2"]


def test_a_7_digit_ez_time_is_filtered_on_every_python(tmp_path, monkeypatch):
    """Python 3.10 reads at most 6 fraction digits: an MFT time outside the
    window was kept there. One inside it is kept."""
    rows = [_row(0, "2023-01-21 13:00:59.3935272"), _row(1, "2024-03-01 10:00:00.1234567")]
    (count, skipped, _), sent = _sent(
        tmp_path, monkeypatch, SHIM, rows, time_field="LastModifiedTimeUTC", time_from=FROM
    )
    assert (count, skipped) == (1, 1)
    assert [a["_source"]["CacheEntryPosition"] for a in sent] == ["1"]
