"""The delimited, JSON, access-log and tool-CSV ingests record each file before
indexing it.

Each file gets its own audit id, and its entry (the file, its sha256 and the
run) is written before any of its records is indexed, so every id a record
carries names the file it came from, even when the run stops part-way. A
file whose entry can't be written is not indexed, and the run says so. The
parsers are fakes; the audit writer records into one sequence with them.
"""

from __future__ import annotations

import argparse
import hashlib
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import ingest_cli

RUN = "run-7f3a"


class _Audit:
    """Ids in order; `fail` names files whose entry write fails."""

    def __init__(self, seq, fail=()):
        self.seq, self.fail, self.n = seq, set(fail), 0

    def __call__(self, mcp_name=""):
        return self

    def _next_audit_id(self):
        self.n += 1
        return f"opensearch-ingest-1-20261009-{self.n:03d}"

    def log(self, **k):
        if (k.get("params") or {}).get("file", "").rsplit("/", 1)[-1] in self.fail:
            return None
        self.seq.append(("entry", k))
        return k.get("audit_id") or self._next_audit_id()


def _fake(seq, crash_on=""):
    def ingest(f, *a, **kw):
        if f.name == crash_on:
            seq.append(("record", f.name, kw["ingest_audit_id"]))
            raise SystemExit("the process stopped")
        seq.append(("record", f.name, kw["ingest_audit_id"]))
        return (1, 0, 0) if f.suffix == ".log" else (1, 0, 0, False)

    return ingest


KINDS = {
    "delimited": ("cmd_ingest_delimited", "opensearch_mcp.parse_delimited.ingest_delimited",
                  "ingest_delimited", ".csv", "a,b\n1,2\n"),
    "json": ("cmd_ingest_json", "opensearch_mcp.parse_json.ingest_json", "ingest_json",
             ".jsonl", '{"a": 1}\n'),
    "accesslog": ("cmd_ingest_accesslog", "opensearch_mcp.parse_accesslog.ingest_accesslog",
                  "ingest_accesslog", ".log",
                  '10.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n'),
}  # fmt: skip


@pytest.fixture
def run(tmp_path, monkeypatch):
    def go(kind, fail=(), crash_on=""):
        cmd, parser, _, ext, text = KINDS[kind]
        folder = tmp_path / kind
        folder.mkdir()
        files = []
        for n in (1, 2, 3):
            f = folder / f"rd01-part{n}{ext}"
            f.write_text(text.replace("1", str(n), 1))
            files.append(f)
        seq: list = []
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", RUN)
        monkeypatch.setattr(ingest_cli, "AuditWriter", _Audit(seq, fail))
        for name in (
            "_ensure_case_active",
            "_preflight_shard_capacity",
            "_write_bg_status",
            "_load_case_host_dict",
            "get_client",
            "_open_unit",
            "write_status",
        ):
            monkeypatch.setattr(ingest_cli, name, MagicMock())  # fmt: skip
        monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
        monkeypatch.setattr(parser, _fake(seq, crash_on))
        if kind == "delimited":
            monkeypatch.setattr(
                "opensearch_mcp.parse_delimited._detect_delimited_format",
                lambda f: {"format": "csv", "delimiter": ",", "header": "first_line"},
            )
        args = argparse.Namespace(
            path=str(folder), hostname="RD01", case=None, time_field=None, delimiter=None,
            format=None, time_from=None, time_to=None, batch_size=1000, dry_run=False,
            index_suffix=None, recursive=False, auto_hosts="",
        )  # fmt: skip
        try:
            getattr(ingest_cli, cmd)(args)
        except SystemExit:
            pass
        return files, seq

    return go


def _entries(seq, tool):
    return [k for kind, *rest in seq if kind == "entry" for k in rest if k["tool"] == tool]


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_each_file_has_its_own_entry_written_before_its_records(run, kind):
    files, seq = run(kind)
    tool = KINDS[kind][2]
    records = [(name, aid) for k, *rest in seq if k == "record" for name, aid in [rest]]
    assert [n for n, _ in records] == [f.name for f in files]
    assert len({aid for _, aid in records}) == 3  # one id per file
    for f, (_, aid) in zip(files, records):
        (entry,) = [e for e in _entries(seq, tool) if e["audit_id"] == aid]
        assert entry["input_files"] == [str(f)]
        assert entry["input_sha256s"] == [hashlib.sha256(f.read_bytes()).hexdigest()]
        assert entry["params"]["file"] == str(f) and entry["params"]["run_id"] == RUN
        assert entry["params"]["hostname"] == "RD01"
        at = next(i for i, x in enumerate(seq) if x[0] == "entry" and x[1] is entry)
        assert at < seq.index(("record", f.name, aid))  # written first
    (summary,) = _entries(seq, f"idx_{tool}")
    assert summary["params"]["run_id"] == RUN
    assert summary.get("audit_id") not in {aid for _, aid in records}


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_file_whose_entry_cant_be_written_is_not_indexed(run, kind, capsys):
    files, seq = run(kind, fail={"rd01-part2" + KINDS[kind][3]})
    indexed = [x[1] for x in seq if x[0] == "record"]
    assert indexed == [files[0].name, files[2].name]
    out = capsys.readouterr().out
    assert "skipped (its audit entry couldn't be written, so it wasn't indexed)" in out
    (summary,) = _entries(seq, f"idx_{KINDS[kind][2]}")
    assert summary["params"]["failed_files_count"] == 1


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_run_that_stops_part_way_leaves_an_entry_for_every_id(run, kind):
    """The process stops while indexing the second file: its records and the
    first file's already carry ids, and each of those ids has its entry."""
    files, seq = run(kind, crash_on=files_name(kind, 2))
    stamped = {x[2] for x in seq if x[0] == "record"}
    assert len(stamped) == 2
    logged = {e["audit_id"]: e["input_files"] for e in _entries(seq, KINDS[kind][2])}
    assert {a: logged[a] for a in stamped} == {
        a: [str(f)] for a, f in zip(sorted(stamped), files[:2])
    }


def files_name(kind, n):
    return f"rd01-part{n}{KINDS[kind][3]}"


def _csv(tmp_path, monkeypatch, fail=False):
    f = tmp_path / "Amcache_UnassociatedFileEntries.csv"
    f.write_text("a,b\n1,2\n")
    seq: list = []
    audit = _Audit(seq, {f.name} if fail else ())
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", RUN)
    monkeypatch.setattr(ingest_cli, "AuditWriter", audit)
    for name in ("get_client", "_open_unit", "_load_case_host_dict"):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr("opensearch_mcp.write_context.index_name", lambda t: f"case-c-{t}-0")

    def fake(csv_path, **kw):
        seq.append(("record", csv_path.name, kw["ingest_audit_id"]))
        return 1, 0, 0

    monkeypatch.setattr(ingest_cli, "ingest_csv", fake)
    args = argparse.Namespace(tool_name="amcache", csv_path=str(f), hostname="RD01", case=None)
    return f, seq, lambda: ingest_cli.cmd_csv(args)


def test_a_tool_csv_is_recorded_before_its_records(tmp_path, monkeypatch):
    f, seq, go = _csv(tmp_path, monkeypatch)
    go()
    (entry,) = _entries(seq, "idx_ingest_csv_amcache")
    assert seq.index(("entry", entry)) < seq.index(("record", f.name, entry["audit_id"]))
    assert entry["input_files"] == [str(f)]
    assert entry["input_sha256s"] == [hashlib.sha256(f.read_bytes()).hexdigest()]
    assert entry["params"]["tool"] == "amcache" and entry["params"]["run_id"] == RUN


def test_a_tool_csv_whose_entry_cant_be_written_is_not_indexed(tmp_path, monkeypatch, capsys):
    f, seq, go = _csv(tmp_path, monkeypatch, fail=True)
    with pytest.raises(SystemExit) as e:
        go()
    assert e.value.code == 1 and not seq
    assert f"{f}: its audit entry couldn't be written, so it wasn't indexed." in (
        capsys.readouterr().err
    )
