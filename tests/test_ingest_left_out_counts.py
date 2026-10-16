"""A JSON, delimited or access-log run says what it left out as two counts:
rows skipped inside the files it read, and files it didn't read. Its Done line
and the status both say "N rows skipped, M files not read"; a split by host
counts its hosts. The ingests run in-process with the bulk writes stubbed. No
cluster is used, and every value is synthetic."""

from __future__ import annotations

import argparse
import os
from unittest import mock

import pytest
from test_ingest_inputs_not_read import GOOD, NOT_JSON, ONE_COL, TWO_COLS, _files, _status

from opensearch_mcp import ingest_cli, ingest_status
from opensearch_mcp import server as srv

ALOG = '192.0.2.{i} - - [10/Oct/2026:13:55:{i:02d} +0000] "GET /p{i} HTTP/1.1" 200 2326 "-" "UA"\n'
ALOG_GOOD = "".join(ALOG.format(i=i) for i in range(1, 6))


@pytest.fixture
def bg(tmp_path, monkeypatch):
    """A background run's status file in tmp_path, a stub client, case c1 (as
    test_ingest_inputs_not_read's)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    (tmp_path / "audit").mkdir()
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-1")
    monkeypatch.setattr(ingest_cli, "get_client", lambda: mock.MagicMock())
    for n in ("_preflight_shard_capacity", "_ensure_case_active"):
        monkeypatch.setattr(ingest_cli, n, mock.MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ingest_cli, "stored_counts", lambda *a, **k: {})
    monkeypatch.setattr(
        "opensearch_mcp.parse_json.flush_bulk", lambda client, actions, **k: (len(actions), 0)
    )
    return ingest_cli


def _done(out: str) -> str:
    (line,) = [ln for ln in out.splitlines() if ln.startswith("Done. ")]
    return line


def _detail(st: dict) -> str:
    (row,) = st["checklist"]
    assert row["status"] == "done", row
    return row["detail"]


# -- the words


@pytest.mark.parametrize("rows, files, want", [
    (0, 0, "0 rows skipped, 0 files not read"),
    (1, 1, "1 row skipped, 1 file not read"),
    (2, 3, "2 rows skipped, 3 files not read"),
    (1234, 0, "1,234 rows skipped, 0 files not read"),
    (0, 1001, "0 rows skipped, 1,001 files not read"),
])  # fmt: skip
def test_left_out_says_rows_and_files_apart(rows, files, want):
    assert ingest_status.left_out(rows, files) == want


# -- JSON


def test_a_json_file_not_read_is_a_file_not_a_row(bg, tmp_path, capsys):
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD, "bad.jsonl": NOT_JSON})
    bg.cmd_ingest_json(argparse.Namespace(path=str(d), case="c1", hostname="h1"))
    assert _done(capsys.readouterr().out) == (
        "Done. 3 indexed, 0 rows skipped, 1 file not read, 0 bulk failed.")  # fmt: skip
    assert _detail(_status()).startswith("3 new; 0 rows skipped, 1 file not read")


def test_json_rows_skipped_inside_a_file_it_read_are_rows(bg, tmp_path, capsys):
    # records before the window are skipped rows of a file that was read
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD})
    bg.cmd_ingest_json(argparse.Namespace(path=str(d), case="c1", hostname="h1",
                                          time_from="2024-01-03"))  # fmt: skip
    assert "1 indexed, 2 rows skipped, 0 files not read" in _done(capsys.readouterr().out)
    assert "; 2 rows skipped, 0 files not read" in _detail(_status())


def test_a_clean_json_run_says_zero_of_each(bg, tmp_path, capsys):
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD})
    bg.cmd_ingest_json(argparse.Namespace(path=str(d), case="c1", hostname="h1"))
    assert "3 indexed, 0 rows skipped, 0 files not read" in _done(capsys.readouterr().out)
    st = _status()
    assert "0 rows skipped, 0 files not read" in _detail(st)
    assert (st["hosts_total"], st["hosts_complete"]) == (1, 1)


# -- delimited


@pytest.fixture
def skips(bg, monkeypatch):
    """ingest_delimited stubbed: 2 rows a file, and 3 skipped for a name with
    'skips'; it raises for 'broken'. Format detection is real, and raises for
    'locked'."""
    from opensearch_mcp import parse_delimited as pd

    def fake(path, *a, **k):
        if "broken" in path.name:
            raise ValueError("bad row at line 2")
        return (2, 3, 0, 0) if "skips" in path.name else (2, 0, 0, 0)

    real_detect = pd._detect_delimited_format

    def detect(path):
        if "locked" in path.name:
            raise PermissionError(13, "Permission denied", str(path))
        return real_detect(path)

    monkeypatch.setattr(pd, "ingest_delimited", fake)
    monkeypatch.setattr(pd, "_detect_delimited_format", detect)
    return bg


def _dargs(path, **kw):
    return argparse.Namespace(path=str(path), case="c1", hostname=kw.pop("hostname", "h1"), **kw)


def test_delimited_says_rows_skipped_and_files_not_read_apart(skips, tmp_path, capsys):
    d = _files(tmp_path / "ev", {"a-skips.csv": TWO_COLS, "broken.csv": TWO_COLS,
                                 "hashes.csv": ONE_COL, "ok.csv": TWO_COLS})  # fmt: skip
    skips.cmd_ingest_delimited(_dargs(d))
    assert _done(capsys.readouterr().out) == (
        "Done. 4 indexed, 3 rows skipped, 2 files not read, 0 bulk failed.")  # fmt: skip
    assert _detail(_status()).startswith("4 new; 3 rows skipped, 2 files not read")


def test_a_clean_delimited_run_says_zero_of_each(skips, tmp_path, capsys):
    d = _files(tmp_path / "ev", {"ok.csv": TWO_COLS})
    skips.cmd_ingest_delimited(_dargs(d))
    assert "2 indexed, 0 rows skipped, 0 files not read" in _done(capsys.readouterr().out)
    assert "0 rows skipped, 0 files not read" in _detail(_status())


def test_the_leaf_returns_its_rows_skipped_last(skips, tmp_path):
    d = _files(tmp_path / "ev", {"a-skips.csv": TWO_COLS, "ok.csv": TWO_COLS})
    result = skips.cmd_ingest_delimited(_dargs(d))
    assert result[5:] == (2, 3)  # files, rows skipped


def test_a_split_by_three_hosts_counts_three_and_sums_what_each_left_out(skips, tmp_path):
    d = _files(tmp_path / "ev", {
        "logons-h1.csv": TWO_COLS, "hashes-h1.csv": ONE_COL,
        "logons-skips-h2.csv": TWO_COLS, "logons-h3.csv": TWO_COLS,
        "broken-h3.csv": TWO_COLS})  # fmt: skip
    result = skips.cmd_ingest_delimited(_dargs(d, hostname="", auto_hosts="h1,h2,h3"))
    st = _status()
    assert (st["hosts_total"], st["hosts_complete"]) == (3, 3), st
    assert st["total_indexed"] == 6, st
    assert "; 3 rows skipped, 2 files not read" in _detail(st)
    assert result[5:] == (5, 3)


def test_a_split_by_host_counts_a_file_whose_name_gives_no_host_as_not_read(skips, tmp_path):
    d = _files(tmp_path / "ev", {"logons-h1.csv": TWO_COLS, "logons-h2.csv": TWO_COLS,
                                 "notes.csv": TWO_COLS})  # fmt: skip
    skips.cmd_ingest_delimited(_dargs(d, hostname="", auto_hosts="h1,h2"))
    st = _status()
    assert any("not ingested" in w and "notes.csv" in w for w in st["warnings"]), st
    assert "; 0 rows skipped, 1 file not read" in _detail(st)


def test_a_split_by_one_host_counts_one(skips, tmp_path):
    d = _files(tmp_path / "ev", {"logons-h1.csv": TWO_COLS})
    skips.cmd_ingest_delimited(_dargs(d, hostname="", auto_hosts="h1"))
    st = _status()
    assert (st["hosts_total"], st["hosts_complete"]) == (1, 1), st


def test_a_recursive_walk_counts_its_subdirectories_and_the_one_that_failed(skips, tmp_path):
    d = _files(tmp_path / "ev", {
        "h1/logons.csv": TWO_COLS, "h1/hashes.csv": ONE_COL,
        "h2/a-skips.csv": TWO_COLS, "h3/a-locked.csv": TWO_COLS,
        "h3/logons.csv": TWO_COLS})  # fmt: skip
    result = skips.cmd_ingest_delimited(_dargs(d, hostname="", recursive=True))
    st = _status()
    # h3 failed whole: 2 of 3 complete; a failed subdirectory counts as one not read
    assert (st["hosts_total"], st["hosts_complete"]) == (3, 2), st
    assert "; 3 rows skipped, 2 files not read" in _detail(st)
    assert result[6] == 3


def test_a_clean_recursive_walk_counts_every_subdirectory_complete(skips, tmp_path):
    d = _files(tmp_path / "ev", {"h1/a.csv": TWO_COLS, "h2/a.csv": TWO_COLS})
    skips.cmd_ingest_delimited(_dargs(d, hostname="", recursive=True))
    st = _status()
    assert (st["hosts_total"], st["hosts_complete"]) == (2, 2), st
    assert "; 0 rows skipped, 0 files not read" in _detail(st)


def test_a_recursive_walk_over_auto_hosts_sums_each_hosts_rows(skips, tmp_path):
    # each host's walk reads the tree (as before this change); the sum is of
    # what each walk returned: 2 walks x 3 rows skipped
    d = _files(tmp_path / "ev", {"x/a-skips-h1.csv": TWO_COLS, "x/b-h2.csv": TWO_COLS})
    skips.cmd_ingest_delimited(_dargs(d, hostname="", recursive=True, auto_hosts="h1,h2"))
    st = _status()
    assert "8 new; 6 rows skipped, 0 files not read" == _detail(st)
    assert (st["hosts_total"], st["hosts_complete"]) == (2, 2), st


def test_a_run_that_read_nothing_fails_and_still_keeps_its_counts(skips, tmp_path):
    d = _files(tmp_path / "ev", {"broken.csv": TWO_COLS})
    with pytest.raises(SystemExit):
        skips.cmd_ingest_delimited(_dargs(d))
    st = _status()
    (row,) = st["checklist"]
    assert st["status"] == "failed" and row["status"] == "failed", st
    assert "rows skipped" not in row["detail"], row  # a failed row reads as before
    (rec,) = ingest_status.read_active_ingests()  # the record keeps both counts
    ((art,),) = [h["artifacts"] for h in rec["hosts"]]
    assert (art["rows_skipped"], art["files_not_read"]) == (0, 1), art


# -- access log


@pytest.fixture
def alog(bg, monkeypatch):
    from opensearch_mcp import bulk, parse_accesslog

    monkeypatch.setattr(parse_accesslog, "flush_bulk", lambda client, actions, **k:
                        (len(actions), 0))  # fmt: skip
    bulk.reset_circuit_breaker()

    def go(folder):
        ingest_cli.cmd_ingest_accesslog(argparse.Namespace(
            path=str(folder), case="c1", hostname="web01", time_from=None, time_to=None,
            dry_run=False, index_suffix=None))  # fmt: skip
        return _status()

    return go


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_access_log_not_read_is_a_file_and_bad_lines_are_rows(alog, tmp_path, capsys):
    d = _files(tmp_path / "logs", {"a.log": ALOG_GOOD + "garbage\nmore garbage\n",
                                   "b-locked.log": ALOG_GOOD})  # fmt: skip
    (d / "b-locked.log").chmod(0)
    try:
        st = alog(d)
    finally:
        (d / "b-locked.log").chmod(0o644)
    assert "5 indexed, 2 rows skipped, 1 file not read" in _done(capsys.readouterr().out)
    assert "; 2 rows skipped, 1 file not read" in _detail(st)


def test_a_clean_access_log_run_says_zero_of_each(alog, tmp_path, capsys):
    st = alog(_files(tmp_path / "logs", {"a.log": ALOG_GOOD}))
    assert "5 indexed, 0 rows skipped, 0 files not read" in _done(capsys.readouterr().out)
    assert "; 0 rows skipped, 0 files not read" in _detail(st)


def test_a_log_none_of_whose_lines_indexed_is_read_its_lines_are_rows(alog, tmp_path, capsys):
    d = _files(tmp_path / "logs", {"a.log": ALOG_GOOD, "junk.log": "not\nan\naccess\nlog\n"})
    st = alog(d)
    assert "5 indexed, 4 rows skipped, 0 files not read" in _done(capsys.readouterr().out)
    assert "; 4 rows skipped, 0 files not read" in _detail(st)


# -- a status without the counts reads as before


def test_a_status_without_the_counts_adds_nothing(bg):
    ingest_cli._write_bg_status("c1", "run-1", "complete", "h1", "enrich", "2026-10-16T00:00:00Z",
                                indexed=7)  # fmt: skip
    st = _status()
    assert _detail(st) == "7 new", st
    assert (st["hosts_total"], st["hosts_complete"]) == (1, 1)


def test_a_running_status_counts_no_host_complete(bg):
    ingest_cli._write_bg_status("c1", "run-1", "running", "h1", "delimited",
                                "2026-10-16T00:00:00Z", hosts_total=3)  # fmt: skip
    st = srv.idx_ingest_status(case_id="c1")["ingests"][0]
    assert (st["hosts_total"], st["hosts_complete"]) == (3, 0), st


def test_more_failed_hosts_than_hosts_never_counts_below_zero(bg):
    ingest_cli._write_bg_status("c1", "run-1", "complete", "(recursive)", "delimited",
                                "2026-10-16T00:00:00Z", hosts_total=1, hosts_failed=2)  # fmt: skip
    assert _status()["hosts_complete"] == 0
