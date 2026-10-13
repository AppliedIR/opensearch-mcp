"""A json, delimited or accesslog run that ingested nothing fails, and a
terminal status of `failed` exits 1.

- None of its files read (each failed to parse, or was refused because an
  index template isn't installed), or a walk whose every host read nothing:
  it was `complete`, exit 0. Now `failed` (no_file_read), exit 1.
- Every record rejected: it was `failed` (all_records_rejected), exit 0.
  Now exit 1.

A script or an MCP caller read either as success. A partial run (one file
read, some records rejected) or a run given no files ends as before:
`complete`, exit 0. In-process, with test_ingest_inputs_not_read's stubs;
values synthetic.
"""

from __future__ import annotations

import argparse

import pytest

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp.write_context import TemplateNotInstalled

from .test_ingest_inputs_not_read import (  # noqa: F401 (fixtures)
    GOOD,
    NOT_JSON,
    ONE_COL,
    TWO_COLS,
    _delim_args,
    _files,
    _status,
    bg,
    delim,
)


def _fails(capsys, run, *args, said="no_file_read: none of ") -> dict:
    with pytest.raises(SystemExit) as e:
        run(*args)
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith(f"Error: {said}"), err
    assert err.count("Error: ") == 1  # a walk's hosts leave it to the walk
    st = _status()
    assert st["status"] == "failed", st
    return st


def _json(path):
    return argparse.Namespace(path=str(path), case="c1", hostname="h1")


# --- json -------------------------------------------------------------------


@pytest.mark.usefixtures("bg")
def test_json_where_every_file_failed_fails(tmp_path, capsys):
    d = _files(tmp_path / "ev", {"a.jsonl": NOT_JSON, "b.jsonl": NOT_JSON})
    _fails(capsys, cli.cmd_ingest_json, _json(d))


@pytest.mark.usefixtures("bg")
def test_json_where_every_file_was_refused_fails(tmp_path, capsys, monkeypatch):
    def refused(client, actions, **k):
        raise TemplateNotInstalled("index template vhir-json is not installed (x)")

    monkeypatch.setattr("opensearch_mcp.parse_json.flush_bulk", refused)
    d = _files(tmp_path / "ev", {"a.jsonl": GOOD})
    _fails(capsys, cli.cmd_ingest_json, _json(d))


@pytest.mark.usefixtures("bg")
def test_json_that_read_one_file_completes(tmp_path):
    """Control: one file read, one failed."""
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD, "a.jsonl": NOT_JSON})
    cli.cmd_ingest_json(_json(d))
    assert _status()["status"] == "complete"


# --- delimited --------------------------------------------------------------


@pytest.mark.usefixtures("delim")
@pytest.mark.parametrize(
    "files",
    [{"broken-a.csv": TWO_COLS, "broken-b.csv": TWO_COLS}, {"hashes.csv": ONE_COL}],
    ids=["every file failed", "no file recognised"],
)
def test_delimited_where_no_file_was_read_fails(tmp_path, capsys, files):
    _fails(capsys, cli.cmd_ingest_delimited, _delim_args(_files(tmp_path / "ev", files)))


@pytest.mark.usefixtures("delim")
def test_a_walk_where_no_host_read_a_file_fails(tmp_path, capsys):
    """The walk's sum fails, once: each host's leaf leaves it to the walk."""
    d = _files(tmp_path / "ev", {"h1/broken.csv": TWO_COLS, "h2/hashes.csv": ONE_COL})
    _fails(capsys, cli.cmd_ingest_delimited, _delim_args(d, hostname="", recursive=True))


@pytest.mark.usefixtures("delim")
def test_auto_hosts_where_no_host_read_a_file_fails(tmp_path, capsys):
    d = _files(tmp_path / "ev", {"broken-h1.csv": TWO_COLS, "broken-h2.csv": TWO_COLS})
    _fails(capsys, cli.cmd_ingest_delimited, _delim_args(d, hostname="", auto_hosts="h1,h2"))


@pytest.mark.usefixtures("delim")
@pytest.mark.parametrize(
    "kw,files",
    [({"recursive": True, "hostname": ""}, {"h1/broken.csv": TWO_COLS, "h2/ok.csv": TWO_COLS}),
     ({}, {"broken.csv": TWO_COLS, "ok.csv": TWO_COLS}),
     ({"recursive": True, "hostname": ""}, {})],
    ids=["walk, one host read", "one file read", "empty walk"],
)  # fmt: skip
def test_a_delimited_run_that_read_a_file_or_had_none_completes(tmp_path, kw, files):
    """Controls."""
    d = _files(tmp_path / "ev", files)
    d.mkdir(parents=True, exist_ok=True)
    cli.cmd_ingest_delimited(_delim_args(d, **kw))
    assert _status()["status"] == "complete"


# --- accesslog --------------------------------------------------------------


@pytest.fixture
def alog(request, monkeypatch):
    """ingest_accesslog stubbed: 2 lines a file, or raises for a name with 'broken'."""
    request.getfixturevalue("bg")

    def fake(path, *a, **k):
        if "broken" in path.name:
            raise ValueError("unreadable log")
        return 2, 0, 0

    monkeypatch.setattr("opensearch_mcp.parse_accesslog.ingest_accesslog", fake)


@pytest.mark.usefixtures("alog")
def test_accesslog_where_every_file_failed_fails(tmp_path, capsys):
    d = _files(tmp_path / "ev", {"broken-access.log": "x\n", "broken2-access.log": "x\n"})
    _fails(capsys, cli.cmd_ingest_accesslog, _json(d))


@pytest.mark.usefixtures("alog")
def test_accesslog_that_read_one_file_completes(tmp_path):
    d = _files(tmp_path / "ev", {"broken-access.log": "x\n", "access.log": "x\n"})
    cli.cmd_ingest_accesslog(_json(d))
    assert _status()["status"] == "complete"


def test_the_status_helper_says_which():
    """0 indexed, 0 rejected: `complete` before, whatever the files did."""
    assert cli._terminal_status(0, 0, "") == ("complete", "")
    assert cli._terminal_status(0, 0, "", 2, ["a (x)"]) == ("complete", "")
    assert cli._terminal_status(0, 0, "", 1, ["a (x)"]) == (
        "failed", "no_file_read: none of 1 file(s) was read, e.g. a (x)"
    )  # fmt: skip
    assert cli._terminal_status(0, 3, "bad", 1, ["a (x)"])[1].startswith("all_records_rejected")


# --- every record rejected: `failed` already, now exit 1 too ------------------

REJECTED = "all_records_rejected: "


def _bulk(monkeypatch, rejected_of):
    """parse_json's flush_bulk: of each batch, `rejected_of(n)` rejected."""

    def flush(client, actions, **k):
        n = len(actions)
        return n - rejected_of(n), rejected_of(n)

    monkeypatch.setattr("opensearch_mcp.parse_json.flush_bulk", flush)


@pytest.mark.usefixtures("bg")
def test_json_whose_every_record_was_rejected_exits_1(tmp_path, capsys, monkeypatch):
    """Was: status `failed`, exit 0."""
    _bulk(monkeypatch, lambda n: n)
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD})
    st = _fails(capsys, cli.cmd_ingest_json, _json(d), said=REJECTED)
    assert st["bulk_failed"] == 3, st


@pytest.mark.usefixtures("bg")
def test_json_with_some_records_rejected_completes(tmp_path, capsys, monkeypatch):
    """Control: partial rejection is `complete`, exit 0."""
    _bulk(monkeypatch, lambda n: 1)
    cli.cmd_ingest_json(_json(_files(tmp_path / "ev", {"good.jsonl": GOOD})))
    st = _status()
    assert (st["status"], st["bulk_failed"]) == ("complete", 1), st
    assert "Error: " not in capsys.readouterr().err


def _delim_rows(monkeypatch, indexed, rejected):
    from opensearch_mcp import parse_delimited as pd

    monkeypatch.setattr(pd, "ingest_delimited", lambda *a, **k: (indexed, 0, rejected, 0))


@pytest.mark.usefixtures("delim")
@pytest.mark.parametrize(
    "kw,files",
    [({}, {"a.csv": TWO_COLS, "b.csv": TWO_COLS}),
     ({"recursive": True, "hostname": ""}, {"h1/a.csv": TWO_COLS, "h2/b.csv": TWO_COLS}),
     ({"hostname": "", "auto_hosts": "h1,h2"}, {"a-h1.csv": TWO_COLS, "b-h2.csv": TWO_COLS})],
    ids=["one host", "recursive walk", "auto-hosts"],
)  # fmt: skip
def test_delimited_whose_every_record_was_rejected_exits_1(
    tmp_path, capsys, monkeypatch, kw, files
):
    _delim_rows(monkeypatch, 0, 2)
    d = _files(tmp_path / "ev", files)
    st = _fails(capsys, cli.cmd_ingest_delimited, _delim_args(d, **kw), said=REJECTED)
    assert st["bulk_failed"] == 4, st


@pytest.mark.usefixtures("delim")
def test_delimited_with_some_records_rejected_completes(tmp_path, capsys, monkeypatch):
    _delim_rows(monkeypatch, 1, 1)
    cli.cmd_ingest_delimited(_delim_args(_files(tmp_path / "ev", {"a.csv": TWO_COLS})))
    assert _status()["status"] == "complete"
    assert "Error: " not in capsys.readouterr().err


def _alog_rows(monkeypatch, indexed, rejected):
    monkeypatch.setattr(
        "opensearch_mcp.parse_accesslog.ingest_accesslog", lambda *a, **k: (indexed, 0, rejected)
    )


@pytest.mark.usefixtures("bg")
def test_accesslog_whose_every_record_was_rejected_exits_1(tmp_path, capsys, monkeypatch):
    _alog_rows(monkeypatch, 0, 2)
    d = _files(tmp_path / "ev", {"access.log": "x\n"})
    st = _fails(capsys, cli.cmd_ingest_accesslog, _json(d), said=REJECTED)
    assert st["bulk_failed"] == 2, st


@pytest.mark.usefixtures("bg")
def test_accesslog_with_some_records_rejected_completes(tmp_path, capsys, monkeypatch):
    _alog_rows(monkeypatch, 1, 1)
    cli.cmd_ingest_accesslog(_json(_files(tmp_path / "ev", {"access.log": "x\n"})))
    assert _status()["status"] == "complete"
    assert "Error: " not in capsys.readouterr().err
