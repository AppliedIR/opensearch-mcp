"""A delimited file with no content (0 bytes, or only space, tab, CR or LF
after an optional BOM, as PowerShell's Export-Csv writes for a host with
nothing to report) is read with nothing in it: detected as "empty", recorded
in the audit trail, never indexed, never counted as not read, and named once
in the status with any file whose rows came to nothing. A file with content
that isn't delimited stays unrecognized, and a run that read nothing still
fails."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from unittest import mock

import pytest

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import parse_delimited as pd
from opensearch_mcp import server as srv

from .test_ingest_inputs_not_read import (  # noqa: F401 (fixtures)
    ONE_COL,
    TWO_COLS,
    _status,
    bg,
)

BOM16 = b"\xff\xfe"
EMPTY = {
    "zero.csv": b"",
    "crlf_only.csv": b"\r\n\r\n",
    "utf8_bom.csv": b"\xef\xbb\xbf",
    "ff_fe.csv": BOM16,
    "ff_fe_crlf.csv": BOM16 + "\r\n".encode("utf-16-le"),
    "fe_ff_crlf.csv": b"\xfe\xff" + "\r\n".encode("utf-16-be"),
    "ws_only.csv": b"   \n  \n",
    "tabs_only.tsv": b"\t\t\n",
}
CSV = {"format": "csv", "delimiter": ",", "header": "first_line"}
TSV = {"format": "tsv", "delimiter": "\t", "header": "first_line"}
UNK = {"format": "unknown"}
CONTENT = {
    "control_3col.csv": (b"a,b,c\n1,2,3\n", CSV),
    "header_only.csv": (b"a,b\n", CSV),
    "utf16_header_only.csv": ("﻿a,b\r\n".encode("utf-16-le"), CSV),
    "utf16_data.csv": ("﻿user,ts\r\nalice,2024-01-01\r\n".encode("utf-16-le"), CSV),
    "blank_lines_first.csv": (b"\r\n\r\nuser,ts\r\nalice,2024-01-01\r\n", CSV),
    "long_blank_run_first.csv": (b"\r\n" * 100000 + b"user,ts\r\nalice,2024-01-01\r\n", CSV),
    "tsv_data.tsv": (b"a\tb\n1\t2\n", TSV),
    "single_col.csv": (ONE_COL.encode(), UNK),
    "prose_commas.txt": (
        b"This is a sentence, with a comma.\nAnother line, more words here, and more, and more.\n",
        CSV,
    ),
    "prose_plain.txt": (b"This is a sentence without delimiters\nAnother plain line here\n", UNK),
    "ws_line_inside.csv": (b"user,ts\n   \nalice,2024-01-01\n", UNK),
    "nul_only.csv": (b"\x00\x00", UNK),
    "nbsp_only.csv": (" \n".encode(), UNK),
    "ff_fe_odd.csv": (b"\xff\xfe\x0a", UNK),
}


@pytest.mark.parametrize("name", sorted(EMPTY))
def test_a_file_with_no_content_is_detected_as_empty(tmp_path, name):
    f = tmp_path / name
    f.write_bytes(EMPTY[name])
    assert pd._detect_delimited_format(f) == {"format": "empty"}


@pytest.mark.parametrize("name", sorted(CONTENT))
def test_a_file_with_content_is_detected_as_before(tmp_path, name):
    body, want = CONTENT[name]
    f = tmp_path / name
    f.write_bytes(body)
    assert pd._detect_delimited_format(f) == want


@pytest.mark.parametrize("how", ["detected", "passed"])
def test_ingest_delimited_refuses_an_empty_file_without_a_call(tmp_path, how):
    f = tmp_path / "e.csv"
    f.write_bytes(BOM16 if how == "detected" else b"a,b\n1,2\n")
    client = mock.MagicMock()
    kw = {"fmt": {"format": "empty"}} if how == "passed" else {}
    with pytest.raises(ValueError) as e:
        pd.ingest_delimited(f, client, "case-c1-delim-e", "h1", **kw)
    assert "no content" in str(e.value), e.value
    assert client.mock_calls == []


@pytest.fixture
def leaf(bg, monkeypatch):  # noqa: F811
    """ingest_delimited stubbed (2 rows; 0 for a name with 'hdr'); detection real;
    the per-file audit helpers and stored_counts recorded."""
    calls = {"ingest": [], "entry": [], "outcome": [], "stored": []}

    def fake(path, *a, **k):
        calls["ingest"].append(path.name)
        return (0, 0, 0, 0) if "hdr" in path.name else (2, 0, 0, 0)

    def entry(audit, tool, f, hostname, index_name, run_id, extra=None):
        calls["entry"].append(Path(f).name)
        return f"aid-{Path(f).name}", ""

    def outcome(audit, aid, tool, summary, f):
        calls["outcome"].append((Path(f).name, summary))

    def stored(client, index, aids):
        calls["stored"].append(index)
        return {} if "hdr" in index else {"stored": 2, "ignored_docs": 0, "ignored": {}}

    monkeypatch.setattr(pd, "ingest_delimited", fake)
    monkeypatch.setattr(cli, "_file_entry", entry)
    monkeypatch.setattr(cli, "_file_outcome", outcome)
    monkeypatch.setattr(cli, "stored_counts", stored)
    return calls


def _write(root: Path, files: dict) -> Path:
    for n, b in files.items():
        (root / n).parent.mkdir(parents=True, exist_ok=True)
        (root / n).write_bytes(b if isinstance(b, bytes) else b.encode())
    return root


def _args(path, **kw):
    ns = dict(path=str(path), case="c1", hostname="h1", format=None)
    ns.update(kw)
    return argparse.Namespace(**ns)


def _named_lines(st):
    return [w for w in st.get("warnings", []) if "had no rows to index" in w]


def _not_read_lines(st):
    return [w for w in st.get("warnings", []) if "not ingested, or only in part" in w]


@pytest.mark.parametrize("override", [None, "csv"])
def test_an_empty_file_is_recorded_as_read_and_not_indexed(leaf, tmp_path, override):
    d = _write(tmp_path / "ev", {"h1-SmbSession.csv": BOM16, "ok.csv": TWO_COLS})
    cli.cmd_ingest_delimited(_args(d, format=override))
    st = _status()
    assert "h1-SmbSession.csv" not in leaf["ingest"], leaf
    assert "h1-SmbSession.csv" in leaf["entry"], leaf
    assert ("h1-SmbSession.csv", "0 indexed: no content") in leaf["outcome"], leaf
    assert not any("h1-SmbSession.csv" in w for w in _not_read_lines(st)), st
    (row,) = st["checklist"]
    assert "0 files not read" in row["detail"], row


def test_an_index_with_no_rows_stays_out_of_the_stored_count(leaf, tmp_path):
    d = _write(tmp_path / "ev", {"ok.csv": TWO_COLS, "hdr.csv": "a,b\n"})
    cli.cmd_ingest_delimited(_args(d))
    st = _status()
    assert not any("hdr" in i for i in leaf["stored"]), leaf["stored"]
    (row,) = st["checklist"]
    assert "2 stored" in row["detail"], row


def test_an_empty_files_index_never_reaches_the_stored_count(leaf, tmp_path):
    d = _write(tmp_path / "ev", {"zzempty.csv": BOM16, "ok.csv": TWO_COLS})
    cli.cmd_ingest_delimited(_args(d))
    assert leaf["stored"], leaf
    assert not any("zzempty" in i for i in leaf["stored"]), leaf["stored"]


def test_a_file_whose_rows_were_all_skipped_adds_no_stored_count(leaf, tmp_path, monkeypatch):
    def fake(path, *a, **k):
        leaf["ingest"].append(path.name)
        return (0, 2, 0, 0) if "win" in path.name else (2, 0, 0, 0)

    def stored(client, index, aids):
        leaf["stored"].append(index)
        return {} if "win" in index else {"stored": 2, "ignored_docs": 0, "ignored": {}}

    monkeypatch.setattr(pd, "ingest_delimited", fake)
    monkeypatch.setattr(cli, "stored_counts", stored)
    d = _write(tmp_path / "ev", {"ok.csv": TWO_COLS, "win.csv": TWO_COLS})
    cli.cmd_ingest_delimited(_args(d))
    (row,) = _status()["checklist"]
    assert "2 stored" in row["detail"], (row, leaf["stored"])


def test_a_rerun_whose_records_are_all_present_keeps_its_stored_count(leaf, tmp_path, monkeypatch):
    from opensearch_mcp import bulk as bk

    def fake(path, *a, **k):
        leaf["ingest"].append(path.name)
        if "rerun" in path.name:  # what flush_bulk does on 409s
            bk._tls.already_present = bk.get_already_present() + 3
            for box in getattr(bk._tls, "present_scopes", ()):
                box[0] += 3
            return (0, 0, 0, 0)
        return (2, 0, 0, 0)

    monkeypatch.setattr(pd, "ingest_delimited", fake)
    d = _write(tmp_path / "ev", {"rerun.csv": TWO_COLS})
    cli.cmd_ingest_delimited(_args(d))
    st = _status()
    assert not any("rerun.csv (no rows)" in w for w in _named_lines(st)), st.get("warnings")
    assert any("rerun" in i for i in leaf["stored"]), leaf["stored"]


def _shape(kind, tmp_path):
    if kind == "leaf":
        d = _write(tmp_path / "ev", {"h1-a.csv": BOM16, "hdr.csv": "a,b\n", "ok.csv": TWO_COLS})
        return d, _args(d), [str(d / "h1-a.csv") + " (empty)", str(d / "hdr.csv") + " (no rows)"]
    if kind == "recursive":
        d = _write(
            tmp_path / "ev",
            {"h1/a.csv": BOM16, "h1/ok.csv": TWO_COLS, "h2/b.csv": BOM16, "h2/ok.csv": TWO_COLS},
        )
        return (
            d,
            _args(d, hostname="", recursive=True),
            [str(d / "h1" / "a.csv") + " (empty)", str(d / "h2" / "b.csv") + " (empty)"],
        )
    d = _write(
        tmp_path / "ev",
        {
            "h1-SmbSession.csv": BOM16,
            "h1-Logons.csv": TWO_COLS,
            "h2-SmbSession.csv": BOM16,
            "h2-Logons.csv": TWO_COLS,
        },
    )
    return (
        d,
        _args(d, hostname="", auto_hosts="h1,h2"),
        [str(d / "h1-SmbSession.csv") + " (empty)", str(d / "h2-SmbSession.csv") + " (empty)"],
    )


@pytest.mark.parametrize("kind", ["leaf", "recursive", "auto_hosts"])
def test_empty_files_are_named_once_in_the_status(leaf, tmp_path, kind):
    d, args, want = _shape(kind, tmp_path)
    cli.cmd_ingest_delimited(args)
    st = _status()
    lines = _named_lines(st)
    assert lines, st.get("warnings")
    joined = " | ".join(lines)
    for w in want:
        assert joined.count(w) == 1, (w, lines)
    assert st["status"] == "complete", st
    assert not _not_read_lines(st), st


@pytest.mark.parametrize("kind", ["recursive", "auto_hosts"])
def test_both_walks_carry_no_rows_files_too(leaf, tmp_path, kind):
    if kind == "recursive":
        d = _write(
            tmp_path / "ev",
            {
                "h1/hdr.csv": "a,b\n",
                "h1/ok.csv": TWO_COLS,
                "h2/a.csv": BOM16,
                "h2/ok.csv": TWO_COLS,
            },
        )
        args = _args(d, hostname="", recursive=True)
        want = [str(d / "h1" / "hdr.csv") + " (no rows)", str(d / "h2" / "a.csv") + " (empty)"]
    else:
        d = _write(
            tmp_path / "ev",
            {
                "h1-hdr.csv": "a,b\n",
                "h1-Logons.csv": TWO_COLS,
                "h2-SmbSession.csv": BOM16,
                "h2-Logons.csv": TWO_COLS,
            },
        )
        args = _args(d, hostname="", auto_hosts="h1,h2")
        want = [str(d / "h1-hdr.csv") + " (no rows)", str(d / "h2-SmbSession.csv") + " (empty)"]
    cli.cmd_ingest_delimited(args)
    joined = " | ".join(_named_lines(_status()))
    for w in want:
        assert joined.count(w) == 1, (w, joined)


def test_the_status_line_names_the_first_ten(leaf, tmp_path):
    files = {f"h1-M{i:02d}.csv": BOM16 for i in range(12)}
    files["ok.csv"] = TWO_COLS
    d = _write(tmp_path / "ev", files)
    cli.cmd_ingest_delimited(_args(d))
    st = _status()
    (line,) = _named_lines(st)
    assert line.startswith("h1: delimited: 12 file(s) had no rows to index ("), line
    assert line.count("(empty)") == 10 and "…" in line, line
    (row,) = st["checklist"]
    assert "0 files not read" in row["detail"], row


@pytest.mark.parametrize("kind", ["leaf", "recursive", "auto_hosts"])
def test_a_run_of_only_empty_files_completes(leaf, tmp_path, kind):
    if kind == "leaf":
        d = _write(tmp_path / "ev", {"h1-a.csv": BOM16, "h1-b.csv": b""})
        args = _args(d)
    elif kind == "recursive":
        d = _write(tmp_path / "ev", {"h1/a.csv": BOM16, "h2/b.csv": BOM16})
        args = _args(d, hostname="", recursive=True)
    else:
        d = _write(tmp_path / "ev", {"h1-SmbSession.csv": BOM16, "h2-SmbSession.csv": BOM16})
        args = _args(d, hostname="", auto_hosts="h1,h2")
    cli.cmd_ingest_delimited(args)  # no SystemExit
    st = _status()
    assert st["status"] == "complete", st
    assert len(" | ".join(_named_lines(st)).split("(empty)")) - 1 == 2, st.get("warnings")


def test_empty_plus_unrecognized_still_fails(leaf, tmp_path, capsys):
    d = _write(tmp_path / "ev", {"a.csv": BOM16, "hashes.csv": ONE_COL})
    with pytest.raises(SystemExit) as e:
        cli.cmd_ingest_delimited(_args(d))
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "none of 1 file(s) was read" in err and "hashes.csv" in err, err


@pytest.mark.parametrize("kind", ["recursive", "auto_hosts"])
def test_empty_plus_unrecognized_still_fails_in_both_walks(leaf, tmp_path, kind):
    if kind == "recursive":
        d = _write(
            tmp_path / "ev",
            {
                "h1/a.csv": BOM16,
                "h1/hashes.csv": ONE_COL,
                "h2/b.csv": BOM16,
                "h2/hashes.csv": ONE_COL,
            },
        )
        args = _args(d, hostname="", recursive=True)
    else:
        d = _write(
            tmp_path / "ev",
            {
                "h1-SmbSession.csv": BOM16,
                "h1-Hashes.csv": ONE_COL,
                "h2-SmbSession.csv": BOM16,
                "h2-Hashes.csv": ONE_COL,
            },
        )
        args = _args(d, hostname="", auto_hosts="h1,h2")
    with pytest.raises(SystemExit) as e:
        cli.cmd_ingest_delimited(args)
    assert e.value.code == 1
    assert _status()["status"] == "failed", _status()


def test_a_run_of_empty_files_whose_entries_fail_still_fails(leaf, tmp_path, monkeypatch):
    def entry(audit, tool, f, hostname, index_name, run_id, extra=None):
        leaf["entry"].append(Path(f).name)
        return "", "the file's entry could not be written"

    monkeypatch.setattr(cli, "_file_entry", entry)
    d = _write(tmp_path / "ev", {"a.csv": BOM16, "b.csv": b""})
    with pytest.raises(SystemExit):
        cli.cmd_ingest_delimited(_args(d))
    assert _status()["status"] == "failed", _status()


@pytest.mark.parametrize("override", ["csv", None])
def test_an_unreadable_file_is_not_read_and_the_run_goes_on(leaf, tmp_path, monkeypatch, override):
    def entry(audit, tool, f, hostname, index_name, run_id, extra=None):
        leaf["entry"].append(Path(f).name)
        if not os.access(f, os.R_OK):  # as the entry's read step reports an OSError
            return "", f"[Errno 13] Permission denied: '{f}'"
        return f"aid-{Path(f).name}", ""

    monkeypatch.setattr(cli, "_file_entry", entry)
    d = _write(tmp_path / "ev", {"locked.csv": TWO_COLS, "ok.csv": TWO_COLS})
    (d / "locked.csv").chmod(0)
    try:
        if os.access(d / "locked.csv", os.R_OK):
            pytest.skip("running as root: chmod 0 doesn't deny")
        cli.cmd_ingest_delimited(_args(d, format=override))
    finally:
        (d / "locked.csv").chmod(0o600)
    st = _status()
    assert st["status"] == "complete", st
    assert any("locked.csv" in w for w in _not_read_lines(st)), st.get("warnings")


def test_the_dry_run_says_empty(tmp_path, monkeypatch):
    f = tmp_path / "h1-SmbSession.csv"
    f.write_bytes(BOM16)
    monkeypatch.setattr(srv, "_active_case", lambda: None)
    monkeypatch.setattr(srv, "_case_path", lambda p, a: (p, ""))
    monkeypatch.setattr(srv, "_validate_path", lambda p: "")
    got = srv.idx_ingest_delimited(path=str(f), hostname="h1", dry_run=True)
    assert got.get("format") == "empty", got


def test_a_run_of_files_with_rows_completes_as_before(leaf, tmp_path):
    d = _write(tmp_path / "ev", {"ok.csv": TWO_COLS, "ok2.csv": TWO_COLS})
    cli.cmd_ingest_delimited(_args(d))
    st = _status()
    assert st["status"] == "complete" and not _not_read_lines(st), st
    (row,) = st["checklist"]
    assert "stored" in row["detail"], row


def test_a_single_column_file_alone_still_fails(leaf, tmp_path, capsys):
    d = _write(tmp_path / "ev", {"hashes.csv": ONE_COL})
    with pytest.raises(SystemExit):
        cli.cmd_ingest_delimited(_args(d))
    assert "unrecognized format" in capsys.readouterr().err
