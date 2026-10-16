"""A Zeek or bodyfile data line with the wrong number of fields isn't indexed.
Each one counts as a row skipped, so the Done line doesn't say "0 rows
skipped" while rows were left out. Blank lines and Zeek's `#` lines stay
uncounted. The bulk writes are stubbed. No cluster is used, and every value is
synthetic."""

from __future__ import annotations

import argparse

import pytest
from test_ingest_inputs_not_read import _files
from test_ingest_left_out_counts import _done, bg  # noqa: F401  (bg is a fixture)

from opensearch_mcp import parse_delimited as pd

ZEEK_HEAD = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\n"
    "#types\ttime\tstring\taddr\n"
)
ZEEK_ROW = "1700000{i:03d}.000000\tC{i}\t192.0.2.{i}\n"
ZEEK_GOOD = ZEEK_HEAD + "".join(ZEEK_ROW.format(i=i) for i in range(1, 4)) + "\n#close\t2026\n"
ZEEK_SHORT = "1700000099.000000\tC99\n"  # a field short, as a log still being written

BODY_ROW = "0|/d/f{i}.txt|{i}|r/rrw-r--r--|0|0|5|1700000000|1700000000|1700000000|1700000000\n"
BODY_GOOD = "".join(BODY_ROW.format(i=i) for i in range(1, 4))
BODY_PIPE_NAME = BODY_ROW.format(i=9).replace("/d/f9.txt", "/d/a|b.txt")  # 12 parts, as fls writes

ZEEK_FMT = {"format": "zeek", "delimiter": "\t", "header": "zeek"}
BODY_FMT = {"format": "bodyfile", "delimiter": "|", "header": None}


@pytest.fixture
def stub_bulk(monkeypatch):
    monkeypatch.setattr(pd, "flush_bulk", lambda client, actions, **k: (len(actions), 0))


def _ingest(path, fmt):
    return pd.ingest_delimited(path, None, "case-x-delimited-h", "h", fmt=fmt)


def test_a_short_zeek_line_is_one_row_skipped_on_the_done_line(bg, stub_bulk, tmp_path, capsys):  # noqa: F811
    lines = ZEEK_GOOD.splitlines(keepends=True)
    body = "".join(lines[:6]) + ZEEK_SHORT + "".join(lines[6:])
    d = _files(tmp_path / "ev", {"conn.log": body})
    bg.cmd_ingest_delimited(argparse.Namespace(path=str(d), case="c1", hostname="h1"))
    assert _done(capsys.readouterr().out) == (
        "Done. 3 indexed, 1 row skipped, 0 files not read, 0 bulk failed.")  # fmt: skip


def test_a_bodyfile_name_with_a_pipe_is_one_row_skipped(stub_bulk, tmp_path):
    p = _files(tmp_path, {"body.txt": BODY_GOOD + BODY_PIPE_NAME}) / "body.txt"
    assert pd._detect_delimited_format(p) == BODY_FMT
    assert _ingest(p, BODY_FMT) == (3, 1, 0, 0)


def test_a_short_bodyfile_line_is_one_row_skipped(stub_bulk, tmp_path):
    short = BODY_ROW.format(i=8).rsplit("|", 1)[0] + "\n"  # 10 parts
    p = _files(tmp_path, {"body.txt": BODY_GOOD + short}) / "body.txt"
    assert _ingest(p, BODY_FMT) == (3, 1, 0, 0)


@pytest.mark.parametrize("name, body, fmt", [
    ("conn.log", ZEEK_GOOD + "\n\n", ZEEK_FMT),
    ("body.txt", BODY_GOOD + "\n", BODY_FMT),
], ids=["zeek", "bodyfile"])  # fmt: skip
def test_clean_files_skip_nothing_and_blank_and_hash_lines_stay_uncounted(
    stub_bulk, tmp_path, name, body, fmt
):
    p = _files(tmp_path, {name: body}) / name
    assert pd._detect_delimited_format(p) == fmt
    assert _ingest(p, fmt) == (3, 0, 0, 0)


def test_every_dropped_line_counts(stub_bulk, tmp_path):
    p = _files(tmp_path, {"conn.log": ZEEK_GOOD + ZEEK_SHORT * 4 + "a\tb\tc\td\n"})
    assert _ingest(p / "conn.log", ZEEK_FMT) == (3, 5, 0, 0)
