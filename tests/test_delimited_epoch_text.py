"""A delimited time column holding an epoch as text is indexed at that time.

csv and Zeek give every value as text, and only real numbers were converted,
so a Zeek `ts` of 1675036674.123456 or a CSV `ts` of 1675036674 went to
@timestamp as digits, which OpenSearch reads as epoch milliseconds:
1970-01-20. Digits whose integer part has 9-10, 13 or 16 digits are now
read as seconds, milliseconds or microseconds. Digits of any other width (a
`20230129` date, `202301292357`, 12 or 15 digits) went to @timestamp too, read
as 1970 and 1976; they now stay in their own field without @timestamp, and
the run's note counts them.
"""

from __future__ import annotations

import pytest

from opensearch_mcp import parse_delimited
from opensearch_mcp.paths import TIME_NOT_UNDERSTOOD, no_time_field_note


def _stamp(tmp_path, monkeypatch, column, value, zeek=False):
    sent: list[dict] = []

    def capture(client, actions, **kw):
        sent.extend(actions)
        return len(actions), 0

    monkeypatch.setattr(parse_delimited, "flush_bulk", capture)
    if zeek:
        path = tmp_path / "conn.log"
        path.write_text(
            f"#separator \\x09\n#path\tconn\n#fields\tts\tuid\n#types\ttime\tstring\n{value}\tC1\n"
        )
    else:
        path = tmp_path / "events.csv"
        path.write_text(f"{column},note\n{value},x\n")
    TIME_NOT_UNDERSTOOD.clear()
    parse_delimited.ingest_delimited(path, None, "case-x-delimited-h", "h")
    (doc,) = [a["_source"] for a in sent]
    assert doc[column if not zeek else "ts"] == value  # its own field, as given
    return doc.get("@timestamp")


@pytest.mark.parametrize(
    "column, value, zeek, expected",
    [
        ("ts", "1675036674.123456", True, "2023-01-29T23:57:54.123"),
        ("ts", "1675036674", False, "2023-01-29T23:57:54+00:00"),
        ("timestamp", "1675036674.5", False, "2023-01-29T23:57:54.500000+00:00"),
        ("ts", "1675036674123456", False, "2023-01-29T23:57:54.123456+00:00"),
    ],
    ids=["zeek seconds", "csv seconds", "csv fraction", "csv micro"],
)
def test_an_epoch_written_as_text_is_indexed_at_its_time(
    tmp_path, monkeypatch, column, value, zeek, expected
):
    assert _stamp(tmp_path, monkeypatch, column, value, zeek).startswith(expected)


@pytest.mark.parametrize(
    "value, instant",
    [("1675036674123", "2023-01-29T23:57:54.123")],
    ids=["13 digits"],
)
def test_anchor_a_millisecond_epoch_keeps_its_instant(tmp_path, monkeypatch, value, instant):
    # OpenSearch already read these digits as milliseconds: the same instant
    stamp = _stamp(tmp_path, monkeypatch, "time", value)
    assert stamp == value or stamp.startswith(instant), stamp


@pytest.mark.parametrize(
    "column, value",
    [
        ("date", "20230129"),
        ("date", "202301292357"),
        ("time", "999999999999"),
        ("time", "167503667412345"),
        ("date", " 20230129 "),
    ],
    ids=["yyyymmdd", "yyyymmddHHMM", "12 digits", "15 digits", "spaced"],
)
def test_digits_of_no_epoch_width_get_no_timestamp_and_are_counted(
    tmp_path, monkeypatch, column, value
):
    assert _stamp(tmp_path, monkeypatch, column, value) is None
    assert TIME_NOT_UNDERSTOOD == [(str((tmp_path / "events.csv").absolute()), 1)]
    assert no_time_field_note() == "1 time values not understood; left without a timestamp"


def test_anchor_an_iso_time_reaches_opensearch_as_before(tmp_path, monkeypatch):
    assert _stamp(tmp_path, monkeypatch, "time", "2023-01-29T23:57:54Z") == "2023-01-29T23:57:54Z"
    assert TIME_NOT_UNDERSTOOD == []
