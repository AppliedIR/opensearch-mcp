"""A scheduled task's registration date becomes the right @timestamp.

Task Scheduler writes seven fraction digits, which Python 3.10's fromisoformat
rejects, so the timestamp was dropped there. A date that carries its own
negative offset was also given the host's zone, giving a wrong UTC time. The
host zone here is America/New_York; values are synthetic or real date shapes.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opensearch_mcp.parse_tasks import parse_tasks_dir

_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
    "<RegistrationInfo><Date>{}</Date></RegistrationInfo></Task>"
)


def _timestamp(tmp_path, date):
    tasks = tmp_path / "Tasks"
    tasks.mkdir()
    (tasks / "T").write_text(_XML.format(date))
    collected = []

    def capture(client, actions, **kw):
        collected.extend(actions)
        return len(actions), 0

    with patch("opensearch_mcp.parse_tasks.flush_bulk", side_effect=capture):
        parse_tasks_dir(tasks, None, "i", "h", system_timezone="America/New_York")
    (doc,) = collected
    return doc["_source"].get("@timestamp")


@pytest.mark.parametrize(
    "date, expected",
    [
        ("2010-09-30T14:53:37.9516706", "2010-09-30T18:53:37.951670Z"),
        ("2024-03-04T05:06:07.12345", "2024-03-04T10:06:07.123450Z"),
    ],
    ids=["seven fraction digits", "five fraction digits"],
)
def test_a_date_with_more_or_fewer_fraction_digits_keeps_its_timestamp(tmp_path, date, expected):
    assert _timestamp(tmp_path, date) == expected


@pytest.mark.parametrize(
    "date, expected",
    [
        ("2005-06-23T13:48:00-08:00", "2005-06-23T21:48:00Z"),
        ("2005-10-11T13:21:17-08:00", "2005-10-11T21:21:17Z"),
        ("2024-03-04T05:06:07.1234567-08:00", "2024-03-04T13:06:07.123456Z"),
        ("2014-01-01T00:00:00-00:00", "2014-01-01T00:00:00Z"),
    ],
    ids=["negative offset", "another negative offset", "fraction and offset", "-00:00"],
)
def test_a_date_with_its_own_offset_keeps_it(tmp_path, date, expected):
    assert _timestamp(tmp_path, date) == expected


@pytest.mark.parametrize(
    "date, expected",
    [
        ("2014-01-01T00:00:00", "2014-01-01T05:00:00Z"),
        ("2024-03-04T05:06:07.123", "2024-03-04T10:06:07.123000Z"),
        ("2005-06-23T13:48:00+08:00", "2005-06-23T13:48:00+08:00"),
        ("2024-03-04T05:06:07.1234567Z", "2024-03-04T05:06:07.1234567Z"),
    ],
    ids=["no fraction", "three fraction digits", "positive offset", "Z"],
)
def test_other_date_forms_are_unchanged(tmp_path, date, expected):
    assert _timestamp(tmp_path, date) == expected
