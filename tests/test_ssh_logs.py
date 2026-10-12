"""sshd logs: Win32-OpenSSH's own log is read, and no line is dropped unnamed.

- Win32-OpenSSH writes `<pid> <date> <time.ms> <message>` in local time: each
  line is indexed in UTC, with `process.pid`, and the pid is in its id (two
  sessions can log one text in one millisecond). A file is read past a BOM.
- A line in the `... sshd:` format keeps its id.
- "Failed password for invalid user X" is a failed logon by X, from its IP.
- A line in no known format, or whose time doesn't parse, is counted per file
  and named in the status. With no time zone, each file is named not indexed.
"""

from __future__ import annotations

import errno
import os
import uuid
from pathlib import Path

import pytest
from ssh_scan_cluster import FakeOS

from opensearch_mcp import parse_ssh

NY = "America/New_York"  # EDT, UTC-4, on 2021-03-23
CASE_UUID = "7b3e11c0ffee4b1d9e0d1c2b3a4f5e6d"
INDEX = "case-7b3e11c0ffee-ssh-0"
LOG = "ProgramData/ssh/logs/sshd.log"

WIN32 = (
    "3032 2021-03-23 16:50:11.120 Server listening on 0.0.0.0 port 22.\n"
    "4120 2021-03-23 16:50:12.345 Accepted password for alice from 10.0.0.5 port 50123 ssh2\n"
    "4188 2021-03-23 16:51:02.001 Failed password for bob from 203.0.113.9 port 50200 ssh2\n"
    "4120 2021-03-23 16:51:05.778 Accepted publickey for bob from 10.0.0.6 port 50201 ssh2: "
    "ED25519 SHA256:abc\n"
    "4190 2021-03-23 16:51:02.001 Failed password for bob from 203.0.113.9 port 50200 ssh2\n"
)
# (UTC time, event, method, user, ip, port, pid, raw line)
WIN32_DOCS = [
    ("2021-03-23T20:50:11.120000Z", "other", None, None, None, None, 3032,
     "Server listening on 0.0.0.0 port 22."),
    ("2021-03-23T20:50:12.345000Z", "auth_accepted", "password", "alice", "10.0.0.5", 50123,
     4120, "Accepted password for alice from 10.0.0.5 port 50123 ssh2"),
    ("2021-03-23T20:51:02.001000Z", "auth_failed", "password", "bob", "203.0.113.9", 50200,
     4188, "Failed password for bob from 203.0.113.9 port 50200 ssh2"),
    ("2021-03-23T20:51:02.001000Z", "auth_failed", "password", "bob", "203.0.113.9", 50200,
     4190, "Failed password for bob from 203.0.113.9 port 50200 ssh2"),
    ("2021-03-23T20:51:05.778000Z", "auth_accepted", "publickey", "bob", "10.0.0.6", 50201,
     4120, "Accepted publickey for bob from 10.0.0.6 port 50201 ssh2: ED25519 SHA256:abc"),
]  # fmt: skip
HEADFMT = (
    "2023-01-25 14:30:00 sshd: Accepted publickey for eve from 198.51.100.7 port 49832 ssh2\n"
    "2023-01-25 14:30:05 sshd[612]: Failed password for root from 198.51.100.7 port 49833 ssh2\n"
)
HEADFMT_IDS = ["224a2f3560f7260fbae6", "65e68a1eb891b362eee9"]  # as 0.6.4 gives them
# sshd.log: Win32, no format, a Win32 shape with month 13, another daemon, head format
MIXED = (
    "4120 2021-03-23 16:50:12.345 Accepted password for alice from 10.0.0.5 port 50123 ssh2\n"
    "this line is in no sshd format\n"
    "3032 2021-13-45 16:50:11.120 a Win32 shape with a date that does not exist\n"
    "2021-03-23 16:50:12 kernel: another daemon's line\n"
    "2023-01-25 14:30:00 sshd: Accepted publickey for eve from 198.51.100.7 port 49832 ssh2\n"
)
OTHER = (
    "garbage one\ngarbage two\n"
    "4300 2021-03-23 17:00:00.000 Accepted password for carol from 10.0.0.7 port 50300 ssh2\n"
)
UNREAD_1 = f"{LOG}: 3 of 5 line(s) not in a known sshd log format, not indexed"
UNREAD_2 = (
    "ProgramData/ssh/logs/z-other.log: 2 of 3 line(s) not in a known sshd log format, not indexed"
)
NO_ZONE = "the system timezone is unknown, so local times can't be read as UTC"


def write(root, files: dict):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text) if isinstance(text, bytes) else p.write_text(text)


@pytest.fixture
def parse(tmp_path, monkeypatch):
    """parse_ssh_log over a volume holding `files`: ((indexed, skipped,
    failed), [(parser id, doc)], notes)."""

    def run(files: dict, tz=NY):
        root = tmp_path / "WKS01"
        write(root, files)
        sent: list = []

        def flush(client, actions):
            sent.extend(actions)
            return len(actions), 0

        monkeypatch.setattr(parse_ssh, "flush_bulk", flush)
        notes: list[str] = []
        ssh_dir = root / "ProgramData" / "ssh"
        res = parse_ssh.parse_ssh_log(
            ssh_dir, None, INDEX, "WKS01", system_timezone=tz, volume_root=root, notes=notes
        )
        return res, [(a["_id"], a["_source"]) for a in sent], notes

    return run


def rows(docs):
    return sorted(
        (d.get("@timestamp"), d.get("ssh.event_type"), d.get("ssh.auth_method"),
         d.get("user.name"), d.get("source.ip"), d.get("source.port"), d.get("process.pid"),
         d.get("ssh.raw_line"))
        for _, d in docs
    )  # fmt: skip


def test_win32_openssh_lines_are_indexed_in_utc_with_their_pid(parse):
    res, docs, notes = parse({LOG: WIN32})
    assert rows(docs) == sorted(WIN32_DOCS)
    assert len({i for i, _ in docs}) == 5  # two sessions, one text, one millisecond: two
    assert {d["vhir.source_file"] for _, d in docs} == {LOG}
    assert (res, notes) == ((5, 0, 0), [])


def test_a_bom_doesnt_hide_the_first_line(parse):
    text = (
        "﻿4120 2021-03-23 16:50:12.345 Accepted password for alice from 10.0.0.5 "
        "port 50123 ssh2\n3032 2021-03-23 16:50:11.120 Server listening on 0.0.0.0 port 22.\n"
    )
    res, docs, notes = parse({LOG: text.encode("utf-8")})
    assert sorted(d["process.pid"] for _, d in docs) == [3032, 4120]
    assert (res, notes) == ((2, 0, 0), [])


def test_a_line_in_the_sshd_format_keeps_its_id(parse):
    res, docs, notes = parse({LOG: HEADFMT})
    assert sorted(i for i, _ in docs) == HEADFMT_IDS
    assert all("process.pid" not in d for _, d in docs)
    assert (res, notes) == ((2, 0, 0), [])


@pytest.mark.parametrize(
    "line",
    [
        "2023-01-25 14:30:20 sshd: Failed password for invalid user admin from 203.0.113.9 "
        "port 49836 ssh2",
        "4188 2021-03-23 16:51:02.001 Failed password for invalid user admin from "
        "203.0.113.9 port 49836 ssh2",
    ],
    ids=["sshd-format", "win32"],
)
def test_a_failed_password_for_an_invalid_user_is_a_failed_logon_by_that_user(parse, line):
    res, ((_, doc),), notes = parse({LOG: line + "\n"})
    got = {k: doc.get(k) for k in ("ssh.event_type", "ssh.auth_method", "user.name",
                                    "source.ip", "source.port")}  # fmt: skip
    assert got == {
        "ssh.event_type": "auth_failed",
        "ssh.auth_method": "password",
        "user.name": "admin",
        "source.ip": "203.0.113.9",
        "source.port": 49836,
    }


def test_unread_lines_are_counted_per_file_and_named(parse):
    res, docs, notes = parse({LOG: MIXED, "ProgramData/ssh/logs/z-other.log": OTHER})
    assert sorted(d["user.name"] for _, d in docs) == ["alice", "carol", "eve"]
    assert res == (3, 5, 0)
    assert notes == [UNREAD_1, UNREAD_2]


# --------------------------------------------------------------------------
# The scan route: what the status and the console say


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """ingest.ingest (idx_ingest's scan) of a Windows volume with these ssh
    logs, into an in-memory cluster; then idx_ingest_status."""
    from sift_common.audit import AuditWriter

    from opensearch_mcp import ingest_status
    from opensearch_mcp import server as srv
    from opensearch_mcp import write_context as wc
    from opensearch_mcp.discover import make_host
    from opensearch_mcp.ingest import ingest

    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")

    def run(files: dict, tz=NY, prepare=None):
        case_id = f"ssh-{uuid.uuid4().hex[:8]}"
        case_dir = wc.case_dir_for(case_id)
        (case_dir / "CASE.yaml").write_text(
            f"case_id: {case_id}\ncase_uuid: {CASE_UUID}\nnaming_version: 2\n"
        )
        (case_dir / "audit").mkdir(exist_ok=True)
        monkeypatch.setenv("VHIR_AUDIT_DIR", str(case_dir / "audit"))
        root = tmp_path / "vol" / "WKS01"
        write(root, files)
        (root / "Windows" / "System32" / "config").mkdir(parents=True)
        (root / "Windows" / "System32" / "config" / "SYSTEM").touch()
        if prepare:  # a change to the volume before the scan
            prepare(root)
        host = make_host("WKS01", root)
        host.system_timezone = tz
        client = FakeOS()
        wc.set_current(None)
        ingest(hosts=[host], client=client, audit=AuditWriter(mcp_name="opensearch-ingest-1"),
               case_id=case_id, include={"ssh"}, status_pid=1, status_run_id="run-ssh",
               case_dir=case_dir)  # fmt: skip
        (st,) = srv.idx_ingest_status(case_id=case_id)["ingests"]
        # the ssh logs' warnings only: on a box with the EZ tools, the volume's
        # empty SYSTEM hive gives shimcache a warning of its own
        ssh = [w for w in st.get("warnings") or [] if "ProgramData/ssh/" in w]
        return ssh, [s for _, _, s in client.all("case-")], root

    return run


def test_the_scan_status_names_each_files_unread_lines(scan, capfd):
    warnings, docs, _ = scan({LOG: MIXED, "ProgramData/ssh/logs/z-other.log": OTHER})
    assert len([d for d in docs if "ssh.event_type" in d]) == 3
    assert warnings == [f"WKS01: {UNREAD_1}; {UNREAD_2}"]
    assert f"  WKS01: ssh: {UNREAD_1}; {UNREAD_2}" in capfd.readouterr().err.splitlines()


def test_with_no_time_zone_each_ssh_log_is_named_not_indexed(scan):
    warnings, docs, root = scan({LOG: WIN32}, tz=None)
    assert [d for d in docs if "ssh.event_type" in d] == []
    assert warnings == [f"WKS01: 1 file(s) not indexed; not indexed: {root / LOG}: {NO_ZONE}"]


BIG = "9" * 4301  # past Python's int-string limit (4,300 digits)
GOOD_1 = "4120 2021-03-23 16:50:12.345 Accepted password for alice from 10.0.0.5 port 50123 ssh2"
GOOD_2 = "4188 2021-03-23 16:51:02.001 Failed password for bob from 203.0.113.9 port 50200 ssh2"


MALLORY = "Accepted password for mallory from 10.0.0.9 port {port} ssh2"


@pytest.mark.parametrize(
    "tz,bad",
    [
        (NY, f"{BIG} 2021-03-23 16:50:13.000 " + MALLORY.format(port=1)),
        (NY, "4120 2021-03-23 16:50:13.000 " + MALLORY.format(port=BIG)),
        (NY, f"2021-03-23 16:50:13 sshd: Failed password for mallory from 10.0.0.9 port {BIG}"),
        ("Asia/Tokyo", "4120 0001-01-01 00:00:00.000 " + MALLORY.format(port=1)),
        (NY, "4120 9999-12-31 23:00:00.000 " + MALLORY.format(port=1)),
    ],
    ids=["pid", "port-win32", "port-sshd-format", "year-0001-tokyo", "year-9999-new-york"],
)
def test_a_line_that_cant_be_read_is_counted_unread_and_the_rest_are_kept(parse, tz, bad):
    """However a line fails (a pid or port no int can hold, a time UTC can't
    hold), it is counted unread and the file's other lines are indexed."""
    res, docs, notes = parse({LOG: f"{GOOD_1}\n{bad}\n{GOOD_2}\n"}, tz=tz)
    assert sorted(d["user.name"] for _, d in docs) == ["alice", "bob"]
    assert res == (2, 1, 0)
    assert notes == [f"{LOG}: 1 of 3 line(s) not in a known sshd log format, not indexed"]


# --------------------------------------------------------------------------
# A log that can't be read is named, and the scan's other logs are indexed

LOGS = "ProgramData/ssh/logs"
CAROL = "4300 2021-03-23 17:00:00.000 Accepted password for carol from 10.0.0.7 port 50300 ssh2"
THREE = {
    f"{LOGS}/a.log": f"{GOOD_1}\n",
    f"{LOGS}/b.log": f"{GOOD_2}\n",
    f"{LOGS}/c.log": f"{CAROL}\n",
}


class _FailsOnRead:
    """A log that opens, then fails on read (a disk error)."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _fail(self, *a):
        raise OSError(errno.EIO, os.strerror(errno.EIO), str(self.path))

    __iter__ = __next__ = read = readline = readlines = _fail


def make_unreadable(how, root, monkeypatch) -> str:
    """Make the middle log, b.log, unreadable; the error it gives."""
    bad = root / LOGS / "b.log"
    if how == "mode 000":
        bad.chmod(0)
        return f"[Errno 13] Permission denied: '{bad}'"
    real = open
    monkeypatch.setattr(
        parse_ssh,
        "open",
        lambda path, *a, **kw: _FailsOnRead(path) if Path(path) == bad else real(path, *a, **kw),
        raising=False,
    )
    return f"[Errno 5] {os.strerror(errno.EIO)}: '{bad}'"


UNREADABLE = [
    pytest.param("mode 000", marks=pytest.mark.skipif(os.geteuid() == 0, reason="root reads it")),
    "EIO on read",
]


@pytest.mark.parametrize("how", UNREADABLE)
def test_an_unreadable_log_is_named_and_the_others_are_parsed(parse, tmp_path, monkeypatch, how):
    root = tmp_path / "WKS01"
    write(root, THREE)
    err = make_unreadable(how, root, monkeypatch)
    res, docs, notes = parse({})
    assert sorted(d["user.name"] for _, d in docs) == ["alice", "carol"]
    assert res == (2, 0, 0)  # named, never counted as a skip
    assert notes == [f"not indexed: {root / LOGS / 'b.log'}: couldn't be read ({err})"]


@pytest.mark.parametrize("how", UNREADABLE)
def test_the_scan_status_names_an_unreadable_log(scan, monkeypatch, how):
    errs = []
    warnings, docs, root = scan(THREE, prepare=lambda root: errs.append(
        make_unreadable(how, root, monkeypatch)))  # fmt: skip
    assert sorted(d["user.name"] for d in docs if "ssh.event_type" in d) == ["alice", "carol"]
    bad = root / LOGS / "b.log"
    assert warnings == [
        f"WKS01: 1 file(s) not indexed; not indexed: {bad}: couldn't be read ({errs[0]})"
    ]


def test_a_scan_of_readable_logs_is_unchanged(scan):
    warnings, docs, _ = scan(THREE)
    assert sorted(d["user.name"] for d in docs if "ssh.event_type" in d) == [
        "alice",
        "bob",
        "carol",
    ]
    assert warnings == []
