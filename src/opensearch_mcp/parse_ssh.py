"""Parse OpenSSH text logs on Windows."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

_SSH_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+[\d:.]+)\s+sshd[:\[]\s*(.+)")
# Win32-OpenSSH's own log (ProgramData/ssh/logs): "<pid> <YYYY-MM-DD> <HH:MM:SS.mmm> <message>",
# in local time. A pid is a DWORD, at most 10 digits
_WIN32_LINE = re.compile(r"^(\d{1,10})\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.+)")
_AUTH_ACCEPTED = re.compile(r"Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")
# "Failed password for invalid user X from ..." is a failed logon by X too
_AUTH_FAILED = re.compile(
    r"Failed\s+(\w+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
NO_ZONE = "the system timezone is unknown, so local times can't be read as UTC"


def _read_lines(log_file: Path, notes: list[str] | None):
    """The file's lines, read as they're parsed. A file that can't be opened
    or read is named; one that fails part way keeps the lines read before,
    and says how far it got. Only the read is guarded: an error parsing or
    sending a line isn't caught here."""
    from opensearch_mcp import ops

    read = 0
    try:
        with open(log_file, encoding="utf-8-sig", errors="replace") as f:
            for read, line in enumerate(f, 1):  # how far it got, if it fails
                yield line
    except OSError as e:
        why = (
            ops.Unreadable(str(e))
            if not read
            else ops.NoEntry(
                f"couldn't be read past line {read} ({e}); the lines before it were read"
            )
        )
        ops.not_indexed(notes, log_file, why)


def parse_ssh_log(
    ssh_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    system_timezone: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    volume_root: Path | None = None,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    host_dict=None,
    notes: list[str] | None = None,
) -> tuple[int, int, int]:
    """Parse sshd.log files — extract auth events.

    SSH timestamps are local system time. Requires system_timezone for
    UTC conversion. With the timezone unknown nothing is indexed, and each
    file is named not indexed in `notes`: wrong timestamps are not
    acceptable evidence. A line in no known format, or whose time doesn't
    parse, is counted in `skipped` and named per file in `notes`.
    """
    from dateutil.tz import gettz, tzutc

    tz_info = gettz(system_timezone) if system_timezone else None
    if not tz_info:
        from opensearch_mcp import ops

        for log_file in sorted(ssh_dir.rglob("*.log")):
            ops.not_indexed(notes, log_file, ops.NoEntry(NO_ZONE))
        return 0, 0, 0

    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    for log_file in sorted(ssh_dir.rglob("*.log")):
        from opensearch_mcp import ops
        from opensearch_mcp.paths import relative_evidence_path

        try:
            step = ops.file_marker(log_file)  # its step, before its records
        except ops.NoEntry as e:
            ops.not_indexed(notes, log_file, e)
            continue

        rel = relative_evidence_path(log_file, volume_root) if volume_root else str(log_file)
        lines = unread = 0
        for line in _read_lines(log_file, notes):  # one that can't be read is named
            line = line.strip()
            if not line:
                continue
            lines += 1

            doc: dict = {
                "host.name": hostname,
                "vhir.source_file": rel,
            }
            if hostname:
                if host_dict is not None:
                    _resolved = host_dict.resolve(hostname)
                    doc["host.id"] = _resolved if _resolved else hostname
                else:
                    doc["host.id"] = hostname

            # any line that can't be read (a field no int or time can hold) is
            # counted unread; it never stops the rest of the file
            try:
                pid = None
                ts_match = _SSH_LINE.match(line)
                if ts_match:
                    raw_ts, message = ts_match.group(1).strip(), ts_match.group(2)
                else:
                    win32 = _WIN32_LINE.match(line)
                    if not win32:
                        unread += 1
                        continue
                    pid, raw_ts, message = win32.group(1), win32.group(2), win32.group(3)
                # Convert local timestamp to UTC
                try:
                    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in raw_ts else "%Y-%m-%d %H:%M:%S"
                    naive = datetime.strptime(raw_ts, fmt)
                    aware = naive.replace(tzinfo=tz_info)
                    doc["@timestamp"] = (
                        aware.astimezone(tzutc()).isoformat().replace("+00:00", "Z")
                    )
                except ValueError:
                    unread += 1
                    continue
                if pid is not None:
                    doc["process.pid"] = int(pid)

                # Time range filter
                if time_from or time_to:
                    try:
                        ts = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
                        if time_from and ts < time_from:
                            skipped += 1
                            continue
                        if time_to and ts > time_to:
                            skipped += 1
                            continue
                    except (ValueError, TypeError):
                        pass

                accepted = _AUTH_ACCEPTED.search(message)
                failed = _AUTH_FAILED.search(message)

                if accepted:
                    doc["ssh.event_type"] = "auth_accepted"
                    doc["ssh.auth_method"] = accepted.group(1)
                    doc["user.name"] = accepted.group(2)
                    doc["source.ip"] = accepted.group(3)
                    doc["source.port"] = int(accepted.group(4))
                elif failed:
                    doc["ssh.event_type"] = "auth_failed"
                    doc["ssh.auth_method"] = failed.group(1)
                    doc["user.name"] = failed.group(2)
                    doc["source.ip"] = failed.group(3)
                    doc["source.port"] = int(failed.group(4))
                else:
                    doc["ssh.event_type"] = "other"

                doc["ssh.raw_line"] = message
                if ingest_audit_id:
                    doc["vhir.ingest_audit_id"] = ingest_audit_id
                if pipeline_version:
                    doc["pipeline_version"] = pipeline_version
                doc["vhir.parse_method"] = "ssh-parser"
                if vss_id:
                    doc["vhir.vss_id"] = vss_id

                from opensearch_mcp.paths import relative_evidence_path

                rel = (
                    relative_evidence_path(log_file, volume_root) if volume_root else str(log_file)
                )
                # a Win32 line's pid is in its id: two sessions can log one text at once
                hashed = message if pid is None else f"{pid} {message}"
                msg_hash = hashlib.sha256(hashed.encode()).hexdigest()[:16]
                id_input = f"{index_name}:{rel}:{doc['@timestamp']}:{msg_hash}"
                doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
            except Exception:  # noqa: BLE001 - counted, and named in the note
                unread += 1
                continue
            actions.append({"_index": index_name, "_id": doc_hash, "_source": doc, **step})

            if len(actions) >= 1000:
                flushed, bf = flush_bulk(client, actions)
                count += flushed
                bulk_failed += bf
                actions = []

        if unread:
            skipped += unread
            if notes is not None:
                notes.append(
                    f"{rel}: {unread} of {lines} line(s) not in a known sshd log format, "
                    "not indexed"
                )

    if actions:
        flushed, bf = flush_bulk(client, actions)
        count += flushed
        bulk_failed += bf

    return count, skipped, bulk_failed
