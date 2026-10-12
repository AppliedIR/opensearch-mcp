"""Generic delimited file ingest (CSV, TSV, Zeek TSV, bodyfile)."""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import ID_TIME_KEY, OLD_RID_KEY, flush_bulk
from opensearch_mcp.hostname import extract_host_from_record
from opensearch_mcp.parse_csv import _detect_encoding, _doc_id
from opensearch_mcp.paths import NO_TIME_FIELD, TIME_NOT_UNDERSTOOD, auto_detect_time_field

csv.field_size_limit(10 * 1024 * 1024)  # 10 MB — L2T CSV can have >131 KB fields

_DELIM_VOLATILE = {
    "host.name",
    "pipeline_version",
    "@timestamp",
    "vhir.source_file",
    "vhir.ingest_audit_id",
    "vhir.parse_method",
}

_BODYFILE_COLUMNS = [
    "md5",
    "name",
    "inode",
    "mode_as_string",
    "uid",
    "gid",
    "size",
    "atime",
    "mtime",
    "ctime",
    "crtime",
]

_ZEEK_NULL = {"-", "(empty)", ""}


def _detect_delimited_format(path: Path) -> dict:
    """Auto-detect format, delimiter, header style.

    After classification, verify the chosen delimiter produces a
    consistent field count across first N lines. Prose files (license
    text, READMEs, syslog) that happen to contain structured-looking
    characters get rejected as "unknown" — random commas in sentences
    parse as wildly-varying field counts, variance check fires, caller
    skips.

    Quote-aware via `csv.reader`: Hayabusa detection output and other
    heavily-quoted CSVs whose quoted fields contain inline delimiters
    now parse correctly. Pre-fix versions did raw character counts and
    silently rejected Hayabusa (89k+ hits dropped per rd01 ingest).
    Multi-line quoted fields stitch correctly because we feed the
    joined head to a single csv.reader rather than per-line counting.
    """
    encoding = _detect_encoding(path)
    with open(path, "r", encoding=encoding, errors="replace") as f:
        first_lines = []
        for line in f:
            line = line.rstrip("\n\r")
            if not line:
                continue
            first_lines.append(line)
            if len(first_lines) >= 10:
                break

    if not first_lines:
        return {"format": "unknown"}

    first = first_lines[0]
    if first.startswith("#separator") or first.startswith("#fields"):
        return {"format": "zeek", "delimiter": "\t", "header": "zeek"}

    if "|" in first:
        parts = first.split("|")
        if len(parts) == 11 and len(parts[0]) in (0, 1, 32):
            # Bodyfile: strict 11-column |-separated format. Parser-level
            # validation catches bad rows. Bypass the variance check —
            # it would pass anyway, but explicit bypass makes intent
            # clear (bodyfile is a strict schema, not a heuristic match).
            return {"format": "bodyfile", "delimiter": "|", "header": None}
        candidate = {"format": "pipe", "delimiter": "|", "header": "first_line"}
    elif first.count("\t") > 0 and first.count("\t") >= first.count(","):
        candidate = {"format": "tsv", "delimiter": "\t", "header": "first_line"}
    else:
        candidate = {"format": "csv", "delimiter": ",", "header": "first_line"}

    # Variance check — quote-aware via csv.reader. Join first N lines
    # so multi-line quoted fields reconstruct naturally; csv.reader
    # consumes them as single logical rows. Field counts (not raw
    # character counts) are what a real parser would see, which is
    # what the consistency check should be gating on.
    delim = candidate["delimiter"]
    try:
        reader = csv.reader(io.StringIO("\n".join(first_lines[:10])), delimiter=delim)
        counts = [len(row) for row in reader]
    except csv.Error:
        return {"format": "unknown"}
    if not counts or min(counts) < 2:
        return {"format": "unknown"}
    if (max(counts) - min(counts)) > max(counts) // 2:
        return {"format": "unknown"}
    return candidate


def _parse_zeek_header(path: Path) -> list[str]:
    """Extract field names from Zeek #fields header."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            if line.strip().startswith("#fields"):
                return line.strip().split("\t")[1:]
    return []


def _iter_delimited(path: Path, fmt: dict, delimiter: str | None = None):
    """Yield row dicts."""
    delim = delimiter or fmt.get("delimiter", ",")
    format_name = fmt.get("format", "csv")

    if format_name == "zeek":
        fields = _parse_zeek_header(path)
        if not fields:
            return
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                values = line.split("\t")
                if len(values) != len(fields):
                    continue
                yield {f: (None if v in _ZEEK_NULL else v) for f, v in zip(fields, values)}

    elif format_name == "bodyfile":
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) != 11:
                    continue
                row = dict(zip(_BODYFILE_COLUMNS, parts))
                for ts_col in ("atime", "mtime", "ctime", "crtime"):
                    try:
                        epoch = int(row.get(ts_col, 0) or 0)
                        if epoch > 0:
                            row[ts_col] = datetime.fromtimestamp(
                                epoch, tz=timezone.utc
                            ).isoformat()
                        else:
                            row.pop(ts_col, None)
                    except (ValueError, OSError):
                        row.pop(ts_col, None)
                yield row
    else:
        encoding = _detect_encoding(path)
        with open(path, encoding=encoding, errors="replace") as f:
            reader = csv.DictReader(f, delimiter=delim)
            for row in reader:
                yield dict(row)


# An epoch written as text (Zeek's ts, a CSV column): the integer part's width,
# leading zeros aside, says the unit (10 digits: seconds from 2001; 13: ms; 16:
# µs). Digits of any other width (20230129, 202301292357) get no @timestamp and
# are counted; zero is no time and isn't counted.
_EPOCH_TEXT = re.compile(r"(\d+)(\.\d+)?")
_EPOCH_DIVISOR = {9: 1, 10: 1, 13: 1e3, 16: 1e6}


def _epoch_text(val: str) -> str | None:
    """The UTC ISO time of a seconds, milliseconds or microseconds epoch
    written as text, or None."""
    m = _EPOCH_TEXT.fullmatch(val.strip())
    divisor = _EPOCH_DIVISOR.get(len(m.group(1).lstrip("0"))) if m else None
    if divisor is None:
        return None
    try:
        when = datetime.fromtimestamp(float(m.group(0)) / divisor, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return when.isoformat()


def _is_a_number_not_zero(val: str) -> bool:
    """Digit text that isn't zero (00000000 is no time, as 0 isn't)."""
    return float(val.strip()) != 0


# A volume of a VHD/VMDK is mounted as its nbd device's partition (nbd3p2)
_NBD_SLOT = re.compile(r"^nbd\d+(p\d+)$")


def _id_input(record: dict, id_root: Path | None) -> dict:
    """The record as its id hashes it: `EvtxFile` relative to `id_root` when
    it's under it, otherwise in full, as it always was."""
    evtx_file = record.get("EvtxFile")
    if id_root is None or not evtx_file:
        return record
    try:
        relative = Path(evtx_file).relative_to(id_root)
    except ValueError:
        return record
    parts = relative.parts
    slot = _NBD_SLOT.match(parts[0]) if parts else None
    if slot:  # a volume mounted under the nbd slot the run got: its partition alone
        relative = Path(slot.group(1), *parts[1:])
    return {**record, "EvtxFile": relative.as_posix()}


def ingest_delimited(
    path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    fmt: dict | None = None,
    delimiter: str | None = None,
    time_field: str | None = None,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    batch_size: int = 1000,
    on_progress: object = None,
    host_dict=None,
    id_root: Path | None = None,
) -> tuple[int, int, int, int]:
    """Ingest delimited file. Returns (indexed, skipped, bulk_failed, host_renamed).

    on_progress: optional callable(indexed_so_far) for status updates on large files.
    id_root: a Hayabusa run's temp directory. An `EvtxFile` under it is hashed
    relative to it, so another run of the same image or archive (in another
    temp directory) gives the same ids; the stored value is unchanged.
    """
    from opensearch_mcp.paths import validate_index_name

    idx_err = validate_index_name(index_name)
    if idx_err:
        raise ValueError(idx_err)

    if fmt is None:
        fmt = _detect_delimited_format(path)
    if fmt.get("format") == "unknown":
        raise ValueError(f"Cannot detect delimited format of {path.name}")

    format_name = fmt.get("format", "csv")
    count = skipped = bulk_failed = host_renamed = 0
    not_understood = 0  # digit-only time values of no epoch width
    actions: list[dict] = []
    ts_field = time_field
    if format_name == "bodyfile" and not ts_field:
        ts_field = "mtime"

    for record in _iter_delimited(path, fmt, delimiter):
        literal = record.get("@timestamp")  # the row's own, before a time field overwrites it
        if ts_field is None:
            ts_field = auto_detect_time_field(record)

        if ts_field and ts_field != "@timestamp" and record.get(ts_field):
            val = record[ts_field]
            if isinstance(val, (int, float)):
                if val > 1e15:
                    val = val / 1e6  # microseconds
                elif val > 1e12:
                    val = val / 1e3  # milliseconds
                record["@timestamp"] = datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
            elif isinstance(val, str) and (epoch := _epoch_text(val)):
                record["@timestamp"] = epoch
            elif isinstance(val, str) and _EPOCH_TEXT.fullmatch(val.strip()):
                # Not an epoch's width: as @timestamp OpenSearch would read
                # epoch milliseconds (20230129 → 1970). Kept in its own field.
                not_understood += _is_a_number_not_zero(val)
            else:
                # Hayabusa writes local time as "2022-11-28 18:48:24.526 +00:00",
                # a form @timestamp rejects; as UTC ISO it's accepted.
                try:
                    fmt_ = "%Y-%m-%d %H:%M:%S.%f %z"
                    val = datetime.strptime(val, fmt_).astimezone(timezone.utc).isoformat()
                except (ValueError, TypeError, OverflowError):  # out of range in UTC
                    pass
                record["@timestamp"] = val

        if (time_from or time_to) and record.get("@timestamp"):
            ts_val = record["@timestamp"]
            try:
                if isinstance(ts_val, (int, float)):
                    if ts_val > 1e12:
                        ts_val = ts_val / 1000.0
                    ts = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                else:
                    ts = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                if time_from and ts < time_from:
                    skipped += 1
                    continue
                if time_to and ts > time_to:
                    skipped += 1
                    continue
            except (ValueError, TypeError, OSError):
                pass

        # Resolve field conflicts: 'host' (string) conflicts with 'host.name' (object)
        if "host" in record and not isinstance(record["host"], dict):
            record["source_host"] = record.pop("host")
            host_renamed += 1

        id_input = _id_input(record, id_root)
        doc_id = old_rid = _doc_id(index_name, id_input, volatile_keys=_DELIM_VOLATILE)
        if literal not in (None, ""):  # rows that differ only in their own time stay apart
            stamped = {**id_input, "@timestamp": literal}
            doc_id = _doc_id(index_name, stamped, volatile_keys=_DELIM_VOLATILE - {"@timestamp"})

        # The row's machine by the shared host-column rule (Hayabusa and EvtxECmd
        # `Computer`, MDE `DeviceName`, any case of a machine-only name), else the
        # CLI hostname. A web log's `host` was renamed to source_host above.
        per_row_host = extract_host_from_record(record)
        computer = record.get("Computer")
        if isinstance(computer, str) and computer.strip() and computer.strip() == per_row_host:
            del record["Computer"]  # the chosen host, stored as host.name as before
        record["host.name"] = per_row_host or hostname
        _raw_host = record.get("host.name")
        if _raw_host:
            if host_dict is not None:
                _resolved = host_dict.resolve(_raw_host)
                record["host.id"] = _resolved if _resolved else _raw_host
            else:
                record["host.id"] = _raw_host
        record["vhir.parse_method"] = f"delimited-{format_name}"
        if source_file:
            record["vhir.source_file"] = source_file
        if ingest_audit_id:
            record["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            record["pipeline_version"] = pipeline_version

        action = {"_index": index_name, "_id": doc_id, "_source": record}
        if doc_id != old_rid:  # the id 0.6.4 gave it, and the time this one hashed
            action[OLD_RID_KEY], action[ID_TIME_KEY] = old_rid, literal
        actions.append(action)
        if len(actions) >= batch_size:
            flushed, failed = flush_bulk(client, actions, depth_limit=True)
            count += flushed
            bulk_failed += failed
            actions = []
            # Periodic progress callback for large single-file ingests
            if callable(on_progress) and count % 10000 < batch_size:
                on_progress(count)

    if actions:
        flushed, failed = flush_bulk(client, actions, depth_limit=True)
        count += flushed
        bulk_failed += failed

    if not ts_field and count and str(path.absolute()) not in NO_TIME_FIELD:
        NO_TIME_FIELD.append(str(path.absolute()))
    if not_understood:
        TIME_NOT_UNDERSTOOD.append((str(path.absolute()), ts_field, not_understood))
    return count, skipped, bulk_failed, host_renamed
