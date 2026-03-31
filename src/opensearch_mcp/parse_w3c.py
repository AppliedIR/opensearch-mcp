"""Parse W3C Extended Log Format (IIS, HTTPERR, Windows Firewall)."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from dateutil import tz as dateutil_tz
from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

# Map W3C field names to ECS equivalents for GeoIP enrichment
_ECS_IP_REMAP = {
    "c-ip": "source.ip",
    "s-ip": "destination.ip",
    "src-ip": "source.ip",
    "dst-ip": "destination.ip",
}


def parse_w3c_log(
    file_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    timestamp_is_utc: bool = True,
    system_timezone: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    parse_method: str = "",
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Parse W3C log file and bulk index.

    Returns (count_indexed, count_skipped, count_bulk_failed).
    """
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []
    fields: list[str] | None = None

    tz_info = None
    if not timestamp_is_utc and system_timezone:
        tz_info = dateutil_tz.gettz(system_timezone)

    line_number = 0
    with open(file_path, encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line_number += 1
            if line.startswith("#Fields:"):
                fields = line[8:].strip().split()
                continue
            if line.startswith("#") or not line.strip():
                continue
            if not fields:
                continue

            values = line.strip().split()
            if len(values) != len(fields):
                skipped += 1
                continue
            row = dict(zip(fields, values))

            # Construct timestamp
            date_val = row.pop("date", "")
            time_val = row.pop("time", "")
            if date_val and time_val:
                if timestamp_is_utc:
                    row["@timestamp"] = f"{date_val}T{time_val}Z"
                elif tz_info:
                    try:
                        naive = datetime.strptime(f"{date_val} {time_val}", "%Y-%m-%d %H:%M:%S")
                        aware = naive.replace(tzinfo=tz_info)
                        row["@timestamp"] = aware.astimezone(dateutil_tz.UTC).isoformat()
                    except ValueError:
                        row["@timestamp"] = f"{date_val}T{time_val}"
                else:
                    # Timezone unknown — skip entry (unreliable timestamp)
                    skipped += 1
                    continue

            # Time range filter
            if time_from or time_to:
                ts_str = row.get("@timestamp", "")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts.tzinfo is None:
                            from datetime import timezone as _tz

                            ts = ts.replace(tzinfo=_tz.utc)
                        if time_from and ts < time_from:
                            skipped += 1
                            continue
                        if time_to and ts > time_to:
                            skipped += 1
                            continue
                    except (ValueError, TypeError):
                        pass

            # Replace W3C dash placeholders and strip None values
            row = {k: v for k, v in row.items() if v != "-" and v is not None}

            # Map W3C IP fields to ECS names for GeoIP enrichment
            for w3c_name, ecs_name in _ECS_IP_REMAP.items():
                if w3c_name in row:
                    row[ecs_name] = row[w3c_name]

            # Deterministic ID — computed BEFORE provenance injection
            # Line number ensures uniqueness for high-volume IIS logs
            # (multiple requests in same second from same IP to same URI)
            id_parts = [
                index_name,
                source_file,
                str(line_number),
                row.get("@timestamp", ""),
                row.get("source.ip", row.get("c-ip", "")),
                row.get("cs-uri-stem", row.get("dst-port", "")),
                row.get("cs-uri-query", ""),
                row.get("s-port", ""),
                row.get("dst-ip", row.get("destination.ip", "")),
                row.get("action", ""),
            ]
            id_str = ":".join(str(p) for p in id_parts)
            doc_hash = hashlib.sha256(id_str.encode()).hexdigest()[:20]

            # Provenance (after ID computation)
            row["host.name"] = hostname
            if source_file:
                row["vhir.source_file"] = source_file
            if ingest_audit_id:
                row["vhir.ingest_audit_id"] = ingest_audit_id
            if pipeline_version:
                row["pipeline_version"] = pipeline_version
            if parse_method:
                row["vhir.parse_method"] = parse_method
            if vss_id:
                row["vhir.vss_id"] = vss_id

            actions.append({"_index": index_name, "_id": doc_hash, "_source": row})

            if len(actions) >= 1000:
                flushed, failed = flush_bulk(client, actions)
                count += flushed
                bulk_failed += failed
                actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, skipped, bulk_failed
