"""Parse Windows Defender MPLog files."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

_TS_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(.+)")
_DETECTION_PATTERN = re.compile(r"DETECTION[_\s]*(ADD|CLEAN|DELETE).*?Name[:\s]*(.+?)(?:#|$)")
_EXCLUSION_ADD = re.compile(r"(?:Adding|Added)\s+exclusion[:\s]*(.+)", re.IGNORECASE)
_EXCLUSION_DEL = re.compile(r"(?:Removing|Removed)\s+exclusion[:\s]*(.+)", re.IGNORECASE)
_THREAT_PATTERN = re.compile(r"ThreatType[:\s]*(.+?)(?:#|\s|$)")
_FILE_PATTERN = re.compile(r"(?:file|path)[:\s]*(.+?)(?:#|\s*$)", re.IGNORECASE)


def parse_mplog(
    mplog_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    system_timezone: str | None = None,
    volume_root: Path | None = None,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Parse all MPLog files in directory. Returns (indexed, skipped, bulk_failed)."""
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    from dateutil.tz import gettz, tzutc

    from opensearch_mcp.paths import relative_evidence_path

    tz_info = gettz(system_timezone) if system_timezone else None

    for log_file in sorted(mplog_dir.glob("MPLog-*.log")):
        rel_file = relative_evidence_path(log_file, volume_root) if volume_root else str(log_file)
        current_ts = None

        with open(log_file, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                doc: dict = {"host.name": hostname}

                ts_match = _TS_PATTERN.match(line)
                if ts_match:
                    current_ts = ts_match.group(1)
                    line_body = ts_match.group(2)
                else:
                    line_body = line

                if current_ts:
                    # Convert non-UTC timestamps to UTC
                    if current_ts.endswith("Z"):
                        doc["@timestamp"] = current_ts
                    elif tz_info:
                        try:
                            naive = datetime.fromisoformat(current_ts)
                            aware = naive.replace(tzinfo=tz_info)
                            utc_ts = aware.astimezone(tzutc()).isoformat().replace("+00:00", "Z")
                            doc["@timestamp"] = utc_ts
                            current_ts = utc_ts  # use converted for filtering
                        except ValueError:
                            doc["@timestamp"] = current_ts
                    else:
                        # No timezone, no Z — skip this line (unreliable timestamp)
                        skipped += 1
                        continue

                # Time range filter
                if current_ts and (time_from or time_to):
                    try:
                        ts = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
                        if time_from and ts < time_from:
                            skipped += 1
                            continue
                        if time_to and ts > time_to:
                            skipped += 1
                            continue
                    except ValueError:
                        pass

                # Classify line
                det = _DETECTION_PATTERN.search(line_body)
                excl_add = _EXCLUSION_ADD.search(line_body)
                excl_del = _EXCLUSION_DEL.search(line_body)

                if det:
                    doc["defender.event_type"] = f"detection_{det.group(1).lower()}"
                    doc["defender.threat_name"] = det.group(2).strip()
                    threat = _THREAT_PATTERN.search(line_body)
                    if threat:
                        doc["defender.threat_type"] = threat.group(1).strip()
                    fpath = _FILE_PATTERN.search(line_body)
                    if fpath:
                        doc["file.path"] = fpath.group(1).strip()
                elif excl_add:
                    doc["defender.event_type"] = "exclusion_added"
                    doc["defender.exclusion_path"] = excl_add.group(1).strip()
                elif excl_del:
                    doc["defender.event_type"] = "exclusion_removed"
                    doc["defender.exclusion_path"] = excl_del.group(1).strip()
                else:
                    skipped += 1
                    continue  # skip noise — only index forensic events

                doc["defender.raw_line"] = line_body
                from opensearch_mcp.paths import relative_evidence_path

                doc["vhir.source_file"] = (
                    relative_evidence_path(log_file, volume_root) if volume_root else str(log_file)
                )
                if ingest_audit_id:
                    doc["vhir.ingest_audit_id"] = ingest_audit_id
                if pipeline_version:
                    doc["pipeline_version"] = pipeline_version
                doc["vhir.parse_method"] = "defender-mplog"
                if vss_id:
                    doc["vhir.vss_id"] = vss_id

                line_hash = hashlib.md5(line_body.encode()).hexdigest()
                id_input = f"{index_name}:{rel_file}:{current_ts or ''}:{line_hash}"
                doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
                actions.append({"_index": index_name, "_id": doc_hash, "_source": doc})

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
