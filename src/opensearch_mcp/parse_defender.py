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
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
) -> tuple[int, int, int]:
    """Parse all MPLog files in directory. Returns (indexed, skipped, bulk_failed)."""
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    for log_file in sorted(mplog_dir.glob("MPLog-*.log")):
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
                    doc["@timestamp"] = current_ts

                # Time range filter
                if current_ts and (time_from or time_to):
                    try:
                        ts = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
                        if time_from and ts < time_from:
                            continue
                        if time_to and ts > time_to:
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
                    doc["defender.event_type"] = "other"

                doc["defender.raw_line"] = line_body
                doc["vhir.source_file"] = str(log_file)
                if ingest_audit_id:
                    doc["vhir.ingest_audit_id"] = ingest_audit_id
                if pipeline_version:
                    doc["pipeline_version"] = pipeline_version
                doc["vhir.parse_method"] = "defender-mplog"

                id_input = f"{index_name}:{log_file}:{current_ts or ''}:{line_body[:100]}"
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
