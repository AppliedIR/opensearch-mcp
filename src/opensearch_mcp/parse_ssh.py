"""Parse OpenSSH text logs on Windows."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

_SSH_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+[\d:.]+)\s+sshd[:\[]\s*(.+)")
_AUTH_ACCEPTED = re.compile(r"Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")
_AUTH_FAILED = re.compile(r"Failed\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")


def parse_ssh_log(
    ssh_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Parse sshd.log files — extract auth events."""
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    for log_file in sorted(ssh_dir.rglob("*.log")):
        with open(log_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                doc: dict = {
                    "host.name": hostname,
                    "vhir.source_file": str(log_file),
                }

                ts_match = _SSH_LINE.match(line)
                if not ts_match:
                    continue
                # Convert "2023-01-17 14:30:00.000" to ISO 8601
                doc["@timestamp"] = ts_match.group(1).strip().replace(" ", "T") + "Z"
                message = ts_match.group(2)

                # Time range filter
                if time_from or time_to:
                    try:
                        ts = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
                        if time_from and ts < time_from:
                            continue
                        if time_to and ts > time_to:
                            continue
                    except ValueError:
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

                id_input = f"{index_name}:{log_file}:{doc['@timestamp']}:{message[:100]}"
                doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
                actions.append({"_index": index_name, "_id": doc_hash, "_source": doc})

                if len(actions) >= 1000:
                    flushed, bf = flush_bulk(client, actions)
                    count += flushed
                    bulk_failed += bf
                    actions = []

    if actions:
        flushed, bf = flush_bulk(client, actions)
        count += flushed
        bulk_failed += bf

    return count, skipped, bulk_failed
