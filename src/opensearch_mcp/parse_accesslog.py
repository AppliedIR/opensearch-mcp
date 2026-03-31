"""Apache/Nginx combined/common access log parser."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

from dateutil.parser import parse as dateutil_parse
from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

_COMBINED_RE = re.compile(
    r"^(\S+) \S+ (\S+) \[([^\]]+)\] "
    r'"(\S+) (\S+)(?: (\S+))?" (\d{3}) (\d+|-)'
    r'(?: "([^"]*)" "([^"]*)")?'
)


def _parse_access_ts(ts_str: str) -> str:
    """Parse: 25/Jan/2023:15:10:30 +0000 → ISO 8601."""
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        try:
            return dateutil_parse(ts_str).isoformat()
        except Exception:
            return ts_str


def ingest_accesslog(
    path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
) -> tuple[int, int, int]:
    """Parse and index access log. Returns (indexed, skipped, bulk_failed)."""
    count = skipped = bulk_failed = 0
    actions: list[dict] = []

    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = _COMBINED_RE.match(line)
            if not m:
                skipped += 1
                continue

            doc: dict = {
                "source.ip": m.group(1),
                "user.name": m.group(2) if m.group(2) != "-" else None,
                "@timestamp": _parse_access_ts(m.group(3)),
                "http.request.method": m.group(4),
                "url.path": m.group(5),
                "http.version": m.group(6),
                "http.response.status_code": int(m.group(7)),
                "http.response.bytes": (int(m.group(8)) if m.group(8) != "-" else None),
            }
            if m.group(9) is not None:
                ref = m.group(9)
                doc["http.request.referrer"] = ref if ref != "-" else None
            if m.group(10) is not None:
                doc["user_agent.original"] = m.group(10)

            doc = {k: v for k, v in doc.items() if v is not None}

            if (time_from or time_to) and "@timestamp" in doc:
                try:
                    ts = datetime.fromisoformat(doc["@timestamp"])
                    if time_from and ts < time_from:
                        skipped += 1
                        continue
                    if time_to and ts > time_to:
                        skipped += 1
                        continue
                except (ValueError, TypeError):
                    pass

            # Dedup: content-based key
            id_input = (
                f"{index_name}:{source_file or path.name}"
                f":{doc.get('@timestamp', '')}"
                f":{doc.get('source.ip', '')}"
                f":{doc.get('http.request.method', '')}"
                f":{doc.get('url.path', '')}"
                f":{doc.get('http.response.status_code', '')}"
                f":{doc.get('http.response.bytes', '')}"
                f":{doc.get('user_agent.original', '')}"
            )
            doc_id = hashlib.sha256(id_input.encode()).hexdigest()[:20]

            doc["host.name"] = hostname
            doc["vhir.parse_method"] = "accesslog"
            if source_file:
                doc["vhir.source_file"] = source_file
            if ingest_audit_id:
                doc["vhir.ingest_audit_id"] = ingest_audit_id
            if pipeline_version:
                doc["pipeline_version"] = pipeline_version

            actions.append({"_index": index_name, "_id": doc_id, "_source": doc})
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
