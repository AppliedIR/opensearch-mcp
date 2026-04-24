"""Generic JSON/JSONL ingest into OpenSearch."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk
from opensearch_mcp.parse_csv import _doc_id
from opensearch_mcp.paths import auto_detect_time_field

_JSON_VOLATILE = {
    "host.name",
    "pipeline_version",
    "@timestamp",
    "vhir.source_file",
    "vhir.ingest_audit_id",
    "vhir.parse_method",
}


def _detect_json_format(path: Path) -> str:
    """Detect: 'jsonl', 'json_array', 'json_single', or 'unknown'.

    Format matrix:
      - jsonl       — each line is a complete JSON object (NDJSON)
      - json_array  — whole file is a JSON array (either inline or
                      pretty-printed starting with a bare `[` on line 1)
      - json_single — whole file is ONE pretty-printed JSON object.
                      Covers client_info.json / collection_context.json
                      from Velociraptor and any other producer that
                      pretty-prints a single object (UAT 2026-04-24).
      - unknown     — file cannot be classified; caller rejects it

    `json_single` is detected by a full-file parse fallback when line 1
    is a bare `{`. That fallback is size-capped (200MB) for the same
    reason json_array is — streaming isn't possible on a bare object.
    """
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line == "[":
                return "json_array"
            if line == "{":
                # Pretty-printed single-object JSON. Confirm by full-
                # file parse; otherwise a malformed file would slip
                # through.
                try:
                    size = path.stat().st_size
                    if size > 200_000_000:
                        # Too large to hold in memory; caller will
                        # reject and log — consistent with json_array
                        # treatment.
                        return "unknown"
                    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        return "json_single"
                    if isinstance(data, list):
                        return "json_array"
                except (json.JSONDecodeError, OSError):
                    pass
                return "unknown"
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    return "jsonl"
                if isinstance(obj, list):
                    return "json_array"
            except json.JSONDecodeError:
                pass
            return "unknown"
    return "unknown"


def _iter_json_records(path: Path, fmt: str):
    """Yield dicts from JSON/JSONL file."""
    if fmt == "jsonl":
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    print(
                        f"WARNING: Malformed JSON at {path.name}:{lineno}",
                        file=sys.stderr,
                    )
    elif fmt == "json_array":
        file_size = path.stat().st_size
        if file_size > 200_000_000:
            raise ValueError(
                f"JSON array file too large ({file_size // 1_000_000}MB). "
                "Convert to JSONL format for streaming ingest."
            )
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
        if isinstance(data, list):
            yield from data
        elif isinstance(data, dict):
            for _key, val in data.items():
                if isinstance(val, list):
                    yield from val
                    break
    elif fmt == "json_single":
        # Single pretty-printed JSON object — yield as one record.
        # Size cap was already enforced in _detect_json_format.
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
        if isinstance(data, dict):
            yield data


def ingest_json(
    path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    time_field: str | None = None,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    batch_size: int = 1000,
) -> tuple[int, int, int, int]:
    """Ingest JSON/JSONL. Returns (indexed, skipped, bulk_failed, host_renamed)."""
    fmt = _detect_json_format(path)
    if fmt == "unknown":
        raise ValueError(f"Cannot detect JSON format in {path.name}")

    count = skipped = bulk_failed = host_renamed = 0
    actions: list[dict] = []
    ts_field = time_field

    for record in _iter_json_records(path, fmt):
        if ts_field is None and not time_field:
            ts_field = auto_detect_time_field(record)

        if ts_field and ts_field != "@timestamp" and record.get(ts_field):
            val = record[ts_field]
            if isinstance(val, (int, float)):
                if val > 1e12:
                    val = val / 1000.0
                record["@timestamp"] = datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
            else:
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

        # Resolve field conflicts: source data with 'host' (string) conflicts
        # with 'host.name' (object.keyword). Rename source field before provenance.
        if "host" in record and not isinstance(record["host"], dict):
            record["source_host"] = record.pop("host")
            host_renamed += 1
        # Same for _source (reserved by OpenSearch/tshark -T ek)
        if "_source" in record and isinstance(record["_source"], dict):
            inner = record.pop("_source")
            record.update(inner)

        doc_id = _doc_id(index_name, record, volatile_keys=_JSON_VOLATILE)

        # Per spec Rev 5 Fix C: prefer a per-doc hostname from the
        # shared priority list (Velociraptor "Hostname" + nested
        # "ClientInfo.Hostname", Windows "ComputerName", Kansa "Host",
        # etc.). Multi-host JSON sources (Velociraptor server exports,
        # log-forwarder dumps) stamp per-doc correctly instead of
        # inheriting the single ingest-level hostname.
        from opensearch_mcp.hostname import extract_host_from_record

        per_doc_host = extract_host_from_record(record)
        record["host.name"] = per_doc_host or hostname
        record["vhir.parse_method"] = "json-ingest"
        if source_file:
            record["vhir.source_file"] = source_file
        if ingest_audit_id:
            record["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            record["pipeline_version"] = pipeline_version

        actions.append({"_index": index_name, "_id": doc_id, "_source": record})
        if len(actions) >= batch_size:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, skipped, bulk_failed, host_renamed
