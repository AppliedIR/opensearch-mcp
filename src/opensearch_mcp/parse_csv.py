"""Ingest EZ Tools CSV output into OpenSearch with native schema."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk


def _detect_encoding(path: Path) -> str:
    """Detect CSV encoding from BOM.

    PowerShell 5.1 Export-Csv outputs UTF-16LE with BOM. Use "utf-16"
    codec (not "utf-16-le") which auto-detects endianness AND strips
    the BOM. The "utf-16-le" codec leaves \\ufeff prepended to the
    first column name, breaking csv.DictReader lookups.
    """
    with open(path, "rb") as f:
        bom = f.read(4)
    if bom[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    return "utf-8-sig"


# Fields containing per-run volatile data (temp dir paths) or VSS metadata.
# Excluded from content hash to ensure dedup stability across re-ingests.
_VOLATILE_KEYS = {"PluginDetailFile", "SourceFile", "vhir.vss_id"}


def _doc_id(
    index_name: str,
    row: dict,
    natural_key: str | None = None,
    volatile_keys: set[str] | None = None,
) -> str:
    """Generate deterministic ID for dedup on re-ingest.

    If natural_key is provided (e.g., MFT 4-field key), use it directly.
    Falls back to content hash if any natural key part is empty.
    volatile_keys are excluded from content hash (temp dir paths, etc.).

    ORDERING: natural key check MUST precede volatile key stripping
    (VSS MFT dedup depends on this — vhir.vss_id is in _VOLATILE_KEYS
    but used as 5th natural key component for MFT when VSS is active).
    """
    if natural_key:
        key_parts = [row.get(k, "") for k in natural_key.split(":")]
        if all(key_parts):
            return hashlib.sha256(f"{index_name}:{':'.join(key_parts)}".encode()).hexdigest()[:20]
    if volatile_keys:
        stable = {k: v for k, v in row.items() if k not in volatile_keys}
    else:
        stable = row
    content = json.dumps(stable, sort_keys=True)
    return hashlib.sha256(f"{index_name}:{content}".encode()).hexdigest()[:20]


def ingest_csv(
    csv_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    table_name: str = "",
    natural_key: str | None = None,
    time_field: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Read CSV, bulk index each row as a document.

    Returns (count_indexed, count_skipped, count_bulk_failed).
    count_skipped = rows dropped by time range filter.
    """
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []
    replacements_logged = False

    encoding = _detect_encoding(csv_path)

    with open(csv_path, encoding=encoding, errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Log if replacement chars detected
            if not replacements_logged and "\ufffd" in str(row):
                print(
                    f"WARNING: Replacement chars in {csv_path.name} — "
                    f"binary data decoded with errors='replace'",
                    file=sys.stderr,
                )
                replacements_logged = True

            # Time range filter
            if time_field and (time_from or time_to):
                ts_str = row.get(time_field, "")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except ValueError:
                        ts = None
                    if ts:
                        if time_from and ts < time_from:
                            skipped += 1
                            continue
                        if time_to and ts > time_to:
                            skipped += 1
                            continue

            row["host.name"] = hostname
            if table_name:
                row["vhir.table"] = table_name

            # VSS: for natural key tools (MFT), inject vss_id BEFORE _doc_id
            # so it becomes part of the natural key. For content-hash tools,
            # vhir.vss_id is in _VOLATILE_KEYS and stripped from the hash.
            if vss_id:
                row["vhir.vss_id"] = vss_id

            # Compute dedup ID BEFORE adding provenance fields.
            # Provenance differs across re-ingests (different source_file),
            # but evidence content is the same — ID must be stable.
            # Also strip volatile fields that change per-run (temp dir paths).
            _id = _doc_id(index_name, row, natural_key, volatile_keys=_VOLATILE_KEYS)

            # Provenance fields (added after ID computation)
            if source_file:
                row["vhir.source_file"] = source_file
            if ingest_audit_id:
                row["vhir.ingest_audit_id"] = ingest_audit_id
            if pipeline_version:
                row["pipeline_version"] = pipeline_version

            actions.append({"_index": index_name, "_id": _id, "_source": row})

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
