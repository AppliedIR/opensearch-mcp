"""Parse Windows Error Reporting crash reports."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk


def parse_wer_file(file_path: Path) -> dict:
    """Parse a single Report.wer file."""
    doc: dict = {}
    sig: dict = {}

    # Try utf-16 first (most WER files), fall back to utf-8
    encoding = "utf-16"
    try:
        with open(file_path, encoding="utf-16") as f:
            f.read(1)
    except (UnicodeDecodeError, UnicodeError):
        encoding = "utf-8-sig"
    with open(file_path, encoding=encoding, errors="replace") as f:
        for line in f:
            line = line.strip()
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            if key == "EventType":
                doc["wer.event_type"] = value
            elif key.startswith("Sig[") and ".Name" in key:
                idx = key.split("[")[1].split("]")[0]
                sig[f"name_{idx}"] = value
            elif key.startswith("Sig[") and ".Value" in key:
                idx = key.split("[")[1].split("]")[0]
                sig[f"value_{idx}"] = value
            elif key.startswith("DynamicSig[") and ".Name" in key:
                idx = key.split("[")[1].split("]")[0]
                sig[f"dyn_name_{idx}"] = value
            elif key.startswith("DynamicSig[") and ".Value" in key:
                idx = key.split("[")[1].split("]")[0]
                sig[f"dyn_value_{idx}"] = value

    doc["process.name"] = sig.get("value_0", "")
    doc["wer.app_version"] = sig.get("value_1", "")
    doc["wer.exception_code"] = sig.get("value_6", "")
    doc["wer.os_version"] = sig.get("dyn_value_1", "")
    doc["wer.report_dir"] = file_path.parent.name

    # Full text for searchability
    doc["wer.full_text"] = file_path.read_text(encoding=encoding, errors="replace")

    # Timestamp from file mtime (preserved on NTFS read-only mount)
    mtime = file_path.stat().st_mtime
    doc["@timestamp"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    return doc


def parse_wer_dir(
    wer_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Parse all Report.wer files in directory tree."""
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    for wer_file in sorted(wer_dir.rglob("Report.wer")):
        try:
            doc = parse_wer_file(wer_file)
        except Exception:
            skipped += 1
            continue

        doc["host.name"] = hostname
        doc["vhir.source_file"] = str(wer_file)
        if ingest_audit_id:
            doc["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            doc["pipeline_version"] = pipeline_version
        doc["vhir.parse_method"] = "wer-parser"
        if vss_id:
            doc["vhir.vss_id"] = vss_id

        id_input = f"{index_name}:{wer_file}"
        doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
        actions.append({"_index": index_name, "_id": doc_hash, "_source": doc})

        if len(actions) >= 100:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, skipped, bulk_failed
