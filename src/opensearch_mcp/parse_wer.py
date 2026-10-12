"""Parse Windows Error Reporting crash reports."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp import ops
from opensearch_mcp.bulk import flush_bulk


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def parse_wer_file(file_path: Path) -> dict:
    """Parse a single Report.wer file. @timestamp is its EventTime when that
    reads as a FILETIME; otherwise unset (parse_wer_dir uses the file's mtime)."""
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
            elif key == "EventTime" and (when := _filetime(value)):
                doc["@timestamp"] = when
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

    return doc


def _filetime(value: str) -> str | None:
    """EventTime, a FILETIME (UTC, 100 ns since 1601), as UTC ISO; None when
    it isn't one or falls outside 1990 to a day from now."""
    try:
        when = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value) // 10)
    except (ValueError, OverflowError):
        return None
    earliest = datetime(1990, 1, 1, tzinfo=timezone.utc)
    latest = datetime.now(timezone.utc) + timedelta(days=1)
    return when.isoformat() if earliest <= when <= latest else None


def parse_wer_dir(
    wer_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    volume_root: Path | None = None,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    host_dict=None,
    notes: list[str] | None = None,
) -> tuple[int, int, int]:
    """Parse all Report.wer files in directory tree."""
    count = 0
    skipped = 0
    bulk_failed = 0
    by_mtime = 0  # reports with no readable EventTime
    actions: list[dict] = []

    for wer_file in sorted(wer_dir.rglob("Report.wer")):
        try:
            doc = parse_wer_file(wer_file)
            by_mt = not doc.get("@timestamp")
            if by_mt:  # no readable EventTime: the file's mtime, counted in a note
                mtime = wer_file.stat().st_mtime
                doc["@timestamp"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except OSError as e:  # unreadable: named, never an ordinary skip
            ops.not_indexed(notes, wer_file, ops.Unreadable(str(e)))
            continue
        except Exception:
            skipped += 1
            continue
        try:
            step = ops.file_marker(wer_file)  # its step, before its records
        except ops.NoEntry as e:
            ops.not_indexed(notes, wer_file, e)
            continue
        by_mtime += by_mt

        from opensearch_mcp.paths import relative_evidence_path

        rel = relative_evidence_path(wer_file, volume_root) if volume_root else str(wer_file)
        doc["host.name"] = hostname
        if hostname:
            if host_dict is not None:
                _resolved = host_dict.resolve(hostname)
                doc["host.id"] = _resolved if _resolved else hostname
            else:
                doc["host.id"] = hostname
        doc["vhir.source_file"] = rel
        if ingest_audit_id:
            doc["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            doc["pipeline_version"] = pipeline_version
        doc["vhir.parse_method"] = "wer-parser"
        if vss_id:
            doc["vhir.vss_id"] = vss_id
        # The file's bytes too: a rebuilt machine can have a different file at the same path.
        id_input = f"{index_name}:{rel}:{_file_sha256(wer_file)}"
        doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
        actions.append({"_index": index_name, "_id": doc_hash, "_source": doc, **step})

        if len(actions) >= 100:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    if by_mtime and notes is not None:
        notes.append(
            f"{by_mtime} WER report(s) have no readable EventTime: "
            "@timestamp is the file's modified time"
        )
    return count, skipped, bulk_failed
