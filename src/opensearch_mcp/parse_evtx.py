"""Parse .evtx files with pyevtx-rs and index into OpenSearch."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from evtx import PyEvtxParser
from opensearchpy import OpenSearch

from opensearch_mcp import __version__
from opensearch_mcp.bulk import flush_bulk
from opensearch_mcp.normalize import normalize_event

_PIPELINE_VERSION = f"opensearch-mcp-{__version__}"


def _resolve_cached(host_dict, raw: str) -> str | None:
    """Per-batch resolve memoization. host_dict carries a `._resolve_cache`
    dict initialized on first call. Reset across parse_and_index calls by
    reattaching a fresh cache on the dict instance.
    """
    cache = getattr(host_dict, "_resolve_cache", None)
    if cache is None:
        cache = {}
        host_dict._resolve_cache = cache
    if raw in cache:
        return cache[raw]
    val = host_dict.resolve(raw)
    cache[raw] = val
    return val


def parse_and_index(
    evtx_path: Path,
    client: OpenSearch,
    index_name: str,
    source_file: str = "",
    ingest_audit_id: str = "",
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    reduced_ids: set[int] | None = None,
    vss_id: str = "",
    host_dict=None,
) -> tuple[int, int, int]:
    """Parse evtx file and bulk index into OpenSearch.

    Returns (count_indexed, count_skipped, count_bulk_failed).
    """
    parser = PyEvtxParser(str(evtx_path))
    actions: list[dict] = []
    count = 0
    skipped = 0
    bulk_failed = 0

    # L4: per-call cache reset so unbounded growth across many files is
    # bounded by per-call unique-hostname cardinality (typically <100).
    if host_dict is not None and hasattr(host_dict, "_resolve_cache"):
        host_dict._resolve_cache = {}

    for record in parser.records_json():
        try:
            data = json.loads(record["data"])
        except (json.JSONDecodeError, KeyError, RuntimeError):
            skipped += 1
            continue

        doc = normalize_event(data)

        # host.id stamping (v1 host-identity).
        # normalize_event already wrote host.name from system.Computer.
        # Resolve via case dict; on miss, stamp host.id = raw (parser
        # resolve-miss policy).
        raw_host = doc.get("host.name")
        if raw_host:
            if host_dict is not None:
                resolved = _resolve_cached(host_dict, raw_host)
                doc["host.id"] = resolved if resolved else raw_host
            else:
                doc["host.id"] = raw_host

        # Time range filter (before ID computation — filtered docs don't need IDs)
        if time_from or time_to:
            try:
                ts = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                ts = None
            if ts:
                if time_from and ts < time_from:
                    skipped += 1
                    continue
                if time_to and ts > time_to:
                    skipped += 1
                    continue

        # Reduced mode filter
        if reduced_ids:
            if doc.get("event.code") not in reduced_ids:
                skipped += 1
                continue

        # Deterministic ID: source_file + event_record_id.
        # NOT content hash — Windows can log identical events with
        # different record IDs (all are real evidence, must be preserved).
        # Re-ingest from the SAME file deduplicates (same record IDs).
        # Re-ingest from a DIFFERENT file (e.g., KAPE vs disk image)
        # adds new docs (different source_file = different IDs).
        record_id = record.get("event_record_id", "")
        id_input = f"{index_name}:{source_file}:{record_id}"
        doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]

        # Provenance fields — injected after ID computation
        doc["pipeline_version"] = _PIPELINE_VERSION
        if source_file:
            doc["vhir.source_file"] = source_file
        if ingest_audit_id:
            doc["vhir.ingest_audit_id"] = ingest_audit_id
        if vss_id:
            doc["vhir.vss_id"] = vss_id
        doc["vhir.parse_method"] = "pyevtx-rs"

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
