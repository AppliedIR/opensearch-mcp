"""Parse forensic artifacts with Plaso and index into OpenSearch."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk
from opensearch_mcp.parse_csv import _doc_id

# Plaso internal metadata fields — excluded from content hash for dedup stability.
_PLASO_VOLATILE_KEYS = {
    "__container_type__",
    "__type__",
    "pathspec",
    "sha256_hash",  # Plaso storage hash, not evidence hash
    "vhir.vss_id",
}


def _run_plaso(
    parser: str,
    input_path: Path,
    tmpdir: Path,
) -> Path:
    """Run log2timeline + psort, return path to JSONL output."""
    plaso_file = tmpdir / "output.plaso"
    jsonl_file = tmpdir / "output.jsonl"

    # log2timeline: --unattended prevents interactive prompts
    # NOTE: --output_time_zone is a psort flag, NOT log2timeline
    subprocess.run(
        [
            "log2timeline.py",
            "--unattended",
            "--parsers",
            parser,
            "--storage_file",
            str(plaso_file),
            str(input_path),
        ],
        check=True,
        capture_output=True,
        timeout=7200,
    )

    # psort: convert to JSONL with UTC timestamps
    subprocess.run(
        [
            "psort.py",
            "--output_time_zone",
            "UTC",
            "-o",
            "json_line",
            "-w",
            str(jsonl_file),
            str(plaso_file),
        ],
        check=True,
        capture_output=True,
        timeout=7200,
    )

    return jsonl_file


def _ingest_jsonl(
    jsonl_file: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    source_dir: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int]:
    """Index Plaso JSONL records into OpenSearch.

    Returns (count_indexed, count_bulk_failed).
    """
    count = 0
    bulk_failed = 0
    actions: list[dict] = []

    with open(jsonl_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            record["host.name"] = hostname

            # Dedup: compute ID BEFORE adding provenance fields.
            # host.name is stable (same host = same value). Plaso-native
            # fields (filename, display_name) come from evidence and are stable.
            # But ingest_audit_id, pipeline_version, and source_dir change per run.
            _id = _doc_id(index_name, record, volatile_keys=_PLASO_VOLATILE_KEYS)

            # Provenance fields (added AFTER ID computation — same pattern as
            # parse_csv.py and parse_evtx.py)
            source = record.get("filename") or record.get("display_name") or source_dir
            record["vhir.source_file"] = source
            if ingest_audit_id:
                record["vhir.ingest_audit_id"] = ingest_audit_id
            if pipeline_version:
                record["pipeline_version"] = pipeline_version
            if vss_id:
                record["vhir.vss_id"] = vss_id
            record["vhir.parse_method"] = "plaso"
            actions.append({"_index": index_name, "_id": _id, "_source": record})

            if len(actions) >= 1000:
                flushed, failed = flush_bulk(client, actions)
                count += flushed
                bulk_failed += failed
                actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, bulk_failed


def parse_prefetch(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
) -> tuple[int, int]:
    """Parse .pf files with Plaso, index into OpenSearch.

    Returns (count_indexed, count_bulk_failed).
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="vhir-plaso-prefetch-"))
    try:
        jsonl_file = _run_plaso("prefetch", prefetch_dir, tmpdir)
        return _ingest_jsonl(
            jsonl_file,
            client,
            index_name,
            hostname,
            source_dir=source_file or str(prefetch_dir),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_srum(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
) -> tuple[int, int]:
    """Parse SRUM database with Plaso, index into OpenSearch.

    The SRUM parser in Plaso is a plugin under the esedb parser.
    The correct specification is 'esedb/srum' (parser/plugin syntax).

    Returns (count_indexed, count_bulk_failed).
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="vhir-plaso-srum-"))
    try:
        jsonl_file = _run_plaso("esedb/srum", srum_path, tmpdir)
        return _ingest_jsonl(
            jsonl_file,
            client,
            index_name,
            hostname,
            source_dir=source_file or str(srum_path),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
