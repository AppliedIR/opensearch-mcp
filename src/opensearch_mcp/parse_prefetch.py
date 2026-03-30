"""Prefetch parsing — wintools-first (PECmd), Plaso fallback."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch


def parse_prefetch(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int]:
    """Parse prefetch files. Returns (count_indexed, count_bulk_failed).

    Strategy: wintools-first (PECmd on Windows), Plaso fallback.
    PECmd produces richer output than Plaso's prefetch parser.
    """
    from opensearch_mcp.wintools import wintools_available

    if wintools_available():
        try:
            return _parse_prefetch_wintools(
                prefetch_dir,
                client,
                index_name,
                hostname,
                ingest_audit_id=ingest_audit_id,
                pipeline_version=pipeline_version,
                vss_id=vss_id,
            )
        except Exception as e:
            print(f"  prefetch: PECmd failed ({e}), trying Plaso...", file=sys.stderr)

    try:
        return _parse_prefetch_plaso(
            prefetch_dir,
            client,
            index_name,
            hostname,
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
        )
    except subprocess.CalledProcessError as e:
        print(f"  prefetch: Plaso failed ({e})", file=sys.stderr)
        return 0, 0


def _parse_prefetch_wintools(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int]:
    """Parse prefetch via PECmd on Windows (wintools-mcp)."""
    from opensearch_mcp.parse_csv import ingest_csv
    from opensearch_mcp.wintools import run_tool_and_get_csv

    csv_files = run_tool_and_get_csv(
        tool_binary="PECmd.exe",
        input_flag="-d",
        evidence_path=str(prefetch_dir),
        purpose="Parse prefetch files for execution history",
    )

    if not csv_files:
        raise RuntimeError("PECmd produced no CSV output")

    total_count = 0
    total_failed = 0
    for csv_file in csv_files:
        count, _sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name=index_name,
            hostname=hostname,
            source_file=str(prefetch_dir),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
        )
        total_count += count
        total_failed += bf

    return total_count, total_failed


def _parse_prefetch_plaso(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int]:
    """Parse prefetch via Plaso prefetch parser."""
    from opensearch_mcp.parse_plaso import parse_prefetch as _plaso_parse_prefetch

    return _plaso_parse_prefetch(
        prefetch_dir=prefetch_dir,
        client=client,
        index_name=index_name,
        hostname=hostname,
        ingest_audit_id=ingest_audit_id,
        pipeline_version=pipeline_version,
        vss_id=vss_id,
    )
