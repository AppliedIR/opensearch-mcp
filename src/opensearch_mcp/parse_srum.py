"""SRUM parsing — wintools-first (SrumECmd), Plaso fallback."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import counting_present
from opensearch_mcp.results import PARSER_COMPLETED, PARSER_FAILED, PARSER_REDUCED


def parse_srum(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    case_id: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
    volume_root: Path | None = None,
) -> tuple[int, int, str, str, int]:
    """Parse SRUM database. Returns (count_indexed, count_bulk_failed, note,
    outcome, rows): outcome is one of results.PARSER_COMPLETED/REDUCED/FAILED,
    and rows are what its final attempt produced, records already in the case
    included.

    Strategy: wintools-first (SrumECmd on Windows), Plaso fallback.
    SRUDB.dat from KAPE triage is frequently dirty/locked — SrumECmd
    handles this (built-in repair), Plaso's esedb parser does not.
    """
    from opensearch_mcp.wintools import mark_wintools_down, wintools_available

    _fallback_note = (
        "srum: parsed with Plaso fallback (reduced fidelity). "
        "Provision wintools-mcp with SrumECmd for reliable SRUM analysis."
    )

    if wintools_available():
        try:
            with counting_present() as kept:  # this attempt's records already in the case
                cnt, bf = _parse_srum_wintools(
                    srum_path,
                    client,
                    index_name,
                    hostname,
                    case_id=case_id,
                    ingest_audit_id=ingest_audit_id,
                    pipeline_version=pipeline_version,
                    vss_id=vss_id,
                    source_file=source_file,
                    host_dict=host_dict,
                )
            # wintools succeeded — no note
            return cnt, bf, "", PARSER_COMPLETED, cnt + bf + kept[0]
        except Exception as e:
            print(f"  srum: SrumECmd failed ({e}), trying Plaso...", file=sys.stderr)
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                mark_wintools_down()

    try:
        with counting_present() as kept:  # this attempt's records already in the case
            cnt, bf = _parse_srum_plaso(
                srum_path,
                client,
                index_name,
                hostname,
                ingest_audit_id=ingest_audit_id,
                pipeline_version=pipeline_version,
                vss_id=vss_id,
                source_file=source_file,
                host_dict=host_dict,
                volume_root=volume_root,
            )
        # Plaso succeeded with reduced fidelity
        return cnt, bf, _fallback_note, PARSER_REDUCED, cnt + bf + kept[0]
    except subprocess.CalledProcessError:
        print(
            "  srum: skipped — dirty database, needs Windows workstation\n"
            f"  NOTE: {_fallback_note}",
            file=sys.stderr,
        )
        return 0, 0, _fallback_note, PARSER_FAILED, 0


def _parse_srum_wintools(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    case_id: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int]:
    """Parse SRUM via SrumECmd on Windows (wintools-mcp).

    Stages SRUDB.dat + SRU log files to the case extractions directory
    (on the SMB share). SrumECmd's ManagedEsent needs write access for
    dirty ESE database recovery.
    """
    from sift_common import resolve_case_dir

    from opensearch_mcp.parse_csv import ingest_csv
    from opensearch_mcp.wintools import run_tool_and_get_csv

    case_dir_str = resolve_case_dir()
    if not case_dir_str:
        raise RuntimeError("No active case directory")
    case_dir = Path(case_dir_str)

    from opensearch_mcp import ops

    # Stage SRUM to case extractions (on the SMB share) for ESE recovery
    srum_workdir = case_dir / "extractions" / "srum" / hostname
    srum_workdir.mkdir(parents=True, exist_ok=True)
    copied = [(srum_path, srum_workdir / "SRUDB.dat")]
    shutil.copy2(srum_path, srum_workdir / "SRUDB.dat")

    # Also copy SRU log files if present (needed for full recovery)
    sru_dir = srum_path.parent
    for log_file in sru_dir.glob("SRU*.log"):
        shutil.copy2(log_file, srum_workdir / log_file.name)
        copied.append((log_file, srum_workdir / log_file.name))
    produced = [ops.staging_step(copied, "SrumECmd.exe")]  # then the wintools call's

    # Pass the staged path — run_tool_and_get_csv handles UNC conversion
    csv_files = run_tool_and_get_csv(
        tool_binary="SrumECmd.exe",
        input_flag="-f",
        evidence_path=str(srum_workdir / "SRUDB.dat"),
        purpose="Parse SRUM database for resource usage monitoring",
        hostname=hostname,
        produced_by=produced,
    )

    if not csv_files:
        raise RuntimeError("SrumECmd produced no CSV output")

    total_count = 0
    total_failed = 0
    for csv_file in csv_files:
        with ops.step(csv_file, produced_by=list(produced)) as sid:
            count, _sk, bf = ingest_csv(
                csv_path=csv_file,
                client=client,
                index_name=index_name,
                hostname=hostname,
                source_file=source_file or str(srum_path),
                ingest_audit_id=sid,
                pipeline_version=pipeline_version,
                vss_id=vss_id,
                parse_method="SrumECmd",
                host_dict=host_dict,
            )
        total_count += count
        total_failed += bf

    return total_count, total_failed


def _parse_srum_plaso(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
    volume_root: Path | None = None,
) -> tuple[int, int]:
    """Parse SRUM via Plaso esedb/srum parser."""
    from opensearch_mcp.parse_plaso import parse_srum as _plaso_srum

    return _plaso_srum(
        srum_path=srum_path,
        client=client,
        index_name=index_name,
        hostname=hostname,
        ingest_audit_id=ingest_audit_id,
        pipeline_version=pipeline_version,
        vss_id=vss_id,
        source_file=source_file,
        host_dict=host_dict,
        volume_root=volume_root,
    )
