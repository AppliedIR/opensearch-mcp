"""SRUM parsing — wintools-first (SrumECmd), Plaso fallback."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch


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
) -> tuple[int, int, str]:
    """Parse SRUM database. Returns (count_indexed, count_bulk_failed, note).

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
            )
            return cnt, bf, ""  # wintools succeeded — no note
        except Exception as e:
            print(f"  srum: SrumECmd failed ({e}), trying Plaso...", file=sys.stderr)
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                mark_wintools_down()

    try:
        cnt, bf = _parse_srum_plaso(
            srum_path,
            client,
            index_name,
            hostname,
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
            source_file=source_file,
        )
        return cnt, bf, _fallback_note  # Plaso succeeded with reduced fidelity
    except subprocess.CalledProcessError:
        print(
            "  srum: skipped — dirty database, needs Windows workstation\n"
            f"  NOTE: {_fallback_note}",
            file=sys.stderr,
        )
        return 0, 0, _fallback_note


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
) -> tuple[int, int]:
    """Parse SRUM via SrumECmd on Windows (wintools-mcp).

    Copies SRUDB.dat to writable [cases] share — SrumECmd's ManagedEsent
    needs write access for dirty ESE database recovery.
    """
    import yaml

    from opensearch_mcp.parse_csv import ingest_csv
    from opensearch_mcp.paths import vhir_dir
    from opensearch_mcp.wintools import run_tool_and_get_csv

    # Copy SRUM to writable [cases] share for ESE recovery
    srum_workdir = vhir_dir() / "cases" / case_id / "extractions" / "srum" / hostname
    srum_workdir.mkdir(parents=True, exist_ok=True)
    work_copy = srum_workdir / "SRUDB.dat"
    shutil.copy2(srum_path, work_copy)

    # Also copy SRU log files if present (needed for full recovery)
    sru_dir = srum_path.parent
    for log_file in sru_dir.glob("SRU*.log"):
        shutil.copy2(log_file, srum_workdir / log_file.name)

    # Convert Linux path to Windows UNC path for SrumECmd
    samba_yaml = vhir_dir() / "samba.yaml"
    sift_host = "sift"
    if samba_yaml.is_file():
        doc = yaml.safe_load(samba_yaml.read_text()) or {}
        sift_host = doc.get("sift_hostname", "sift")
    rel_path = f"extractions\\srum\\{hostname}\\SRUDB.dat"
    unc_path = f"\\\\{sift_host}\\cases\\{rel_path}"

    csv_files = run_tool_and_get_csv(
        tool_binary="SrumECmd.exe",
        input_flag="-f",
        evidence_path=unc_path,
        purpose="Parse SRUM database for resource usage monitoring",
    )

    if not csv_files:
        raise RuntimeError("SrumECmd produced no CSV output")

    total_count = 0
    total_failed = 0
    for csv_file in csv_files:
        count, _sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name=index_name,
            hostname=hostname,
            source_file=source_file or str(srum_path),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
            parse_method="SrumECmd",
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
    )
