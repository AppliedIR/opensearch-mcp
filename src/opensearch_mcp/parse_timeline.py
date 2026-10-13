"""Windows 10 Timeline (ActivitiesCache.db) via WxTCmd on wintools-mcp.

Each database is staged with its SQLite -wal and -shm companions (it runs in
WAL mode: rows still in the WAL are in no other file), and the staged FILE is
passed to WxTCmd's -f; a folder there reads nothing. There's no fallback: with
wintools-mcp unavailable the run says so for each database.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import counting_present
from opensearch_mcp.results import PARSER_COMPLETED

NO_WINTOOLS = (
    "WxTCmd runs through wintools-mcp, which isn't available: the Windows "
    "Timeline (ActivitiesCache.db) isn't parsed. Provision wintools-mcp with WxTCmd."
)


def _staging(case_dir: Path, hostname: str, db: Path) -> Path:
    """extractions/timeline/<host>/<account>/<its folder>/: one per database
    (an account can have several, e.g. L.<name> and a device id)."""
    parts = db.parts
    lower = [p.lower() for p in parts]
    # the profile folder after the LAST "users" (a mount point can hold one too)
    at = max((i for i, p in enumerate(lower[:-1]) if p == "users"), default=None)
    account = parts[at + 1] if at is not None else "unknown"
    return case_dir / "extractions" / "timeline" / hostname / account / db.parent.name


def parse_timeline(
    db_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int, str, str, int]:
    """(indexed, bulk_failed, note, outcome, rows), as parse_srum returns it."""
    from sift_common import resolve_case_dir

    from opensearch_mcp import ops
    from opensearch_mcp.parse_csv import ingest_csv
    from opensearch_mcp.wintools import (
        mark_wintools_down,
        run_tool_and_get_csv,
        wintools_available,
    )

    if not wintools_available():
        raise RuntimeError(NO_WINTOOLS)
    case_dir_str = resolve_case_dir()
    if not case_dir_str:
        raise RuntimeError("No active case directory")
    workdir = _staging(Path(case_dir_str), hostname, db_path)
    workdir.mkdir(parents=True, exist_ok=True)
    copied = []
    for f in [db_path, *(db_path.with_name(db_path.name + s) for s in ("-wal", "-shm"))]:
        if f.is_file():
            shutil.copy2(f, workdir / f.name)
            copied.append((f, workdir / f.name))
    produced = [ops.staging_step(copied, "WxTCmd.exe")]
    try:
        csv_files = run_tool_and_get_csv(
            tool_binary="WxTCmd.exe",
            input_flag="-f",
            evidence_path=str(workdir / db_path.name),
            purpose="Parse the Windows 10 Timeline (ActivitiesCache.db)",
            hostname=hostname,
            produced_by=produced,
        )
    except Exception as e:
        if "connection" in str(e).lower() or "timeout" in str(e).lower():
            mark_wintools_down()
        raise
    if not csv_files:
        raise RuntimeError("WxTCmd produced no CSV output")

    source = source_file or str(db_path)
    total = failed = 0
    with counting_present() as kept:  # this run's records already in the case
        for csv_file in csv_files:
            with ops.step(csv_file, produced_by=list(produced)) as sid:
                count, _sk, bf = ingest_csv(
                    csv_path=csv_file,
                    client=client,
                    index_name=index_name,
                    hostname=hostname,
                    source_file=source,
                    id_source=source,  # the database's path is in the id
                    time_field="LastModifiedTime",
                    ingest_audit_id=sid,
                    pipeline_version=pipeline_version,
                    vss_id=vss_id,
                    parse_method="WxTCmd",
                    host_dict=host_dict,
                )
            total += count
            failed += bf
    return total, failed, "", PARSER_COMPLETED, total + failed + kept[0]
