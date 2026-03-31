"""EZ Tool wrappers: run tool → collect CSV → call ingest_csv."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.parse_csv import ingest_csv


@dataclass
class ToolConfig:
    """Configuration for an EZ tool."""

    cli_name: str  # canonical name for --include/--exclude
    binary: str  # executable name
    tier: int  # 1=always, 2=default, 3=opt-in
    index_suffix: str  # e.g., "amcache" → case-{id}-amcache-{host}
    time_field: str | None  # primary timestamp column for --from/--to
    natural_key: str | None  # for MFT dedup; None = content hash
    multi_csv: bool  # glob("*.csv") for multi-output tools


TOOLS: dict[str, ToolConfig] = {
    "amcache": ToolConfig(
        cli_name="amcache",
        binary="AmcacheParser",
        tier=1,
        index_suffix="amcache",
        time_field="FileKeyLastWriteTimestamp",  # VERIFY
        natural_key=None,
        multi_csv=True,
    ),
    "shimcache": ToolConfig(
        cli_name="shimcache",
        binary="AppCompatCacheParser",
        tier=1,
        index_suffix="shimcache",
        time_field="LastModifiedTimeUTC",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "registry": ToolConfig(
        cli_name="registry",
        binary="RECmd",
        tier=1,
        index_suffix="registry",
        time_field="LastWriteTimestamp",  # VERIFY
        natural_key=None,
        multi_csv=True,
    ),
    "shellbags": ToolConfig(
        cli_name="shellbags",
        binary="SBECmd",
        tier=1,
        index_suffix="shellbags",
        time_field="LastInteracted",  # Verified by Test agent
        natural_key=None,
        multi_csv=False,
    ),
    "jumplists": ToolConfig(
        cli_name="jumplists",
        binary="JLECmd",
        tier=2,
        index_suffix="jumplists",
        time_field="LastModified",  # VERIFY
        natural_key=None,
        multi_csv=False,
    ),
    "lnk": ToolConfig(
        cli_name="lnk",
        binary="LECmd",
        tier=2,
        index_suffix="lnk",
        time_field="TargetModified",  # VERIFY
        natural_key=None,
        multi_csv=False,
    ),
    "recyclebin": ToolConfig(
        cli_name="recyclebin",
        binary="RBCmd",
        tier=2,
        index_suffix="recyclebin",
        time_field="DeletedOn",  # VERIFY
        natural_key=None,
        multi_csv=False,
    ),
    "mft": ToolConfig(
        cli_name="mft",
        binary="MFTECmd",
        tier=3,
        index_suffix="mft",
        time_field="Created0x10",  # VERIFY
        natural_key="EntryNumber:SequenceNumber:FileName:ParentEntryNumber",
        multi_csv=False,
    ),
    "usn": ToolConfig(
        cli_name="usn",
        binary="MFTECmd",
        tier=3,
        index_suffix="usn",
        time_field="UpdateTimestamp",  # VERIFY
        natural_key=None,
        multi_csv=False,
    ),
    "timeline": ToolConfig(
        cli_name="timeline",
        binary="WxTCmd",
        tier=3,
        index_suffix="timeline",
        time_field="LastModifiedTime",  # VERIFY
        natural_key=None,
        multi_csv=False,
    ),
    "evtxecmd": ToolConfig(
        cli_name="evtxecmd",
        binary="",  # CSV-only — no binary to run
        tier=1,
        index_suffix="evtx",  # same index as pyevtx-rs output
        time_field="TimeCreated",
        natural_key=None,
        multi_csv=False,
    ),
}

# RECmd batch file path
_RECMD_BATCH = "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb"


_TOOL_TIMEOUT = 7200  # 2 hours — generous for MFT/large artifacts


def _run_tool(cmd: list[str], label: str) -> None:
    """Run an EZ tool subprocess, raising on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed (exit {result.returncode}): {result.stderr[:500]}")


def run_and_ingest(
    tool_name: str,
    artifact_path: Path,
    client: OpenSearch,
    case_id: str,
    hostname: str,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    time_from=None,
    time_to=None,
    vss_id: str = "",
    natural_key_override: str | None = None,
) -> tuple[int, int, int]:
    """Run an EZ tool against an artifact and ingest the CSV output.

    Returns (count_indexed, count_skipped, count_bulk_failed).
    natural_key_override: if set, overrides cfg.natural_key (used for VSS MFT).
    """
    cfg = TOOLS.get(tool_name)
    if cfg is None:
        raise ValueError(f"Unknown tool: {tool_name}")

    from opensearch_mcp.ingest import _sanitize_index_component

    index_name = (
        f"case-{_sanitize_index_component(case_id)}"
        f"-{cfg.index_suffix}"
        f"-{_sanitize_index_component(hostname)}"
    )
    tmpdir = tempfile.mkdtemp(prefix=f"vhir-{tool_name}-")
    natural_key = natural_key_override if natural_key_override is not None else cfg.natural_key

    try:
        # Build command
        cmd = _build_command(cfg, tool_name, artifact_path, tmpdir)
        _run_tool(cmd, cfg.binary)

        # Collect CSV output — warn if tool exited 0 but produced nothing
        csv_files = sorted(Path(tmpdir).glob("*.csv"))

        if not csv_files:
            import sys

            print(
                f"WARNING: {cfg.binary} completed but produced no CSV output",
                file=sys.stderr,
            )
            return 0, 0, 0

        total_count = 0
        total_skipped = 0
        total_bulk_failed = 0

        for csv_file in csv_files:
            table_name = ""
            if cfg.multi_csv:
                # EZ tools prefix with timestamp: 20260329224802_Amcache_DeviceContainers
                # Strip the timestamp prefix (digits + underscore) to get meaningful name
                stem = csv_file.stem
                parts = stem.split("_", 1)
                if len(parts) > 1 and parts[0].isdigit():
                    table_name = parts[1]
                else:
                    table_name = stem
            count, sk, bf = ingest_csv(
                csv_path=csv_file,
                client=client,
                index_name=index_name,
                hostname=hostname,
                source_file=source_file or str(artifact_path),
                ingest_audit_id=ingest_audit_id,
                pipeline_version=pipeline_version,
                table_name=table_name,
                natural_key=natural_key,
                time_field=cfg.time_field,
                time_from=time_from,
                time_to=time_to,
                vss_id=vss_id,
                parse_method=cfg.cli_name,
            )
            total_count += count
            total_skipped += sk
            total_bulk_failed += bf

        return total_count, total_skipped, total_bulk_failed

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_command(cfg: ToolConfig, tool_name: str, artifact_path: Path, tmpdir: str) -> list[str]:
    """Build the command line for an EZ tool."""
    binary = cfg.binary

    if tool_name == "amcache":
        # --nl: skip transaction log check (dirty hives from live collection)
        return [binary, "-f", str(artifact_path), "--csv", tmpdir, "--nl"]

    if tool_name == "shimcache":
        # --nl: skip transaction log check (dirty hives from live collection)
        return [
            binary,
            "-f",
            str(artifact_path),
            "--csv",
            tmpdir,
            "--csvf",
            "shimcache.csv",
            "--nl",
        ]

    if tool_name == "registry":
        # RECmd -d expects a DIRECTORY, not a file. Discovery returns
        # individual hive file paths (SYSTEM, SOFTWARE, etc.) — use
        # the parent directory (Windows/System32/config/).
        reg_dir = artifact_path if artifact_path.is_dir() else artifact_path.parent
        # --nl: skip transaction log check (dirty hives from live collection)
        return [
            binary,
            "-d",
            str(reg_dir),
            "--csv",
            tmpdir,
            "--nl",
            "--bn",
            _RECMD_BATCH,
        ]

    if tool_name == "shellbags":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir]

    if tool_name == "jumplists":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir]

    if tool_name == "lnk":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir, "--all"]

    if tool_name == "recyclebin":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir]

    if tool_name == "mft":
        return [binary, "-f", str(artifact_path), "--csv", tmpdir, "--csvf", "mft.csv"]

    if tool_name == "usn":
        # USN Journal needs the $MFT for resolution — check for it
        mft_path = artifact_path.parent / "$MFT"
        cmd = [binary, "-f", str(artifact_path), "--csv", tmpdir, "--csvf", "usn.csv"]
        if mft_path.is_file():
            cmd.extend(["-m", str(mft_path)])
        return cmd

    if tool_name == "timeline":
        return [binary, "-f", str(artifact_path), "--csv", tmpdir]

    raise ValueError(f"No command builder for tool: {tool_name}")


def get_active_tools(
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    full: bool = False,
) -> list[ToolConfig]:
    """Get the list of tools to run based on tier and include/exclude flags.

    full=True includes all tiers (1+2+3), equivalent to --full flag.
    """
    active = []
    for name, cfg in TOOLS.items():
        # CSV-only tools (no binary) are excluded from scan mode
        if not cfg.binary:
            continue
        # --full: include all tiers
        if full:
            if exclude and name in exclude:
                continue
            active.append(cfg)
            continue
        # Tier 3 only if explicitly included
        if cfg.tier == 3 and (not include or name not in include):
            continue
        # Tier 1-2 unless explicitly excluded
        if exclude and name in exclude:
            continue
        # If --include specified, only run those + tier 1
        if include and name not in include and cfg.tier != 1:
            continue
        active.append(cfg)
    return active
