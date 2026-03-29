"""CLI for ingesting forensic evidence into OpenSearch."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sift_common.audit import AuditWriter

from opensearch_mcp.client import get_client
from opensearch_mcp.ingest import discover, ingest
from opensearch_mcp.manifest import sha256_file
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.tools import TOOLS

_ACTIVE_CASE_FILE = Path.home() / ".vhir" / "active_case"
_VHIR_CONFIG = Path.home() / ".vhir" / "config.yaml"


def _resolve_case_id(args_case: str | None) -> str:
    if args_case:
        return args_case
    if _ACTIVE_CASE_FILE.exists():
        raw = _ACTIVE_CASE_FILE.read_text().strip()
        if raw:
            return Path(raw).name
    print("Error: No case ID. Use --case or run 'vhir case init' first.", file=sys.stderr)
    sys.exit(1)


def _resolve_examiner(args_examiner: str | None) -> str:
    if args_examiner:
        return args_examiner
    if _VHIR_CONFIG.exists():
        try:
            config = yaml.safe_load(_VHIR_CONFIG.read_text()) or {}
            if config.get("examiner"):
                return config["examiner"]
        except Exception:
            pass
    import os

    return os.environ.get("USER", "unknown")


def _parse_date(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_set(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {v.strip().lower() for v in value.split(",")}


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> None:
    """Scan a directory for artifacts, run EZ tools, index."""
    root = Path(args.path)
    if not root.is_dir():
        print(f"Error: {root} is not a directory.", file=sys.stderr)
        sys.exit(1)

    case_id = _resolve_case_id(getattr(args, "case", None))
    _resolve_examiner(getattr(args, "examiner", None))  # validate early
    time_from = _parse_date(args.time_from) if getattr(args, "time_from", None) else None
    time_to = _parse_date(args.time_to) if getattr(args, "time_to", None) else None
    include = _parse_set(getattr(args, "include", None))
    exclude = _parse_set(getattr(args, "exclude", None))
    hostname = getattr(args, "hostname", None)

    # Discover
    print("Scanning...")
    hosts = discover(root, hostname=hostname)

    if not hosts:
        if not hostname:
            print(
                "Error: No host directories found. Use --hostname for flat evidence directories.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Error: No Windows artifacts found in {root}", file=sys.stderr)
        sys.exit(1)

    # Show summary
    for host in hosts:
        artifact_names = sorted({a[0] for a in host.artifacts})
        evtx_note = ""
        if host.evtx_dir:
            evtx_count = sum(1 for f in host.evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
            evtx_note = f"{evtx_count} evtx, "
        arts = ", ".join(artifact_names)
        print(f"  {host.hostname}: {evtx_note}{arts}")

    if not getattr(args, "yes", False):
        try:
            answer = input(f"\nIngest {len(hosts)} host(s)? [y/N] ")
            if answer.lower() not in ("y", "yes"):
                print("Aborted.")
                return
        except EOFError:
            print(
                "Non-interactive mode. Use --yes to skip confirmation.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Ingest with status tracking
    import os
    import uuid

    client = get_client()
    audit = AuditWriter(mcp_name="opensearch-mcp")
    run_id = str(uuid.uuid4())

    def _cli_progress(event: str, **kw) -> None:
        if event == "host_start":
            print(f"\n{kw['hostname']}:")
        elif event == "evtx_file":
            fn = kw["filename"]
            n, t, c = kw["file_num"], kw["file_total"], kw["count"]
            print(f"  evtx [{n}/{t}] {fn}... {c:,} events")
        elif event == "evtx_done":
            idx = kw["indexed"]
            sk = kw.get("skipped", 0)
            bf = kw.get("bulk_failed", 0)
            parts = [f"{idx:,} total"]
            if sk:
                parts.append(f"{sk} skipped")
            if bf:
                parts.append(f"{bf} bulk failed")
            err = kw.get("error", "")
            if err:
                parts.append(f"ERRORS: {err}")
            print(f"  evtx: {', '.join(parts)}")
        elif event == "artifact_start":
            print(f"  {kw['artifact']}...", end=" ", flush=True)
        elif event == "artifact_done":
            idx = kw["indexed"]
            sk = kw.get("skipped", 0)
            parts = [f"{idx:,} entries"]
            if sk:
                parts.append(f"{sk} skipped")
            print(", ".join(parts))
        elif event == "artifact_failed":
            print(f"FAILED: {kw['error']}")

    result = ingest(
        hosts=hosts,
        client=client,
        audit=audit,
        case_id=case_id,
        status_pid=os.getpid(),
        status_run_id=run_id,
        include=include,
        exclude=exclude,
        time_from=time_from,
        time_to=time_to,
        on_progress=_cli_progress,
    )

    # Summary
    failed = []
    for h in result.hosts:
        for a in h.artifacts:
            if a.error:
                failed.append(f"{h.hostname}/{a.artifact}: {a.error}")
    minutes = result.elapsed_seconds / 60
    print(f"\nDone in {minutes:.1f} minutes. ", end="")
    print(f"{len(result.hosts)} host(s), {result.total_indexed:,} entries indexed.")
    if failed:
        print(f"\n{len(failed)} artifact(s) failed:")
        for fail_msg in failed:
            print(f"  {fail_msg}")


# ---------------------------------------------------------------------------
# csv subcommand
# ---------------------------------------------------------------------------


def cmd_csv(args: argparse.Namespace) -> None:
    """Ingest a pre-parsed CSV (examiner identifies the tool)."""
    tool_name = args.tool_name
    csv_path = Path(args.csv_path)

    if tool_name not in TOOLS:
        valid = ", ".join(sorted(TOOLS))
        print(f"Error: Unknown tool '{tool_name}'. Valid: {valid}", file=sys.stderr)
        sys.exit(1)
    if not csv_path.is_file():
        print(f"Error: {csv_path} is not a file.", file=sys.stderr)
        sys.exit(1)

    hostname = args.hostname
    if not hostname:
        print("Error: --hostname is required for csv subcommand.", file=sys.stderr)
        sys.exit(1)

    case_id = _resolve_case_id(getattr(args, "case", None))
    from opensearch_mcp import __version__

    cfg = TOOLS[tool_name]
    index_name = f"case-{case_id}-{cfg.index_suffix}-{hostname}".lower()

    client = get_client()
    audit = AuditWriter(mcp_name="opensearch-mcp")
    pipeline_version = f"opensearch-mcp-{__version__}"

    file_hash = sha256_file(csv_path)
    aid = audit._next_audit_id()

    print(f"Ingesting {csv_path.name} as {tool_name} → {index_name}")

    count, sk, bf = ingest_csv(
        csv_path=csv_path,
        client=client,
        index_name=index_name,
        hostname=hostname,
        source_file=str(csv_path),
        ingest_audit_id=aid,
        pipeline_version=pipeline_version,
        natural_key=cfg.natural_key,
        time_field=cfg.time_field,
    )

    audit.log(
        tool=f"ingest_csv_{tool_name}",
        audit_id=aid,
        params={"hostname": hostname, "tool": tool_name, "file": str(csv_path)},
        result_summary=f"{count} indexed"
        + (f", {sk} skipped" if sk else "")
        + (f", {bf} bulk failed" if bf else ""),
        input_files=[str(csv_path)],
        input_sha256s=[file_hash],
        source_evidence=str(csv_path),
    )

    print(f"Indexed {count:,} entries" + (f" ({sk} skipped)" if sk else ""))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="opensearch-ingest",
        description="Ingest forensic evidence into OpenSearch",
    )
    sub = parser.add_subparsers(dest="command")

    # scan subcommand
    p_scan = sub.add_parser("scan", help="Scan directory for artifacts, run EZ tools, index")
    p_scan.add_argument("path", help="Triage directory or evidence directory")
    p_scan.add_argument("--case", help="Case ID")
    p_scan.add_argument("--hostname", help="Override hostname (flat dirs)")
    p_scan.add_argument("--examiner", help="Examiner name")
    p_scan.add_argument("--from", dest="time_from", help="Start date (ISO)")
    p_scan.add_argument("--to", dest="time_to", help="End date (ISO)")
    p_scan.add_argument("--include", help="Opt-in artifact types (comma-sep)")
    p_scan.add_argument("--exclude", help="Opt-out artifact types (comma-sep)")
    p_scan.add_argument("--yes", action="store_true", help="Skip confirmation")
    p_scan.set_defaults(func=cmd_scan)

    # csv subcommand
    p_csv = sub.add_parser("csv", help="Ingest a pre-parsed CSV (examiner identifies tool)")
    p_csv.add_argument("tool_name", help=f"Tool ({', '.join(sorted(TOOLS))})")
    p_csv.add_argument("csv_path", help="Path to the CSV file")
    p_csv.add_argument("--hostname", required=True, help="Source hostname")
    p_csv.add_argument("--case", help="Case ID")
    p_csv.add_argument("--examiner", help="Examiner name")
    p_csv.set_defaults(func=cmd_csv)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
