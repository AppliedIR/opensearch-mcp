"""Vhir plugin registration for opensearch-mcp commands."""

from __future__ import annotations

import argparse


def register(subparsers, registered: set) -> None:
    """Register opensearch-mcp commands with vhir CLI."""
    if "ingest" not in registered:
        p = subparsers.add_parser("ingest", help="Ingest evidence into OpenSearch")
        p.add_argument("path", help="Path to evidence directory or archive")
        p.add_argument("--hostname", help="Override hostname (required for flat directories)")
        p.add_argument("--case", help="Case ID (reads ~/.vhir/active_case if omitted)")
        p.add_argument("--password", help="Archive password")
        p.add_argument("--from", dest="time_from", help="Start date (ISO)")
        p.add_argument("--to", dest="time_to", help="End date (ISO)")
        p.add_argument("--all-logs", action="store_true", help="Parse all evtx files")
        p.add_argument("--reduced-ids", action="store_true", help="Filter to high-value Event IDs")
        p.add_argument(
            "--reduced", action="store_true", dest="reduced_ids", help=argparse.SUPPRESS
        )
        p.add_argument("--source-timezone", help="Evidence system's local timezone")
        p.add_argument("--include", help="Artifact types (comma-separated)")
        p.add_argument("--exclude", help="Artifact types (comma-separated)")
        p.add_argument("--full", action="store_true", help="Include all tiers")
        p.add_argument("--config", help="YAML config file")
        p.add_argument("--vss", action="store_true", help="Include volume shadow copies")
        p.add_argument("--parallel", type=int, default=4, help=argparse.SUPPRESS)
        p.add_argument("--yes", action="store_true", help="Skip confirmation")
        p.add_argument(
            "--skip-triage",
            action="store_true",
            help="Skip post-ingest triage baseline enrichment",
        )
        p.add_argument(
            "--no-hayabusa",
            action="store_true",
            help="Skip Hayabusa detection after evtx ingest",
        )
        p.set_defaults(func=_cmd_ingest)
        registered.add("ingest")

    if "ingest-memory" not in registered:
        p = subparsers.add_parser("ingest-memory", help="Parse memory image with Volatility 3")
        p.add_argument("path", help="Path to memory image")
        p.add_argument(
            "--hostname",
            required=True,
            help="Source hostname (required)",
        )
        p.add_argument("--case", help="Case ID")
        p.add_argument(
            "--tier",
            type=int,
            default=1,
            choices=[1, 2, 3],
            help="Analysis depth (1=fast, 2=default, 3=deep)",
        )
        p.add_argument("--plugins", help="Specific plugins (comma-separated)")
        p.add_argument(
            "--timeout",
            type=int,
            default=3600,
            help="Per-plugin timeout in seconds",
        )
        p.add_argument("--yes", action="store_true", help="Skip confirmation")
        p.set_defaults(func=_cmd_ingest_memory)
        registered.add("ingest-memory")

    if "ingest-json" not in registered:
        p = subparsers.add_parser("ingest-json", help="Ingest JSON/JSONL files")
        p.add_argument("path", help="JSON/JSONL file or directory")
        p.add_argument("--hostname", required=True)
        p.add_argument("--index-suffix")
        p.add_argument("--time-field")
        p.add_argument("--case")
        p.add_argument("--from", dest="time_from")
        p.add_argument("--to", dest="time_to")
        p.add_argument("--batch-size", type=int, default=1000)
        p.add_argument("--dry-run", action="store_true")
        p.set_defaults(func=_cmd_ingest_json)
        registered.add("ingest-json")

    if "ingest-delimited" not in registered:
        p = subparsers.add_parser("ingest-delimited", help="Ingest CSV/TSV/Zeek/bodyfile")
        p.add_argument("path", help="Delimited file or directory")
        p.add_argument("--hostname")
        p.add_argument("--recursive", action="store_true", help="Treat subdirectories as hosts")
        p.add_argument("--index-suffix")
        p.add_argument("--time-field")
        p.add_argument("--delimiter")
        p.add_argument("--format", choices=["csv", "tsv", "zeek", "bodyfile"])
        p.add_argument("--case")
        p.add_argument("--from", dest="time_from")
        p.add_argument("--to", dest="time_to")
        p.add_argument("--batch-size", type=int, default=1000)
        p.add_argument("--dry-run", action="store_true")
        p.set_defaults(func=_cmd_ingest_delimited)
        registered.add("ingest-delimited")

    if "enrich-intel" not in registered:
        p = subparsers.add_parser(
            "enrich-intel", help="Enrich indexed data with OpenCTI threat intel"
        )
        p.add_argument("--case", help="Case ID (default: active case)")
        p.add_argument(
            "--dry-run",
            action="store_true",
            help="Extract IOCs and show counts without lookup",
        )
        p.add_argument(
            "--force",
            action="store_true",
            help="Re-enrich even if already enriched",
        )
        p.set_defaults(func=_cmd_enrich_intel)
        registered.add("enrich-intel")

    if "ingest-accesslog" not in registered:
        p = subparsers.add_parser("ingest-accesslog", help="Ingest Apache/Nginx access logs")
        p.add_argument("path", help="Access log file or directory")
        p.add_argument("--hostname", required=True)
        p.add_argument("--index-suffix", default="accesslog")
        p.add_argument("--case")
        p.add_argument("--from", dest="time_from")
        p.add_argument("--to", dest="time_to")
        p.add_argument("--dry-run", action="store_true")
        p.set_defaults(func=_cmd_ingest_accesslog)
        registered.add("ingest-accesslog")


def _cmd_ingest(args, identity) -> None:
    """Delegate to opensearch_mcp ingest logic."""
    from opensearch_mcp.ingest_cli import cmd_ingest

    cmd_ingest(args, examiner=identity.get("examiner", "unknown"))


def _cmd_ingest_memory(args, identity) -> None:
    """Delegate to opensearch_mcp memory ingest logic."""
    from opensearch_mcp.ingest_cli import cmd_ingest_memory

    cmd_ingest_memory(args, examiner=identity.get("examiner", "unknown"))


def _cmd_ingest_json(args, identity) -> None:
    from opensearch_mcp.ingest_cli import cmd_ingest_json

    cmd_ingest_json(args, examiner=identity.get("examiner", "unknown"))


def _cmd_ingest_delimited(args, identity) -> None:
    from opensearch_mcp.ingest_cli import cmd_ingest_delimited

    cmd_ingest_delimited(args, examiner=identity.get("examiner", "unknown"))


def _cmd_ingest_accesslog(args, identity) -> None:
    from opensearch_mcp.ingest_cli import cmd_ingest_accesslog

    cmd_ingest_accesslog(args, examiner=identity.get("examiner", "unknown"))


def _cmd_enrich_intel(args, identity) -> None:
    from opensearch_mcp.ingest_cli import cmd_enrich_intel

    cmd_enrich_intel(args, examiner=identity.get("examiner", "unknown"))
