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
        p.set_defaults(func=_cmd_ingest)
        registered.add("ingest")


def _cmd_ingest(args, identity) -> None:
    """Delegate to opensearch_mcp ingest logic.

    vhir calls handler(args, identity). We pass both through.
    """
    from opensearch_mcp.ingest_cli import cmd_ingest

    cmd_ingest(args, examiner=identity.get("name", "unknown"))
