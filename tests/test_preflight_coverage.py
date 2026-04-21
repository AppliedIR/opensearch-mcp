"""A5 lint test — every idx_ingest* MCP tool must pre-flight shard capacity.

Prevents silent regression if a future entry point is added without
wiring up the pre-flight check. The UAT incident that motivated Fix A
happened precisely because no such guard existed.
"""

from __future__ import annotations

import inspect


def test_all_ingest_entry_points_have_preflight():
    """Every idx_ingest* tool in server.py must either call
    check_shard_headroom directly, route through _launch_background
    (which calls it), or be the read-only status tool.
    """
    from opensearch_mcp import server as srv

    ingest_tools = [
        (name, obj)
        for name, obj in inspect.getmembers(srv)
        if callable(obj) and name.startswith("idx_ingest") and not name.startswith("_")
    ]
    # Status reader is exempt — it's not an ingest entry point.
    ingest_tools = [(name, obj) for name, obj in ingest_tools if name != "idx_ingest_status"]

    assert ingest_tools, "No idx_ingest* tools found — test harness wrong?"

    missing = []
    for name, obj in ingest_tools:
        try:
            src = inspect.getsource(obj)
        except (OSError, TypeError):
            continue
        if "check_shard_headroom" in src or "_launch_background" in src:
            continue
        missing.append(name)

    assert not missing, (
        f"These idx_ingest* tools are missing pre-flight shard-capacity "
        f"checks: {missing}. Every ingest entry point must call "
        f"check_shard_headroom() or route through _launch_background "
        f"(which calls it). The UAT incident that motivated Fix A was "
        f"caused by exactly this kind of silent gap."
    )


def test_cli_ingest_commands_have_preflight():
    """Every cmd_ingest* CLI function in ingest_cli.py must call
    _preflight_shard_capacity. Complements the server-side check —
    vhir CLI bypasses the MCP tools.
    """
    from opensearch_mcp import ingest_cli

    cli_cmds = [
        (name, obj)
        for name, obj in inspect.getmembers(ingest_cli)
        if callable(obj) and name.startswith("cmd_ingest")
    ]
    assert cli_cmds, "No cmd_ingest* CLI functions found"

    missing = []
    for name, obj in cli_cmds:
        try:
            src = inspect.getsource(obj)
        except (OSError, TypeError):
            continue
        if "_preflight_shard_capacity" in src:
            continue
        # cmd_ingest wraps cmd_scan internally — check cmd_scan instead
        if name == "cmd_ingest" and "cmd_scan" in src:
            try:
                scan_src = inspect.getsource(ingest_cli.cmd_scan)
                if "_preflight_shard_capacity" in scan_src:
                    continue
            except (OSError, TypeError, AttributeError):
                pass
        missing.append(name)

    assert not missing, (
        f"These cmd_ingest* CLI functions are missing pre-flight shard-capacity checks: {missing}."
    )
