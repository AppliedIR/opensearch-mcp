"""Automated Volatility 3 memory image parsing.

Runs vol3 plugins as subprocesses with JSON output, indexes structured
results into OpenSearch. Tiered execution: fast plugins always, slow
plugins opt-in.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk
from opensearch_mcp.paths import sanitize_index_component

# Plugin tiers — ordered within each tier for dependency resolution
TIER_1 = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.netstat",
    "windows.svcscan",
    "windows.modules",
    "windows.registry.hivelist",
]

TIER_2 = TIER_1 + [
    "windows.dlllist",
    "windows.envars",
    "windows.getsids",
    "windows.psscan",
    "windows.ldrmodules",
    "windows.callbacks",
    "windows.ssdt",
    "windows.registry.userassist",
]

TIER_3 = TIER_2 + [
    "windows.handles",
    "windows.filescan",
    "windows.malfind",
    "windows.vadinfo",
    "windows.registry.hashdump",
    "windows.shimcachemem",
    "windows.driverscan",
    "windows.mutantscan",
    "timeliner",
]

# Natural keys per plugin (content-intrinsic, version-independent)
_NATURAL_KEYS: dict[str, list[str]] = {
    "windows.pslist": ["PID", "CreateTime"],
    "windows.pstree": ["PID", "CreateTime"],
    "windows.netscan": ["LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "PID"],
    "windows.netstat": ["LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "PID"],
    "windows.svcscan": ["Name", "PID"],
    "windows.cmdline": ["PID"],
    "windows.dlllist": ["PID", "Base", "Name"],
    "windows.handles": ["PID", "Offset(V)"],
    "windows.modules": ["Base", "Name"],
    "windows.registry.hivelist": ["Offset(V)"],
    "windows.registry.hashdump": ["User", "rid"],
}

# Primary timestamp field per plugin — mapped to @timestamp
_TIMESTAMP_FIELD: dict[str, str | None] = {
    "windows.info": None,
    "windows.pslist": "CreateTime",
    "windows.pstree": "CreateTime",
    "windows.psscan": "CreateTime",
    "windows.cmdline": None,
    "windows.netscan": "Created",
    "windows.netstat": "Created",
    "windows.svcscan": None,
    "windows.modules": None,
    "windows.registry.hivelist": None,
    "windows.dlllist": "LoadTime",
    "windows.envars": None,
    "windows.getsids": None,
    "windows.ldrmodules": None,
    "windows.callbacks": None,
    "windows.ssdt": None,
    "windows.registry.userassist": "LastWriteTime",
    "windows.handles": None,
    "windows.filescan": None,
    "windows.malfind": None,
    "windows.vadinfo": None,
    "windows.registry.hashdump": None,
    "windows.shimcachemem": "LastModified",
    "windows.driverscan": None,
    "windows.mutantscan": None,
    "timeliner": None,
}

# Handle type filtering — only index forensically relevant handle types
_HANDLE_TYPES_KEEP = {
    "File",
    "Key",
    "Mutant",
    "Event",
    "Section",
    "ALPC Port",
    "Directory",
    "SymbolicLink",
    "Thread",
    "Process",
}

_MAX_JSON_BYTES = 200 * 1024 * 1024  # 200MB

_VOL3_CMD: str | None = None


def _find_vol3() -> str:
    """Find the vol3 command. Tries vol3, vol, python3 -m volatility3."""
    global _VOL3_CMD
    if _VOL3_CMD:
        return _VOL3_CMD

    for candidate in ["vol3", "vol", "python3 -m volatility3"]:
        try:
            cmd = candidate.split() + ["--version"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if "Volatility 3" in (result.stdout + result.stderr):
                _VOL3_CMD = candidate
                return _VOL3_CMD
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    raise RuntimeError(
        "Volatility 3 not found. Tried: vol3, vol, python3 -m volatility3\n"
        "Install: pip install volatility3"
    )


def _plugin_to_index_suffix(plugin: str) -> str:
    """windows.pslist → vol-pslist, windows.registry.hivelist → vol-hivelist."""
    parts = plugin.split(".")
    return f"vol-{parts[-1]}"


def run_vol3_plugin(
    image_path: Path,
    plugin: str,
    timeout: int = 3600,
) -> list[dict]:
    """Run a single vol3 plugin with JSON output."""
    vol_cmd = _find_vol3()
    cmd = vol_cmd.split() + [
        "-f",
        str(image_path),
        "--renderer",
        "json",
        "-q",
        plugin,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        stderr = result.stderr[:500] if result.stderr else ""
        raise RuntimeError(f"vol3 {plugin} failed (exit {result.returncode}): {stderr}")
    if not result.stdout.strip():
        return []

    if len(result.stdout) > _MAX_JSON_BYTES:
        print(
            f"WARNING: vol3 {plugin} produced {len(result.stdout) // (1024 * 1024)}MB "
            f"of JSON — memory spike during parsing",
            file=sys.stderr,
        )

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"vol3 {plugin} produced invalid JSON: {e}") from e

    if isinstance(raw, dict) and "columns" in raw:
        cols = [c["name"] for c in raw["columns"]]
        return [dict(zip(cols, row)) for row in raw.get("data", [])]
    elif isinstance(raw, list):
        return raw
    return []


def _flatten_records(records: list[dict]) -> list[dict]:
    """Recursively flatten __children into a flat list."""
    flat = []
    for record in records:
        children = record.pop("__children", [])
        flat.append(record)
        if children:
            flat.extend(_flatten_records(children))
    return flat


def _vol3_doc_id(index_name: str, plugin: str, record: dict, source_file: str) -> str:
    """Deterministic ID — natural key or content hash."""
    source_name = Path(source_file).name

    nk_fields = _NATURAL_KEYS.get(plugin)
    if nk_fields:
        parts = [str(record.get(f, "")) for f in nk_fields]
        if all(parts):
            key = f"{index_name}:{source_name}:{plugin}:{':'.join(parts)}"
            return hashlib.sha256(key.encode()).hexdigest()[:20]

    stable = {
        k: v
        for k, v in record.items()
        if not k.startswith("vhir.")
        and k != "host.name"
        and k != "pipeline_version"
        and k != "@timestamp"
    }
    content = json.dumps(stable, sort_keys=True, default=str)
    return hashlib.sha256(f"{index_name}:{source_name}:{content}".encode()).hexdigest()[:20]


def _index_vol3_records(
    records: list[dict],
    client: OpenSearch,
    index_name: str,
    plugin: str,
    hostname: str,
    source_file: str,
    ingest_audit_id: str,
    pipeline_version: str,
) -> tuple[int, int]:
    """Index vol3 JSON records into OpenSearch."""
    count = 0
    bulk_failed = 0
    actions: list[dict] = []

    flat = _flatten_records(records)

    if plugin == "windows.handles":
        flat = [r for r in flat if r.get("Type") in _HANDLE_TYPES_KEEP]

    for record in flat:
        ts_field = _TIMESTAMP_FIELD.get(plugin)
        if ts_field and record.get(ts_field):
            record["@timestamp"] = record[ts_field]

        doc_id = _vol3_doc_id(index_name, plugin, record, source_file)

        record["host.name"] = hostname
        record["vhir.source_file"] = source_file
        record["vhir.parse_method"] = f"vol3-{plugin}"
        if ingest_audit_id:
            record["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            record["pipeline_version"] = pipeline_version

        actions.append({"_index": index_name, "_id": doc_id, "_source": record})

        if len(actions) >= 500:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, bulk_failed


def _register_memory_evidence(image_path: Path, hostname: str) -> None:
    """Register memory image with case-mcp (best-effort)."""
    try:
        from opensearch_mcp.gateway import call_tool

        call_tool(
            "evidence_register",
            {
                "path": str(image_path),
                "description": f"Memory image from {hostname} (vol3 analysis)",
            },
        )
    except Exception:
        pass


def ingest_memory(
    image_path: Path,
    client: OpenSearch,
    case_id: str,
    hostname: str,
    tier: int = 1,
    plugins: list[str] | None = None,
    timeout: int = 3600,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    on_progress=None,
    audit_log=None,
) -> dict:
    """Run vol3 plugins and index results.

    Returns dict with per-plugin results.
    """
    if plugins is not None and len(plugins) > 0:
        plugin_list = plugins
    elif tier >= 3:
        plugin_list = TIER_3
    elif tier >= 2:
        plugin_list = TIER_2
    else:
        plugin_list = TIER_1

    source_file = str(image_path)
    results: dict = {}

    vol_cmd = _find_vol3()

    # Pre-flight: check symbol availability by running windows.info
    # This catches missing symbols early with a clear error instead of
    # failing cryptically on the first real plugin.
    try:
        test_cmd = vol_cmd.split() + [
            "-f",
            str(image_path),
            "--renderer",
            "json",
            "-q",
            "windows.info",
        ]
        test = subprocess.run(test_cmd, capture_output=True, text=True, timeout=60)
        if "Unsatisfied" in test.stderr:
            print(
                "ERROR: Volatility 3 symbols not available for this image.\n"
                "  Download symbols: vol -f <image> windows.info\n"
                "  Or set symbol path: export VOLATILITY_SYMBOLS=/path/to/symbols/",
                file=sys.stderr,
            )
            return {"windows.info": {"status": "failed", "error": "Symbols not available"}}
    except subprocess.TimeoutExpired:
        pass  # Slow but not a symbol issue — continue

    _register_memory_evidence(image_path, hostname)

    safe_host = sanitize_index_component(hostname)
    safe_case = sanitize_index_component(case_id)

    for plugin in plugin_list:
        suffix = _plugin_to_index_suffix(plugin)
        index_name = f"case-{safe_case}-{suffix}-{safe_host}"

        if on_progress:
            on_progress("plugin_start", plugin=plugin, hostname=hostname)

        try:
            records = run_vol3_plugin(image_path, plugin, timeout=timeout)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            results[plugin] = {"status": "failed", "error": str(e)}
            if audit_log:
                audit_log(
                    tool=f"vol3_{suffix}",
                    params={"plugin": plugin, "image": source_file},
                    result_summary=f"FAILED: {e}",
                )
            if on_progress:
                on_progress("plugin_failed", plugin=plugin, error=str(e))
            continue

        if not records:
            results[plugin] = {"status": "empty", "indexed": 0}
            if on_progress:
                on_progress("plugin_done", plugin=plugin, indexed=0)
            continue

        count, bf = _index_vol3_records(
            records=records,
            client=client,
            index_name=index_name,
            plugin=plugin,
            hostname=hostname,
            source_file=source_file,
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
        )
        results[plugin] = {"status": "complete", "indexed": count, "bulk_failed": bf}
        if on_progress:
            on_progress("plugin_done", plugin=plugin, indexed=count)

    return results
