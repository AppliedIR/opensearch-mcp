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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import OLD_RID_KEY, flush_bulk
from opensearch_mcp.ingest_counts import stored_counts
from opensearch_mcp.memory_tiers import TIER_1, TIER_2, TIER_3, TIERS  # noqa: F401

# Natural keys per plugin (content-intrinsic, version-independent)
_NATURAL_KEYS: dict[str, list[str]] = {
    "windows.pslist": ["PID", "CreateTime"],
    "windows.pstree": ["PID", "CreateTime"],
    # the object's offset, state and creation time are in the key
    "windows.netscan": [
        "LocalAddr",
        "LocalPort",
        "ForeignAddr",
        "ForeignPort",
        "PID",
        "Offset",
        "State",
        "Created",
    ],
    "windows.netstat": [
        "LocalAddr",
        "LocalPort",
        "ForeignAddr",
        "ForeignPort",
        "PID",
        "Offset",
        "State",
        "Created",
    ],
    "windows.svcscan": ["Name", "PID", "Offset"],
    "windows.cmdline": ["PID"],
    "windows.dlllist": ["PID", "Base", "Name"],
    "windows.handles": ["PID", "Offset(V)"],
    "windows.modules": ["Base", "Name"],
    "windows.registry.hivelist": ["Offset(V)"],
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
    # Vol3's registry.userassist TreeGrid column is "Last Write Time"
    # (with spaces), not "LastWriteTime" — see volatility3 source:
    # framework/plugins/windows/registry/userassist.py:380-390. The
    # JSON renderer preserves column names verbatim. Prior value
    # "LastWriteTime" never matched the emitted field, so @timestamp
    # was silently left unset on every userassist row (UAT 2026-04-23).
    "windows.registry.userassist": "Last Write Time",
    "windows.handles": None,
    "windows.filescan": None,
    "windows.malfind": None,
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
            # Run bare: Volatility 3 has no --version, and 2.28 rejects it
            # before printing its banner. Bare, it prints the banner and exits 2.
            cmd = candidate.split()
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


def _flatten_records(records: list[dict], _depth: int = 0) -> list[dict]:
    """Recursively flatten __children into a flat list."""
    flat = []
    for record in records:
        children = record.pop("__children", [])
        flat.append(record)
        if children and _depth < 50:
            flat.extend(_flatten_records(children, _depth + 1))
    return flat


# the plugins whose ids 0.6.5 changed: their records carry vhir.id_scheme 2
_ID_SCHEME_2 = frozenset({"windows.netscan", "windows.netstat", "windows.svcscan"})
# 0.6.4's keys for them, for the id each record was stored under then
_NATURAL_KEYS_064 = {
    "windows.netscan": ["LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "PID"],
    "windows.netstat": ["LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "PID"],
    "windows.svcscan": ["Name", "PID"],
}


def _vol3_doc_id(
    index_name: str, plugin: str, record: dict, source_file: str, as_064: bool = False
) -> str:
    """Deterministic ID — natural key or content hash, with the image's
    evidence unit (its basename outside an ingest run), so two images with
    one file name never share an id. `as_064`: the id 0.6.4 gave a record of
    a plugin in _ID_SCHEME_2."""
    from opensearch_mcp.write_context import current

    ctx = current()
    source_name = ctx.unit if ctx is not None else Path(source_file).name

    nk_fields = _NATURAL_KEYS_064[plugin] if as_064 else _NATURAL_KEYS.get(plugin)
    if nk_fields:
        parts = [str(record.get(f, "")) for f in nk_fields]
        if plugin in _ID_SCHEME_2 and not as_064:  # the object's offset keys it
            if record.get("Offset") is not None:
                parts = ["" if record.get(f) is None else str(record.get(f)) for f in nk_fields]
                key = f"{index_name}:{source_name}:{plugin}:{':'.join(parts)}"
                return hashlib.sha256(key.encode()).hexdigest()[:20]
            parts = [""]  # no offset: the content hash
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


# Before this, a memory record's time is garbage (vol3 reads 0027 and 9905 as
# load times), and a timeline would show it as an event.
_EARLIEST_TIME = datetime(1990, 1, 1, tzinfo=timezone.utc)


def _plausible_time(value) -> bool:
    """Between 1990 and a day from now. A value that doesn't parse isn't."""
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return _EARLIEST_TIME <= t <= datetime.now(timezone.utc) + timedelta(days=1)


def _index_vol3_records(
    records: list[dict],
    client: OpenSearch,
    index_name: str,
    plugin: str,
    hostname: str,
    source_file: str,
    ingest_audit_id: str,
    pipeline_version: str,
    host_dict=None,
) -> tuple[int, int, int]:
    """Index vol3 JSON records into OpenSearch. Returns (indexed, bulk
    failed, records whose time was implausible and set no @timestamp)."""
    count = 0
    bulk_failed = 0
    implausible = 0
    actions: list[dict] = []

    flat = _flatten_records(records)

    if plugin == "windows.handles":
        flat = [r for r in flat if r.get("Type") in _HANDLE_TYPES_KEEP]

    for record in flat:
        ts_field = _TIMESTAMP_FIELD.get(plugin)
        if ts_field and record.get(ts_field):
            if _plausible_time(record[ts_field]):
                record["@timestamp"] = record[ts_field]
            else:
                implausible += 1  # the raw field stays as vol3 gave it

        doc_id = _vol3_doc_id(index_name, plugin, record, source_file)
        old_rid = plugin in _ID_SCHEME_2 and _vol3_doc_id(
            index_name, plugin, record, source_file, as_064=True
        )

        record["host.name"] = hostname
        if hostname:
            if host_dict is not None:
                _resolved = host_dict.resolve(hostname)
                record["host.id"] = _resolved if _resolved else hostname
            else:
                record["host.id"] = hostname
        record["vhir.source_file"] = source_file
        record["vhir.parse_method"] = f"vol3-{plugin}"
        if ingest_audit_id:
            record["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            record["pipeline_version"] = pipeline_version

        action = {"_index": index_name, "_id": doc_id, "_source": record}
        if old_rid:  # the id 0.6.4 gave it
            action[OLD_RID_KEY] = old_rid
        actions.append(action)

        if len(actions) >= 500:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, bulk_failed, implausible


_NAME_VARIABLES = ("COMPUTERNAME", "USERDOMAIN")


def observe_envar_names(records: list[dict]) -> list[str]:
    """Record the image's COMPUTERNAME and USERDOMAIN values as names its
    evidence gives. They are observations only: the image keeps the machine
    it was given."""
    from sift_common import host_identity

    from opensearch_mcp.write_context import current

    ctx = current()
    found: list[tuple[str, str]] = []
    for r in records:
        var, value = str(r.get("Variable") or ""), r.get("Value")
        if var.upper() in _NAME_VARIABLES and isinstance(value, str) and value.strip():
            pair = (value.strip(), f"windows.envars {var.upper()}")
            if pair not in found:
                found.append(pair)
    if ctx is not None and found:
        host_identity.append_observations(
            ctx.case_dir,
            [{"kind": "name", "unit": ctx.unit, "raw": raw, "evidence": ev,
              "origin": host_identity.ARTIFACT} for raw, ev in found],
        )  # fmt: skip
    return [raw for raw, _ in found]


def ingest_memory(
    image_path: Path,
    client: OpenSearch,
    case_id: str,
    hostname: str,
    tier: int = 1,
    plugins: list[str] | None = None,
    timeout: int = 3600,
    ingest_audit_id: str = "",
    run_id: str = "",
    pipeline_version: str = "",
    on_progress=None,
    audit=None,
    host_dict=None,
    case_dir=None,
) -> dict:
    """Run vol3 plugins and index results.

    Each plugin's run is one step: its entry, written once vol3 has returned
    and before any of its records is indexed, names the image (by the registry,
    or by the manifest of the extraction that wrote it) and its place; the
    plugin's records carry its id. A plugin that fails is that one entry.

    Returns dict with per-plugin results.
    """
    from opensearch_mcp import ops
    from opensearch_mcp import write_context as wc

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
    image_in, image_reg = ops.image_input(case_dir, image_path)

    def step(tool: str, params: dict, summary: str) -> str:
        if audit is None:
            return ""
        return ops.write(
            audit, tool, params=params, summary=summary, inputs=[image_in],
            input_registered=[image_reg] if image_reg else None,
        )  # fmt: skip

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

    for plugin in plugin_list:
        suffix = _plugin_to_index_suffix(plugin)
        from opensearch_mcp.write_context import index_name as _index_name

        index_name = _index_name(suffix)

        if on_progress:
            on_progress("plugin_start", plugin=plugin, hostname=hostname)

        tool = f"ingest_vol3_{suffix}"
        params = {"plugin": plugin, "image": source_file, "hostname": hostname,
                  "index_name": index_name, "run_id": run_id}  # fmt: skip
        try:
            records = run_vol3_plugin(image_path, plugin, timeout=timeout)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            results[plugin] = {"status": "failed", "error": str(e)}
            step(tool, params, f"FAILED: {e}")  # the plugin's one entry
            if on_progress:
                on_progress("plugin_failed", plugin=plugin, error=str(e))
            continue

        if plugin == "windows.envars":
            observe_envar_names(records)
        aid = step(tool, params, f"{len(records)} record(s) from vol3, recorded before indexing")
        if not records:
            results[plugin] = {"status": "empty", "indexed": 0}
            if on_progress:
                on_progress("plugin_done", plugin=plugin, indexed=0)
            continue
        if audit is not None and not aid:  # its records would carry an id with no entry
            results[plugin] = {"status": "failed", "error": ops.NO_ENTRY}
            if on_progress:
                on_progress("plugin_failed", plugin=plugin, error=ops.NO_ENTRY)
            continue

        with wc.op(aid or ingest_audit_id):
            count, bf, implausible = _index_vol3_records(
                records=records,
                client=client,
                index_name=index_name,
                plugin=plugin,
                hostname=hostname,
                source_file=source_file,
                ingest_audit_id=aid or ingest_audit_id,
                pipeline_version=pipeline_version,
                host_dict=host_dict,
            )
        results[plugin] = {
            "status": "complete",
            "indexed": count,
            "bulk_failed": bf,
            "implausible_time": implausible,
        }
        stamped = aid or ingest_audit_id
        counts = stored_counts(client, index_name, stamped) if stamped else {}
        results[plugin].update(counts)
        if aid and bf:  # rejected records: a later fact about the plugin's step
            ops.later(audit, aid, tool, f"{count} indexed, {bf} bulk failed",
                      {**params, "bulk_failed": bf})  # fmt: skip

        if on_progress:
            on_progress(
                "plugin_done",
                plugin=plugin,
                indexed=count,
                implausible_time=implausible,
                **counts,
            )

    return results
