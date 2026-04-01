"""Post-ingest triage enrichment — batch gateway calls + registry persistence rules.

Gateway-dependent: check_file/check_service via windows-triage-mcp.
Gateway-independent: registry persistence R1-R17 via update_by_query.
"""

from __future__ import annotations

import sys

from opensearchpy import OpenSearch

from opensearch_mcp.gateway import call_tool, gateway_available
from opensearch_mcp.paths import sanitize_index_component

_MAX_CONSECUTIVE_FAILURES = 3


def enrich_remote(
    client: OpenSearch,
    case_id: str,
    on_progress=None,
) -> dict:
    """Run batch triage enrichment against indexed data.

    Returns dict with counts per artifact type.
    """
    safe_case = sanitize_index_component(case_id)

    # Refresh indices so aggregations see all recently ingested docs
    try:
        client.indices.refresh(index=f"case-{safe_case}-*")
    except Exception:
        pass

    results: dict = {}

    # --- Gateway-independent: registry persistence (R1-R7, R11-R14, R16) ---
    results["registry_persistence"] = _enrich_registry_persistence(client, safe_case, on_progress)

    # --- Gateway-dependent: file + service enrichment ---
    if not gateway_available():
        results["_gateway"] = "not configured — file/service enrichment skipped"
        return results

    try:
        call_tool("windows-triage-mcp__get_health", {})
    except Exception:
        results["_gateway"] = "windows-triage-mcp not available"
        return results

    # File enrichment (check_file)
    # Fields with .keyword: dynamically mapped text fields (no explicit template mapping).
    # Fields without: explicitly mapped as keyword in their template.
    # Vol3 pslist/pstree/psscan excluded: ImageFileName is a bare 14-char name
    # (no path) — check_file gives wrong is_system_path, all system procs → SUSPICIOUS.
    # Vol3 dlllist uses Path (full Windows path), not Name (bare DLL name).
    for name, suffix, field, query in [
        ("shimcache", "shimcache", "Path.keyword", "*"),
        ("amcache", "amcache", "FullPath.keyword", "*"),
        ("evtx_proc", "evtx", "process.name", "event.code:(4688 OR 1)"),
        ("tasks", "tasks", "task.command", "*"),
        ("vol_dlls", "vol-dlllist", "Path.keyword", "*"),
    ]:
        results[name] = _enrich_file_artifact(
            client,
            safe_case,
            index_pattern=f"case-{safe_case}-{suffix}-*",
            path_field=field,
            artifact_name=name,
            query=query,
            on_progress=on_progress,
        )

    # Service enrichment (check_service)
    results["evtx_svc"] = _enrich_evtx_services(client, safe_case, on_progress)
    results["vol_svcs"] = _enrich_service_artifact(
        client,
        safe_case,
        index_pattern=f"case-{safe_case}-vol-svcscan-*",
        name_field="Name.keyword",
        artifact_name="vol_svcs",
        on_progress=on_progress,
    )
    results["registry_svcs"] = _enrich_registry_services(client, safe_case, on_progress)

    # Registry Run keys (check_file on ValueData)
    results["registry_run"] = _enrich_registry_run_keys(client, safe_case, on_progress)

    return results


# ---------------------------------------------------------------------------
# File enrichment (check_file)
# ---------------------------------------------------------------------------


def _enrich_file_artifact(
    client: OpenSearch,
    safe_case: str,
    index_pattern: str,
    path_field: str,
    artifact_name: str,
    query: str = "*",
    on_progress=None,
) -> dict:
    """Enrich file-based artifacts in batch via check_file."""
    try:
        agg_result = client.search(
            index=index_pattern,
            body={
                "query": {"query_string": {"query": query}},
                "aggs": {"paths": {"terms": {"field": path_field, "size": 5000}}},
                "size": 0,
            },
        )
    except Exception:
        return {"status": "skipped", "reason": "index not found"}

    buckets = agg_result.get("aggregations", {}).get("paths", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    verdicts: dict = {}
    consecutive_failures = 0
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            print(
                f"  WARNING: {consecutive_failures} consecutive gateway failures "
                f"— stopping {artifact_name}",
                file=sys.stderr,
            )
            break
        path = bucket["key"]
        # Skip non-path entries (AppX metadata, hex strings, empty)
        if not path or not (path[0] in ("\\", "/") or (len(path) > 1 and path[1] == ":")):
            continue
        try:
            result = call_tool("check_file", {"path": path}, timeout=15)
            consecutive_failures = 0
            if result.get("verdict"):
                verdicts[path] = result
        except Exception:
            consecutive_failures += 1
            continue

    if not verdicts:
        return {"status": "complete", "checked": len(buckets), "enriched": 0}

    enriched = 0
    for path, verdict in verdicts.items():
        enriched += _stamp_file_verdict(client, index_pattern, path_field, path, verdict)

    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )

    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


def _stamp_file_verdict(
    client: OpenSearch,
    index_pattern: str,
    path_field: str,
    path: str,
    result: dict,
) -> int:
    """Stamp a check_file verdict onto matching documents."""
    verdict_str = result.get("verdict", "UNKNOWN")
    reasons = result.get("reasons", [])
    reason_str = "; ".join(reasons) if reasons else ""

    script_lines = [
        "ctx._source['triage.verdict'] = params.verdict",
        "ctx._source['triage.checked'] = true",
        "ctx._source['triage.confidence'] = params.confidence",
    ]
    params: dict = {
        "verdict": verdict_str,
        "confidence": result.get("confidence", "low"),
    }
    if reason_str:
        script_lines.append("ctx._source['triage.reason'] = params.reason")
        params["reason"] = reason_str
    if result.get("is_lolbin"):
        script_lines.append("ctx._source['triage.lolbin'] = true")

    try:
        resp = client.update_by_query(
            index=index_pattern,
            body={
                "query": {"term": {path_field: path}},
                "script": {
                    "source": "; ".join(script_lines),
                    "lang": "painless",
                    "params": params,
                },
            },
            conflicts="proceed",
        )
        return resp.get("updated", 0)
    except Exception as e:
        print(f"  WARNING: update_by_query failed for {path}: {e}", file=sys.stderr)
        return 0


# ---------------------------------------------------------------------------
# Service enrichment (check_service)
# ---------------------------------------------------------------------------


def _enrich_evtx_services(client, safe_case, on_progress=None):
    """Enrich evtx 7045 service install events via check_service."""
    index = f"case-{safe_case}-evtx-*"
    try:
        # No _source filter — "winlog.event_data" is a literal dotted key
        # (normalize.py:128), not a nested path. _source filtering treats
        # dots as path separators and would miss it.
        result = client.search(
            index=index,
            body={"query": {"term": {"event.code": 7045}}, "size": 5000},
        )
    except Exception:
        return {"status": "skipped"}

    hits = result["hits"]["hits"]
    if not hits:
        return {"status": "empty", "checked": 0}

    service_names = set()
    for h in hits:
        ed = h["_source"].get("winlog.event_data", {})
        if isinstance(ed, dict) and ed.get("ServiceName"):
            service_names.add(ed["ServiceName"])

    if on_progress:
        on_progress("triage_start", artifact="evtx_svc", unique_values=len(service_names))

    enriched = 0
    consecutive_failures = 0
    for name in service_names:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        try:
            verdict = call_tool(
                "check_service",
                {"service_name": name, "os_version": "Windows"},
                timeout=15,
            )
            consecutive_failures = 0
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"event.code": 7045}},
                                {"term": {"winlog.event_data.ServiceName": name}},
                            ]
                        }
                    },
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if on_progress:
        on_progress(
            "triage_done",
            artifact="evtx_svc",
            checked=len(service_names),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(service_names), "enriched": enriched}


def _enrich_service_artifact(
    client, safe_case, index_pattern, name_field, artifact_name, on_progress=None
):
    """Enrich service-based artifacts (vol3 svcscan, registry Services)."""
    try:
        agg_result = client.search(
            index=index_pattern,
            body={
                "query": {"match_all": {}},
                "aggs": {"names": {"terms": {"field": name_field, "size": 5000}}},
                "size": 0,
            },
        )
    except Exception:
        return {"status": "skipped"}

    buckets = agg_result.get("aggregations", {}).get("names", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    enriched = 0
    consecutive_failures = 0
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        name = bucket["key"]
        try:
            verdict = call_tool(
                "check_service",
                {"service_name": name, "os_version": "Windows"},
                timeout=15,
            )
            consecutive_failures = 0
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index_pattern,
                body={
                    "query": {"term": {name_field: name}},
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


def _enrich_registry_services(client, safe_case, on_progress=None):
    """Enrich registry Services key entries via check_service."""
    index = f"case-{safe_case}-registry-*"
    # Services keys: KeyPath ends with \Services\{ServiceName},
    # need to extract service names from KeyPath, not ValueName.
    # Use a scroll/search instead to extract unique last path components.
    try:
        result = client.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*\\\\Services\\\\*"}},
                            {"term": {"ValueName.keyword": "ImagePath"}},
                        ]
                    }
                },
                "size": 5000,
            },
        )
    except Exception:
        return {"status": "skipped"}

    hits = result["hits"]["hits"]
    if not hits:
        return {"status": "empty", "checked": 0}

    # Extract unique service names from KeyPath
    services: dict = {}  # service_name -> image_path
    for h in hits:
        src = h["_source"]
        key_path = src.get("KeyPath", "")
        # KeyPath: ...\Services\ServiceName
        parts = key_path.replace("/", "\\").rsplit("\\", 1)
        if len(parts) > 1:
            svc_name = parts[-1]
            services[svc_name] = src.get("ValueData", "")

    if on_progress:
        on_progress("triage_start", artifact="registry_svcs", unique_values=len(services))

    enriched = 0
    consecutive_failures = 0
    for svc_name in services:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        try:
            verdict = call_tool(
                "check_service",
                {"service_name": svc_name, "os_version": "Windows"},
                timeout=15,
            )
            consecutive_failures = 0
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {"wildcard": {"KeyPath.keyword": f"*\\\\Services\\\\{svc_name}*"}},
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_svcs",
            checked=len(services),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(services), "enriched": enriched}


# ---------------------------------------------------------------------------
# Registry Run keys (check_file on ValueData)
# ---------------------------------------------------------------------------


def _enrich_registry_run_keys(client, safe_case, on_progress=None):
    """Enrich registry Run key entries with check_file."""
    index = f"case-{safe_case}-registry-*"
    try:
        result = client.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"KeyPath.keyword": "*\\\\Run\\\\*"}},
                            {"wildcard": {"KeyPath.keyword": "*\\\\Run"}},
                        ],
                        "minimum_should_match": 1,
                        "filter": [{"exists": {"field": "ValueData"}}],
                    }
                },
                "size": 0,
                "aggs": {"values": {"terms": {"field": "ValueData.keyword", "size": 5000}}},
            },
        )
    except Exception:
        return {"status": "skipped"}

    buckets = result.get("aggregations", {}).get("values", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact="registry_run", unique_values=len(buckets))

    enriched = 0
    consecutive_failures = 0
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        value_data = bucket["key"]
        if not value_data.strip():
            continue
        try:
            verdict = call_tool("check_file", {"path": value_data}, timeout=15)
            consecutive_failures = 0
            if not verdict.get("verdict"):
                continue
            enriched += _stamp_file_verdict(
                client, index, "ValueData.keyword", value_data, verdict
            )
        except Exception:
            consecutive_failures += 1

    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_run",
            checked=len(buckets),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


# ---------------------------------------------------------------------------
# Registry persistence R1-R17 (no gateway — pure update_by_query)
# ---------------------------------------------------------------------------


def _enrich_registry_persistence(client, safe_case, on_progress=None):
    """Flag registry persistence mechanisms via update_by_query.

    Implements R1-R7, R11-R14, R16. R8-R10 (LSA packages), R15 (Active
    Setup), R17 (NetSh) deferred — need complex Painless or gateway calls.

    No gateway calls — queries OpenSearch directly. Runs even when
    gateway is unavailable.
    """
    index = f"case-{safe_case}-registry-*"
    total_updated = 0

    rules = [
        # R1: IFEO Debugger (T1546.012)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Image File Execution Options*"}},
                        {"term": {"ValueName.keyword": "Debugger"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "IFEO debugger: ",
        },
        # R2: Silent Process Exit Monitor (T1546.012)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*SilentProcessExit*"}},
                        {"term": {"ValueName.keyword": "MonitorProcess"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "SilentProcessExit monitor: ",
        },
        # R3: AppInit_DLLs (T1546.010)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*CurrentVersion\\\\Windows*"}},
                        {"term": {"ValueName.keyword": "AppInit_DLLs"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "AppInit_DLLs: ",
        },
        # R6: Winlogon mpnotify (T1547.004)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Winlogon*"}},
                        {"term": {"ValueName.keyword": "mpnotify"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "Winlogon mpnotify: ",
        },
        # R11: Print Monitors (T1547.010)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Print\\\\Monitors*"}},
                        {"term": {"ValueName.keyword": "Driver"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "Print Monitor DLL: ",
        },
        # R12: Command Processor AutoRun (T1546)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Command Processor*"}},
                        {"term": {"ValueName.keyword": "AutoRun"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "cmd.exe AutoRun: ",
        },
        # R13: Explorer Load (T1547.001)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*CurrentVersion\\\\Windows*"}},
                        {"term": {"ValueName.keyword": "Load"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "Explorer Load: ",
        },
        # R16: Terminal Services InitialProgram (T1547.001)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Terminal Services*"}},
                        {"term": {"ValueName.keyword": "InitialProgram"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "TS InitialProgram: ",
        },
    ]

    # Simple rules: any match with ValueData → SUSPICIOUS
    for rule in rules:
        try:
            resp = client.update_by_query(
                index=index,
                body={
                    "query": rule["query"],
                    "script": {
                        "source": (
                            "ctx._source['triage.verdict'] = 'SUSPICIOUS'; "
                            "ctx._source['triage.reason'] = params.prefix + "
                            "ctx._source['ValueData']; "
                            "ctx._source['triage.checked'] = true"
                        ),
                        "lang": "painless",
                        "params": {"prefix": rule["reason_prefix"]},
                    },
                },
                conflicts="proceed",
            )
            total_updated += resp.get("updated", 0)
        except Exception:
            continue

    # R4: Winlogon Shell — conditional (not explorer.exe → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Winlogon*"}},
                            {"term": {"ValueName.keyword": "Shell"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        int idx = val.lastIndexOf('\\\\');
                        String filename = idx >= 0 ? val.substring(idx + 1) : val;
                        if (!filename.equals('explorer.exe')) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            String vd = ctx._source.getOrDefault('ValueData', '');
                            ctx._source['triage.reason'] = params.prefix + vd;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                    "params": {"prefix": "Winlogon Shell: "},
                },
            },
            conflicts="proceed",
        )
        total_updated += resp.get("updated", 0)
    except Exception:
        pass

    # R5: Winlogon Userinit — conditional (not userinit.exe → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Winlogon*"}},
                            {"term": {"ValueName.keyword": "Userinit"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.endsWith(',')) { val = val.substring(0, val.length() - 1).trim(); }
                        if (!val.endsWith('userinit.exe')) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            String vd = ctx._source.getOrDefault('ValueData', '');
                            ctx._source['triage.reason'] = params.prefix + vd;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                    "params": {"prefix": "Winlogon Userinit: "},
                },
            },
            conflicts="proceed",
        )
        total_updated += resp.get("updated", 0)
    except Exception:
        pass

    # R7: BootExecute — conditional (not "autocheck autochk *" → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Session Manager*"}},
                            {"term": {"ValueName.keyword": "BootExecute"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].trim();
                        if (!val.equals('autocheck autochk *')) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            ctx._source['triage.reason'] = params.prefix + val;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                    "params": {"prefix": "BootExecute: "},
                },
            },
            conflicts="proceed",
        )
        total_updated += resp.get("updated", 0)
    except Exception:
        pass

    # R14: Screensaver — conditional (non-.scr or outside System32 → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Control Panel\\\\Desktop*"}},
                            {"term": {"ValueName.keyword": "SCRNSAVE.EXE"}},
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
                        boolean suspicious = false;
                        String reason = '';
                        if (!val.endsWith('.scr')) {
                            suspicious = true;
                            reason = 'Screensaver non-.scr: ' + ctx._source['ValueData'];
                        } else if (val.contains('\\\\') && !val.contains('system32')
                                   && !val.contains('winsxs')) {
                            suspicious = true;
                            reason = 'Screensaver outside System32: ' + ctx._source['ValueData'];
                        }
                        if (suspicious) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            ctx._source['triage.reason'] = reason;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                },
            },
            conflicts="proceed",
        )
        total_updated += resp.get("updated", 0)
    except Exception:
        pass

    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_persistence",
            checked=0,
            enriched=total_updated,
        )
    return {"status": "complete", "enriched": total_updated}
