"""Remote triage enrichment — batch MCP calls after ingest completes.

Used when opensearch-mcp is on a different VM from windows-triage-mcp.
Queries unique filenames/services from indexed data, checks them in
batches via the gateway, then updates documents with _update_by_query.
"""

from __future__ import annotations

import sys

from opensearchpy import OpenSearch


def enrich_remote(
    client: OpenSearch,
    case_id: str,
    on_progress=None,
) -> dict:
    """Run batch triage enrichment against indexed data via gateway.

    Steps:
    1. Aggregate unique filenames from shimcache/amcache
    2. Aggregate unique services from registry
    3. Check each batch against triage MCP via gateway
    4. Update matching documents with _update_by_query

    Returns dict with counts per artifact type.
    """
    from opensearch_mcp.wintools import _load_gateway_config

    config = _load_gateway_config()
    if not config or not config.get("url"):
        return {"error": "Gateway not configured"}
    base_url = config["url"].split("/mcp/")[0]
    token = config.get("token", "")

    results: dict = {}

    # --- Shimcache file enrichment ---
    results["shimcache"] = _enrich_file_artifact(
        client,
        case_id,
        base_url,
        token,
        index_pattern=f"case-{case_id}-shimcache-*",
        path_field="Path",
        artifact_name="shimcache",
        on_progress=on_progress,
    )

    # --- Amcache file enrichment ---
    results["amcache"] = _enrich_file_artifact(
        client,
        case_id,
        base_url,
        token,
        index_pattern=f"case-{case_id}-amcache-*",
        path_field="FullPath",
        artifact_name="amcache",
        on_progress=on_progress,
    )

    # --- Evtx process creation (4688/1) ---
    results["evtx_proc"] = _enrich_file_artifact(
        client,
        case_id,
        base_url,
        token,
        index_pattern=f"case-{case_id}-evtx-*",
        path_field="process.name",
        artifact_name="evtx_proc",
        query="event.code:(4688 OR 1)",
        on_progress=on_progress,
    )

    # --- Tasks ---
    results["tasks"] = _enrich_file_artifact(
        client,
        case_id,
        base_url,
        token,
        index_pattern=f"case-{case_id}-tasks-*",
        path_field="task.command",
        artifact_name="tasks",
        on_progress=on_progress,
    )

    return results


def _enrich_file_artifact(
    client: OpenSearch,
    case_id: str,
    base_url: str,
    token: str,
    index_pattern: str,
    path_field: str,
    artifact_name: str,
    query: str = "*",
    on_progress=None,
) -> dict:
    """Enrich file-based artifacts in batch."""
    # Step 1: Get unique filenames
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
        on_progress(
            "triage_start",
            artifact=artifact_name,
            unique_values=len(buckets),
        )

    # Step 2: Check each filename via gateway MCP
    verdicts: dict = {}
    for bucket in buckets:
        path = bucket["key"]

        try:
            from opensearch_mcp.wintools import _call_gateway_tool

            result = _call_gateway_tool(
                base_url,
                token,
                "check_file",
                {"path": path},
            )
            if result.get("verdict"):
                verdicts[path] = result
        except Exception:
            continue

    if not verdicts:
        return {"status": "complete", "checked": len(buckets), "enriched": 0}

    # Step 3: Update documents with verdicts
    enriched = 0
    for path, verdict in verdicts.items():
        if verdict.get("verdict") in ("EXPECTED", "UNKNOWN") and not verdict.get("lolbin"):
            continue  # Only update SUSPICIOUS, EXPECTED_LOLBIN, or UNKNOWN with extra info

        script_lines = [
            "ctx._source['triage.verdict'] = params.verdict",
            "ctx._source['triage.checked'] = true",
        ]
        params = {"verdict": verdict["verdict"]}
        if verdict.get("reason"):
            script_lines.append("ctx._source['triage.reason'] = params.reason")
            params["reason"] = verdict["reason"]
        if verdict.get("lolbin"):
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
            )
            enriched += resp.get("updated", 0)
        except Exception as e:
            print(f"  WARNING: update_by_query failed for {path}: {e}", file=sys.stderr)

    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )

    return {"status": "complete", "checked": len(buckets), "enriched": enriched}
