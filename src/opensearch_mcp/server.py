"""OpenSearch MCP server — 10 tools for forensic evidence querying and ingest."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from opensearchpy.exceptions import AuthorizationException, ConnectionTimeout
from opensearchpy.exceptions import ConnectionError as OSConnectionError
from sift_common.audit import AuditWriter

from opensearch_mcp.client import get_client

server = FastMCP("opensearch-mcp")
audit = AuditWriter(mcp_name="opensearch-mcp")

_client = None
_client_verified = False


def _get_os():
    """Get cached OpenSearch client. Health check on first call only.

    If the cached client hits a connection error (OpenSearch went down),
    the next _get_os() call will create a fresh client and re-verify.
    """
    global _client, _client_verified
    if _client is None:
        try:
            _client = get_client()
        except FileNotFoundError as e:
            raise RuntimeError(str(e)) from e
    if not _client_verified:
        try:
            _client.cluster.health()
            _client_verified = True
        except Exception as e:
            _client = None
            raise RuntimeError(
                f"OpenSearch not running or not reachable: {e}\n"
                "Run 'opensearch-setup' to start OpenSearch."
            ) from e
    return _client


def _os_call(fn, *args, **kwargs):
    """Call an OpenSearch client method, resetting cache on connection failure."""
    global _client, _client_verified
    try:
        return fn(*args, **kwargs)
    except (OSConnectionError, ConnectionTimeout, AuthorizationException):
        _client = None
        _client_verified = False
        raise RuntimeError(
            "Lost connection to OpenSearch. Is the container running?\n"
            "Check: docker ps | grep vhir-opensearch"
        )


def _strip_hits(hits: list[dict]) -> list[dict]:
    """Extract _source from hits, trim large field sets."""
    results = []
    for hit in hits:
        src = hit.get("_source", {})
        doc = {"_id": hit.get("_id"), "_index": hit.get("_index")}
        doc.update(src)
        results.append(doc)
    return results


@server.tool()
def idx_search(
    query: str,
    index: str = "case-*",
    limit: int = 50,
    sort: str = "@timestamp:desc",
) -> dict:
    """Search indexed evidence using OpenSearch query_string syntax.

    Args:
        query: OpenSearch query_string (e.g., 'event.code:4624 AND user.name:admin').
        index: Index pattern (default: all evtx indices).
        limit: Max results (default 50, max 200).
        sort: Sort field:order (default @timestamp:desc).
    """
    client = _get_os()
    limit = min(limit, 200)

    sort_field, _, sort_order = sort.partition(":")
    if sort_order not in ("asc", "desc", ""):
        sort_order = "desc"
    sort_body = [{sort_field: {"order": sort_order or "desc"}}]

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "sort": sort_body,
            "size": limit,
        },
    )

    total = result["hits"]["total"]["value"]
    docs = _strip_hits(result["hits"]["hits"])

    resp = {"total": total, "returned": len(docs), "results": docs}
    aid = audit.log(
        tool="idx_search",
        params={"query": query, "index": index, "limit": limit},
        result_summary=f"{total} total, {len(docs)} returned",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_count(
    query: str = "*",
    index: str = "case-*",
) -> dict:
    """Count matching documents.

    Args:
        query: OpenSearch query_string (default: all).
        index: Index pattern.
    """
    client = _get_os()
    result = _os_call(
        client.count,
        index=index,
        body={"query": {"query_string": {"query": query}}},
    )
    resp = {"count": result["count"]}
    aid = audit.log(
        tool="idx_count",
        params={"query": query, "index": index},
        result_summary=f"count={result['count']}",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_aggregate(
    field: str,
    query: str = "*",
    index: str = "case-*",
    limit: int = 50,
) -> dict:
    """Aggregate (group by) a field with optional query filter.

    Args:
        field: Field to aggregate on (e.g., 'host.name', 'event.code').
        query: OpenSearch query_string filter (default: all).
        index: Index pattern.
        limit: Max buckets (default 50, max 500).
    """
    client = _get_os()
    limit = min(limit, 500)

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {"agg": {"terms": {"field": field, "size": limit}}},
            "size": 0,
        },
    )

    buckets = [
        {"key": b["key"], "count": b["doc_count"]}
        for b in result["aggregations"]["agg"]["buckets"]
    ]

    resp = {
        "field": field,
        "total_docs": result["hits"]["total"]["value"],
        "buckets": buckets,
    }
    aid = audit.log(
        tool="idx_aggregate",
        params={"field": field, "query": query, "index": index},
        result_summary=f"{len(buckets)} buckets",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_get_event(
    doc_id: str,
    index: str,
) -> dict:
    """Retrieve a single document by ID.

    Args:
        doc_id: Document _id.
        index: Exact index name (not a pattern).
    """
    client = _get_os()
    result = _os_call(client.get, index=index, id=doc_id)
    doc = {"_id": result["_id"], "_index": result["_index"]}
    doc.update(result.get("_source", {}))
    aid = audit.log(
        tool="idx_get_event",
        params={"doc_id": doc_id, "index": index},
        result_summary=f"doc {doc_id}",
    )
    if aid:
        doc["audit_id"] = aid
    return doc


@server.tool()
def idx_timeline(
    query: str = "*",
    index: str = "case-*",
    interval: str = "1h",
    time_field: str = "@timestamp",
) -> dict:
    """Show event count over time as a date histogram.

    Args:
        query: OpenSearch query_string filter.
        index: Index pattern.
        interval: Histogram bucket size (e.g., '1m', '1h', '1d').
        time_field: Timestamp field (default @timestamp).
    """
    client = _get_os()

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": time_field,
                        "fixed_interval": interval,
                        "min_doc_count": 1,
                    }
                }
            },
            "size": 0,
        },
    )

    buckets = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in result["aggregations"]["timeline"]["buckets"]
    ]

    resp = {
        "total_docs": result["hits"]["total"]["value"],
        "interval": interval,
        "buckets": buckets,
    }
    aid = audit.log(
        tool="idx_timeline",
        params={"query": query, "index": index, "interval": interval},
        result_summary=f"{len(buckets)} buckets",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_field_values(
    field: str,
    query: str = "*",
    index: str = "case-*",
    limit: int = 50,
) -> dict:
    """List unique values for a field (terms aggregation).

    Args:
        field: Field to enumerate (e.g., 'winlog.provider_name').
        query: OpenSearch query_string filter.
        index: Index pattern.
        limit: Max values (default 50, max 500).
    """
    client = _get_os()
    limit = min(limit, 500)

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {"values": {"terms": {"field": field, "size": limit}}},
            "size": 0,
        },
    )

    values = [
        {"value": b["key"], "count": b["doc_count"]}
        for b in result["aggregations"]["values"]["buckets"]
    ]

    resp = {"field": field, "values": values}
    aid = audit.log(
        tool="idx_field_values",
        params={"field": field, "query": query, "index": index},
        result_summary=f"{len(values)} values",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_status() -> dict:
    """Show OpenSearch index status: names, doc counts, sizes."""
    client = _get_os()

    indices = _os_call(client.cat.indices, format="json")
    case_indices = [
        {
            "index": idx["index"],
            "docs": idx.get("docs.count", "0"),
            "size": idx.get("store.size", "0"),
            "status": idx.get("status", "unknown"),
        }
        for idx in indices
        if idx["index"].startswith("case-")
    ]

    case_indices.sort(key=lambda x: x["index"])

    health = _os_call(client.cluster.health)

    resp = {
        "cluster_status": health.get("status"),
        "indices": case_indices,
        "total_indices": len(case_indices),
    }
    aid = audit.log(
        tool="idx_status",
        params={},
        result_summary=f"{len(case_indices)} indices",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_ingest(
    path: str,
    hostname: str = "",
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    timezone: str = "",
    all_logs: bool = False,
    reduced_ids: bool = False,
    dry_run: bool = True,
) -> dict:
    """Discover and ingest forensic artifacts into OpenSearch.

    Case ID is read from ~/.vhir/active_case. Not accepted as a
    parameter — set via 'vhir case activate'.

    Args:
        path: Directory containing evidence (triage package, mounted image).
        hostname: Source hostname. Auto-detected from directory structure
            if multi-host triage package. Required for flat directories.
        include: Only these artifact types (e.g., ["mft", "usn"]).
        exclude: Skip these artifact types (e.g., ["jumplists"]).
        dry_run: Preview what would be ingested without indexing (default True).
    """
    import sys
    from pathlib import Path

    from opensearch_mcp.ingest import discover

    evidence_path = Path(path).resolve()
    if not evidence_path.is_dir():
        return {"error": f"Not a directory: {path}"}
    # Restrict to reasonable evidence locations
    from opensearch_mcp.paths import vhir_home

    home = vhir_home().resolve()
    allowed = [home, Path("/mnt").resolve(), Path("/evidence").resolve(), Path("/tmp").resolve()]
    if not any(evidence_path.is_relative_to(a) for a in allowed):
        return {"error": f"Path not in allowed locations (~/, /mnt/, /evidence/, /tmp/): {path}"}

    # Read case from active_case
    from opensearch_mcp.paths import vhir_dir

    active_case = vhir_dir() / "active_case"
    if not active_case.exists():
        return {"error": "No active case. Run 'vhir case activate' first."}
    raw = active_case.read_text().strip()
    if not raw:
        return {"error": "No active case. Run 'vhir case activate' first."}
    case_id = Path(raw).name

    # Discover
    hosts = discover(evidence_path, hostname=hostname or None)
    if not hosts:
        return {"error": f"No Windows artifacts found in {path}"}

    # dry_run: return discovery summary
    if dry_run:
        client = _get_os()
        summary = []
        for host in hosts:
            artifact_names = sorted({a[0] for a in host.artifacts})
            evtx_count = 0
            if host.evtx_dir:
                evtx_count = sum(1 for f in host.evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
            # Check existing indices — map artifact names to index suffixes
            existing = {}
            from opensearch_mcp.ingest import _artifact_to_tool
            from opensearch_mcp.tools import TOOLS as _TOOLS

            checked_suffixes = set()
            for aname in artifact_names:
                tool_name = _artifact_to_tool(aname)
                if not tool_name or tool_name not in _TOOLS:
                    continue
                suffix = _TOOLS[tool_name].index_suffix
                if suffix in checked_suffixes:
                    continue
                checked_suffixes.add(suffix)
                idx = f"case-{case_id}-{suffix}-{host.hostname}".lower()
                try:
                    r = client.count(index=idx)
                    existing[idx] = r["count"]
                except Exception:
                    pass
            if evtx_count:
                idx = f"case-{case_id}-evtx-{host.hostname}".lower()
                try:
                    r = client.count(index=idx)
                    existing[idx] = r["count"]
                except Exception:
                    pass

            host_info = {
                "hostname": host.hostname,
                "artifacts": artifact_names,
            }
            if evtx_count:
                host_info["evtx_files"] = evtx_count
            if existing:
                host_info["existing"] = existing
            summary.append(host_info)

        aid = audit.log(
            tool="idx_ingest",
            params={"path": path, "dry_run": True},
            result_summary=f"discovery: {len(hosts)} hosts",
        )
        resp = {"status": "preview", "hosts": summary, "case_id": case_id}
        if aid:
            resp["audit_id"] = aid
        return resp

    # dry_run=False: launch ingest as a subprocess that survives gateway restart.
    import os as _os
    import subprocess as _sp
    import uuid as _uuid

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["VHIR_INGEST_RUN_ID"] = run_id

    cmd = [
        sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        "scan",
        path,
        "--case",
        case_id,
        "--yes",
    ]
    if hostname:
        cmd.extend(["--hostname", hostname])
    if include:
        cmd.extend(["--include", ",".join(include)])
    if exclude:
        cmd.extend(["--exclude", ",".join(exclude)])
    if timezone:
        cmd.extend(["--timezone", timezone])
    if all_logs:
        cmd.append("--all-logs")
    if reduced_ids:
        cmd.append("--reduced-ids")

    proc = _sp.Popen(
        cmd,
        stdout=_sp.PIPE,
        stderr=_sp.STDOUT,
        env=env,
        start_new_session=True,
    )

    host_names = [h.hostname for h in hosts]
    aid = audit.log(
        tool="idx_ingest",
        params={
            "path": path,
            "dry_run": False,
            "hosts": host_names,
            "pid": proc.pid,
            "run_id": run_id,
        },
        result_summary=f"started ingest (pid {proc.pid}) for {len(hosts)} hosts",
    )
    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "hosts": host_names,
        "case_id": case_id,
        "message": (
            "Ingest started. IMPORTANT: Call idx_ingest_status() every 30 seconds "
            "to monitor progress and report it to the examiner as a checklist. "
            "Continue polling until status is 'complete' or 'failed'."
        ),
    }
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_ingest_status() -> dict:
    """Check status of running or recent ingest operations.

    IMPORTANT: Present the checklist to the examiner showing each host
    and artifact with its status icon. If status is 'running', call
    this tool again in 30 seconds to get updated progress. Continue
    polling until all ingests show 'complete' or 'failed'.

    Cleans up status files older than 24 hours.
    """
    from opensearch_mcp.ingest_status import read_active_ingests

    ingests = read_active_ingests()
    if not ingests:
        return {"ingests": [], "message": "No active or recent ingests."}

    summaries = []
    for ing in ingests:
        status = ing.get("status", "unknown")
        elapsed = ing.get("elapsed_seconds", 0)
        minutes = int(elapsed // 60)

        totals = ing.get("totals", {})
        s = {
            "case_id": ing.get("case_id"),
            "status": status,
            "pid": ing.get("pid"),
            "elapsed": f"{minutes}m",
            "total_indexed": totals.get("indexed", 0),
            "hosts_complete": totals.get("hosts_complete", 0),
            "hosts_total": totals.get("hosts_total", 0),
            "artifacts_complete": totals.get("artifacts_complete", 0),
            "artifacts_total": totals.get("artifacts_total", 0),
        }

        # Build per-host checklist for the LLM to present
        checklist = []
        for h in ing.get("hosts", []):
            hostname = h.get("hostname", "?")
            for a in h.get("artifacts", []):
                a_status = a.get("status", "pending")
                indexed = a.get("indexed", 0)
                if a_status == "complete":
                    icon = "done"
                    detail = f"{indexed:,} entries"
                elif a_status == "running":
                    files_done = a.get("files_done", 0)
                    files_total = a.get("files_total", 0)
                    if files_total:
                        detail = f"{files_done}/{files_total} files, {indexed:,} so far"
                    else:
                        detail = f"{indexed:,} so far" if indexed else "starting"
                    icon = "running"
                elif a_status == "failed":
                    icon = "failed"
                    detail = a.get("error", "unknown error")
                else:
                    icon = "pending"
                    detail = "waiting"
                checklist.append(
                    {
                        "host": hostname,
                        "artifact": a["name"],
                        "status": icon,
                        "detail": detail,
                    }
                )
        s["checklist"] = checklist

        if status == "running":
            s["message"] = (
                "Ingest in progress. Present the checklist above to the examiner. "
                "Call idx_ingest_status() again in 30 seconds for updated progress."
            )
        elif status == "killed":
            s["message"] = (
                "Ingest process died unexpectedly. Re-run to continue — dedup prevents duplicates."
            )
        elif status == "complete":
            errors = [
                f"{item['host']}/{item['artifact']}: {item['detail']}"
                for item in checklist
                if item["status"] == "failed"
            ]
            if errors:
                s["message"] = f"Ingest complete with {len(errors)} error(s)."
                s["errors"] = errors
            else:
                s["message"] = (
                    f"Ingest complete. {totals.get('indexed', 0):,} entries indexed "
                    f"across {totals.get('hosts_total', 0)} host(s) in {minutes}m."
                )

        summaries.append(s)

    return {"ingests": summaries}


@server.tool()
def idx_list_detections(
    severity: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List Sigma detection findings from Security Analytics.

    Args:
        severity: Filter by severity (critical, high, medium, low).
                  Empty = all severities.
        limit: Max results (default 50).
        offset: Starting position for pagination (default 0).
    """
    client = _get_os()

    # Fetch more than requested when filtering by severity (API doesn't support it)
    fetch_size = limit * 3 if severity else limit
    params: dict = {
        "detectorType": "windows",
        "size": fetch_size,
        "startIndex": offset,
        "sortOrder": "desc",
    }

    response = _os_call(
        client.transport.perform_request,
        "GET",
        "/_plugins/_security_analytics/findings/_search",
        params=params,
    )

    sev_filter = severity.lower() if severity else ""
    findings = []
    for finding in response.get("findings", []):
        rules = []
        for q in finding.get("queries", []):
            rules.append(
                {
                    "name": q.get("name"),
                    "tags": q.get("tags", []),
                }
            )

        # Python-side severity filter — API doesn't support severity param
        if sev_filter and rules:
            if not any(sev_filter in t.lower() for r in rules for t in r.get("tags", [])):
                continue

        findings.append(
            {
                "id": finding.get("id"),
                "timestamp": finding.get("timestamp"),
                "index": finding.get("index"),
                "rules": rules,
                "matched_docs": len(finding.get("related_doc_ids", [])),
            }
        )

        if len(findings) >= limit:
            break

    resp = {
        "findings": findings,
        "total": response.get("total_findings", 0),
        "returned": len(findings),
        "offset": offset,
    }
    aid = audit.log(
        tool="idx_list_detections",
        params={"severity": severity, "limit": limit, "offset": offset},
        result_summary=f"{len(findings)} findings",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def main():
    """Run the MCP server."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
