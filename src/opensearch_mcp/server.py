"""OpenSearch MCP server — 17 tools for forensic evidence querying, ingest, and enrichment."""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP
from opensearchpy.exceptions import (
    AuthorizationException,
    ConnectionTimeout,
    RequestError,
)
from opensearchpy.exceptions import ConnectionError as OSConnectionError
from sift_common.audit import AuditWriter

from opensearch_mcp.client import get_client


def _validate_index(index: str) -> str | None:
    """Validate index parameter starts with 'case-'. Returns error or None."""
    if not index.startswith("case-"):
        return (
            "Index parameter must start with 'case-' (security: blocks access to system indices)"
        )
    return None


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
    except (OSConnectionError, ConnectionTimeout) as e:
        _client = None
        _client_verified = False
        raise RuntimeError(
            "OpenSearch connection temporarily lost — client reset. "
            "Retry your query. If it persists: "
            "docker ps | grep vhir-opensearch"
        ) from e
    except AuthorizationException as e:
        _client = None
        _client_verified = False
        raise RuntimeError(
            "OpenSearch authentication failed. Check opensearch.yaml credentials."
        ) from e
    except RequestError as e:
        # 400 Bad Request — malformed query, missing field, etc.
        info = getattr(e, "info", None) or {}
        err = info.get("error", {})
        reason = err.get("reason", str(e)) if isinstance(err, dict) else str(e)
        raise ValueError(f"Query error: {reason}") from e


def _strip_hits(hits: list[dict]) -> list[dict]:
    """Extract _source from hits with artifact type for cross-index queries."""
    results = []
    for hit in hits:
        src = hit.get("_source", {})
        idx_name = hit.get("_index", "")
        doc = {"_id": hit.get("_id"), "_index": idx_name}
        # Extract artifact type from index name: case-{id}-{type}-{host}
        parts = idx_name.split("-", 2)
        if len(parts) >= 3:
            remainder = parts[2]  # {type}-{host}
            type_parts = remainder.rsplit("-", 1)
            doc["_type"] = type_parts[0] if type_parts else remainder
        doc.update(src)
        results.append(doc)
    return results


def _resolve_index(index: str, case_id: str) -> str:
    """Resolve index pattern from explicit index, case_id, or active case."""
    if index:
        return index
    from opensearch_mcp.paths import sanitize_index_component

    cid = case_id or _get_active_case() or ""
    if cid:
        return f"case-{sanitize_index_component(cid)}-*"
    return "case-*"


def _detect_preparsed_csvs(path: Path) -> str | None:
    """Check for pre-parsed CSV output and suggest the right ingest tool."""
    # Scan flat + one level of subdirs (avoid full tree walk on USB)
    csv_files = [f for f in path.iterdir() if f.suffix.lower() == ".csv"]
    for d in path.iterdir():
        if d.is_dir() and not d.name.startswith("."):
            csv_files.extend(f for f in d.iterdir() if f.suffix.lower() == ".csv")
        if len(csv_files) >= 100:
            break
    csv_files = csv_files[:100]
    if not csv_files:
        return None

    # ZimmermanTools patterns
    zt_patterns = {
        "amcache": "Amcache",
        "shimcache": "AppCompatCache",
        "evtxecmd": "EvtxECmd",
        "mft": "MFTECmd",
        "prefetch": "PECmd",
        "registry": "RECmd",
        "shellbags": "SBECmd",
        "usn": "UsnJrnl",
    }
    found_zt: set[str] = set()
    for f in csv_files:
        name_lower = f.name.lower()
        for key, pattern in zt_patterns.items():
            if pattern.lower() in name_lower:
                found_zt.add(key)

    # Hayabusa detection (check header of first few CSVs)
    hayabusa = False
    for f in csv_files[:5]:
        try:
            header = f.read_text(errors="replace")[:200].lower()
            if "ruletitle" in header and "eventid" in header:
                hayabusa = True
                break
        except OSError:
            pass

    parts = []
    if found_zt:
        parts.append(
            f"Detected ZimmermanTools CSV output "
            f"({', '.join(sorted(found_zt))}). "
            "Use idx_ingest_delimited(path=..., hostname=...) "
            "to ingest."
        )
    if hayabusa:
        parts.append(
            "Detected Hayabusa CSV output. "
            "Use idx_ingest_delimited(path=..., hostname=...) "
            "to ingest."
        )
    if not parts and csv_files:
        parts.append(
            f"Found {len(csv_files)} CSV files but no raw Windows "
            "artifacts. If these are pre-parsed tool output, use "
            "idx_ingest_delimited(path=..., hostname=...)."
        )
    return " ".join(parts) if parts else None


def _validate_path(path: str) -> str | None:
    """Validate path is in allowed locations. Returns error string or None."""
    from opensearch_mcp.paths import vhir_home

    p = Path(path).resolve()
    home = vhir_home().resolve()
    allowed = [
        home,
        Path("/mnt").resolve(),
        Path("/media").resolve(),
        Path("/run/media").resolve(),
        Path("/evidence").resolve(),
        Path("/tmp").resolve(),
    ]
    if not any(p.is_relative_to(a) for a in allowed):
        return f"Path not in allowed locations (~/, /mnt/, /media/, /evidence/, /tmp/): {path}"
    return None


@server.tool()
def idx_search(
    query: str,
    index: str = "",
    case_id: str = "",
    limit: int = 50,
    offset: int = 0,
    sort: str = "@timestamp:desc",
    time_from: str = "",
    time_to: str = "",
) -> dict:
    """Search indexed evidence using OpenSearch query_string syntax.

    Args:
        query: OpenSearch query_string (e.g., 'event.code:4624 AND user.name:admin').
            Quote values with special chars: source.ip:"::1" (IPv6 needs quotes).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern.
        limit: Max results (default 50, max 200).
        offset: Skip first N results for pagination (default 0).
        sort: Sort field:order (default @timestamp:desc).
        time_from: Start time (ISO 8601, e.g., '2023-01-25T14:00:00Z').
        time_to: End time (ISO 8601).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()
    limit = min(limit, 200)

    sort_field, _, sort_order = sort.partition(":")
    if sort_order not in ("asc", "desc", ""):
        sort_order = "desc"
    sort_body = [{sort_field: {"order": sort_order or "desc", "unmapped_type": "date"}}]

    query_body: dict = {"query_string": {"query": query}}
    if time_from or time_to:
        range_filter: dict = {"@timestamp": {}}
        if time_from:
            range_filter["@timestamp"]["gte"] = time_from
        if time_to:
            range_filter["@timestamp"]["lte"] = time_to
        query_body = {
            "bool": {"must": [{"query_string": {"query": query}}, {"range": range_filter}]}
        }

    search_body: dict = {
        "query": query_body,
        "sort": sort_body,
        "size": limit,
    }
    if offset > 0:
        search_body["from"] = min(offset, 10000)  # OpenSearch max_result_window

    result = _os_call(
        client.search,
        index=index,
        body=search_body,
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
    index: str = "",
    case_id: str = "",
) -> dict:
    """Count matching documents.

    Args:
        query: OpenSearch query_string (default: all).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern.
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
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
    index: str = "",
    case_id: str = "",
    limit: int = 50,
) -> dict:
    """Aggregate (group by) a field with optional query filter.

    Args:
        field: Field to aggregate on (e.g., 'host.name', 'event.code').
        query: OpenSearch query_string filter (default: all).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern.
        limit: Max buckets (default 50, max 500).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
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
        {"key": b["key"], "count": b["doc_count"], "doc_count": b["doc_count"]}
        for b in result["aggregations"]["agg"]["buckets"]
    ]

    resp = {
        "field": field,
        "total_docs": result["hits"]["total"]["value"],
        "buckets": buckets,
        "truncated": len(buckets) >= limit,
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
    err = _validate_index(index)
    if err:
        return {"error": err}
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
    index: str = "",
    case_id: str = "",
    interval: str = "1h",
    time_field: str = "@timestamp",
    time_from: str = "",
    time_to: str = "",
) -> dict:
    """Show event count over time as a date histogram.

    Args:
        query: OpenSearch query_string filter.
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern.
        interval: Histogram bucket size (e.g., '1m', '1h', '1d').
        time_field: Timestamp field (default @timestamp).
        time_from: Start time (ISO 8601, e.g., '2023-01-25T14:00:00Z').
        time_to: End time (ISO 8601).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()

    query_body: dict = {"query_string": {"query": query}}
    if time_from or time_to:
        range_filter: dict = {time_field: {}}
        if time_from:
            range_filter[time_field]["gte"] = time_from
        if time_to:
            range_filter[time_field]["lte"] = time_to
        query_body = {
            "bool": {"must": [{"query_string": {"query": query}}, {"range": range_filter}]}
        }

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": query_body,
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
    index: str = "",
    case_id: str = "",
    limit: int = 50,
) -> dict:
    """List unique values for a field (terms aggregation).

    Args:
        field: Field to enumerate (e.g., 'winlog.provider_name').
        query: OpenSearch query_string filter.
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern.
        limit: Max values (default 50, max 500).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
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
        {"value": b["key"], "count": b["doc_count"], "doc_count": b["doc_count"]}
        for b in result["aggregations"]["values"]["buckets"]
    ]

    resp = {"field": field, "values": values, "truncated": len(values) >= limit}
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
            "docs": int(idx.get("docs.count", 0)),
            "size": idx.get("store.size", "0"),
            "status": idx.get("status", "unknown"),
        }
        for idx in indices
        if idx["index"].startswith("case-")
    ]

    case_indices.sort(key=lambda x: x["index"])

    health = _os_call(client.cluster.health)
    cluster_status = health.get("status")
    nodes = health.get("number_of_nodes", 0)
    if cluster_status == "yellow" and nodes <= 1:
        cluster_status = "yellow (normal for single-node deployment)"

    resp = {
        "cluster_status": cluster_status,
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
def idx_case_summary(case_id: str = "") -> dict:
    """Get a complete overview of indexed evidence for a case.

    Returns hosts, artifact types with doc counts, available fields
    per artifact type, and enrichment status. Call this at investigation
    start to understand what data is available before querying.

    Args:
        case_id: Case ID (default: active case).
    """
    from opensearch_mcp.paths import sanitize_index_component

    cid = case_id or _get_active_case()
    if not cid:
        return {"error": "No active case. Run 'vhir case activate' first."}

    client = _get_os()
    safe = sanitize_index_component(cid)
    pattern = f"case-{safe}-*"

    # Get all indices for this case
    try:
        indices = _os_call(client.cat.indices, index=pattern, format="json")
    except ValueError:
        # RequestError — likely no matching indices
        return {"case_id": cid, "error": "No indices found for this case"}
    except RuntimeError as e:
        return {"case_id": cid, "error": str(e)}
    except Exception as e:
        return {"case_id": cid, "error": f"OpenSearch error: {type(e).__name__}"}

    if not indices:
        return {"case_id": cid, "hosts": [], "artifacts": {}, "total_docs": 0}

    # Get hosts from document field (reliable — index name parsing
    # breaks on hostnames with dashes)
    hosts: set = set()
    try:
        host_agg = client.search(
            index=pattern,
            body={
                "size": 0,
                "aggs": {"hosts": {"terms": {"field": "host.name", "size": 500}}},
            },
        )
        for bucket in host_agg["aggregations"]["hosts"]["buckets"]:
            hosts.add(bucket["key"])
    except Exception:
        pass

    # Build artifact map — strip known hostnames from index suffixes
    # to extract the artifact type. Index format: case-{id}-{type}-{host}
    # where both type and host may contain dashes.
    artifacts: dict = {}
    total_docs = 0
    prefix = f"case-{safe}-"
    host_suffixes = sorted(hosts, key=len, reverse=True)  # longest first
    for idx in indices:
        name = idx["index"]
        docs = int(idx.get("docs.count", 0))
        total_docs += docs
        remainder = name[len(prefix) :] if name.startswith(prefix) else name
        # Try stripping each known host suffix
        artifact_type = remainder
        matched_host = ""
        for h in host_suffixes:
            suffix = f"-{h}"
            if remainder.endswith(suffix):
                artifact_type = remainder[: -len(suffix)]
                matched_host = h
                break
        if artifact_type not in artifacts:
            artifacts[artifact_type] = {"docs": 0, "hosts": [], "indices": []}
        artifacts[artifact_type]["docs"] += docs
        if matched_host and matched_host not in artifacts[artifact_type]["hosts"]:
            artifacts[artifact_type]["hosts"].append(matched_host)
        artifacts[artifact_type]["indices"].append(name)

    # Get field mappings per artifact type with types (sample one index per type)
    def _flatten_props(props: dict, prefix: str = "") -> list[dict]:
        fields = []
        for key, val in props.items():
            full = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            if isinstance(val, dict) and "properties" in val:
                fields.extend(_flatten_props(val["properties"], full))
            elif isinstance(val, dict):
                fields.append({"field": full, "type": val.get("type", "object")})
            else:
                fields.append({"field": full, "type": "unknown"})
        return fields

    fields_per_type: dict = {}
    for atype, info in artifacts.items():
        if not info["indices"]:
            continue
        try:
            mapping = client.indices.get_mapping(index=info["indices"][0])
            idx_name = info["indices"][0]
            props = mapping.get(idx_name, {}).get("mappings", {}).get("properties", {})
            fields_per_type[atype] = sorted(_flatten_props(props), key=lambda f: f["field"])[:150]
        except Exception:
            pass

    # Enrichment status
    enrichment: dict = {}
    try:
        triage_count = client.count(
            index=pattern,
            body={"query": {"exists": {"field": "triage.checked"}}},
        )["count"]
        if triage_count:
            suspicious = client.count(
                index=pattern,
                body={"query": {"term": {"triage.verdict": "SUSPICIOUS"}}},
            )["count"]
            enrichment["triage"] = {
                "checked": triage_count,
                "suspicious": suspicious,
            }
    except Exception:
        pass

    try:
        intel_count = client.count(
            index=pattern,
            body={"query": {"exists": {"field": "threat_intel.checked"}}},
        )["count"]
        if intel_count:
            malicious = client.count(
                index=pattern,
                body={"query": {"term": {"threat_intel.verdict": "MALICIOUS"}}},
            )["count"]
            enrichment["threat_intel"] = {
                "checked": intel_count,
                "malicious": malicious,
            }
    except Exception:
        pass

    # Time range
    time_range: dict = {}
    try:
        min_ts = client.search(
            index=pattern,
            body={"size": 0, "aggs": {"min_ts": {"min": {"field": "@timestamp"}}}},
        )
        max_ts = client.search(
            index=pattern,
            body={"size": 0, "aggs": {"max_ts": {"max": {"field": "@timestamp"}}}},
        )
        min_val = min_ts["aggregations"]["min_ts"].get("value_as_string")
        max_val = max_ts["aggregations"]["max_ts"].get("value_as_string")
        if min_val:
            time_range["earliest"] = min_val
        if max_val:
            time_range["latest"] = max_val
    except Exception:
        pass

    resp = {
        "case_id": cid,
        "hosts": sorted(hosts),
        "artifacts": artifacts,
        "total_docs": total_docs,
        "time_range": time_range,
        "fields_per_type": fields_per_type,
        "enrichment": enrichment,
    }
    aid = audit.log(
        tool="idx_case_summary",
        params={"case_id": cid},
        result_summary=f"{len(hosts)} hosts, {len(artifacts)} artifact types, {total_docs} docs",
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
    source_timezone: str = "",
    all_logs: bool = False,
    reduced_ids: bool = False,
    full: bool = False,
    dry_run: bool = True,
    vss: bool = False,
    password: str = "",
) -> dict:
    """Discover and ingest forensic artifacts into OpenSearch.

    Case ID is read from ~/.vhir/active_case. Not accepted as a
    parameter — set via 'vhir case activate'.

    Supports directories (triage packages, mounted images) AND container
    files (VHDX, E01, VMDK, 7z, raw). Containers are auto-detected and
    mounted by the CLI backend.

    Triage enrichment runs automatically during ingest when the Windows
    baseline database is available (local SQLite or remote via gateway).
    Use idx_enrich_triage to re-run on already-indexed data.

    Args:
        path: Evidence path — directory or container file (VHDX, E01, 7z, raw).
        hostname: Source hostname. Auto-detected from directory structure
            if multi-host triage package. Required for flat directories.
        include: Only these artifact types (e.g., ["mft", "usn"]).
        exclude: Skip these artifact types (e.g., ["jumplists"]).
        source_timezone: Evidence system's local timezone (e.g., "Eastern Standard Time").
        all_logs: Parse all evtx files (default: forensic logs only).
        reduced_ids: Filter to ~78 high-value Event IDs.
        full: Include all tiers including MFT, USN, timeline.
        dry_run: Preview without indexing (default True). Set False to execute
            immediately if path and parameters are confirmed.
    """
    import subprocess as _check_sp
    import sys
    from pathlib import Path

    from opensearch_mcp.containers import detect_container
    from opensearch_mcp.ingest import discover

    evidence_path = Path(path).resolve()
    if not evidence_path.exists():
        return {"error": f"Path not found: {path}"}
    path_err = _validate_path(path)
    if path_err:
        return {"error": path_err}

    # Read case from active_case
    from opensearch_mcp.paths import vhir_dir

    active_case = vhir_dir() / "active_case"
    if not active_case.exists():
        return {"error": "No active case. Run 'vhir case activate' first."}
    raw = active_case.read_text().strip()
    if not raw:
        return {"error": "No active case. Run 'vhir case activate' first."}
    case_id = Path(raw).name

    # Container files (VHDX, E01, 7z, raw) — preview without mounting
    container_type = detect_container(evidence_path)
    if container_type in ("ewf", "raw", "nbd", "archive"):
        if dry_run:
            sudo_ok = _check_sp.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
            resp = {
                "status": "preview",
                "container": {
                    "type": container_type,
                    "file": evidence_path.name,
                    "size_mb": round(evidence_path.stat().st_size / 1048576),
                },
                "case_id": case_id,
                "message": (
                    f"Container image detected ({container_type}). "
                    "Set dry_run=false to mount and ingest."
                ),
            }
            if not sudo_ok:
                resp["warning"] = (
                    "Container mounting requires sudo. If ingest fails, "
                    "mount manually and point idx_ingest at the mount."
                )
            if hostname:
                resp["hostname"] = hostname
            else:
                resp["suggested_hostname"] = evidence_path.stem.split("-")[0]
            aid = audit.log(
                tool="idx_ingest",
                params={
                    "path": path,
                    "dry_run": True,
                    "container": container_type,
                },
                result_summary=f"container preview: {container_type}",
            )
            if aid:
                resp["audit_id"] = aid
            return resp
        # dry_run=False falls through to subprocess launch below

    elif not evidence_path.is_dir():
        return {"error": f"Not a directory or supported container: {path}"}

    # Discover (directories only — containers handled by CLI subprocess)
    if evidence_path.is_dir():
        hosts = discover(evidence_path, hostname=hostname or None)
    else:
        hosts = []  # container file — skip discover, go to subprocess

    if not hosts and evidence_path.is_dir():
        csv_hint = _detect_preparsed_csvs(evidence_path)
        if csv_hint:
            return {
                "error": ("No raw Windows artifacts found (no registry hives, evtx files, etc.)."),
                "suggestion": csv_hint,
            }
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
                from opensearch_mcp.paths import sanitize_index_component as _sic

                idx = f"case-{_sic(case_id)}-{suffix}-{_sic(host.hostname)}"
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
    if source_timezone:
        cmd.extend(["--source-timezone", source_timezone])
    if all_logs:
        cmd.append("--all-logs")
    if reduced_ids:
        cmd.append("--reduced-ids")
    if full:
        cmd.append("--full")
    if vss:
        cmd.append("--vss")
    if password:
        cmd.extend(["--password", password])

    proc = _sp.Popen(
        cmd,
        stdout=_sp.DEVNULL,
        stderr=_sp.DEVNULL,
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
            "log_file": ing.get("log_file", ""),
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
def idx_ingest_json(
    path: str,
    hostname: str,
    index_suffix: str = "",
    time_field: str = "",
    dry_run: bool = True,
) -> dict:
    """Ingest JSON/JSONL file into OpenSearch.

    Args:
        path: Path to JSON/JSONL file or directory.
        hostname: Source hostname.
        index_suffix: Index suffix (default: json-{filename}).
        time_field: Timestamp field name (default: auto-detect).
        dry_run: Preview (default True). Set False to execute immediately.
    """
    path_err = _validate_path(path)
    if path_err:
        return {"error": path_err}
    if dry_run:
        from opensearch_mcp.parse_json import _detect_json_format

        p = Path(path)
        if p.is_file():
            fmt = _detect_json_format(p)
            return {"status": "preview", "file": p.name, "format": fmt}
        files = sorted(f.name for f in p.iterdir() if f.suffix.lower() in (".json", ".jsonl"))
        return {"status": "preview", "files": files, "count": len(files)}

    return _launch_background("json", path, hostname, index_suffix, time_field)


@server.tool()
def idx_ingest_delimited(
    path: str,
    hostname: str,
    index_suffix: str = "",
    time_field: str = "",
    delimiter: str = "",
    dry_run: bool = True,
) -> dict:
    """Ingest delimited files (CSV, TSV, Zeek, bodyfile) into OpenSearch.

    Args:
        path: Path to delimited file or directory.
        hostname: Source hostname.
        index_suffix: Index suffix (default: format-{filename}).
        time_field: Timestamp field (default: auto-detect).
        delimiter: Delimiter character (default: auto-detect).
        dry_run: Preview (default True). Set False to execute immediately.
    """
    path_err = _validate_path(path)
    if path_err:
        return {"error": path_err}
    if dry_run:
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        p = Path(path)
        if p.is_file():
            fmt = _detect_delimited_format(p)
            return {"status": "preview", "file": p.name, "format": fmt.get("format")}
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        files = sorted(f.name for f in p.iterdir() if f.suffix.lower() in exts)
        return {"status": "preview", "files": files, "count": len(files)}

    return _launch_background("delimited", path, hostname, index_suffix, time_field)


@server.tool()
def idx_ingest_accesslog(
    path: str,
    hostname: str,
    index_suffix: str = "accesslog",
    dry_run: bool = True,
) -> dict:
    """Ingest Apache/Nginx access logs into OpenSearch.

    Args:
        path: Path to access log file or directory.
        hostname: Source hostname.
        index_suffix: Index suffix (default: accesslog).
        dry_run: Preview (default True). Set False to execute immediately.
    """
    path_err = _validate_path(path)
    if path_err:
        return {"error": path_err}
    if dry_run:
        p = Path(path)
        if p.is_file():
            return {"status": "preview", "file": p.name}
        files = sorted(
            f.name
            for f in p.iterdir()
            if f.suffix.lower() in (".log", ".txt") or "access" in f.name.lower()
        )
        return {"status": "preview", "files": files, "count": len(files)}

    return _launch_background("accesslog", path, hostname, index_suffix)


@server.tool()
def idx_enrich_intel(
    case_id: str = "",
    dry_run: bool = True,
    force: bool = False,
) -> dict:
    """Enrich indexed evidence with OpenCTI threat intelligence.

    Extracts unique IOCs (IPs, hashes, domains) from indexed data,
    looks them up in OpenCTI via the gateway, and stamps matching
    documents with threat_intel.verdict and confidence.

    No LLM tokens consumed — all lookups are programmatic.

    Args:
        case_id: Case to enrich (default: active case).
        dry_run: Extract and count IOCs without lookup (default True).
        force: Re-enrich even if already enriched (default False).
    """
    from opensearch_mcp.paths import sanitize_index_component
    from opensearch_mcp.threat_intel import enrich_case, extract_unique_iocs

    cid = case_id or _get_active_case()
    if not cid:
        return {"error": "No active case. Run 'vhir case activate' first."}

    client = _get_os()
    safe_case = sanitize_index_component(cid)

    if dry_run:
        iocs = extract_unique_iocs(client, f"case-{safe_case}-*", force=force)
        return {
            "status": "preview",
            "case_id": cid,
            "ips": len(iocs["ip"]),
            "hashes": len(iocs["hash"]),
            "domains": len(iocs["domain"]),
            "total_iocs": sum(len(v) for v in iocs.values()),
        }

    result = enrich_case(client, cid, force=force)
    audit.log(
        tool="idx_enrich_intel",
        params={"case_id": cid, "force": force},
        result_summary=(
            f"{result.get('documents_updated', 0)} docs updated, "
            f"{result.get('malicious', 0)} malicious"
            if result.get("status") == "complete"
            else result.get("status", "unknown")
        ),
    )
    return result


@server.tool()
def idx_enrich_triage(
    case_id: str = "",
) -> dict:
    """Run triage baseline enrichment on already-indexed data.

    Checks indexed filenames and services against the Windows baseline
    database (known_good.db) via the gateway. Stamps documents with
    triage.verdict (EXPECTED, SUSPICIOUS, UNKNOWN, EXPECTED_LOLBIN).

    Use this after ingesting evidence to add baseline context, or to
    re-enrich after the triage database is updated.

    Requires gateway with windows-triage-mcp backend running.

    Args:
        case_id: Case to enrich (default: active case).
    """
    from opensearch_mcp.triage_remote import enrich_remote

    cid = case_id or _get_active_case()
    if not cid:
        return {"error": "No active case. Run 'vhir case activate' first."}

    client = _get_os()
    results = enrich_remote(client, cid)

    if "error" in results:
        return results

    total_enriched = sum(r.get("enriched", 0) for r in results.values() if isinstance(r, dict))
    resp = {
        "status": "complete",
        "documents_enriched": total_enriched,
        "details": results,
    }
    audit.log(
        tool="idx_enrich_triage",
        params={"case_id": cid},
        result_summary=f"{total_enriched} docs enriched",
    )
    return resp


_MAX_CONCURRENT_INGESTS = 3


def _launch_background(subcommand, path, hostname, index_suffix="", time_field=""):
    """Launch a generic ingest as background subprocess with concurrency control."""
    import os as _os
    import subprocess as _sp
    import sys as _sys
    import uuid as _uuid
    from datetime import datetime, timezone

    from opensearch_mcp.ingest_status import read_active_ingests, write_status

    active_case = _get_active_case()
    if not active_case:
        return {"error": "No active case. Run 'vhir case activate' first."}

    # Concurrency gate — prevent OpenSearch OOM from unbounded parallelism
    active = read_active_ingests()
    running = [i for i in active if i.get("status") == "running"]
    if len(running) >= _MAX_CONCURRENT_INGESTS:
        return {
            "error": (
                f"Too many concurrent ingests ({len(running)} running, "
                f"max {_MAX_CONCURRENT_INGESTS}). Wait for current ingests "
                "to complete. Use idx_ingest_status() to check progress."
            ),
            "running": [{"case_id": r.get("case_id"), "pid": r.get("pid")} for r in running],
        }

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["VHIR_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        subcommand,
        path,
        "--hostname",
        hostname,
        "--case",
        active_case,
    ]
    if index_suffix:
        cmd.extend(["--index-suffix", index_suffix])
    if time_field:
        cmd.extend(["--time-field", time_field])

    # Log to file instead of DEVNULL so errors are visible
    from opensearch_mcp.paths import vhir_dir

    log_dir = vhir_dir() / "ingest-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.log"
    log_fh = open(log_file, "w")

    proc = _sp.Popen(
        cmd,
        stdout=log_fh,
        stderr=_sp.STDOUT,
        env=env,
        start_new_session=True,
    )
    log_fh.close()

    # Write initial status so concurrency gate sees this process immediately
    started_ts = datetime.now(timezone.utc).isoformat()
    write_status(
        case_id=active_case,
        pid=proc.pid,
        run_id=run_id,
        status="running",
        hosts=[{"hostname": hostname, "artifacts": [{"name": subcommand, "status": "running"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    return {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "log_file": str(log_file),
        "message": (
            f"Ingest started. Call idx_ingest_status() to monitor progress. Log file: {log_file}"
        ),
    }


@server.tool()
def idx_ingest_memory(
    path: str,
    hostname: str,
    tier: int = 1,
    plugins: list[str] | None = None,
    dry_run: bool = True,
) -> dict:
    """Parse a memory image with Volatility 3 and index results.

    Args:
        path: Path to memory image (.raw, .vmem, .dmp, etc.)
        hostname: Source hostname for the memory image.
        tier: Analysis depth (1=fast/essential, 2=moderate, 3=deep).
        plugins: Override tier — run only these specific plugins.
        dry_run: Preview plugins (default True). Set False to execute.
    """
    path_err = _validate_path(path)
    if path_err:
        return {"error": path_err}
    from opensearch_mcp.parse_memory import TIER_1, TIER_2, TIER_3

    if plugins:
        plugin_list = plugins
    elif tier >= 3:
        plugin_list = TIER_3
    elif tier >= 2:
        plugin_list = TIER_2
    else:
        plugin_list = TIER_1

    if dry_run:
        resp = {
            "status": "preview",
            "tier": tier,
            "plugins": plugin_list,
            "plugin_count": len(plugin_list),
        }
        aid = audit.log(
            tool="idx_ingest_memory",
            params={"path": path, "dry_run": True, "tier": tier},
            result_summary=f"preview: {len(plugin_list)} plugins",
        )
        if aid:
            resp["audit_id"] = aid
        return resp

    # dry_run=False: launch as subprocess
    import subprocess as _sp
    import sys as _sys

    active_case = _get_active_case()
    if not active_case:
        return {"error": "No active case. Run 'vhir case activate' first."}

    cmd = [
        _sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        "memory",
        path,
        "--hostname",
        hostname,
        "--case",
        active_case,
        "--tier",
        str(tier),
        "--yes",
    ]
    if plugins:
        cmd.extend(["--plugins", ",".join(plugins)])

    proc = _sp.Popen(cmd, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, start_new_session=True)

    resp = {
        "status": "started",
        "pid": proc.pid,
        "tier": tier,
        "plugins": plugin_list,
        "message": (
            f"Memory analysis started ({len(plugin_list)} plugins). "
            "This may take several minutes. Use idx_ingest_status() to monitor."
        ),
    }
    aid = audit.log(
        tool="idx_ingest_memory",
        params={"path": path, "tier": tier, "pid": proc.pid},
        result_summary=f"started tier {tier} ({len(plugin_list)} plugins)",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def _get_active_case() -> str | None:
    """Read active case ID."""
    from opensearch_mcp.paths import vhir_dir

    active_case = vhir_dir() / "active_case"
    if active_case.exists():
        raw = active_case.read_text().strip()
        if raw:
            from pathlib import Path

            return Path(raw).name
    return None


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

    try:
        response = _os_call(
            client.transport.perform_request,
            "GET",
            "/_plugins/_security_analytics/findings/_search",
            params=params,
        )
    except (RuntimeError, ValueError, Exception) as e:
        if "security_analytics" in str(e).lower() or "400" in str(e) or "404" in str(e):
            return {"error": "Security Analytics plugin not available", "findings": []}
        raise

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
