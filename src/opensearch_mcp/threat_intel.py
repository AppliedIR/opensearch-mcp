"""Post-ingest threat intel enrichment via OpenCTI (through gateway)."""

from __future__ import annotations

import ipaddress
import sys
from datetime import datetime, timezone

from opensearchpy import OpenSearch

# Fields for aggregation and term queries.
# Explicitly-mapped keyword/ip fields use bare names.
# Dynamically-mapped text fields need .keyword suffix.
_IP_FIELDS = [
    "source.ip",  # explicit ip type in evtx/accesslog/w3c templates
    "ForeignAddr.keyword",  # dynamic in vol3_template
    "LocalAddr.keyword",  # dynamic in vol3_template
]

_HASH_FIELDS = [
    "SHA1.keyword",  # dynamic in csv_template
    "SHA256.keyword",  # dynamic in csv_template
    "MD5.keyword",  # dynamic in csv_template
]

_DOMAIN_FIELDS = [
    "dns.query.keyword",  # dynamic in json_template
    "query.keyword",  # dynamic in json/delimited
    "source_host.keyword",  # dynamic (B36 renamed field)
    "server_name.keyword",  # dynamic in delimited
]


def _is_external(ip_str: str) -> bool:
    """Filter out RFC1918, loopback, link-local, multicast."""
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


def extract_unique_iocs(
    client: OpenSearch,
    index_pattern: str,
    force: bool = False,
) -> dict[str, set[str]]:
    """Extract unique IOCs from indexed data using aggregations.

    If force=False, skip docs already enriched (threat_intel.checked: true).
    """
    iocs: dict[str, set[str]] = {"ip": set(), "hash": set(), "domain": set()}

    query: dict = {"match_all": {}}
    if not force:
        query = {
            "bool": {
                "must_not": [{"exists": {"field": "threat_intel.checked"}}],
            }
        }

    for ioc_type, fields in [
        ("ip", _IP_FIELDS),
        ("hash", _HASH_FIELDS),
        ("domain", _DOMAIN_FIELDS),
    ]:
        for field in fields:
            try:
                result = client.search(
                    index=index_pattern,
                    body={
                        "query": query,
                        "size": 0,
                        "aggs": {"values": {"terms": {"field": field, "size": 10000}}},
                    },
                    timeout="60s",
                )
                for bucket in result["aggregations"]["values"]["buckets"]:
                    val = str(bucket["key"])
                    if ioc_type == "ip":
                        if _is_external(val):
                            iocs["ip"].add(val)
                    else:
                        iocs[ioc_type].add(val)
            except Exception as e:
                if "AuthorizationException" in type(e).__name__:
                    print(
                        f"WARNING: OpenSearch auth error during IOC extraction: {e}",
                        file=sys.stderr,
                    )
                continue

    return iocs


def batch_lookup(
    iocs: dict[str, set[str]],
    on_progress=None,
) -> dict[str, dict]:
    """Look up IOCs via gateway -> opencti-mcp -> OpenCTI.

    Returns {ioc_value: result_dict} for found IOCs only.
    """
    from opensearch_mcp.gateway import call_tool, gateway_available

    if not gateway_available():
        print(
            "WARNING: Gateway not configured — skipping OpenCTI lookup",
            file=sys.stderr,
        )
        return {}

    results = {}
    total = sum(len(v) for v in iocs.values())
    done = 0
    consecutive_failures = 0

    for ioc_type, values in iocs.items():
        for value in values:
            if consecutive_failures >= 3:
                print(
                    "WARNING: 3 consecutive OpenCTI failures — stopping lookup",
                    file=sys.stderr,
                )
                return results
            done += 1
            if on_progress and done % 50 == 0:
                on_progress("looking_up", done=done, total=total)
            try:
                resp = call_tool("lookup_ioc", {"ioc": value}, timeout=15)
                consecutive_failures = 0

                if not resp.get("found", False):
                    # Mark as checked (no verdict) so --force skip works
                    results[value] = {
                        "threat_intel.checked": True,
                        "threat_intel.ioc_type": ioc_type,
                        "threat_intel.ioc_value": value,
                        "threat_intel.source": "opencti",
                    }
                    continue

                confidence = resp.get("confidence", 0) or 0
                labels = resp.get("labels", [])

                results[value] = {
                    "threat_intel.verdict": ("MALICIOUS" if confidence >= 80 else "SUSPICIOUS"),
                    "threat_intel.confidence": confidence,
                    "threat_intel.labels": labels,
                    "threat_intel.ioc_type": ioc_type,
                    "threat_intel.ioc_value": value,
                    "threat_intel.source": "opencti",
                }

            except Exception as e:
                consecutive_failures += 1
                print(
                    f"WARNING: OpenCTI lookup failed for {value}: {e}",
                    file=sys.stderr,
                )
                continue

    return results


def stamp_documents(
    client: OpenSearch,
    index_pattern: str,
    ioc_results: dict[str, dict],
) -> int:
    """Stamp indexed documents with threat_intel.* fields via update-by-query."""
    now = datetime.now(timezone.utc).isoformat()
    total_updated = 0

    for ioc_value, intel in ioc_results.items():
        ioc_type = intel.get("threat_intel.ioc_type", "")

        if ioc_type == "ip":
            fields = _IP_FIELDS
        elif ioc_type == "hash":
            fields = _HASH_FIELDS
        elif ioc_type == "domain":
            fields = _DOMAIN_FIELDS
        else:
            continue

        should_clauses = [{"term": {field: ioc_value}} for field in fields]

        intel_with_ts = dict(intel)
        intel_with_ts["threat_intel.enriched_at"] = now
        intel_with_ts["threat_intel.checked"] = True

        set_clauses = []
        params = {}
        for k, v in intel_with_ts.items():
            safe_key = k.replace(".", "_")
            set_clauses.append(f"ctx._source['{k}'] = params.{safe_key}")
            params[safe_key] = v

        try:
            result = client.update_by_query(
                index=index_pattern,
                body={
                    "query": {
                        "bool": {
                            "should": should_clauses,
                            "minimum_should_match": 1,
                        }
                    },
                    "script": {
                        "source": "; ".join(set_clauses),
                        "lang": "painless",
                        "params": params,
                    },
                },
                timeout="120s",
                conflicts="proceed",
                requests_per_second=1000,
            )
            total_updated += result.get("updated", 0)
        except Exception as e:
            print(
                f"WARNING: Update failed for {ioc_value}: {e}",
                file=sys.stderr,
            )

    return total_updated


def enrich_case(
    client: OpenSearch,
    case_id: str,
    force: bool = False,
    on_progress=None,
) -> dict:
    """Full enrichment pipeline for a case.

    Returns summary dict.
    """
    from opensearch_mcp.paths import sanitize_index_component

    safe_case = sanitize_index_component(case_id)
    index_pattern = f"case-{safe_case}-*"

    if on_progress:
        on_progress("extracting", message="Extracting unique IOCs from indexed data")
    iocs = extract_unique_iocs(client, index_pattern, force=force)

    total_iocs = sum(len(v) for v in iocs.values())
    if on_progress:
        on_progress(
            "extracted",
            ips=len(iocs["ip"]),
            hashes=len(iocs["hash"]),
            domains=len(iocs["domain"]),
        )

    if total_iocs == 0:
        return {
            "status": "no_iocs",
            "message": "No external IOCs found in indexed data",
        }

    if on_progress:
        on_progress("looking_up", total=total_iocs)
    results = batch_lookup(iocs, on_progress=on_progress)

    malicious = sum(1 for r in results.values() if r.get("threat_intel.verdict") == "MALICIOUS")
    suspicious = sum(1 for r in results.values() if r.get("threat_intel.verdict") == "SUSPICIOUS")

    if on_progress:
        on_progress("stamping", matched=len(results))
    updated = stamp_documents(client, index_pattern, results)

    return {
        "status": "complete",
        "iocs_extracted": total_iocs,
        "iocs_looked_up": len(results),
        "malicious": malicious,
        "suspicious": suspicious,
        "documents_updated": updated,
    }
