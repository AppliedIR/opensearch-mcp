"""Post-ingest threat intel enrichment via OpenCTI (through gateway)."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from opensearchpy import OpenSearch

# --- Rate-limit pacing + hint parsing (Fix F) ---
#
# OpenCTI server (opencti_mcp/client.py:407-411) raises
# RateLimitError(wait, limit_type) with a wait hint when its token
# bucket drains. Message format (errors.py:101):
#   "Rate limit exceeded for {limit_type}. Wait {wait_seconds:.1f}s."
# Pre-Fix-F, the client ignored the hint and counted each rate-limit
# as a circuit-breaker failure. Pacing + hint parsing together prevent
# self-inflicted rate limits.

_WAIT_RE = re.compile(r"[Ww]ait\s+([\d.]+)", re.IGNORECASE)

# Env-configurable with lower-bound clamping. Read at call time so
# tests can monkeypatch via monkeypatch.setenv after import. A typo of
# 0 would disable pacing/halting entirely, defeating the purpose.


def _min_interval_sec() -> float:
    return max(10, int(os.environ.get("VHIR_INTEL_MIN_INTERVAL_MS", "100"))) / 1000.0


def _circuit_threshold() -> int:
    return max(1, int(os.environ.get("VHIR_INTEL_BREAKER_THRESHOLD", "10")))


def _rate_limit_max_retries() -> int:
    return max(1, int(os.environ.get("VHIR_INTEL_RATE_LIMIT_RETRIES", "5")))


class IntelEnrichmentHalted(RuntimeError):
    """Raised when enrichment halts due to consecutive non-rate-limit
    errors exceeding the circuit-breaker threshold."""


def _parse_wait_hint(msg: str, default: float = 20.0) -> float:
    """Extract 'Wait X.Xs' seconds from a rate-limit message.

    Returns hinted seconds + 0.5s jitter, clamped to [0.5, 120.0].
    Falls back to default on unparseable input.
    """
    if not msg:
        return default
    m = _WAIT_RE.search(msg)
    if not m:
        return default
    try:
        return max(0.5, min(float(m.group(1)) + 0.5, 120.0))
    except ValueError:
        return default


def _is_rate_limit(msg: str) -> bool:
    """True if an OpenCTI error message indicates rate-limiting."""
    lower = (msg or "").lower()
    return "rate limit" in lower or "too many requests" in lower


# --- Coverage map persistence (Fix F) ---
#
# The enrichment loop persists a per-IOC status map to
# {case_dir}/enrichment/coverage-{run_id}.json via atomic rename on
# every IOC completion. A crash mid-run leaves a valid JSON file on
# disk reflecting the last-completed IOC, so the examiner can resume
# enrichment targeting only the unenriched IOCs.


def _coverage_path_for_run(run_id: str) -> Path:
    """Resolve the on-disk coverage-map path for this enrichment run."""
    from opensearch_mcp.paths import vhir_dir

    active_case_file = vhir_dir() / "active_case"
    case_dir: Path
    if active_case_file.exists():
        raw = active_case_file.read_text().strip()
        case_dir = Path(raw) if raw else vhir_dir() / "cases" / "unknown"
    else:
        case_dir = vhir_dir() / "cases" / "unknown"
    enrichment_dir = case_dir / "enrichment"
    enrichment_dir.mkdir(parents=True, exist_ok=True)
    safe_run = re.sub(r"[^A-Za-z0-9._-]", "_", run_id or "unknown")
    return enrichment_dir / f"coverage-{safe_run}.json"


def _atomic_write_coverage(path: Path, data: dict) -> None:
    """Write coverage map via atomic rename.

    POSIX os.replace is atomic on the same filesystem. Crash after
    rename leaves a valid JSON; crash before leaves the previous
    version intact.
    """
    tmp = path.with_suffix(f".tmp.{os.getpid()}")
    try:
        tmp.write_text(json.dumps(data, indent=2, default=str))
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _load_coverage(path: Path) -> dict:
    """Load existing coverage map (for resume) or return empty scaffold."""
    try:
        if path.exists():
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                data.setdefault("enriched", [])
                data.setdefault("skipped", {})
                return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"enriched": [], "skipped": {}}


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
    warnings: list[str] = []
    any_succeeded = False

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
                    request_timeout=60,
                )
                any_succeeded = True
                agg_vals = result["aggregations"]["values"]
                other_count = agg_vals.get("sum_other_doc_count", 0)
                if other_count > 0:
                    warnings.append(
                        f"{field}: {other_count} additional unique values "
                        "not included (limit 10000)"
                    )
                for bucket in agg_vals["buckets"]:
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

    if not any_succeeded:
        raise RuntimeError("IOC extraction failed -- all OpenSearch queries failed")

    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    return iocs


def batch_lookup(
    iocs: dict[str, set[str]],
    on_progress=None,
) -> dict[str, dict]:
    """Look up IOCs via gateway -> opencti-mcp -> OpenCTI.

    Rev 6 — adds:
      - Inter-request pacing (~10 QPS default, env-configurable) to
        avoid self-inflicting OpenCTI rate-limits.
      - Rate-limit hint parsing ("Wait X.Xs"); sleeps + retries without
        counting against the circuit breaker.
      - Per-IOC coverage map persisted via atomic rename, enabling
        resume after crash.

    Returns {ioc_value: result_dict} for found IOCs + a
    "_intel_coverage" key with the complete enriched/skipped map.
    """
    from opensearch_mcp.gateway import call_tool, gateway_available

    if not gateway_available():
        print(
            "WARNING: Gateway not configured — skipping OpenCTI lookup",
            file=sys.stderr,
        )
        return {}

    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or f"enrich-{os.getpid()}"
    coverage_path = _coverage_path_for_run(run_id)
    coverage = _load_coverage(coverage_path)  # resume-aware
    already_done = set(coverage["enriched"]) | set(coverage["skipped"].keys())

    # Snapshot env-tuned thresholds at call time (allows monkeypatch in tests).
    min_interval = _min_interval_sec()
    circuit_threshold = _circuit_threshold()
    rate_limit_max_retries = _rate_limit_max_retries()

    results: dict = {}
    total = sum(len(v) for v in iocs.values())
    done = 0
    consecutive_failures = 0
    last_call = 0.0  # monotonic clock of last request

    for ioc_type, values in iocs.items():
        for value in values:
            if consecutive_failures >= circuit_threshold:
                print(
                    f"WARNING: {consecutive_failures} consecutive OpenCTI "
                    f"non-rate-limit errors — halting enrichment",
                    file=sys.stderr,
                )
                coverage["skipped"].setdefault(value, "circuit_breaker_halt")
                _atomic_write_coverage(coverage_path, coverage)
                results["_intel_coverage"] = coverage
                return results

            done += 1
            if on_progress and done % 50 == 0:
                on_progress("looking_up", done=done, total=total)

            # Resume: skip IOCs previously handled (enriched or skipped).
            if value in already_done:
                continue

            # Pacing: enforce minimum gap since previous request return.
            elapsed = time.monotonic() - last_call
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

            attempt = 0
            ioc_handled = False
            while attempt < rate_limit_max_retries and not ioc_handled:
                try:
                    resp = call_tool("lookup_ioc", {"ioc": value}, timeout=15)
                except Exception as e:
                    consecutive_failures += 1
                    coverage["skipped"][value] = f"exception: {str(e)[:120]}"
                    print(
                        f"WARNING: OpenCTI lookup failed for {value}: {e}",
                        file=sys.stderr,
                    )
                    ioc_handled = True
                    break
                last_call = time.monotonic()
                err = resp.get("error")
                msg = resp.get("message", err or "") if err else ""

                if err and _is_rate_limit(msg):
                    wait = _parse_wait_hint(msg)
                    print(
                        f"INFO: OpenCTI rate-limit on {value}; sleeping "
                        f"{wait:.1f}s (attempt {attempt + 1}/"
                        f"{rate_limit_max_retries})",
                        file=sys.stderr,
                    )
                    time.sleep(wait)
                    attempt += 1
                    continue

                if err:
                    # Genuine non-rate-limit error — count toward breaker.
                    consecutive_failures += 1
                    coverage["skipped"][value] = f"error: {msg[:120]}"
                    print(
                        f"WARNING: OpenCTI error for {value}: {msg}",
                        file=sys.stderr,
                    )
                    ioc_handled = True
                    break

                # Success — reset breaker; record enrichment.
                consecutive_failures = 0
                coverage["enriched"].append(value)

                if not resp.get("found", False):
                    results[value] = {
                        "threat_intel.checked": True,
                        "threat_intel.ioc_type": ioc_type,
                        "threat_intel.ioc_value": value,
                        "threat_intel.source": "opencti",
                    }
                else:
                    confidence = resp.get("confidence", 0) or 0
                    labels = resp.get("labels", [])
                    results[value] = {
                        "threat_intel.verdict": (
                            "MALICIOUS" if confidence >= 80 else "SUSPICIOUS"
                        ),
                        "threat_intel.confidence": confidence,
                        "threat_intel.labels": labels,
                        "threat_intel.ioc_type": ioc_type,
                        "threat_intel.ioc_value": value,
                        "threat_intel.source": "opencti",
                    }
                ioc_handled = True
                break

            if not ioc_handled:
                # Loop exhausted on rate-limits only — skip this IOC
                # without counting as a breaker failure (transient).
                print(
                    f"WARNING: exhausted {rate_limit_max_retries} "
                    f"rate-limit retries for {value}; skipping",
                    file=sys.stderr,
                )
                coverage["skipped"][value] = "rate_limit_exhausted"

            # Persist coverage after every IOC (resumability).
            _atomic_write_coverage(coverage_path, coverage)

    results["_intel_coverage"] = coverage
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
                request_timeout=120,
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
