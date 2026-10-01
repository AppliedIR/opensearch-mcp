"""Post-ingest threat intel enrichment via OpenCTI (through gateway)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    """Raised when an enrichment run cannot report itself complete: an
    extracted IOC has no confirmed lookup (gateway missing, lookups failing,
    rate limit exhausted, an unconfirmed not-found, the circuit breaker), or
    a stamp did not land. The verdicts that were confirmed are still
    stamped; the message says what is missing and why.

    `summary` holds the run's counts when the halt comes after stamping:
    documents were modified, and the caller records them."""

    def __init__(self, reason: str, summary: dict | None = None):
        super().__init__(reason)
        self.summary = summary


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


# Fields read for each IOC type. A bare name is a `keyword` field as the json
# and delimited templates map it; its `.keyword` form is the sub-field a
# dynamically mapped `text` field gets (csv, vol3). A form an index does not
# have aggregates to nothing. The newer names were measured on real cases
# (2026-09-30): the evidence held its IOCs under them and nothing read them.
_IP_FIELDS = [
    "source.ip",  # explicit ip type in evtx/accesslog/w3c templates
    "ForeignAddr.keyword",  # dynamic in vol3_template
    "LocalAddr.keyword",  # dynamic in vol3_template
    "ForeignAddress",  # Kansa netstat
    "ForeignAddress.keyword",
    "Raddr.IP",  # Velociraptor Windows.Network.Netstat remote address
    "Raddr.IP.keyword",
    "winlog.event_data.IpAddress",  # Security logons
    "winlog.event_data.IpAddress.keyword",
    "winlog.event_data.SourceIp",  # Sysmon network connections
    "winlog.event_data.SourceIp.keyword",
    "winlog.event_data.DestinationIp",
    "winlog.event_data.DestinationIp.keyword",
]

_HASH_FIELDS = [
    "SHA1.keyword",  # dynamic in csv_template (Amcache, EZ CSV)
    "SHA256.keyword",  # dynamic in csv_template
    "MD5.keyword",  # dynamic in csv_template
    "Hash.MD5",  # Velociraptor Windows.System.Pslist
    "Hash.MD5.keyword",
    "Hash.SHA1",
    "Hash.SHA1.keyword",
    "Hash.SHA256",
    "Hash.SHA256.keyword",
    "Hash",  # Kansa ProcsWMI (upper-case MD5); a Prefetch path hash fails validation
    "Hash.keyword",
    "winlog.event_data.Hashes",  # Sysmon 1/6/7: "MD5=…,SHA256=…,IMPHASH=…", parsed
    "winlog.event_data.Hashes.keyword",
]

# Bulk filesystem hashes — about 140,000 per host — are read only on request.
_FILESYSTEM_HASH_FIELDS = [
    "md5",  # bodyfile
    "md5.keyword",
]

_DOMAIN_FIELDS = [
    "dns.query.keyword",  # dynamic in json_template
    "query.keyword",  # dynamic in json/delimited
    "source_host.keyword",  # dynamic (B36 renamed field)
    "server_name.keyword",  # dynamic in delimited
    "winlog.event_data.QueryName",  # Sysmon DNS queries
    "winlog.event_data.QueryName.keyword",
]

# The hashes of zero bytes. They identify no file — pslist records them for
# processes with no image path (System, Registry) — and threat-intel sources
# list them as indicators, so a lookup would mark those processes suspicious.
_EMPTY_INPUT_HASHES = frozenset(
    hashlib.new(algorithm, b"").hexdigest() for algorithm in ("md5", "sha1", "sha256")
)

# Hash kinds kept from a Sysmon `Hashes` value. IMPHASH hashes a PE's import
# table, not the file, so it is never looked up as a file hash.
_SYSMON_HASH_KINDS = frozenset({"MD5", "SHA1", "SHA256"})


def _sysmon_hashes(value: str) -> list[str]:
    """The MD5 / SHA1 / SHA256 parts of a Sysmon `Hashes` value."""
    parts = []
    for part in value.split(","):
        kind, _, digest = part.strip().partition("=")
        if kind.strip().upper() in _SYSMON_HASH_KINDS:
            parts.append(digest.strip())
    return parts


_PARSED_FIELDS = {
    "winlog.event_data.Hashes": _sysmon_hashes,
    "winlog.event_data.Hashes.keyword": _sysmon_hashes,
}


class IOCExtractionError(RuntimeError):
    """A request extraction depends on failed; its values are unknown, which
    must not read as "no IOCs"."""


def _is_external(ip_str: str) -> bool:
    """Filter out RFC1918, loopback, link-local, multicast."""
    try:
        address = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # `is_global` is True for multicast (224.0.0.251, 239.255.255.250,
    # ff02::fb), which Sysmon DestinationIp and Kansa ARP carry.
    return address.is_global and not address.is_multicast


# Hash validation — covers every STIX file-hash type OpenCTI's
# stix_cyber_observable schema accepts (UAT 2026-04-23 follow-up to the
# rate-limit raise). Without this, the extractor used to ship any value
# from a SHA256/SHA1/MD5 field to OpenCTI, including text fragments
# that looked nothing like a hash — OpenCTI's fuzzy search would return
# real-looking label matches (malware-bazaar, rat, loader) and stamp
# clean docs MALICIOUS. Fast + noisy is worse than slow + noisy, so
# validator ships before any bulk run against the raised rate limit.
#
# Hex hash lengths (all length-ambiguous — we do NOT pre-classify by
# length; OpenCTI's stix_cyber_observable.list(search=...) multi-field
# matches across all hash fields. Pre-classification would misattribute
# IMPHASH as MD5, PESHA1 as SHA-1, etc.):
#   32  — MD5, IMPHASH, AUTHENTIHASH, GIMPHASH, MD6, JA3, JA3S
#   40  — SHA-1, RIPEMD-160, PESHA1  (NOTE: Ethereum wallets are 40-hex
#         but always carry a `0x` prefix → _HEX_RE rejects them here;
#         the 0x prefix makes the total length 42 and the `x` fails the
#         hex class. Wallets in hash fields are therefore correctly
#         dropped; a future crypto-wallet observable type would extract
#         them from a dedicated field.)
#   56  — SHA-224, SHA3-224
#   64  — SHA-256, SHA3-256, PESHA256, BLAKE2s, BLAKE3
#   96  — SHA-384, SHA3-384
#   128 — SHA-512, SHA3-512, WHIRLPOOL, BLAKE2b
#
# Fuzzy hashes (non-hex):
#   SSDEEP   — <n>:<base64ish>:<base64ish>
#   TLSH     — T1/T2 + 70 hex (first char is T)
#   TELFHASH — 70 lowercase alphanumeric
#
# Not supported (fall through to reject — rare enough in forensic
# corpora that the 2-line addition isn't worth the surface area):
#   JA4      — colon-segmented (e.g. t13d1516h2_8daaf6152771_...)
#   JARM     — 62 hex
# Add to _HEX_HASH_LENGTHS / a dedicated regex if they become needed.
_HEX_HASH_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SSDEEP_RE = re.compile(r"^\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")
_TLSH_RE = re.compile(r"^T[12][0-9A-Fa-f]{70}$")
_TELFHASH_RE = re.compile(r"^[a-z0-9]{70}$")


def _is_valid_hash(val: str) -> bool:
    """Validate a hash observable against STIX file-hash formats.

    Accepts any hex hash at a recognised cryptographic length, plus
    SSDEEP / TLSH / TELFHASH fuzzy hashes. Rejects everything else —
    including text fragments from mis-mapped amcache/evtx/mft fields
    that previously slipped through as `ioc_type=hash` and drove the
    observed false-positive MALICIOUS stamps.
    """
    if not val:
        return False
    length = len(val)
    if length in _HEX_HASH_LENGTHS and _HEX_RE.match(val):
        return True
    if length == 72 and _TLSH_RE.match(val):
        return True
    if length == 70 and _TELFHASH_RE.match(val):
        return True
    if _SSDEEP_RE.match(val):
        return True
    return False


# Domain validation — RFC 1035 label rules, with pragmatic concessions:
# single-label hostnames are rejected (netbios names aren't OpenCTI
# observables), IP-as-string is rejected here (gets routed to ip path),
# anything with whitespace, control chars, or path separators is
# rejected (source_host.keyword picks up a lot of these from evtx).
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _is_valid_domain(val: str) -> bool:
    """Validate a domain observable against RFC 1035 label rules.

    Rejects single-label hostnames (netbios), IP literals (routed via
    the ip path), and anything with whitespace / control chars /
    path separators. Accepts underscores ONLY in labels that are not
    the TLD — pure-DNS policies reject underscores but many real
    records (DMARC, DKIM TXT) include them, and OpenCTI stores them.
    """
    if not val or len(val) > 253:
        return False
    # Reject control chars, whitespace, slashes, and common garbage.
    if any(c.isspace() or c in "\\/:\x00" for c in val):
        return False
    # Reject IP literals — they belong on the ip path.
    try:
        ipaddress.ip_address(val)
        return False
    except ValueError:
        pass
    labels = val.split(".")
    if len(labels) < 2:
        return False  # Single-label hostnames aren't DNS observables
    for label in labels:
        # Allow underscores in non-TLD labels (DMARC / DKIM etc.).
        check = _DOMAIN_LABEL_RE
        if label is not labels[-1] and "_" in label:
            if not re.match(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$", label):
                return False
            continue
        if not check.match(label):
            return False
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    return True


def _lookup_form(ioc_type: str, value: str) -> str:
    """The value as it is looked up and deduplicated: lower case where case
    carries no meaning (hex hashes, IPs, domains). SSDEEP is base64 and TLSH
    has a format prefix, so both are kept as they are."""
    if ioc_type != "hash" or _HEX_RE.match(value):
        return value.lower()
    return value


def _aggregatable_indices(caps: dict, field: str) -> list[str]:
    """The indices where a terms aggregation on `field` can run.

    An index that maps the field as text (PECmd prefetch's `Hash`, by dynamic
    mapping) fails the request when it is the only one, and fails its shards
    in a 200 otherwise. `caps` is a `_field_caps` response; an entry lists its
    indices only when the field has more than one type.
    """
    found: set[str] = set()
    for entry in caps.get("fields", {}).get(field, {}).values():
        indices = set(entry.get("indices", caps.get("indices", [])))
        if entry.get("aggregatable"):
            found |= indices
        elif "non_aggregatable_indices" in entry:
            found |= indices - set(entry["non_aggregatable_indices"])
    return sorted(found)


def extract_unique_iocs(
    client: OpenSearch,
    index_pattern: str,
    force: bool = False,
    include_filesystem: bool = False,
) -> dict[str, dict[str, set[tuple[str, str]]]]:
    """Extract unique IOCs from indexed data using aggregations.

    Returns {ioc_type: {lookup value: {(field, value as stored)}}}: stamping
    needs the stored form, which differs from the lookup value for an
    upper-case hash and for every part of a Sysmon `Hashes` string.

    If force=False, skip docs already enriched (threat_intel.checked: true).
    `include_filesystem` adds bulk filesystem hashes (bodyfile).

    A failed request raises IOCExtractionError: its values are unknown, and
    reading them as absent would report a case as having no IOCs.
    """
    iocs: dict[str, dict[str, set[tuple[str, str]]]] = {"ip": {}, "hash": {}, "domain": {}}
    warnings: list[str] = []
    # Per-field rejection counts. Without field attribution, operators
    # can't tell WHICH field is feeding garbage values into the
    # extractor — and can't tune the field list. Aggregate rejects
    # per field and surface them as warnings at the end.
    rejected_by_field: dict[str, int] = {}

    query: dict = {"match_all": {}}
    if not force:
        query = {
            "bool": {
                "must_not": [{"exists": {"field": "threat_intel.checked"}}],
            }
        }

    # Per-type validators (UAT 2026-04-23): without these, any value
    # aggregated from a *_HASH_FIELDS / *_DOMAIN_FIELDS field was passed
    # through to OpenCTI. OpenCTI's fuzzy-label match then produced
    # real-looking MALICIOUS stamps on doc fragments like
    # "astloggedonuser:[(-1,1)]..." — ~845K false positives in the
    # observed case. Validators reject malformed values at extraction
    # time so OpenCTI only ever sees something that parses as its
    # claimed type. IP already had _is_external (which requires a
    # parseable address).
    validators: dict[str, Any] = {
        "ip": _is_external,
        "hash": _is_valid_hash,
        "domain": _is_valid_domain,
    }

    hash_fields = _HASH_FIELDS + (_FILESYSTEM_HASH_FIELDS if include_filesystem else [])
    field_sets = [("ip", _IP_FIELDS), ("hash", hash_fields), ("domain", _DOMAIN_FIELDS)]
    try:
        caps = client.field_caps(
            index=index_pattern,
            fields=",".join(field for _, fields in field_sets for field in fields),
            request_timeout=60,
        )
    except Exception as e:
        raise IOCExtractionError(
            f"IOC extraction failed reading field mappings: {type(e).__name__}: {e}"
        ) from e
    for ioc_type, fields in field_sets:
        validate = validators[ioc_type]
        for field in fields:
            indices = _aggregatable_indices(caps, field)
            if not indices:
                continue
            try:
                # The index list goes in the request body: in the URL, a
                # case's index names pass the 4096-byte HTTP line limit.
                (result,) = client.msearch(
                    body=[
                        {"index": indices},
                        {
                            "query": query,
                            "size": 0,
                            "aggs": {"values": {"terms": {"field": field, "size": 10000}}},
                        },
                    ],
                    request_timeout=60,
                )["responses"]
                if "error" in result:
                    raise RuntimeError(json.dumps(result["error"])[:500])
            except Exception as e:
                raise IOCExtractionError(
                    f"IOC extraction failed on {field}: {type(e).__name__}: {e}"
                ) from e
            agg_vals = result["aggregations"]["values"]
            other_count = agg_vals.get("sum_other_doc_count", 0)
            if other_count > 0:
                warnings.append(
                    f"{field}: {other_count} additional unique values not included (limit 10000)"
                )
            split = _PARSED_FIELDS.get(field)
            field_rejects = 0
            for bucket in agg_vals["buckets"]:
                stored = str(bucket["key"])
                for val in split(stored) if split else [stored]:
                    if validate(val):
                        lookup = _lookup_form(ioc_type, val)
                        if ioc_type == "hash" and lookup in _EMPTY_INPUT_HASHES:
                            continue
                        iocs[ioc_type].setdefault(lookup, set()).add((field, stored))
                    else:
                        field_rejects += 1
            if field_rejects:
                rejected_by_field[field] = rejected_by_field.get(field, 0) + field_rejects

    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    # Surface per-field rejection totals so operators can audit which
    # mapped field is producing non-IOC text (e.g. amcache
    # astloggedonuser bleeding into SHA256.keyword). Sorted high→low so
    # the top offender is obvious.
    if rejected_by_field:
        total = sum(rejected_by_field.values())
        print(
            f"INFO: dropped {total} malformed values at extraction "
            "(failed type validation; would otherwise produce OpenCTI "
            "false-positive stamps):",
            file=sys.stderr,
        )
        for field, count in sorted(rejected_by_field.items(), key=lambda kv: -kv[1])[:10]:
            print(f"  {field}: {count} rejected", file=sys.stderr)

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
        raise IntelEnrichmentHalted("gateway not configured — no IOC was looked up")

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
                if not isinstance(resp, dict):
                    resp = {"text": json.dumps(resp)}
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

                if "found" not in resp or "note" in resp or "error" in resp:
                    # Confirmed only when the answer says found or not found
                    # and carries no note or error. A not-found with a note
                    # did not complete (the observable search failed, say),
                    # and a reply without `found` (a tool's plain-text
                    # output) answered nothing: neither is stamped or counted.
                    detail = resp.get("note") or resp.get("text") or json.dumps(resp)
                    coverage["skipped"][value] = f"unconfirmed: {str(detail)[:120]}"
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


# Stamp order: a verdict of higher rank is written later, so it stands.
_VERDICT_RANK = {"SUSPICIOUS": 1, "MALICIOUS": 2}


def stamp_documents(
    client: OpenSearch,
    index_pattern: str,
    ioc_results: dict[str, dict],
    origins: dict[str, set[tuple[str, str]]],
) -> tuple[int, int, int]:
    """Stamp indexed documents with threat_intel.* fields via update-by-query.

    Returns (documents updated, version conflicts, stamp requests that failed).

    `origins` maps each looked-up value to the (field, value as stored) pairs
    extraction found it under. The documents are matched on those: the lookup
    value is lower-cased, and a Sysmon `Hashes` part is stored inside the
    whole string, so a term on the lookup value missed both.

    A document carrying several IOCs is stamped once per IOC, and the last
    stamp's fields stand. So the IOCs are stamped in ascending rank — not
    found, then SUSPICIOUS, then MALICIOUS — and each request refreshes, so
    the next one reads the document it just wrote. Without the refresh a
    later request met a stale version and skipped the document: measured on
    copies of real pslist, Sysmon and ProcsWMI documents, 123-289 of 1,124
    lost their MALICIOUS verdict. A conflict that still happens is counted
    and returned, never retried here.
    """
    now = datetime.now(timezone.utc).isoformat()
    total_updated = 0
    conflicts = 0
    failed = 0

    ranked = sorted(
        ioc_results.items(),
        key=lambda item: (_VERDICT_RANK.get(item[1].get("threat_intel.verdict"), 0), item[0]),
    )
    for ioc_value, intel in ranked:
        where = origins.get(ioc_value)
        if not where:
            continue

        should_clauses = [{"term": {field: stored}} for field, stored in sorted(where)]

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
                refresh=True,
            )
            total_updated += result.get("updated", 0)
            conflicts += result.get("version_conflicts", 0)
        except Exception as e:
            failed += 1
            print(
                f"WARNING: Update failed for {ioc_value}: {e}",
                file=sys.stderr,
            )

    return total_updated, conflicts, failed


def _incomplete(
    iocs: dict[str, dict], coverage: dict, conflicts: int, failed_stamps: int
) -> str | None:
    """Why the run is not complete, or None if it is: every extracted IOC has
    a confirmed lookup and every stamp landed."""
    enriched = set(coverage.get("enriched", []))
    skipped = coverage.get("skipped", {})
    extracted = [value for found in iocs.values() for value in found]
    causes: dict[str, int] = {}
    first = ""
    for value in extracted:
        if value in enriched:
            continue
        detail = skipped.get(value, "not looked up")
        cause = detail.split(":", 1)[0].strip()
        causes[cause] = causes.get(cause, 0) + 1
        first = first or f"{value}: {detail}"
    parts = []
    if causes:
        breakdown = ", ".join(f"{cause} {n}" for cause, n in sorted(causes.items()))
        missing = sum(causes.values())
        parts.append(
            f"{missing} of {len(extracted)} IOCs have no confirmed lookup ({breakdown}; "
            f"first: {first})"
        )
    if conflicts:
        parts.append(f"{conflicts} documents skipped on a version conflict while stamping")
    if failed_stamps:
        parts.append(f"{failed_stamps} stamp requests failed")
    return "; ".join(parts) or None


def enrich_case(
    client: OpenSearch,
    case_id: str,
    force: bool = False,
    on_progress=None,
    include_filesystem: bool = False,
) -> dict:
    """Full enrichment pipeline for a case.

    `include_filesystem` also looks up bulk filesystem hashes (bodyfile).

    Returns summary dict.
    """
    from opensearch_mcp.paths import sanitize_index_component

    safe_case = sanitize_index_component(case_id)
    index_pattern = f"case-{safe_case}-*"

    if on_progress:
        on_progress("extracting", message="Extracting unique IOCs from indexed data")
    iocs = extract_unique_iocs(
        client, index_pattern, force=force, include_filesystem=include_filesystem
    )

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
    coverage = results.pop("_intel_coverage", {})

    malicious = sum(1 for r in results.values() if r.get("threat_intel.verdict") == "MALICIOUS")
    suspicious = sum(1 for r in results.values() if r.get("threat_intel.verdict") == "SUSPICIOUS")

    if on_progress:
        on_progress("stamping", matched=len(results))
    origins = {value: where for found in iocs.values() for value, where in found.items()}
    updated, conflicts, failed_stamps = stamp_documents(client, index_pattern, results, origins)

    counts = {
        "iocs_extracted": total_iocs,
        "iocs_looked_up": len(results),
        "malicious": malicious,
        "suspicious": suspicious,
        "documents_updated": updated,
        "version_conflicts": conflicts,
    }
    # Complete only when every IOC had a confirmed lookup and every stamp
    # landed. A run that looked nothing up read "complete, 0 malicious".
    reason = _incomplete(iocs, coverage, conflicts, failed_stamps)
    if reason:
        raise IntelEnrichmentHalted(reason, summary={"status": "incomplete", **counts})

    return {"status": "complete", **counts}
