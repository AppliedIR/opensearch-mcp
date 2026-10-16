"""OpenSearch MCP server — 17 tools for forensic evidence querying, ingest, and enrichment."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
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
from opensearch_mcp.ingest_counts import NOTE as _COUNTS_NOTE
from opensearch_mcp.ingest_counts import describe as _describe_counts
from opensearch_mcp.ingest_status import _LIVE, left_out
from opensearch_mcp.ingest_status import MAX_RUNNING as _MAX_RUNNING
from opensearch_mcp.paths import members

logger = logging.getLogger(__name__)


def _validate_index(index: str) -> str | None:
    """Validate all index segments start with 'case-'. Returns error or None."""
    if not index or not index.strip():
        return "Index parameter must not be empty"
    for segment in index.split(","):
        segment = segment.strip()
        if not segment:
            continue
        if not segment.startswith("case-"):
            return (
                f"Index segment '{segment}' must start with 'case-' "
                "(security: blocks access to system indices)"
            )
    return None


server = FastMCP("opensearch-mcp")
audit = AuditWriter(mcp_name="opensearch-mcp")

# --- Enrichment Token Budget: Layer 11 shimcache/amcache decay ---
_shimcache_reminder_count = 0


def _add_shimcache_reminder(resp: dict, index_pattern: str, docs: list) -> None:
    """Add discipline reminder when query hits shimcache/amcache indices."""
    global _shimcache_reminder_count
    hits = (
        "shimcache" in index_pattern
        or "appcompatcache" in index_pattern
        or "amcache" in index_pattern
    )
    if not hits and docs:
        hits = any(
            "shimcache" in d.get("_index", "")
            or "appcompatcache" in d.get("_index", "")
            or "amcache" in d.get("_index", "")
            for d in docs
        )
    if not hits:
        return
    _shimcache_reminder_count += 1
    if _shimcache_reminder_count <= 2:
        resp["discipline_reminder"] = (
            "IMPORTANT: Shimcache and Amcache prove FILE PRESENCE only, "
            "never execution. The 'Executed' column in AppCompatCacheParser "
            "is unreliable on all Windows versions — do not use it to prove "
            "or disprove execution. To prove execution: check Prefetch, "
            "RegRipper BAM plugin (rip.pl -r SYSTEM -p bam — Windows 10 1709+ only, "
            "entries expire after 7 days, local executables only), UserAssist "
            "(rip.pl -r NTUSER.DAT -p userassist), or process creation "
            "events (EID 4688, Sysmon EID 1)."
        )
    else:
        resp["discipline_reminder"] = "Shimcache/Amcache = PRESENCE only, not execution."


def _elapsed_seconds(ing: dict) -> float:
    """A finished run's own elapsed_seconds. A live run's status writes don't
    pass it, so its time is counted from `started` (UTC when it names no zone)."""
    stored = ing.get("elapsed_seconds", 0)
    if ing.get("status") not in _LIVE:
        return stored
    from datetime import datetime, timezone

    try:
        started = datetime.fromisoformat(str(ing.get("started", "")))
    except ValueError:
        return stored
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return max(stored, (datetime.now(timezone.utc) - started).total_seconds())


# --- Enrichment Token Budget: Layer 9 investigation hints decay ---
_hints_delivered: set[tuple[str, str]] = set()  # (case, hint) already returned


def _add_investigation_hints(resp: dict, artifacts: dict, case: str) -> None:
    """Add investigation hints to idx_case_summary. Each hint is given once per
    case, the first time its artifact type is there; the pointer after."""
    hints = []
    art_keys = set(artifacts.keys())
    has_mft = any("mft" in k for k in art_keys)
    has_usn = any("usn" in k or "usnjournal" in k for k in art_keys)
    has_evtx = any("evtx" in k for k in art_keys)
    has_prefetch = any("prefetch" in k or "pecmd" in k for k in art_keys)
    if has_mft:
        hints.append(
            "MFT indexed. Timestomping: SI<FN:True OR "
            "uSecZeros:True (exclude WinSxS). "
            "Deleted: InUse:False. ADS: HasAds:True. "
            "Zone.Identifier: FileName\\*:(*.exe\\:Zone.Identifier OR "
            "*.dll\\:Zone.Identifier OR *.ps1\\:Zone.Identifier)"
        )
    if has_usn:
        hints.append(
            "USN Journal indexed. "
            + (  # only the EZ usn index has no event time; delim-/json- copies map one
                "It has no event time, so time_from/time_to skip it: filter on its own "
                "field, UpdateTimestamp:[<from> TO <to>], with index=. "
                if "usn" in art_keys
                else "Use time_from/time_to. "
            )
            + "Deleted Prefetch: UpdateReasons:*Delete* AND ParentPath:*Prefetch*. "
            "Code deployment: Name:(*.exe OR *.dll OR *.ps1) AND UpdateReasons:*FileCreate*. "
            "SDelete: Name:AAAAAAA* AND UpdateReasons:*Rename* "
            "(verify with surrounding entries). "
            "Cross-host: idx_aggregate(field='host.id', "
            "query='(Name:<file>) AND _exists_:UpdateReasons'); omit index, and pass "
            "case_id unless this case is active"
        )
    if has_evtx:
        hints.append(
            "EVTX indexed. Key queries: event.code:4624 (logons), "
            "event.code:4688 (process creation), event.code:7045 (service install). "
            "Use idx_aggregate on event.code for frequency overview."
        )
    if has_prefetch and has_mft:
        hints.append(
            "Cross-ref Prefetch+MFT: prefetched exe with InUse=False in MFT = "
            "executed then deleted (anti-forensics)."
        )

    if not hints:
        return
    hints = [h for h in hints if (case, h) not in _hints_delivered]
    if not hints:  # the pointer names only the types this case has
        held = [n for n, has in (("MFT", has_mft), ("USN", has_usn), ("evtx", has_evtx)) if has]
        resp["investigation_hints"] = [
            f"{'/'.join(held)} indexed — call suggest_tools for investigation patterns"
        ]
        return

    # Budget: sort by doc count, keep top 3, cap at 500 chars
    def _doc_count(hint: str) -> int:
        for art_name, art_info in artifacts.items():
            if isinstance(art_info, dict) and art_name in hint.lower():
                return art_info.get("docs", 0)
        return 0

    hints.sort(key=_doc_count, reverse=True)
    kept: list[str] = []
    total = 0
    for hint in hints:
        if total + len(hint) > 500 and kept:
            break
        kept.append(hint)
        total += len(hint)
        if len(kept) >= 3:
            break

    resp["investigation_hints"] = kept
    _hints_delivered.update((case, h) for h in kept)


# --- Field name mismatch detection (cached per case) ---
_case_index_cache: dict[str, set[str]] = {}

_FIELD_HINT_EVTX_EVTXECMD = (
    "This case has EvtxECmd CSV indices alongside native evtx indices. "
    "EvtxECmd uses different field names — key mappings:\n"
    "SAFE ALIASES: event.code (evtx) = EventId (EvtxECmd). "
    "@timestamp (evtx) = TimeCreated (EvtxECmd). host.name = same.\n"
    "FIELDS THAT DON'T MAP 1:1 — EvtxECmd PayloadData is POSITIONAL:\n"
    "  UserName = Subject account (NOT the target user)\n"
    "  RemoteHost = Source IP (when present)\n"
    "  ExecutableInfo = Process path (when present)\n"
    "  EID 4624 (Logon): PayloadData1='Target: DOMAIN\\User', "
    "PayloadData2='LogonType N' (3=network, 10=RDP)\n"
    "  EID 4688 (Process): PayloadData1='Parent process: path', "
    "ExecutableInfo=new process\n"
    "  EID 7045 (Service): PayloadData1='Name: ServiceName', "
    "PayloadData2='StartType: ...'\n"
    "  EID 4648 (Explicit Creds): PayloadData1='Target: DOMAIN\\User', "
    "PayloadData2='TargetServerName: host'\n"
    "  EID 4672 (Special Privs): PayloadData1='PrivilegeList: ...'\n"
    "EvtxECmd queries: EventId:4624 AND PayloadData1:*username*, "
    "EventId:4688 AND ExecutableInfo:*process*, "
    "EventId:7045 AND PayloadData1:*servicename*, "
    "EventId:4624 AND PayloadData2:*LogonType 3* (lateral movement).\n"
    "Prefer native evtx when available — proper ECS fields. For native evtx records "
    "only, query (<your query>) AND _exists_:winlog.channel; omit index, and pass "
    "case_id unless this case is active."
)

_field_hint_delivered = False


def _get_case_indices(index_pattern: str, client) -> set[str]:
    """Get index names for a pattern, cached per case prefix.

    Handles comma-separated patterns (e.g., 'case-x-evtx-*,case-x-delim-*').
    """
    cache_key = index_pattern
    if cache_key in _case_index_cache:
        return _case_index_cache[cache_key]
    names: set[str] = set()
    # Handle comma-separated patterns
    for segment in index_pattern.split(","):
        segment = segment.strip()
        if not segment:
            continue
        try:
            cat_result = client.cat.indices(index=segment, format="json", h="index")
            if cat_result:
                names.update(i["index"] for i in cat_result)
        except Exception:
            pass
    if names:
        _case_index_cache[cache_key] = names
    return names


def invalidate_index_cache() -> None:
    """Clear the index cache after ingest operations."""
    _case_index_cache.clear()


def _add_field_hint(resp: dict, index_pattern: str, client) -> None:
    """Add field_hint when query targets indices with different field names.

    Full hint on first delivery, one-line pointer after (token budget).
    """
    global _field_hint_delivered
    if "*" not in index_pattern:
        return
    idx_names = _get_case_indices(index_pattern, client)
    # per-file stems use "_" since 0.6.4 (delim-evtxecmd_<file>), "-" before
    has_evtx = any("-evtx-" in n for n in idx_names)
    has_evtxecmd = any(re.search(r"-delim-evtxecmd[-_]", n) for n in idx_names)
    if not (has_evtx and has_evtxecmd):
        return
    if _field_hint_delivered:
        resp["field_hint"] = (
            "Mixed evtx/EvtxECmd indices — query (<your query>) AND _exists_:winlog.channel "
            "for ECS fields, or (<your query>) AND _exists_:EventId for CSV fields; omit "
            "index, and pass "
            "case_id unless this case is active."
        )
    else:
        resp["field_hint"] = _FIELD_HINT_EVTX_EVTXECMD
        _field_hint_delivered = True


def reset_enrichment_state() -> None:
    """Reset enrichment counters for test isolation."""
    global _shimcache_reminder_count, _field_hint_delivered
    _shimcache_reminder_count = 0
    _hints_delivered.clear()
    _field_hint_delivered = False
    _case_index_cache.clear()


_client = None
_client_verified = False


def _get_os():
    """Get cached OpenSearch client. Health check on first call only.

    If the cached client hits a connection error (OpenSearch went down),
    the next _get_os() call will create a fresh client and re-verify.
    """
    global _client, _client_verified, _install_settled, _install_at
    if _client is None:
        try:
            _client = get_client()
        except FileNotFoundError as e:
            raise RuntimeError(str(e)) from e
    if not _client_verified:
        try:
            _client.cluster.health()
            _client_verified = True
            _install_settled, _install_at = False, None  # each verified connection installs
        except Exception as e:
            _client = None
            raise RuntimeError(
                f"OpenSearch not running or not reachable: {e}\n"
                "Run 'opensearch-setup' to start OpenSearch."
            ) from e
    _install_templates(_client)
    return _client


_install_settled = False  # the template install succeeded, or an operator template governs evtx
_install_at: float | None = None  # time.monotonic() of its last attempt
_INSTALL_RETRY_SECONDS = 60


def _install_templates(client) -> None:
    """Install the winlog pipeline, the evtx template and the other index
    templates on each verified connection, and again on a later call, at
    most once a minute, until an install is ok. An operator's template on the
    evtx pattern isn't retried (a retry can't change it), and only the first
    attempt gives the active case's indices the stamp fields (one audit
    entry, not one a minute). Idempotent: validate-before-PUT means a broken
    pipeline body never replaces the running one."""
    global _install_settled, _install_at
    now = time.monotonic()
    if _install_settled or (
        _install_at is not None and now - _install_at < _INSTALL_RETRY_SECONDS
    ):
        return
    first, _install_at = _install_at is None, now
    try:
        from opensearch_mcp.mappings import ensure_winlog_pipeline

        result = ensure_winlog_pipeline(client, audit, _active_case_indices() if first else "")
        _install_settled = result.get("status") == "ok" or bool(result.get("operator_template"))
        if result.get("status") != "ok":
            logger.warning(
                "winlog pipeline install reported %s%s: %s",
                result.get("status"),
                "" if _install_settled else " (tried again in a minute)",
                result.get("error") or result.get("other_templates"),
            )
    except Exception as _install_e:
        logger.warning("winlog pipeline auto-install failed (non-fatal): %s", _install_e)


def _active_case_indices() -> str:
    """`case-<c12>-*` of the active case, the one the server's audit writes
    to: the indices its template install gives the stamp fields ("" for none)."""
    try:
        c12 = _case_c12(_get_active_case() or "")
    except Exception:
        c12 = ""
    return f"case-{c12}-*" if c12 else ""


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
        root = (err.get("root_cause") or [{}])[0] if isinstance(err, dict) else {}
        if isinstance(root, dict) and root.get("reason"):  # what failed, and where
            reason += f": {root['reason']}" + (f" ({root['index']})" if root.get("index") else "")
        named = []  # each failed index whose own reason has a repair, with it
        shards = err.get("failed_shards") if isinstance(err, dict) else None
        for f in shards if isinstance(shards, list) else ():
            index, cause = (f.get("index"), f.get("reason")) if isinstance(f, dict) else (0, 0)
            if isinstance(index, str) and isinstance(cause, dict) and index not in dict(named):
                if fix := _repair(str(cause.get("reason", "")), "", index):
                    named.append((index, fix))
        if named:
            more = f"; and {len(named) - 5} more indices" if len(named) > 5 else ""
            reason += f" ({'; '.join(i + fix for i, fix in named[:5])}{more})"
        raise ValueError(f"Query error: {reason}") from e


# Fields excluded from idx_search results by default (token optimization).
# These are duplicated content, raw unparsed data where parsed equivalents
# exist, or metadata with zero triage value. Full docs via idx_get_event.
_SEARCH_EXCLUDE_FIELDS = frozenset(
    {
        # Duplicated content (parsed equivalents exist)
        "ExtraFieldInfo",  # Hayabusa: duplicates Details
        "Payload",  # EvtxECmd: raw XML, PayloadData1-6 already extracted
        "FilesLoaded",  # PECmd: bulk DLL list
        "Directories",  # PECmd: bulk directory list
        "task.xml",  # Scheduled tasks: full XML
        "wer.full_text",  # WER: full crash report text
        # EvtxECmd duplicate/metadata
        "SourceFile",  # duplicates vhir.source_file
        "Computer",  # duplicated to host.name by parse_delimited
        # Metadata (available via idx_get_event, zero triage value)
        "ExtraDataOffset",
        "HiddenRecord",
        "Keywords",
        "ChunkNumber",
        "pipeline_version",
        "vhir.source_file",
        "vhir.ingest_audit_id",
        "vhir.parse_method",
        # MFT structural fields (low triage value, high field count)
        "UpdateSequenceNumber",
        "LogfileSequenceNumber",
        "SecurityId",
        "ReferenceCount",
        "NameType",
        "IsAds",
        "Is256",
        # --- EvtxECmd low-value fields ---
        "RecordNumber",
        "EventRecordId",
        "ProcessId",
        "ThreadId",
        "UserId",
    }
)

_MAX_FIELD_CHARS = 500


def _host_review(case_id: str = "") -> tuple[set[str], str]:
    """The machine keys the examiner hasn't confirmed (proposed by Start now,
    or new), and the rename-incomplete note while a host operation is
    unfinished. Both empty when the case has no host logs."""
    from sift_common import host_identity as hi

    case_dir = _scan_case_dir(case_id)
    if case_dir is None:
        return set(), ""
    try:
        state = hi.load(case_dir)
        op = hi.unfinished_op(case_dir)
    except hi.HostLogError as e:
        return set(), f"host logs unreadable: {e}"
    keys = {k for m in state.machines.values() if m.state != hi.CONFIRMED for k in m.keys}
    from opensearch_mcp.host_ops import unfinished_note

    note = unfinished_note(op) if op else ""
    return keys, note


def _annotate_hosts(resp: dict, case_id: str, client=None, index="", query_body=None,
                    field: str = "", hits=None) -> dict:  # fmt: skip
    """Mark what came from machines the examiner hasn't confirmed: each search
    hit (`host_unconfirmed`), or for a count, aggregate or timeline the number
    of documents, per bucket for an aggregate. Adds the rename-incomplete note."""
    keys, note = _host_review(case_id)
    if note:
        resp["host_note"] = note
    if not keys:
        return resp
    if hits is not None:  # the documents of a search, in the order of its hits
        for doc, hit in zip(resp["results"], hits):
            if (hit.get("_source") or {}).get("vhir.host_key") in keys:
                doc["host_unconfirmed"] = True
        return resp
    try:  # a separate count: the answer above stands whatever this gives
        body: dict = {
            "query": {"bool": {"must": [query_body], "filter": [
                {"terms": {"vhir.host_key": sorted(keys)}}]}},
            "size": 0,
            "track_total_hits": True,
        }  # fmt: skip
        if field:
            body["aggs"] = {"agg": {"terms": {"field": field, "size": 500}}}
        result = client.search(index=index, body=body, ignore_unavailable=True)
        total = int(result["hits"]["total"]["value"])
        per = {b["key"]: int(b["doc_count"]) for b in result.get("aggregations", {})
               .get("agg", {}).get("buckets", [])} if field else {}  # fmt: skip
    except Exception as e:  # said, never dropped: the answer above stands
        resp["host_unconfirmed_error"] = (
            f"documents from machines not yet confirmed couldn't be counted: "
            f"{type(e).__name__}: {e}"
        )
        return resp
    if total:
        resp["host_unconfirmed"] = total
        resp["host_unconfirmed_note"] = (
            f"{total:,} document(s) come from machines the examiner hasn't confirmed"
        )
    for b in resp.get("buckets", []):
        if per.get(b.get("key")):
            b["host_unconfirmed"] = per[b["key"]]
    return resp


def _strip_hits(
    hits: list[dict],
    exclude_fields: frozenset[str] = _SEARCH_EXCLUDE_FIELDS,
    max_chars: int = _MAX_FIELD_CHARS,
) -> list[dict]:
    """Extract _source from hits with field exclusion and truncation.

    Default behavior (compact): excludes bloat fields and truncates
    values > 500 chars; an object or list over that is cut from its JSON.
    Pass empty exclude_fields and large max_chars for full documents.
    """
    results = []
    for hit in hits:
        src = hit.get("_source", {})
        idx_name = hit.get("_index", "")
        doc: dict = {"_id": hit.get("_id"), "_index": idx_name}
        # Note: _type extraction via rsplit is unreliable for dashed hostnames
        # (e.g., evtx-web-server-01 → type=evtx-web-server). Use _index for
        # authoritative artifact type. Removed _type field from results.

        truncated_fields = []
        for key, val in src.items():
            if key in exclude_fields:
                continue
            # an object or list is cut as JSON, never as a Python repr
            sval = (
                val if isinstance(val, str) else json.dumps(val, ensure_ascii=False, default=str)
            )
            if len(sval) > max_chars:
                doc[key] = sval[:max_chars] + "..."
                truncated_fields.append(key)
            else:
                doc[key] = val

        if truncated_fields:
            doc["_truncated"] = truncated_fields

        results.append(doc)
    return results


def _resolve_index(index: str, case_id: str, client=None) -> tuple[str, str]:
    """(index expression, error): the case's indices (`case_id`, or the
    active case), or an explicit expression when it stays inside that case."""
    from opensearch_mcp.case_scope import CaseScopeError, confine

    err = _validate_index(index) if index else None
    if err:
        return "", err
    try:
        return confine(index, case_id or _get_active_case() or "", client), ""
    except CaseScopeError as e:
        return "", str(e)


def _search_index(index: str, case_id: str, client) -> tuple[str, str]:
    """(index expression, error) a search tool queries. Only an implicit
    search is refused with no active case: an explicit `index` is then
    searched as given, and a `case_id` names its indices from its case
    folder. With an active case, an `index` stays inside it. The active case
    is read once, so the check and the expression agree."""
    if case_id:
        from opensearch_mcp.write_context import case_dir_for

        folder = case_dir_for(case_id)
        if folder is None or not (folder / "CASE.yaml").is_file():
            return "", (
                f"Case {case_id!r} has no folder on this box, so its indices can't be "
                "resolved; pass index= or activate it."
            )
        return _resolve_index(index, case_id, client)
    case_id = _get_active_case() or ""
    if not case_id:
        if not index:
            return "", "No active case. Run 'vhir case activate' first, or pass case_id or index."
        err = _validate_index(index)  # the examiner's own expression, as asked
        return ("", err) if err else (index, "")
    return _resolve_index(index, case_id, client)


def _mixed_type_refusal(client, index: str, field: str) -> dict | None:
    """An error when field is ip in some target indices and keyword in others."""
    caps = _os_call(client.field_caps, index=index, fields=field)
    types = caps.get("fields", {}).get(field, {})
    if "ip" in types and "keyword" in types:
        ip_idx = types["ip"].get("indices", [])
        kw_idx = types["keyword"].get("indices", [])
        return {
            "error": f"{field} is mapped as ip in {ip_idx} and as keyword in {kw_idx}: "
            "one aggregation can't combine them. Aggregate each set with index=<those names>, "
            "or narrow the pattern."
        }
    return None


def _hayabusa_index(case_id: str = "", client=None) -> str:
    """The Hayabusa alert indices of case_id, or of the active case; ""
    when there's no case."""
    from opensearch_mcp.case_scope import CaseScopeError, case_read_scope

    if client is None:  # a pre-0.6.4 case's alerts are named only with the cluster's answer
        try:
            client = _get_os()
        except Exception:
            client = None
    try:
        cid = case_id or _get_active_case() or ""
        return case_read_scope(cid, client, artifact_type="hayabusa")
    except CaseScopeError:
        return ""


def _hayabusa_query(query: str, expr: str, case_id: str = "", client=None) -> str:
    """An idx_search call over the Hayabusa alerts `expr` names, in a form its
    `index` accepts: an expression it would refuse (an exclusion, or a
    pre-0.6.4 wildcard another case's indices could match) becomes the
    indices it names, and the index is left out when those can't be named."""
    from opensearch_mcp.case_scope import CaseScopeError, confine

    if not expr:
        return f"idx_search(query='{query}')"
    if client is None:
        try:
            client = _get_os()
        except Exception:
            client = None
    try:
        if _validate_index(expr) is None:
            confine(expr, case_id or _get_active_case() or "", client)
            return f"idx_search(query='{query}', index='{expr}')"
    except CaseScopeError:
        pass
    try:
        expr = ",".join(sorted(client.indices.get(index=expr, expand_wildcards="open")))
    except Exception:
        expr = ""
    return f"idx_search(query='{query}'" + (f", index='{expr}')" if expr else ")")


_GATE_ANSWER_SECONDS = 10.0  # how long a launch waits to say whether the run waits


def _awaited_names(data: dict):
    """The raw names an awaiting status waits on; a unit with no name shows
    as `(no name) <locator>`. A status written without the raw field gives
    its host's name."""
    for h in data.get("hosts") or []:
        for a in h.get("artifacts") or []:
            if "locator" not in a:
                yield str(h.get("hostname", ""))
            else:
                yield str(a.get("raw") or f"(no name) {a['locator']}")


def _answer_after_gate(resp: dict, case_id: str, pid: int, run_id: str) -> dict:
    """Say whether a just-started run waits for host confirmation: watch its
    status until the worker passes the gate, waits at it, or ends. A run
    whose hosts can't be known yet (an archive being extracted) says so."""
    import json as _json
    import time as _time

    from opensearch_mcp.ingest_status import AWAITING, _status_path_safe

    path = _status_path_safe(case_id, pid, run_id)
    deadline = _time.monotonic() + _GATE_ANSWER_SECONDS
    while True:
        try:
            data = _json.loads(path.read_text())
        except (OSError, ValueError):
            data = {}
        if data.get("status") == AWAITING:
            hosts = [
                a.get("note", "")
                for h in data.get("hosts") or []
                for a in h.get("artifacts") or []
            ]
            if not resp.get("hosts"):  # each raw name it waits on, once
                resp["hosts"] = list(dict.fromkeys(_awaited_names(data)))
            resp.update(
                status=AWAITING,
                unresolved=(data.get("totals") or {}).get("unresolved", len(hosts)),
                unresolved_hosts=hosts,
                message=(
                    f"Nothing is written yet: {data.get('message', '').rstrip('.')}. "
                    "Then call idx_ingest_status() to follow the run."
                ),
            )
            return resp
        if data.get("status") in ("failed", "cancelled"):  # what happened, not "started"
            error = data.get("error", "")
            resp.update(
                status=data["status"],
                error=error,
                message=(
                    f"The run {data['status']}: {error}. idx_ingest_status() shows what it did."
                ),
            )
            return resp
        if data.get("hosts_confirmed") or data.get("status") == "complete":
            return resp
        if _time.monotonic() >= deadline:
            resp["hosts_note"] = (
                "Its host names are checked once the run reads them; if they need the "
                f"examiner, idx_ingest_status() shows '{AWAITING}'."
            )
            return resp
        _time.sleep(0.2)


def _launch_summary(resp: dict, started: str) -> str:
    """The audit's summary of a launch, once the gate answer is in: a run that
    already failed or was cancelled is named so, never "started"."""
    if resp.get("status") in ("failed", "cancelled"):
        return f"run {resp['status']} (pid {resp.get('pid')}): {resp.get('error', '')}"
    return started


def _with_host_list_hint(resp: dict, case_id: str = "") -> dict:
    """Add the host-list encouragement while the case has no list loaded."""
    from sift_common.host_gate import host_list_hint

    case_dir = _scan_case_dir(case_id)
    hint = host_list_hint(case_dir) if case_dir is not None else ""
    if hint:
        resp["host_list_hint"] = hint
    return resp


def _scan_case_dir(case_id: str = ""):
    from opensearch_mcp.write_context import case_dir_for

    cid = case_id or _get_active_case() or ""
    d = case_dir_for(cid) if cid else None
    return d if d is not None and (d / "CASE.yaml").is_file() else None


def _folder_scan(hosts: list, case_id: str) -> list[dict]:
    """The names scan of a folder's hosts, recorded in the case's host logs."""
    from opensearch_mcp import names_scan

    case_dir = _scan_case_dir(case_id)
    units = [names_scan.host_folder_unit(h, case_dir) for h in hosts]
    return names_scan.record(case_dir, units) if case_dir else [u.summary() for u in units]


def _container_scan(image: Path, container_type: str, case_id: str) -> dict:
    """What a container's scan can say before anything is mounted or
    extracted: a disk image's volumes as candidates (read without mounting),
    or, for an archive, that its names arrive after extraction."""
    from opensearch_mcp import names_scan

    if container_type == "archive":
        return {"note": "names arrive after extraction: the run scans what the archive holds"}
    from opensearch_mcp.parse_plaso import volume_inventory

    leaves, error = volume_inventory(image)
    case_dir = _scan_case_dir(case_id)
    units = names_scan.image_candidates(image, leaves, case_dir)
    out: dict = {
        "volumes": names_scan.record(case_dir, units)
        if case_dir
        else [u.summary() for u in units],
        "note": "each volume is a candidate machine; its names are read when the run reaches it",
    }
    if error:
        out["error"] = error
    return out


def _memory_scan(image: Path, hostname: str, case_id: str = "") -> list[dict]:
    """The names scan of a memory image (or an archive of them: names
    arrive after extraction), in `case_id` (else the active case)."""
    from opensearch_mcp import names_scan

    case_dir = _scan_case_dir(case_id)
    if image.suffix.lower() in (".7z", ".zip"):
        return [{"locator": str(image), "note": "names arrive after extraction"}]
    unit = names_scan.memory_unit(image, image, "", hostname or "", case_dir)
    return names_scan.record(case_dir, [unit]) if case_dir else [unit.summary()]


def _detect_preparsed_csvs(path: Path) -> str | None:
    """Check for pre-parsed CSV output and suggest the right ingest tool."""
    # Scan flat + one level of subdirs (avoid full tree walk on USB)
    # Single-pass scan: collect CSVs and subdirs together
    csv_files = []
    subdirs = []
    for entry in path.iterdir():
        if entry.is_file() and entry.suffix.lower() == ".csv":
            csv_files.append(entry)
        elif entry.is_dir() and not entry.name.startswith("."):
            subdirs.append(entry)
    for d in subdirs:
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
            with open(f, "r", errors="replace") as fh:
                header = fh.read(200).lower()
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


def _kept(folder: Path, keep, skipped: list, prefix: str = "") -> list[Path]:
    """A folder's entries `keep` takes, never a link; each link `keep` would
    take is added to `skipped` (as `prefix` + its name), to be named."""
    kept, links = members(folder)
    skipped += [prefix + f.name for f in links if keep(f)]
    return [f for f in kept if keep(f)]


def _named(skipped: list) -> dict:
    """`{"skipped_links": [...]}` for a preview, {} when nothing was skipped."""
    return {"skipped_links": sorted(skipped)} if skipped else {}


def _detect_hostnames_from_filenames(path: Path, skipped: list | None = None) -> set[str]:
    """Best-effort hostname detection from forensic CSV naming.

    Supports two patterns:
    - Suffix: EvtxECmd-hostname.csv (ZimmermanTools)
    - Prefix: hayabusa-caseid-hostname.csv (Hayabusa pipeline output)
    Each file's host is names_scan.filename_host's, its folder the context:
    Kansa's hostname-Module.csv in a folder named for the host, or under
    Kansa's Output_<14 digits>/<Module>/, gives the host, not the module.
    """
    if not path.is_dir():
        return set()
    from collections import Counter

    exts = {".csv", ".tsv"}
    files = _kept(path, lambda f: f.suffix.lower() in exts, [] if skipped is None else skipped)
    files = files[:50]
    if not files:
        return set()
    from opensearch_mcp.names_scan import filename_host

    suffix_counts: Counter = Counter()
    for f in files:
        named = filename_host(f)
        if named:
            suffix_counts[named.lower()] += 1
    threshold = len(files) * 0.3
    return {h for h, c in suffix_counts.items() if c >= threshold}


# Where evidence may be ingested from, beside the user's home folder
ALLOWED_ROOTS = ("/mnt", "/media", "/run/media", "/evidence", "/cases", "/tmp")


def _case_path(path: str, active=None) -> tuple[str, str | None]:
    """(path, refusal): a relative path is read in the active case's folder,
    the one its pointer names (as case-mcp reads it), joined as case-mcp's
    evidence_register joins it (not normalised, no realpath: a `..` after a
    link is the kernel's), never in this server's cwd. One that leaves the
    case folder by its own `..`, or names the folder itself, is refused before
    anything is read. An absolute path is returned as given. `active`: the
    call's one read of `_active_case()`."""
    if os.path.isabs(path):
        return path, None
    case_id, case_dir = active if active is not None else _active_case()
    if not case_id or not case_dir.is_dir():
        return path, "No active case. Run 'vhir case activate' first."
    rel = os.path.normpath(path)
    if rel == ".":
        return path, (
            f"{path!r} names the case folder itself; give the evidence file or folder "
            "in it (e.g. evidence/...)."
        )
    if rel == ".." or rel.startswith(".." + os.sep):
        return path, (
            f"{path} leaves the case folder ({case_dir}); give a path inside the case, "
            "or an absolute path."
        )
    return str(case_dir / path), None


def _validate_path(path: str) -> str | None:
    """Validate path is in allowed locations, or is an original registered in
    the active case wherever it lies (never home or its hidden folders).
    Returns error string or None."""
    from opensearch_mcp.paths import vhir_home

    p = Path(path).resolve()
    home = vhir_home().resolve()
    # HOME itself, and the hidden files and folders directly in it, hold credentials
    if p.is_relative_to(home):
        below = p.relative_to(home).parts
        if not below or below[0].startswith("."):
            return (
                f"Refused: {path} (resolved target: {p}) is your home folder, or is in your "
                "home folder's hidden configuration area, which can hold credentials, so it "
                "isn't ingested. Copy or move the evidence into a folder that isn't hidden, "
                "such as the case's evidence/ folder, and ingest it from there; if your cases "
                "folder is itself inside a hidden folder, move it to a folder that isn't "
                "hidden first."
            )
    allowed = [home, *(Path(a).resolve() for a in ALLOWED_ROOTS)]
    if not any(p.is_relative_to(a) for a in allowed) and not _registered_original(p):
        return (
            f"Path not in allowed locations "
            f"(~/, /mnt/, /media/, /evidence/, /cases/, /tmp/): {path} "
            f"(resolved target: {p}). The target must be under one of these; copy it in, "
            "or mount or bind it under /mnt, /media or /evidence, or register it where it "
            "lies (a link in the case's evidence/ folder) and ingest it then."
        )
    return None


def _registered_original(p: Path) -> bool:
    """`p` (resolved) is an original registered in the active case, wherever it
    lies: a file, a folder, or a file in a registered folder. case-mcp records
    the target of a link in evidence/, so evidence on read-only storage is
    registered where it is. Never one in the system's folders or Valhuntir's
    keys, registered or not."""
    import json

    from sift_common import SYSTEM_DIRS

    from opensearch_mcp.write_context import case_dir_for

    if any(p.is_relative_to(Path(d).resolve()) for d in SYSTEM_DIRS):
        return False
    try:
        # the case the ingest writes to: ~/.vhir/active_case, as the tools read it
        case_dir = case_dir_for(_get_active_case() or "")
        if case_dir is None:  # no active case: never the working folder's registry
            return False
        registry = json.loads((case_dir / "evidence.json").read_text())
    except Exception:  # noqa: BLE001 - no case or registry: nothing registered
        return False
    files = registry.get("files") if isinstance(registry, dict) else registry
    for e in files if isinstance(files, list) else []:
        if isinstance(e, dict) and e.get("path"):
            root = (case_dir / str(e["path"])).resolve()
            if p == root or (e.get("kind") == "folder" and p.is_relative_to(root)):
                return True
    return False


def _no_index_matched(result: dict, index: str) -> dict | None:
    """An error when the pattern matched no open index, so nothing was searched."""
    if result.get("_shards", {}).get("total") == 0:
        return {
            "error": f"No open index matches {index!r}: nothing was searched. "
            "Check the case id or index pattern."
        }
    return None


_PARTIAL_LOW = (
    "Totals, counts and buckets are a lower bound: they cover only the shards that "
    "answered, and 0 is not 'no match'."
)
_TEXT_FIELD = re.compile(r"fielddata=true on \[([^\]]+)\]")


def _repair(reason: str, case: str, index: str) -> str:
    """What repairs a shard failure: a field that is text where a keyword was
    meant. A vhir.* field is text only in an index made without its template;
    any other is aggregated through a keyword form, in that index alone (a
    case-wide aggregation leaves out every index without it)."""
    m = _TEXT_FIELD.search(reason)
    if not m:
        return ""
    field = m.group(1)
    if field.startswith("vhir."):
        return (
            f"; {field} is text there: the index was made without its template, "
            "delete the index and re-ingest it"
        )
    return (
        f"; {field} is text there: aggregate on a keyword form of {field} "
        f"with index={index}, if that index has one"
    )


def _gap_parts(result: dict, case: str = "") -> tuple[list[str], dict]:
    """What a reply's shards didn't answer, as clauses with this reply's own
    counts (none when every shard answered in time: a skipped shard answered,
    it can't match), and its shard numbers."""
    shards = result.get("_shards") or {}
    total, failed = int(shards.get("total") or 0), int(shards.get("failed") or 0)
    # a red index's shards are neither successful nor failed, with no failures entry
    lost = max(0, total - int(shards.get("successful", total) or 0) - failed)
    timed_out = bool(result.get("timed_out"))
    names, why = [], []
    for f in shards.get("failures") or []:  # grouped: one per index and reason
        index = str(f.get("index") or "?")  # a node's failure has none
        if index in names:
            continue
        reason = str((f.get("reason") or {}).get("reason", ""))
        names.append(index)
        why.append(f"{index}: {reason.split('. ')[0][:200]}{_repair(reason, case, index)}")
    parts = []
    if failed:
        named = f" in {'; '.join(why[:5])}" if why else ""
        more = f"; and {len(why) - 5} more indices" if len(why) > 5 else ""
        parts.append(f"{failed} of {total} shard(s) failed{named}{more}")
    if lost:
        parts.append(f"{lost} of {total} shard(s) unavailable")
    if timed_out:
        parts.append("the search timed out")
    numbers = {"total": total, "failed": failed, **({"unavailable": lost} if lost else {})}
    return parts, {"shards": numbers, "failed_indices": names, "timed_out": timed_out}


def _shard_gap(result: dict, case: str = "") -> dict:
    """{} when every shard answered in time. Otherwise `partial: true`, the
    shard counts, the indices that failed, and a warning naming each with its
    reason and what repairs it: an answer from only some shards is a lower
    bound."""
    parts, numbers = _gap_parts(result, case)
    if not parts:
        return {}
    return {
        "partial": True,
        **numbers,
        "partial_warning": f"Incomplete answer: {'; '.join(parts)}. {_PARTIAL_LOW}",
    }


# A wildcard on an IPv4 address: 10.1.2.*, 172.16.5.1?
_IP_WILDCARD = re.compile(r"\b\d{1,3}\.[\d.]*[*?]")
_IP_WILDCARD_HINT = (
    "IP-typed fields return nothing for wildcards: use CIDR, "
    'source.ip:"10.1.2.0/24", ORed with the wildcard across older indices.'
)


def _stale_dates_hint(client, scope: str, query: str, time_field: str = "") -> str:
    """A hint for each index of `scope` that maps an EZ date field the query
    (or `time_field`) names without the template's format: a date range on it
    matches none of that index's records. "" for any other query."""
    from opensearch_mcp.mappings import csv_date_fields, stale_date_indices

    named = {f for f in csv_date_fields() if f == time_field
             or re.search(rf"(?<![\w.]){re.escape(f)}\s*:", query or "")}  # fmt: skip
    if not named:
        return ""
    return " ".join(
        f"{index} was made before 0.6.5; its EZ date fields aren't read as dates, so date "
        "ranges on them miss its records: delete the index and re-ingest, then re-run "
        "idx_enrich_triage/intel"
        for index in stale_date_indices(client, scope, named)
    )


def _add_hint(resp: dict, hint: str) -> None:
    if hint:
        resp["hint"] = hint + (f" {resp['hint']}" if resp.get("hint") else "")


_INGEST_AGG_CAP = 1000


def _ingest_aggs() -> dict:
    """Sibling aggregations that record which ingests a query's records came
    from: their distinct `vhir.ingest_audit_id` (capped) and how many carry
    none."""
    field = "vhir.ingest_audit_id"
    return {
        "result_ingests": {"terms": {"field": field, "size": _INGEST_AGG_CAP}},
        "result_ingests_missing": {"missing": {"field": field}},
    }


def _ingest_params(result: dict) -> dict:
    """The audit params from `_ingest_aggs`: the sorted ids, and, when not
    zero, the records with no id and those past the cap: never dropped
    silently."""
    aggs = result.get("aggregations") or {}
    terms = aggs.get("result_ingests") or {}
    ids = sorted(
        b["key"] for b in terms.get("buckets", []) if isinstance(b.get("key"), str) and b["key"]
    )
    out: dict = {"result_ingests": ids}
    missing = (aggs.get("result_ingests_missing") or {}).get("doc_count", 0)
    if missing:
        out["result_ingests_missing"] = missing
    overflow = terms.get("sum_other_doc_count", 0)
    if overflow:
        out["result_ingests_overflow"] = overflow
        out["result_ingests_cap"] = _INGEST_AGG_CAP
    return out


_NOT_RECORDED = "not recorded: no active case, or the audit write failed"


def _logged_query(resp: dict, queried: str = "", **entry) -> dict:
    """Write a query's audit entry, and save its response, as returned to the
    AI, beside it: `extractions/<audit id>/response.json`, its SHA-256 on the
    entry, so a quote of the response can be checked against what the AI was
    given. A query naming another case (`queried`, the tool's case_id) says
    which case it read. Returns the response with its audit id; without an
    entry, the response saying it wasn't recorded, and nothing saved."""
    import hashlib

    audit_dir = audit._get_audit_dir()
    aid = audit._next_audit_id(audit_dir)
    out = {**resp, "audit_id": aid}
    saved = None
    if audit_dir is not None:
        folder = Path(audit_dir).parent / "extractions" / aid
        try:
            folder.mkdir(parents=True, exist_ok=False)
            data = json.dumps(out, ensure_ascii=False, default=str).encode("utf-8")
            (folder / "response.json").write_bytes(data)
            saved = {"path": str(folder / "response.json"),
                     "sha256": hashlib.sha256(data).hexdigest()}  # fmt: skip
        except OSError as e:
            logger.warning("query response not saved: %s", e)
    # The entry goes where its id was minted and its response saved: the case
    # resolved once, as the call started, whatever is active by now
    writer = audit
    if audit_dir is not None:
        writer = AuditWriter(mcp_name=audit.mcp_name, audit_dir=str(audit_dir))
        entry.setdefault("case_id", Path(audit_dir).parent.name)  # that case's, too
        if queried and queried != Path(audit_dir).parent.name:
            entry["params"] = {**(entry.get("params") or {}), "queried_case": queried}
    logged = writer.log(audit_id=aid, extra={"response": saved} if saved else None, **entry)
    if logged is None:
        if saved:  # an entry that wasn't written leaves no file of its own
            Path(saved["path"]).unlink(missing_ok=True)
            Path(saved["path"]).parent.rmdir()
        return {**resp, "audit": _NOT_RECORDED}
    return out


def _related_doc_params(client, related: list[dict]) -> dict:
    """The documents the findings matched, as a search's records are recorded
    (ingest, content hash, original), read with one mget."""
    docs = [{"_index": r["index"], "_id": d} for r in related for d in r["related_doc_ids"]]
    if not docs:
        return {}
    fields = ["vhir.ingest_audit_id", "vhir.content_hash", "vhir.original.sha256",
              "triage.op_id", "threat_intel.iocs"]  # fmt: skip
    try:
        got = client.mget(body={"docs": docs}, _source_includes=fields)
    except Exception as e:  # recorded, not dropped: the findings still name them
        return {"result_docs_error": str(e)[:200]}
    return _hit_params([d for d in got.get("docs", []) if d.get("found")])


def _enrichment_ops(src: dict) -> dict:
    """The enrichment groups on a record and the step that wrote each: the
    triage group's `triage.op_id`, each threat-intel entry's `op_id`."""
    out: dict = {}
    triage = _field(src, "triage.op_id")
    if isinstance(triage, str) and triage:
        out["triage"] = triage
    iocs = _field(src, "threat_intel.iocs")
    ids = sorted({e["op_id"] for e in iocs if isinstance(e, dict) and e.get("op_id")}) if (
        isinstance(iocs, list)
    ) else []  # fmt: skip
    if ids:
        out["threat_intel"] = ids
    return out


def _field(src: dict, dotted: str):
    """`dotted` in a record, given dotted or nested."""
    if dotted in src:
        return src[dotted]
    node = src
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _hit_params(hits: list) -> dict:
    """What a query returned, for its audit entry: the ingests its records
    came from, how many carry none (never dropped silently), and each record
    (its index, id, ingest, content hash and original) so a finding citing it
    can be checked against the stored record."""
    ids: set = set()
    missing = 0
    docs = []
    for h in hits:
        src = h.get("_source") if isinstance(h.get("_source"), dict) else {}
        aid = _field(src, "vhir.ingest_audit_id")
        if isinstance(aid, str) and aid:
            ids.add(aid)
        else:
            missing += 1
        doc = {
            "_index": h.get("_index", ""),
            "_id": h.get("_id", ""),
            "ingest_audit_id": aid if isinstance(aid, str) else "",
            "content_hash": _field(src, "vhir.content_hash") or "",
            "original_sha256": _field(src, "vhir.original.sha256") or "",
        }
        enrichment = _enrichment_ops(src)
        if enrichment:  # the enrichment groups on it, with the step that wrote each
            doc["enrichment"] = enrichment
        docs.append(doc)
    out: dict = {"result_ingests": sorted(ids), "result_docs": docs}
    if missing:
        out["result_ingests_missing"] = missing
    return out


def _untimed_note(client, index: str, why: str) -> str:
    """The indices `index` names whose mapping has no @timestamp (the EZ-tool
    CSV indices idx_ingest makes; other routes' templates map it), which a
    window, the default timeline and the case time range leave out: a note
    naming them, or "". Read from the mapping, so an index whose records all
    fall outside a window isn't named. A failed read says so."""
    from opensearch_mcp.tools import TOOLS
    from opensearch_mcp.write_context import artifact_type_of

    try:
        got = client.indices.get_field_mapping(
            index=index, fields="@timestamp", allow_no_indices=True, ignore_unavailable=True
        )
    except Exception as e:
        return f"{_UNCHECKED} ({type(e).__name__}); EZ-tool CSV indices {why}"
    names = sorted(n for n, m in (got or {}).items() if not (m or {}).get("mappings"))
    if not names:
        return ""
    fields = {c.index_suffix: c.time_field for c in TOOLS.values() if c.time_field}

    def one(n: str) -> str:
        f = fields.get(artifact_type_of(n))
        return f"{n} (time field {f})" if f else n

    more = f", and {len(names) - 5} more indices" if len(names) > 5 else ""
    return (
        f"{len(names)} index(es) have no event time and {why}: "
        + ", ".join(one(n) for n in names[:5])
        + f"{more}; query them by their own field with index="
    )


def _agg_time(agg: dict) -> str | None:
    """A min/max date aggregation's time, as OpenSearch writes it. Over indices
    some of which lack the field, 3.5.0 gives only `value` (epoch ms): that time
    is written the same way."""
    if agg.get("value_as_string"):
        return agg["value_as_string"]
    if not isinstance(agg.get("value"), (int, float)):
        return None
    from datetime import datetime, timezone

    t = datetime.fromtimestamp(agg["value"] / 1000, tz=timezone.utc)
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


_WINDOW = "are left out of time_from/time_to"
_UNCHECKED = "couldn't check which indices lack an event time"  # the failed-read note's start


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
    compact: bool = True,
) -> dict:
    """Search indexed evidence using OpenSearch query_string syntax.

    Hosts: filter and group by host.id, the machine's name (what comes from a
    machine the examiner hasn't confirmed is marked host_unconfirmed);
    host.name is the raw name a record carried (one machine can carry several).
    Index names carry no host (case-<id>-<type>-…), so never pick an index for
    a host. idx_host_inventory lists the machines.

    Results are compact by default -- bloat fields excluded, long values
    truncated to 500 chars. Use compact=False for full documents, or
    idx_get_event(id, index) to fetch individual full documents.

    IMPORTANT: OpenSearch tokenizes on dots/hyphens. For filename searches,
    include the extension: 'ServiceUpdater.exe' not 'ServiceUpdater'.
    Use wildcards for partial matches: '*ServiceUpdater*'. IP-typed fields
    (source.ip on most indices) return nothing for wildcards: use CIDR,
    source.ip:"10.1.2.0/24". Across a case with older indices, OR the two:
    source.ip:10.1.2.* OR source.ip:"10.1.2.0/24".

    Args:
        query: OpenSearch query_string (e.g., 'event.code:4624 AND user.name:admin').
            Quote values with special chars: source.ip:"::1" (IPv6 needs quotes).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern. Default: the
            active case; with no index, case_id or active case, it refuses.
        limit: Max results (default 50, max 200).
        offset: Skip first N results for pagination (default 0).
        sort: Sort field:order (default @timestamp:desc).
        time_from: Start time (ISO 8601, e.g., '2023-01-25T14:00:00Z').
        time_to: End time (ISO 8601).
    """
    requested = index
    client = _get_os()
    index, err = _search_index(index, case_id, client)
    if err:
        return {"error": err}
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
    if err := _no_index_matched(result, index):
        aid = audit.log(
            tool="idx_search",
            params={"query": query, "index": requested, "scope": index, "limit": limit},
            result_summary="no open index matched",
        )
        if aid:
            err["audit_id"] = aid
        return err

    total = result["hits"]["total"]["value"]
    total_capped = result["hits"]["total"].get("relation") == "gte"
    if compact:
        docs = _strip_hits(result["hits"]["hits"])
    else:
        docs = _strip_hits(result["hits"]["hits"], exclude_fields=frozenset(), max_chars=999999)

    resp: dict = {"total": total, "returned": len(docs), "results": docs, "compact": compact}
    gap = _shard_gap(result, case_id)
    resp.update(gap)
    if total_capped:
        resp["total_capped"] = True
        resp["total_note"] = f"At least {total} results. Use idx_count for exact total."
    if (time_from or time_to) and (note := _untimed_note(client, index, _WINDOW)):
        resp["time_note"] = note
    # "have none" only when the window found nothing and the note names the indices:
    # never on a failed read, nor on a page past the end of what the window found,
    # nor when some shards didn't answer
    if not total and not gap and not resp.get("time_note", _UNCHECKED).startswith(_UNCHECKED):
        resp["hint"] = (
            "No results with an event time in the window. The indices in time_note "
            "have none, so the window left them out."
        )
    elif not total and not gap:  # partial, or past the last page: never "No results"
        resp["hint"] = (
            "No results. If searching for filenames, include the extension "
            "(e.g., 'svchost.exe' not 'svchost'). Use wildcards for partial: "
            "'*svchost*'. OpenSearch tokenizes on dots/hyphens. " + _IP_WILDCARD_HINT
        )
    elif _IP_WILDCARD.search(query):
        # Hits from indices that keep the address as text don't mean the
        # IP-typed ones matched: there the wildcard silently matches nothing.
        resp["hint"] = _IP_WILDCARD_HINT
    _add_hint(resp, _stale_dates_hint(client, index, query))
    if compact:
        resp["note"] = (
            "Results are compact — bloat fields excluded, long values truncated. "
            "Use idx_get_event(id, index) for full documents."
        )

    # Detect when query targets indices with different field naming.
    # Check existing index names (cached per case), not results, because
    # field-specific queries silently miss index types using different names.
    _add_field_hint(resp, index, client)

    _add_shimcache_reminder(resp, index, docs)
    _annotate_hosts(resp, case_id, hits=result["hits"]["hits"])
    return _logged_query(
        resp,
        tool="idx_search",
        queried=case_id,
        params={
            "query": query,
            "index": requested,
            "scope": index,
            "limit": limit,
            **_hit_params(result["hits"]["hits"]),
        },  # fmt: skip
        result_summary=f"{total} total, {len(docs)} returned",
    )


@server.tool()
def idx_count(
    query: str = "*",
    index: str = "",
    case_id: str = "",
) -> dict:
    """Count matching documents.

    Hosts: filter and group by host.id, the machine's name (what comes from a
    machine the examiner hasn't confirmed is marked host_unconfirmed);
    host.name is the raw name a record carried (one machine can carry several).
    Index names carry no host (case-<id>-<type>-…), so never pick an index for
    a host. idx_host_inventory lists the machines.

    Args:
        query: OpenSearch query_string (default: all).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern. Default: the
            active case; with no index, case_id or active case, it refuses.
    """
    requested = index
    client = _get_os()
    index, err = _search_index(index, case_id, client)
    if err:
        return {"error": err}
    # a search of no records, so the same request records the ingests counted
    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": _ingest_aggs(),
            "size": 0,
            "track_total_hits": True,
        },
    )
    if err := _no_index_matched(result, index):
        aid = audit.log(
            tool="idx_count",
            params={"query": query, "index": requested, "scope": index},
            result_summary="no open index matched",
        )
        if aid:
            err["audit_id"] = aid
        return err
    count = result["hits"]["total"]["value"]
    resp = {"count": count, **_shard_gap(result, case_id)}
    _add_hint(resp, _stale_dates_hint(client, index, query))
    _annotate_hosts(resp, case_id, client, index, {"query_string": {"query": query}})
    return _logged_query(
        resp,
        tool="idx_count",
        queried=case_id,
        params={"query": query, "index": requested, "scope": index, **_ingest_params(result)},
        result_summary=f"count={count}",
    )


@server.tool()
def idx_aggregate(
    field: str,
    query: str = "*",
    index: str = "",
    case_id: str = "",
    limit: int = 50,
) -> dict:
    """Aggregate (group by) a field with optional query filter.

    Hosts: filter and group by host.id, the machine's name (what comes from a
    machine the examiner hasn't confirmed is marked host_unconfirmed);
    host.name is the raw name a record carried (one machine can carry several).
    Index names carry no host (case-<id>-<type>-…), so never pick an index for
    a host. idx_host_inventory lists the machines.

    Args:
        field: Field to aggregate on (e.g., 'host.id', 'event.code').
        query: OpenSearch query_string filter (default: all).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern. Default: the
            active case; with no index, case_id or active case, it refuses.
        limit: Max buckets (default 50, max 500).
    """
    requested = index
    client = _get_os()
    index, err = _search_index(index, case_id, client)
    if err:
        return {"error": err}
    limit = min(limit, 500)
    if refusal := _mixed_type_refusal(client, index, field):
        return refusal

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {"agg": {"terms": {"field": field, "size": limit}}, **_ingest_aggs()},
            "size": 0,
            "track_total_hits": True,  # total_docs is reported; otherwise it stops at 10,000
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
        "truncated": len(buckets) >= limit,
        **_shard_gap(result, case_id),
    }
    _annotate_hosts(resp, case_id, client, index, {"query_string": {"query": query}}, field)
    return _logged_query(
        resp,
        tool="idx_aggregate",
        queried=case_id,
        params={
            "field": field,
            "query": query,
            "index": requested,
            "scope": index,
            **_ingest_params(result),
        },  # fmt: skip
        result_summary=f"{len(buckets)} buckets",
    )


@server.tool()
def idx_get_event(
    event_id: str,
    index: str,
) -> dict:
    """Retrieve a single document by its _id.

    Args:
        event_id: Document _id from search results.
        index: Exact index name (not a pattern).
    """
    if not index or not index.strip():
        return {"error": "Index parameter must not be empty"}
    client = _get_os()
    _, err = _resolve_index(index, "", client)
    if err:
        return {"error": err}
    result = _os_call(client.get, index=index, id=event_id)
    doc = {"_id": result["_id"], "_index": result["_index"]}
    doc.update(result.get("_source", {}))
    doc["_note"] = "Full document — all fields included, no truncation"
    return _logged_query(
        doc,
        tool="idx_get_event",
        params={
            "event_id": event_id,
            "index": index,
            **_hit_params([result]),
        },  # fmt: skip
        result_summary=f"doc {event_id}",
    )


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

    Hosts: filter and group by host.id, the machine's name (what comes from a
    machine the examiner hasn't confirmed is marked host_unconfirmed);
    host.name is the raw name a record carried (one machine can carry several).
    Index names carry no host (case-<id>-<type>-…), so never pick an index for
    a host. idx_host_inventory lists the machines.

    Args:
        query: OpenSearch query_string filter.
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID — auto-constructs case-{id}-* pattern. Default: the
            active case; with no index, case_id or active case, it refuses.
        interval: Histogram bucket size (e.g., '1m', '1h', '1d').
        time_field: Timestamp field (default @timestamp).
        time_from: Start time (ISO 8601, e.g., '2023-01-25T14:00:00Z').
        time_to: End time (ISO 8601).
    """
    import re as _re_mod

    if not _re_mod.match(r"^\d+[smhd]$", interval):
        return {"error": f"Invalid interval '{interval}'. Use Ns/Nm/Nh/Nd (e.g., 1h, 30m)."}
    requested = index
    client = _get_os()
    index, err = _search_index(index, case_id, client)
    if err:
        return {"error": err}

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
                },
                **_ingest_aggs(),
            },
            "size": 0,
            "track_total_hits": True,  # total_docs is reported; otherwise it stops at 10,000
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
        **_shard_gap(result, case_id),
    }
    if time_field == "@timestamp":  # the histogram itself reads @timestamp, window or not
        why = _WINDOW if (time_from or time_to) else "aren't in this timeline"
        if note := _untimed_note(client, index, why):
            resp["time_note"] = note
    _add_hint(resp, _stale_dates_hint(client, index, query, time_field))
    _annotate_hosts(resp, case_id, client, index, query_body)
    return _logged_query(
        resp,
        tool="idx_timeline",
        queried=case_id,
        params={
            "query": query,
            "index": requested,
            "scope": index,
            "interval": interval,
            **_ingest_params(result),
        },  # fmt: skip
        result_summary=f"{len(buckets)} buckets",
    )


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
        case_id: Case ID — auto-constructs case-{id}-* pattern. Default: the
            active case; with no index, case_id or active case, it refuses.
        limit: Max values (default 50, max 500).
    """
    requested = index
    client = _get_os()
    index, err = _search_index(index, case_id, client)
    if err:
        return {"error": err}
    limit = min(limit, 500)
    if refusal := _mixed_type_refusal(client, index, field):
        return refusal

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {"values": {"terms": {"field": field, "size": limit}}, **_ingest_aggs()},
            "size": 0,
        },
    )

    values = [
        {"value": b["key"], "count": b["doc_count"], "doc_count": b["doc_count"]}
        for b in result["aggregations"]["values"]["buckets"]
    ]

    resp = {"field": field, "values": values, "truncated": len(values) >= limit,
            **_shard_gap(result, case_id)}  # fmt: skip
    return _logged_query(
        resp,
        tool="idx_field_values",
        queried=case_id,
        params={
            "field": field,
            "query": query,
            "index": requested,
            "scope": index,
            **_ingest_params(result),
        },  # fmt: skip
        result_summary=f"{len(values)} values",
    )


@server.tool()
def idx_status() -> dict:
    """Show OpenSearch index status: names, doc counts, sizes."""
    client = _get_os()

    indices = _os_call(client.cat.indices, format="json")
    case_indices = [
        {
            "index": idx["index"],
            "docs": _cat_doc_count(idx),  # None: unknown (a red index), never 0
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
    _name_unknown_counts(resp, [i["index"] for i in case_indices if i["docs"] is None])
    aid = audit.log(
        tool="idx_status",
        params={},
        result_summary=f"{len(case_indices)} indices",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_shard_status() -> dict:
    """Report OpenSearch shard usage and capacity headroom.

    Returns current shard count, configured max_shards_per_node,
    effective cluster-wide max (max_per_node x data_nodes), and
    headroom percentage. Use before large ingests to sanity-check
    capacity.
    """
    from opensearch_mcp.shard_capacity import _resolve_setting

    client = _get_os()
    try:
        stats = client.cluster.stats(
            filter_path=["indices.shards.total", "nodes.count.data"],
            request_timeout=10,
        )
        # flat_settings=True conflicts with dotted filter_path; drop it.
        settings = client.cluster.get_settings(
            include_defaults=True,
            filter_path=[
                "persistent.cluster.max_shards_per_node",
                "transient.cluster.max_shards_per_node",
                "defaults.cluster.max_shards_per_node",
            ],
            request_timeout=10,
        )
    except Exception as e:
        return {"status": "error", "error": str(e)}

    current = (stats.get("indices") or {}).get("shards", {}).get("total", 0) or 0
    data_nodes = (stats.get("nodes") or {}).get("count", {}).get("data", 1) or 1
    try:
        max_per_node = int(_resolve_setting(settings, "cluster.max_shards_per_node", default=1000))
    except (TypeError, ValueError):
        max_per_node = 1000
    max_total = max_per_node * int(data_nodes)
    headroom_pct = round(((max_total - current) / max_total) * 100, 1) if max_total else 0.0

    # Top 10 indices by shard count for capacity diagnosis.
    # Exclude system/hidden indices (.opendistro_security, .tasks, etc.)
    # so the top-10 reflects case data, not cluster housekeeping.
    try:
        indices_info = client.cat.indices(format="json", request_timeout=10) or []
    except Exception:
        indices_info = []
    visible = [i for i in indices_info if not (i.get("index") or "").startswith(".")]
    top_indices = sorted(
        visible,
        key=lambda i: int(i.get("pri", 0) or 0) + int(i.get("rep", 0) or 0),
        reverse=True,
    )[:10]
    top = [
        {
            "index": i.get("index"),
            "primary_shards": int(i.get("pri", 0) or 0),
            "replica_shards": int(i.get("rep", 0) or 0),
            "doc_count": _cat_doc_count(i),  # None: unknown (a red index), never 0
            "size": i.get("store.size"),
        }
        for i in top_indices
    ]

    aid = audit.log(
        tool="idx_shard_status",
        params={},
        result_summary=(f"{current}/{max_total} shards ({headroom_pct}% headroom)"),
    )
    resp = {
        "current_shards": int(current),
        "max_shards_per_node": max_per_node,
        "data_nodes": int(data_nodes),
        "max_total": max_total,
        "headroom_pct": headroom_pct,
        "status": ("ok" if headroom_pct >= 10 else "warning" if headroom_pct >= 2 else "critical"),
        "top_indices_by_shard_count": top,
    }
    _name_unknown_counts(resp, [i["index"] for i in top if i["doc_count"] is None])
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_install_pipelines() -> dict:
    """Install or verify the winlog_data_normalize ingest pipeline and
    evtx template.

    Idempotent. Runs collision detection against operator-installed
    templates; simulates the pipeline against all 3 expected input
    shapes (object/string/list) BEFORE PUT so a broken new pipeline
    cannot overwrite a working one. Writes an audit entry.

    Returns status="ok" on success, status="error" with actionable
    reason otherwise.
    """
    from opensearch_mcp.mappings import ensure_winlog_pipeline

    client = _get_os()
    result = ensure_winlog_pipeline(client, audit, _active_case_indices())

    # Surface the non-evtx template install outcome in the summary so
    # operators running this manually see both halves of the work.
    # Also promote per-template failures to an explicit `warnings` list
    # on the response + a logger.warning so ops noticing template-install
    # problems don't have to dig through the nested other_templates dict.
    other = result.get("other_templates") or {}
    failed_tpls = other.get("failed", [])
    if failed_tpls:
        warn_msgs = [
            f"Template install failed: {f.get('template')} — {f.get('error', '')[:200]}"
            for f in failed_tpls
        ]
        result.setdefault("warnings", []).extend(warn_msgs)
        for m in warn_msgs:
            logger.warning(m)
    tpl_counts = (
        f" templates:installed={len(other.get('installed', []))}"
        f",failed={len(failed_tpls)}"
        f",skipped={len(other.get('skipped', []))}"
        if other
        else ""
    )
    aid = audit.log(
        tool="idx_install_pipelines",
        params={},
        result_summary=(
            f"status={result.get('status')}"
            + (f" error={result.get('error')[:200]}" if result.get("error") else "")
            + tpl_counts
        ),
    )
    if aid:
        result["audit_id"] = aid
    return result


def _cat_doc_count(row: dict) -> int | None:
    """A `_cat/indices` row's document count, or None when it has none: a red
    index's docs.count is null."""
    try:
        return int(row.get("docs.count", 0))
    except (TypeError, ValueError):
        return None


def _name_unknown_counts(resp: dict, names: list[str]) -> None:
    """Flag `resp` partial and name the indices whose count is unknown."""
    if not names:
        return
    names = sorted(names)
    more = f" and {len(names) - 5} more" if len(names) > 5 else ""
    resp["partial"] = True
    resp.setdefault("warnings", []).append(
        f"Document counts: partial; failing indices: {', '.join(names[:5])}{more}; "
        "their counts are unknown"
    )


def _failed_artifact_warnings(
    cid: str, docs_by_index: dict[str, int | None], host_docs=None
) -> list[str]:
    """One warning per (host, artifact) whose most recent ingest failed and left
    an index: it may hold only part of the artifact. Read from the case audit
    log, which outlives the ingest status files."""
    from sift_common.host_identity import spelling

    from opensearch_mcp.ingest import _CUSTOM_ARTIFACTS, _PLASO_ARTIFACTS
    from opensearch_mcp.paths import build_index_name, legacy_index_name
    from opensearch_mcp.tools import TOOLS

    suffix = {n: c.index_suffix for n, c in TOOLS.items()}
    suffix.update({n: n for n in _PLASO_ARTIFACTS | _CUSTOM_ARTIFACTS})  # indexed by name
    suffix["evtx"] = "evtx"  # the evtx parser's own entries (ingest_evtx)
    audit_dir = audit._get_audit_dir()  # where the ingest workers' entries go
    dirs = [audit_dir] if audit_dir else []
    # and the case's own audit dir when it isn't the active case's
    if cid and not any(s in cid for s in ("..", "/", "\\")):
        own = Path(os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases"))) / cid / "audit"
        if own.is_dir() and not any(own.samefile(d) for d in dirs):
            dirs.append(own)
    c12 = _case_c12(cid)
    # (index, host) -> (ts, result, tool, host, run)
    last: dict[tuple[str, str], tuple[str, str, str, str, str]] = {}
    for f in [f for d in dirs for f in sorted(d.glob("opensearch-ingest-*.jsonl"))]:
        own_dir = f.parent.parent.name == cid
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            params = e.get("params") if isinstance(e, dict) else None
            case = e.get("case_id") if isinstance(e, dict) else None
            # an entry written with no active case has case_id "": it's this
            # case's only when the log is in this case's own directory
            if not isinstance(params, dict) or not (case == cid or (own_dir and case == "")):
                continue
            # the entry's own name, ingest_<tool>: not every success records params.tool
            host, tool = params.get("hostname"), str(e.get("tool", "")).removeprefix("ingest_")
            if not (host and tool in suffix):
                continue
            rs = e.get("result_summary")
            rs = str(rs.get("value", "") if isinstance(rs, dict) else rs or "")
            ts = str(e.get("ts", ""))
            # the shared index, or a pre-0.6.4 per-host one; DEV01 and dev01 are one host
            index = build_index_name(c12, suffix[tool]) if c12 else ""
            if index not in docs_by_index:
                index = legacy_index_name(cid, suffix[tool], host)
            run = params.get("run_id") or ts  # an entry from before run ids is its own run
            prev = last.get((index, spelling(host)), ("", "", "", "", ""))
            if prev[4] == run and prev[1].startswith("FAILED"):
                continue  # one failed profile or directory fails its run
            if ts >= prev[0]:
                last[(index, spelling(host))] = (ts, rs, tool, host, run)
    warnings = []
    for (index, _h), (_ts, rs, tool, host, _run) in sorted(last.items()):
        if rs.startswith("FAILED") and index in docs_by_index:
            # a shared index holds every host's records: count this host's
            n, whole = (None, True)
            if host_docs and index.endswith("-0"):
                n, whole = host_docs(index, host)
            if not whole:  # some shards didn't answer: unknown, never their count
                docs = "document count unknown"
            elif n is not None:
                docs = f"{n:,} docs from {host}"
            elif docs_by_index[index] is not None:
                docs = f"{docs_by_index[index]:,} docs"
            else:  # a red index: its count is unknown
                docs = "document count unknown"
            warnings.append(
                f"{index} ({docs}) may be incomplete: the most"
                f" recent ingest of {tool} on {host} failed ({rs[:200]})"
            )
    return warnings


def _outcome_is(outcome: str) -> dict:
    """Documents with an IOC entry of this outcome, whether the index maps
    the field as keyword or (from before it was declared) as text."""
    return {
        "bool": {
            "should": [
                {"term": {"threat_intel.iocs.outcome": outcome}},
                {"term": {"threat_intel.iocs.outcome.keyword": outcome}},
            ],
            "minimum_should_match": 1,
        }
    }


def _intel_counts(client, pattern: str, gaps: list | None = None) -> dict:
    """Documents checked, with any IOC matched, with any IOC unanswered, and
    carrying an older release's single stamp. Each count's reply goes to
    `gaps`, for its shards."""

    def count(query: dict) -> int:
        result = client.count(index=pattern, body={"query": query})
        if gaps is not None:
            gaps.append(result)
        return result["count"]

    return {
        "checked": count({"exists": {"field": "threat_intel.checked"}}),
        "matched": count(_outcome_is("MATCH")),
        "unavailable": count(_outcome_is("UNAVAILABLE")),
        "legacy": count({"exists": {"field": "threat_intel.verdict"}}),
    }


def _case_c12(case_id: str) -> str:
    """The index id of the case named `case_id`, or "" when it has no directory."""
    from opensearch_mcp.write_context import case_dir_for, case_identity

    case_dir = case_dir_for(case_id)
    if case_dir is None or not (case_dir / "CASE.yaml").is_file():
        return ""
    return case_identity(case_dir)[0]


def _existing_host_docs(client, case_id: str, artifact_type: str, hostname: str, out: dict):
    """Record how many documents of `artifact_type` already carry `hostname`:
    in the case's shared index, and, in a case from before 0.6.4, in its
    pre-0.6.4 per-host index, with the notice that this ingest adds a second
    copy (under the "notes" key)."""
    from opensearch_mcp.case_scope import CaseScopeError, scope_of
    from opensearch_mcp.paths import build_index_name, legacy_index_name
    from opensearch_mcp.write_context import SECOND_COPY_NOTE

    try:
        scope = scope_of(case_id)
    except CaseScopeError:
        return
    idx = build_index_name(scope.c12, artifact_type)
    try:
        n = client.count(index=idx, body={"query": {"term": {"host.name": hostname}}})["count"]
        if n:
            out[idx] = n
    except Exception:
        pass
    if scope.naming_version != 1:
        return
    idx = legacy_index_name(scope.legacy_id, artifact_type, hostname)
    try:
        n = client.count(index=idx)["count"]
    except Exception:
        return
    out[idx] = n
    if n:
        notes = out.setdefault("notes", [])
        note = f"{artifact_type}: {SECOND_COPY_NOTE}"
        if note not in notes:
            notes.append(note)


@server.tool()
def idx_case_summary(case_id: str = "", include_fields: bool = False) -> dict:
    """Get a complete overview of indexed evidence for a case.

    Returns hosts, artifact types with doc counts, and enrichment status.

    Args:
        case_id: Case ID (default: active case).
        include_fields: Include field mappings per artifact type (large output).
            Default False to keep response compact.
    """
    from opensearch_mcp.case_scope import (
        CaseScopeError,
        case_read_scope,
        scope_of,
        unattributed_indices,
    )
    from opensearch_mcp.case_scope import (
        artifact_type as _artifact_type,
    )

    try:
        scope = scope_of(case_id or _get_active_case() or "")
    except CaseScopeError as e:
        return {"error": str(e)}
    cid = scope.case_id
    client = _get_os()
    resp: dict = {}
    pattern = case_read_scope(cid, client)

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
        err = {
            "case_id": cid,
            "error": f"No index matches {pattern!r}: nothing was summarized. "
            "Check the case id, or ingest evidence into this case first.",
        }
        return err

    # Hosts are machines: host.id, with the raw names their records carry,
    # read from the documents (index names carry no host).
    hosts: set = set()
    host_names: dict = {}
    index_hosts: dict = {}
    ingested: dict = {}  # which ingests the summarised records came from

    gaps: dict[str, dict] = {}  # part -> its failing indices, and whether any were unavailable

    def shard_gap(what: str, result: dict) -> None:  # a part only some shards answered
        parts, numbers = _gap_parts(result, cid)
        if not parts:
            return
        gap = gaps.setdefault(what, {"indices": set(), "unavailable": False, "timed_out": False})
        gap["indices"].update(numbers["failed_indices"])
        gap["unavailable"] |= bool(numbers["shards"].get("unavailable"))
        gap["timed_out"] |= numbers["timed_out"]
        say(what)

    def say(what: str) -> None:  # the part's one warning, from all its gaps so far
        gap = gaps[what]
        # names only, no numbers: each tool's own reply has the counts
        names = sorted(gap["indices"])
        clauses = ["partial"]
        if names:
            more = f" and {len(names) - 5} more" if len(names) > 5 else ""
            clauses.append(f"failing indices: {', '.join(names[:5])}{more}")
        if gap["unavailable"]:
            clauses.append("some shards were unavailable")
        if gap["timed_out"]:
            clauses.append("the search timed out")
        if what == "Time range":  # a partial min/max is narrower, not lower
            clauses.append("the earliest and latest may be narrower")
        else:
            clauses.append("the counts are lower bounds")
        text = f"{what}: {'; '.join(clauses)}"
        resp["partial"] = True
        warnings = resp.setdefault("warnings", [])
        mine = [i for i, w in enumerate(warnings) if w.startswith(f"{what}: ")]
        if mine:  # one warning per part
            warnings[mine[0]] = text
        else:
            warnings.append(text)

    try:
        host_agg = client.search(
            index=pattern,
            body={
                "size": 0,
                "aggs": {
                    **_ingest_aggs(),
                    "hosts": {
                        "terms": {"field": "host.id", "size": 5000},
                        "aggs": {"names": {"terms": {"field": "host.name", "size": 50}}},
                    },
                    "by_index": {
                        "terms": {"field": "_index", "size": 5000},
                        "aggs": {"hosts": {"terms": {"field": "host.id", "size": 500}}},
                    },
                },
            },
        )
        ingested = host_agg
        shard_gap("Host detection", host_agg)
        for bucket in host_agg["aggregations"]["hosts"]["buckets"]:
            hosts.add(bucket["key"])
            host_names[bucket["key"]] = sorted(b["key"] for b in bucket["names"]["buckets"])
        cut = host_agg["aggregations"]["hosts"].get("sum_other_doc_count", 0)
        if cut:
            resp.setdefault("warnings", []).append(
                f"Host list cut at 5000 host.id values: {cut} documents carry hosts not listed."
            )
        for bucket in host_agg["aggregations"]["by_index"]["buckets"]:
            index_hosts[bucket["key"]] = [b["key"] for b in bucket["hosts"]["buckets"]]
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Host detection query failed: {e}")

    # Artifact type: the remainder after case-<c12>- with -0 removed; for a
    # pre-0.6.4 index, its type with the host tail dropped.
    artifacts: dict = {}
    total_docs = 0
    for idx in indices:
        name = idx["index"]
        docs = _cat_doc_count(idx)
        if docs is None:  # unknown, not 0: named, and the counts are lower bounds
            gap = gaps.setdefault("Document counts", {"indices": set(), "unavailable": False,
                                                      "timed_out": False})  # fmt: skip
            gap["indices"].add(name)
            say("Document counts")
            continue
        total_docs += docs
        atype = _artifact_type(name, scope)
        if atype not in artifacts:
            artifacts[atype] = {"docs": 0, "hosts": [], "indices": []}
        artifacts[atype]["docs"] += docs
        for h in index_hosts.get(name, []):
            if h not in artifacts[atype]["hosts"]:
                artifacts[atype]["hosts"].append(h)
        artifacts[atype]["indices"].append(name)

    # Aggregate sub-indices (e.g., delim-amcache-devicecontainers → delim-amcache)
    # to prevent 30 hosts × 6 sub-tables = 180 entries bloating the response.
    _AGGREGATE_PREFIXES = (
        "delim-amcache-",
        "delim-mftecmd-",
        "delim-srumecmd-",
        "delim-sqlecmd-",
    )
    merged: dict = {}
    for atype, info in artifacts.items():
        parent = atype
        for pfx in _AGGREGATE_PREFIXES:
            if atype.startswith(pfx):
                parent = pfx.rstrip("-")
                break
        if parent not in merged:
            merged[parent] = {"docs": 0, "hosts": [], "indices": []}
        merged[parent]["docs"] += info["docs"]
        for h in info.get("hosts", []):
            if h not in merged[parent]["hosts"]:
                merged[parent]["hosts"].append(h)
        merged[parent]["indices"].extend(info["indices"])
    artifacts = merged

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
    if include_fields:
        for atype, info in artifacts.items():
            if not info["indices"]:
                continue
            try:
                mapping = client.indices.get_mapping(index=info["indices"][0])
                idx_name = info["indices"][0]
                props = mapping.get(idx_name, {}).get("mappings", {}).get("properties", {})
                fields_per_type[atype] = sorted(_flatten_props(props), key=lambda f: f["field"])[
                    :150
                ]
            except Exception as e:
                resp.setdefault("warnings", []).append(
                    f"Field mapping query failed for {atype}: {e}"
                )

    # Enrichment status
    enrichment: dict = {}
    try:
        triage = client.count(
            index=pattern,
            body={"query": {"exists": {"field": "triage.checked"}}},
        )
        shard_gap("Triage stats", triage)
        triage_count = triage["count"]
        if triage_count:
            triage = client.count(
                index=pattern,
                body={"query": {"term": {"triage.verdict": "SUSPICIOUS"}}},
            )
            shard_gap("Triage stats", triage)
            suspicious = triage["count"]
            enrichment["triage"] = {
                "checked": triage_count,
                "suspicious": suspicious,
            }
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Triage stats query failed: {e}")

    try:
        intel_replies: list = []
        intel = _intel_counts(client, pattern, intel_replies)
        for reply in intel_replies:
            shard_gap("Intel stats", reply)
        if any(intel.values()):
            enrichment["threat_intel"] = intel
        if intel["legacy"]:
            resp.setdefault("warnings", []).append(
                f"{intel['legacy']} documents carry an older release's single threat-intel "
                "stamp; a forced enrichment run (idx_enrich_intel force=true) clears them and "
                "stamps each IOC's answer"
            )
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Intel stats query failed: {e}")

    # Time range (single query for both min and max)
    time_range: dict = {}
    try:
        ts_result = client.search(
            index=pattern,
            body={
                "size": 0,
                "aggs": {
                    "min_ts": {"min": {"field": "@timestamp"}},
                    "max_ts": {"max": {"field": "@timestamp"}},
                },
            },
        )
        shard_gap("Time range", ts_result)
        min_val = _agg_time(ts_result["aggregations"]["min_ts"])
        max_val = _agg_time(ts_result["aggregations"]["max_ts"])
        if min_val:
            time_range["earliest"] = min_val
        if max_val:
            time_range["latest"] = max_val
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Time range query failed: {e}")
    if note := _untimed_note(client, pattern, "aren't in time_range"):
        resp.setdefault("warnings", []).append(f"Time range: {note}")

    resp.update(
        {
            "case_id": cid,
            "hosts": sorted(hosts),
            "host_names": host_names,
            "artifacts": artifacts,
            "total_docs": total_docs,
            "time_range": time_range,
            "enrichment": enrichment,
        }
    )
    if fields_per_type:
        resp["fields_per_type"] = fields_per_type
    unclaimed = unattributed_indices(client, scope)
    if unclaimed:  # e.g. a case whose folder is gone: no case reads them
        resp["unattributed_indices"] = unclaimed
        resp.setdefault("warnings", []).append(
            f"{len(unclaimed)} case indices belong to no case directory on this machine, "
            "so no case reads them: " + ", ".join(unclaimed[:10])
        )
    docs_by_index = {i["index"]: _cat_doc_count(i) for i in indices}
    try:

        def host_docs(index, host):  # (its count or None, whether every shard answered)
            try:
                body = {"query": {"term": {"host.name": host}}}
                reply = client.count(index=index, body=body)
                shards = reply.get("_shards") or {}
                return reply["count"], shards.get("successful", 0) >= shards.get("total", 0)
            except Exception:
                return None, True

        partial = _failed_artifact_warnings(cid, docs_by_index, host_docs)
    except OSError as e:
        partial = [f"Could not read the ingest audit log: {e}"]
    if partial:
        resp.setdefault("warnings", []).extend(partial)
    _add_investigation_hints(resp, artifacts, scope.c12)
    return _logged_query(
        resp,
        tool="idx_case_summary",
        params={"case_id": cid, **_ingest_params(ingested)},
        result_summary=f"{len(hosts)} hosts, {len(artifacts)} artifact types, {total_docs} docs",
    )


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
    no_hayabusa: bool = False,
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
        include: These artifact types (e.g., ["mft", "usn"]), plus the tier-1
            defaults and any event logs found.
        exclude: Skip these artifact types (e.g., ["jumplists"]).
        source_timezone: Evidence system's local timezone (e.g., "Eastern Standard Time").
        all_logs: Parse all evtx files (default: forensic logs only).
        reduced_ids: Filter to ~78 high-value Event IDs.
        full: Include all tiers including MFT, USN, timeline.
        vss: Also ingest the image's volume shadow copies. A record's
            vhir.vss_id is "live" if the record exists on the live volume;
            otherwise the earliest shadow copy that holds it (vss1 first).
        dry_run: Preview without indexing (default True). Set False to execute
            immediately if path and parameters are confirmed.
    """
    import subprocess as _check_sp
    import sys
    from pathlib import Path

    from opensearch_mcp.containers import SUDO_REMEDY, detect_container
    from opensearch_mcp.ingest import discover

    active = _active_case()  # one read: the input's folder and the run's case
    path, path_err = _case_path(path, active)
    path_err = path_err or _validate_path(path)
    if path_err:
        return {"error": path_err}
    evidence_path = Path(path).resolve()
    if not evidence_path.exists():
        return {"error": f"Path not found: {path}"}

    case_id = active[0]
    if not case_id:
        return {"error": "No active case. Run 'vhir case activate' first."}

    # Container files (VHDX, E01, 7z, raw) — preview without mounting
    container_type = detect_container(evidence_path)
    if container_type in ("ewf", "raw", "nbd", "archive", "dmg"):
        if dry_run:
            # A .dmg is never mounted: Plaso reads it, with no sudo.
            sudo_ok = (
                container_type == "dmg"
                or _check_sp.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
            )
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
                resp["warning"] = SUDO_REMEDY
            if hostname:
                resp["hostname"] = hostname
            resp["scan"] = _container_scan(evidence_path, container_type, case_id)
            _with_host_list_hint(resp, case_id)
            aid = audit.log(
                tool="idx_ingest",
                params={
                    "path": path,
                    "dry_run": True,
                    "container": container_type,
                },
                result_summary=f"container preview: {container_type}",
                **_audit_case(active),
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
        return {"error": f"No Windows, Linux or macOS artifacts found in {path}"}

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
                _existing_host_docs(client, case_id, suffix, host.hostname, existing)
            if evtx_count:
                _existing_host_docs(client, case_id, "evtx", host.hostname, existing)

            host_info = {
                "hostname": host.hostname,
                "artifacts": artifact_names,
            }
            if evtx_count:
                host_info["evtx_files"] = evtx_count
            notes = existing.pop("notes", None)
            if notes:
                host_info["second_copy"] = notes
            if existing:
                host_info["existing"] = existing
            summary.append(host_info)

        aid = audit.log(
            tool="idx_ingest",
            params={"path": path, "dry_run": True},
            result_summary=f"discovery: {len(hosts)} hosts",
            **_audit_case(active),
        )
        resp = {"status": "preview", "hosts": summary, "case_id": case_id}
        resp["scan"] = _folder_scan(hosts, case_id)
        _with_host_list_hint(resp, case_id)
        if aid:
            resp["audit_id"] = aid
        return resp

    # dry_run=False: launch ingest as a subprocess that survives gateway restart.
    # Defensive reset — breaker state is module-level in the MCP
    # server process; clear any inherited state from prior tool
    # invocations in the same server lifetime.
    from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb

    _reset_cb()

    # Pre-flight: abort if cluster shard capacity is exhausted. Halts
    # loudly instead of discovering the condition mid-ingest through
    # silent bulk rejections.
    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    client = get_client()
    ok, reason = check_shard_headroom(
        client,
        expected_new_shards=_estimate_new_shards("evtx"),
        min_headroom_pct=10.0,
    )
    if not ok:
        aid = audit.log(
            tool="idx_ingest",
            params={"path": path, "dry_run": False},
            result_summary=f"aborted: {reason[:120]}",
            **_audit_case(active),
        )
        # Write terminal status so idx_ingest_status surfaces the
        # refusal (otherwise it returns "no active ingests" after a
        # refuse). Error-prefix convention: HALT_SHARD_CAPACITY.
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.ingest_status import (
            HALT_SHARD_CAPACITY,
            write_status,
        )

        write_status(
            case_id=case_id,
            pid=os.getpid(),
            run_id="",  # no run yet — refusal happens before subprocess spawn
            status="failed",
            hosts=[],
            totals={},
            started=_dt.now(_tz.utc).isoformat(),
            error=f"{HALT_SHARD_CAPACITY}: {reason}",
        )
        resp = {"status": "failed", "error": "shard_capacity", "message": reason}
        if aid:
            resp["audit_id"] = aid
        return resp

    import os as _os
    import uuid as _uuid

    if refused := _admission_refusal():
        return refused

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["VHIR_INGEST_RUN_ID"] = run_id

    cmd = [
        sys.executable,
        "-I",
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
        env["VHIR_ARCHIVE_PASSWORD"] = password
    if no_hayabusa:
        cmd.append("--no-hayabusa")

    # Log to file so errors are visible (same as _launch_background)
    from opensearch_mcp.paths import vhir_dir as _vhir_dir

    _log_dir = _vhir_dir() / "ingest-logs"
    _log_dir.mkdir(parents=True, exist_ok=True)
    _log_file = _log_dir / f"{run_id}.log"
    _log_fh = open(_log_file, "w")

    proc = _spawn_ingest(cmd, env, _log_fh, run_id)
    _log_fh.close()  # Safe: Popen dup2'd the fd, subprocess has its own copy

    host_names = [h.hostname for h in hosts] if hosts else ([hostname] if hostname else [])
    # A record under the worker's pid, so a worker that dies before writing
    # its own shows as failed rather than not at all.
    from datetime import datetime as _dt_scan
    from datetime import timezone as _tz_scan

    from opensearch_mcp.ingest_status import write_status as _ws_scan

    _ws_scan(
        case_id=case_id,
        pid=proc.pid,
        run_id=run_id,
        status="starting",
        hosts=[{"hostname": h, "artifacts": []} for h in host_names],
        totals={"indexed": 0},
        started=_dt_scan.now(_tz_scan.utc).isoformat(),
        log_file=str(_log_file),
    )
    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "hosts": host_names,
        "case_id": case_id,
        "log_file": str(_log_file),
        "message": (
            "Ingest started. IMPORTANT: Call idx_ingest_status() every 30 seconds "
            "to monitor progress and report it to the examiner as a checklist. "
            "Continue polling until status is 'complete' or 'failed'."
        ),
    }
    resp = _answer_after_gate(resp, case_id, proc.pid, run_id)
    aid = audit.log(
        tool="idx_ingest",
        params={
            "path": path,
            "dry_run": False,
            "hosts": host_names,
            "pid": proc.pid,
            "run_id": run_id,
        },
        result_summary=_launch_summary(
            resp, f"started ingest (pid {proc.pid}) for {len(hosts)} hosts"
        ),
        input_files=[path],
        **_audit_case(active),
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def _log_tail(path: str, limit: int = 2048) -> list[str]:
    """The last lines of a worker's log, at most `limit` bytes of it."""
    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.path.getsize(path) - limit))
            return f.read().decode(errors="replace").splitlines()[-10:]
    except OSError:
        return []


# Evtx files an ingest dropped before parsing, or found cut short, by the status key it records.
_DROPPED_EVTX = {
    "not_in_log_set": "not in the forensic-logs set were not ingested; ingest with "
    "all_logs=True to include them",
    "under_one_chunk": "under one chunk (69,632 bytes) were skipped as empty",
    "truncated": "are cut short: records past the cut, and any in a partial last chunk, "
    "were not indexed",
}


@server.tool()
def idx_ingest_status(case_id: str = "") -> dict:
    """Check status of running or recent ingest operations.

    Defaults to active case. Pass case_id="*" to see all cases.

    "awaiting host confirmation": the run has read its evidence's host names
    and writes nothing until the examiner confirms them (or chooses Start
    now) in the portal's Hosts tab; you can't confirm them. It then ingests
    by itself. idx_host_inventory shows what it waits for.
    The same status with the message "Its hosts are confirmed. It starts when
    one of the 3 running ingests ends." means only that: no one needs to
    confirm anything, and the run starts by itself when a place frees.

    Args:
        case_id: Filter to this case (default: active case). "*" for all.
    """
    from opensearch_mcp.ingest_status import read_active_ingests

    ingests = read_active_ingests()

    # Filter by case (default: active case)
    filter_case = case_id or _get_active_case() or ""
    if filter_case and filter_case != "*":
        ingests = [i for i in ingests if i.get("case_id") == filter_case]

    if not ingests:
        return {"ingests": [], "message": "No active or recent ingests."}

    summaries = []
    for ing in ingests:
        status = ing.get("status", "unknown")
        elapsed = _elapsed_seconds(ing)
        minutes = int(elapsed // 60)

        totals = ing.get("totals", {})
        bf = ing.get("bulk_failed", 0) or totals.get("bulk_failed", 0)
        s = {
            "case_id": ing.get("case_id"),
            "status": status,
            "pid": ing.get("pid"),
            "run_id": ing.get("run_id", ""),  # one process can run several (an archive's images)
            "elapsed": f"{minutes}m",
            "total_indexed": totals.get("indexed", 0),
            "bulk_failed": bf,
            "hosts_complete": totals.get("hosts_complete", 0),
            "hosts_total": totals.get("hosts_total", 0),
            "artifacts_complete": totals.get("artifacts_complete", 0),
            "artifacts_total": totals.get("artifacts_total", 0),
            "log_file": ing.get("log_file", ""),
        }
        if totals.get("already_present"):
            s["already_present"] = totals["already_present"]
        # Warn the LLM/user when rejections occurred — makes silent
        # drops visible in the response payload, not only in stderr.
        if bf > 0:
            warnings = s.setdefault("warnings", [])
            reason = ing.get("bulk_failed_reason", "")
            warn_msg = f"{bf:,} events rejected by OpenSearch during bulk write"
            if reason:
                warn_msg += f" (first reason: {reason[:160]})"
            warn_msg += (
                ". Likely cluster capacity or mapping issue. Run idx_shard_status() to diagnose."
            )
            warnings.append(warn_msg)

        # Build per-host checklist for the LLM to present
        checklist = []
        for h in ing.get("hosts", []):
            hostname = h.get("hostname", "?")
            for a in h.get("artifacts", []):
                skipped = a.get("skipped_files") or []
                if skipped:  # hostname='auto' could tie these to none of the hosts
                    shown = ", ".join(skipped[:10]) + (", …" if len(skipped) > 10 else "")
                    s.setdefault("warnings", []).append(
                        f"{len(skipped)} file(s) not ingested: their names give none of the "
                        f"detected hosts ({shown}). Ingest them with an explicit hostname."
                    )
                if a.get("note") and "locator" in a:  # it names its locator and raw name
                    s.setdefault("warnings", []).append(a["note"])
                elif a.get("note"):
                    s.setdefault("warnings", []).append(f"{hostname}: {a['note']}")
                if a.get("not_read"):
                    unread = a["not_read"]
                    shown = "; ".join(unread[:10]) + ("; …" if len(unread) > 10 else "")
                    s.setdefault("warnings", []).append(
                        f"{hostname}: {a['name']}: {len(unread)} file(s) or folder(s) were not "
                        f"ingested, or only in part ({shown})"
                    )
                for key, text in _DROPPED_EVTX.items():
                    if a.get(key):
                        names = a[key]
                        shown = ", ".join(names[:10]) + (", …" if len(names) > 10 else "")
                        s.setdefault("warnings", []).append(
                            f"{hostname}: {len(names)} evtx file(s) {text} ({shown})"
                        )
                if a.get("warnings_only"):  # not an artifact: its warnings above say it all
                    continue
                a_status = a.get("status", "pending")
                indexed = a.get("indexed", 0)
                if a_status == "complete":
                    icon = "done"
                    detail = f"{indexed:,} new" + _describe_counts(a)
                    if "rows_skipped" in a:  # a delimited, JSON or access-log run
                        detail += "; " + left_out(a["rows_skipped"], a.get("files_not_read", 0))
                    if a.get("implausible_time"):
                        n = a["implausible_time"]
                        detail += f"; {n:,} with an implausible time, @timestamp not set"
                    # A running Windows image always has processes. 0 indexed has
                    # more than one cause, and the status can't tell them apart.
                    if a.get("name") == "windows.pslist" and indexed == 0:
                        s.setdefault("warnings", []).append(
                            f"{hostname}: windows.pslist indexed no processes (a running "
                            "Windows image always has some). Either the process list "
                            "couldn't be walked (possible memory smear or unsupported "
                            "layout), in which case windows.psscan can recover processes "
                            '(tier 2, or plugins=["windows.psscan"]); or the results '
                            "weren't indexed, in which case check the ingest log."
                        )
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
        if any("stored" in a for h in ing.get("hosts", []) for a in h.get("artifacts", [])):
            s["counts_note"] = _COUNTS_NOTE

        if status == "running":
            s["message"] = (
                "Ingest in progress. Present the checklist above to the examiner. "
                "Call idx_ingest_status() again in 30 seconds for updated progress."
            )
        elif status == "killed":
            s["message"] = (
                "Ingest process died unexpectedly. Re-run to continue — dedup prevents duplicates."
            )
        elif status == "failed":
            # Error-prefix convention: refuse sites write status=failed
            # with error="<halt_token>: <reason>". Surface the prefix
            # in the message so the client sees which halt path fired.
            _err = ing.get("error", "") or ""
            _prefix = ""
            if ":" in _err:
                _prefix = _err.split(":", 1)[0].strip()
            s["halt_reason"] = _prefix or "unspecified"
            if _prefix == "shard_capacity_exhausted":
                s["message"] = (
                    f"Ingest refused before start ({_prefix}). No documents "
                    f"were indexed. Address the underlying condition "
                    f"(raise cluster.max_shards_per_node, archive old cases, "
                    f"or run idx_shard_status() to inspect) then re-run."
                )
            elif _prefix == "circuit_breaker_tripped":
                s["message"] = (
                    f"Ingest halted mid-run ({_prefix}). "
                    f"{totals.get('indexed', 0):,} docs indexed before halt. "
                    f"Re-run on the same evidence after resolving capacity; "
                    f"dedup prevents duplicates."
                )
            elif _prefix == "hayabusa_no_rules":
                s["message"] = f"Ingest failed ({_prefix}): {_err[:200]}"
            elif _prefix == "all_plugins_failed":
                # whole: the fix it names (the SIFT update) comes after the cause
                s["message"] = f"Ingest failed ({_prefix}): {_err[len(_prefix) + 2 :]}"
            elif _prefix == "process_died_unexpectedly":  # longer: its cause ends in the fix
                s["message"] = f"Ingest failed: {_err[:600]}"
            else:
                s["message"] = f"Ingest failed: {_err[:200]}"
            if _prefix == "process_died_unexpectedly" and s["log_file"]:
                # The worker died without saying why: its log does.
                s["log_tail"] = _log_tail(s["log_file"])
        elif status == "complete":
            invalidate_index_cache()  # new indices may exist
            errors = [
                f"{item['host']}/{item['artifact']}: {item['detail']}"
                for item in checklist
                if item["status"] == "failed"
            ]
            if errors:
                s["message"] = f"Ingest complete with {len(errors)} error(s)."
                s["errors"] = errors
            else:
                kept = totals.get("already_present", 0)
                s["message"] = (
                    f"Ingest complete. {totals.get('indexed', 0):,} new docs "
                    f"across {totals.get('hosts_total', 0)} host(s) in {minutes}m."
                    + (
                        f" {kept:,} entries were already in the case and kept their first ingest."
                        if kept
                        else ""
                    )
                )
            # Layer 1: post-ingest next_steps
            artifacts_done = {item["artifact"] for item in checklist if item["status"] == "done"}
            next_steps = []
            if "evtx" in artifacts_done or any("evtx" in a for a in artifacts_done):
                next_steps.append(
                    "Run idx_case_summary for investigation overview, "
                    "then idx_aggregate on host.name and event.code"
                )
            if "hayabusa" in artifacts_done or any("hayabusa" in a for a in artifacts_done):
                hb_case = ing.get("case_id") or ""
                hb = _hayabusa_query(_HAYABUSA_TOP_QUERY, _hayabusa_index(hb_case), hb_case)
                next_steps.append(f"Query Hayabusa alerts: {hb}")
            # Pick a concrete artifact_type example from what was ingested
            example_type = "event_logs_security"
            for art in artifacts_done:
                if "evtx" in art:
                    example_type = "event_logs_security"
                    break
                if "prefetch" in art or "pecmd" in art:
                    example_type = "prefetch"
                    break
                if "amcache" in art:
                    example_type = "amcache"
                    break
            next_steps.append(
                f"Call suggest_tools(artifact_type='{example_type}') on sift-mcp "
                "for deep analysis tools beyond OpenSearch queries"
            )
            s["next_steps"] = next_steps

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
    active = _active_case()  # one read: the input's folder and the run's case
    path, path_err = _case_path(path, active)
    path_err = path_err or _validate_path(path)
    if path_err:
        return {"error": path_err}
    if dry_run:
        from opensearch_mcp.parse_json import _detect_json_format

        p = Path(path)
        if p.is_file():
            fmt = _detect_json_format(p)
            return {"status": "preview", "file": p.name, "format": fmt}
        skipped: list = []
        files = sorted(f.name for f in _kept(p, lambda f: f.suffix.lower() in (".json", ".jsonl"),
                                             skipped))  # fmt: skip
        return {"status": "preview", "files": files, "count": len(files), **_named(skipped)}

    return _launch_background("json", path, hostname, index_suffix, time_field, active=active)


@server.tool()
def idx_ingest_delimited(
    path: str,
    hostname: str = "",
    index_suffix: str = "",
    time_field: str = "",
    delimiter: str = "",
    recursive: bool = False,
    dry_run: bool = True,
) -> dict:
    """Ingest delimited files (CSV, TSV, Zeek, bodyfile) into OpenSearch.

    Args:
        path: Path to delimited file or directory.
        hostname: Source hostname. Required unless recursive=True.
            Use hostname="auto" to auto-detect hostnames from filenames
            in a flat directory (e.g., Hayabusa per-host CSVs).
        index_suffix: Index suffix (default: format-{filename}).
        time_field: Timestamp field (default: auto-detect).
        delimiter: Delimiter character (default: auto-detect).
        recursive: Treat immediate subdirectories as hosts (dirname =
            hostname). One level only — does NOT walk nested
            subdirectories. Top-level files directly inside `path`
            are ignored when recursive=True; use a non-recursive
            per-host call or `hostname="auto"` for flat layouts.
        dry_run: Preview (default True). Set False to execute immediately.
    """
    active = _active_case()  # one read: the input's folder and the run's case
    path, path_err = _case_path(path, active)
    path_err = path_err or _validate_path(path)
    if path_err:
        return {"error": path_err}

    # Auto-detect mode: flat directory with multi-host files
    if hostname == "auto":
        p = Path(path)
        if not p.is_dir():
            return {"error": "hostname='auto' requires a directory path"}
        skipped: list = []
        detected = _detect_hostnames_from_filenames(p, skipped)
        if not detected:
            return {"error": "Could not auto-detect hostnames from filenames.", **_named(skipped)}
        if dry_run:
            return {
                "status": "preview",
                "auto_detect": True,
                "detected_hostnames": sorted(detected),
                "total_hosts": len(detected),
                **_named(skipped),
            }
        # Single background process iterates all detected hosts sequentially
        return _launch_background(
            "delimited",
            path,
            "",
            index_suffix,
            time_field,
            delimiter=delimiter,
            auto_hosts=",".join(sorted(detected)),
            active=active,
        )

    # Recursive mode: subdirs are hosts
    if recursive:
        p = Path(path)
        if not p.is_dir():
            return {"error": "recursive requires a directory path"}
        skipped: list = []
        subdirs = sorted(d for d in _kept(p, lambda d: d.is_dir(), skipped)
                         if not d.name.startswith("."))  # fmt: skip
        if not subdirs:
            return {"error": f"No subdirectories found in {path}", **_named(skipped)}
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        if dry_run:
            hosts_preview = []
            for d in subdirs:
                files = [f.name for f in _kept(d, lambda f: f.suffix.lower() in exts, skipped,
                                               f"{d.name}/")]  # fmt: skip
                if files:
                    hosts_preview.append(
                        {
                            "hostname": d.name,
                            "files": len(files),
                        }
                    )
            return {
                "status": "preview",
                "recursive": True,
                "hosts": hosts_preview,
                "total_hosts": len(hosts_preview),
                **_named(skipped),
            }
        # Single background process iterates all hosts sequentially
        return _launch_background(
            "delimited",
            path,
            "",
            index_suffix,
            time_field,
            delimiter=delimiter,
            recursive=True,
            active=active,
        )

    # Non-recursive: hostname required
    if not hostname:
        suggestion = _detect_hostnames_from_filenames(Path(path))
        if suggestion:
            return {
                "error": "hostname is required for non-recursive ingest.",
                "detected_hostnames": sorted(suggestion),
                "suggestion": (
                    "Detected possible hostnames from filenames: "
                    + ", ".join(sorted(suggestion))
                    + ". Pass hostname=... to confirm, or use "
                    "recursive=true for per-host subdirectories."
                ),
            }
        return {
            "error": (
                "hostname is required. Pass hostname='...' or use "
                "recursive=true for per-host subdirectories."
            )
        }

    if dry_run:
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        p = Path(path)
        if p.is_file():
            fmt = _detect_delimited_format(p)
            return {"status": "preview", "file": p.name, "format": fmt.get("format")}
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        skipped: list = []
        files = sorted(f.name for f in _kept(p, lambda f: f.suffix.lower() in exts, skipped))
        return {"status": "preview", "files": files, "count": len(files), **_named(skipped)}

    return _launch_background(
        "delimited",
        path,
        hostname,
        index_suffix,
        time_field,
        delimiter=delimiter,
        active=active,
    )


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
    active = _active_case()  # one read: the input's folder and the run's case
    path, path_err = _case_path(path, active)
    path_err = path_err or _validate_path(path)
    if path_err:
        return {"error": path_err}
    if dry_run:
        p = Path(path)
        if p.is_file():
            return {"status": "preview", "file": p.name}
        skipped: list = []
        files = sorted(
            f.name
            for f in _kept(
                p,
                lambda f: f.suffix.lower() in (".log", ".txt") or "access" in f.name.lower(),
                skipped,
            )
        )
        return {"status": "preview", "files": files, "count": len(files), **_named(skipped)}

    return _launch_background("accesslog", path, hostname, index_suffix, active=active)


@server.tool()
def idx_enrich_intel(
    case_id: str = "",
    dry_run: bool = True,
    force: bool = False,
    include_filesystem: bool = False,
) -> dict:
    """Enrich indexed evidence with threat intelligence.

    Extracts unique IOCs (IPs, hashes, domains) from indexed data, looks
    each up with lookup_ioc (threat intel) via the gateway, and stamps
    every document carrying it with an entry in threat_intel.iocs: the
    outcome (MATCH, NO_MATCH, or UNAVAILABLE when it couldn't be asked)
    and each platform's own records, verbatim. No verdict is computed.

    No LLM tokens consumed — all lookups are programmatic.

    Args:
        case_id: Case to enrich (default: active case).
        dry_run: Extract and count IOCs without lookup (default True).
        force: Re-enrich even if already enriched (default False).
        include_filesystem: Also look up bulk filesystem hashes — bodyfile,
            about 140,000 per host (default False). The default sources are
            process and execution evidence.

    Execute mode (dry_run=False) runs asynchronously. The tool returns
    immediately with `{status: "started", pid, run_id, log_file}`; the
    worker enriches in the background. For realistic corpora (1k–10k
    IOCs × rate-limited OpenCTI), enrichment takes 15–60 minutes,
    which is well past the gateway's 300-second synchronous tool
    timeout — hence the async shape.

    Progress is surfaced through the existing `idx_ingest_status`
    tool. Enrichment runs appear alongside ingest runs with
    `artifact_name="intel"` — use that to disambiguate.
    """
    from opensearch_mcp.threat_intel import extract_unique_iocs

    cid = case_id or _get_active_case()
    if not cid:
        return {"error": "No active case. Run 'vhir case activate' first."}

    if dry_run:
        from opensearch_mcp.case_scope import CaseScopeError, case_read_scope

        client = _get_os()
        try:
            scope = case_read_scope(cid, client)
        except CaseScopeError as e:
            return {"error": str(e)}
        iocs = extract_unique_iocs(
            client, scope, force=force, include_filesystem=include_filesystem
        )
        return {
            "status": "preview",
            "case_id": cid,
            "ips": len(iocs["ip"]),
            "hashes": len(iocs["hash"]),
            "domains": len(iocs["domain"]),
            "total_iocs": sum(len(v) for v in iocs.values()),
        }

    return _launch_enrich_background(cid, force=force, include_filesystem=include_filesystem)


@server.tool()
def idx_enrich_triage(
    case_id: str = "",
) -> dict:
    """Run triage baseline enrichment on already-indexed data.

    Checks indexed files and services against the default-install Windows
    baseline (known_good.db) via the gateway, and stamps triage.verdict
    (EXPECTED, EXPECTED_LOLBIN, SUSPICIOUS, UNKNOWN). EXPECTED means a default
    file or service in its default place, never "benign":
    - a service needs its name and its executable (the ImagePath, the 7045
      event's, or svcscan's registry binary) to match; only the docs carrying
      that pair get the verdict;
    - Amcache entries are checked with their SHA1; a SHA1 that matches no
      reference build reads UNKNOWN (often a patch level), never EXPECTED;
    - process-creation events (4688, Sysmon 1) carry their image's verdict;
      other events get no stamp;
    - tasks, Run, Active Setup and NetSh entries only flag (SUSPICIOUS, or
      UNKNOWN with the LOLBin flag): the entry itself isn't in the baseline.
    A re-run removes stamps this version no longer writes and re-stamps the rest.

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

    from opensearch_mcp.host_ops import HostOpRefused, case_writes
    from opensearch_mcp.write_context import case_dir_for

    client = _get_os()
    case_dir = case_dir_for(cid)
    try:
        if case_dir is None:
            results = enrich_remote(client, cid, audit=audit)
        else:
            with case_writes(case_dir):
                results = enrich_remote(client, cid, audit=audit)
    except HostOpRefused as e:
        return {"error": f"Not enriched: {e}"}

    if "error" in results:
        return results

    total_enriched = sum(r.get("enriched", 0) for r in results.values() if isinstance(r, dict))
    failed = [k for k, r in results.items() if isinstance(r, dict) and r.get("status") == "failed"]
    resp = {
        "status": "incomplete" if failed else "complete",
        "documents_enriched": total_enriched,
        "details": results,
    }
    if failed:
        resp["failed_artifacts"] = failed
    from opensearch_mcp import ops

    # what the run did: a later fact about its reference step
    aid = ops.later(audit, results.get("_reference_op", ""), "idx_enrich_triage",
                    f"{total_enriched} docs enriched", {"case_id": cid})  # fmt: skip
    if aid:
        resp["audit_id"] = aid
    return resp


_MAX_CONCURRENT_INGESTS = _MAX_RUNNING


def _admission_refusal() -> dict | None:
    """The refusal of a new ingest while the most runs are already running or
    starting (listed, with their cases). A run waiting for host confirmation
    takes no place: it writes nothing, and once its hosts are confirmed it
    starts only when a place is free. Places are counted by process, as the
    slots are: an archive's images run in the archive's process and share
    its place."""
    from opensearch_mcp.ingest_status import AWAITING, active_runs

    runs = [r for r in active_runs() if r.get("status") != AWAITING]
    holding = {r.get("pid") for r in runs}
    if len(holding) < _MAX_CONCURRENT_INGESTS:
        return None
    msg = (
        f"Too many concurrent ingests ({len(holding)} running, max {_MAX_CONCURRENT_INGESTS})."
        " Wait for current ingests to complete."
    )
    return {
        "error": msg + " Use idx_ingest_status() to check progress.",
        "running": [
            {
                "case_id": r.get("case_id"),
                "pid": r.get("pid"),
                "run_id": r.get("run_id"),
                "status": r.get("status"),
            }
            for r in runs
        ],  # fmt: skip
    }


def _spawn_ingest(cmd, env, stdout, run_id):
    """Spawn ingest subprocess, isolated in its own cgroup when possible.

    Uses systemd-run --user --scope for cgroup isolation so OOM kills
    the ingest, not the gateway. Falls back to bare Popen if systemd-run
    is unavailable or fails (missing D-Bus, non-systemd host, etc.).
    """
    import subprocess as _sp
    import time as _time

    # The index templates install on the first verified connection, which no
    # ingest call otherwise makes: without this, an ingest started first
    # after a restart creates its indices under the previous templates. A
    # cluster that's down is the ingest's own to report.
    try:
        _get_os()
    except Exception as e:  # noqa: BLE001
        logger.warning("Template install before ingest skipped: %s", e)

    # Ensure D-Bus address is available for systemd-run --user
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        import os

        uid = os.getuid()
        bus = f"unix:path=/run/user/{uid}/bus"
        env["DBUS_SESSION_BUS_ADDRESS"] = bus
    if "XDG_RUNTIME_DIR" not in env:
        import os

        env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"

    scope = [
        "systemd-run",
        "--user",
        "--scope",
        "--property=MemoryMax=8G",
        "--property=MemoryHigh=6G",
    ]
    scope_cmd = scope + [f"--unit=vhir-ingest-{run_id[:12]}"] + cmd

    # Workers never read the server's stdin: it's the MCP pipe, and a child
    # that reads it (7z prompting for a password) consumes requests.
    try:
        proc = _sp.Popen(
            scope_cmd,
            stdout=stdout,
            stderr=_sp.STDOUT,
            stdin=_sp.DEVNULL,
            env=env,
            start_new_session=True,
        )
        # systemd-run may fail after Popen succeeds (no D-Bus, etc.)
        _time.sleep(0.3)
        if proc.poll() is not None and proc.returncode != 0:
            # Clean up failed scope unit
            _sp.run(
                ["systemctl", "--user", "reset-failed", f"vhir-ingest-{run_id[:12]}"],
                capture_output=True,
            )
            # With --scope the worker's own exit status comes back, so a
            # worker that failed fast reads like systemd-run failing. Run it
            # again outside the scope only if a scope can't start at all.
            try:
                probe = _sp.run(
                    scope + ["--quiet", "true"], env=env, capture_output=True, timeout=10
                )
                scoped = probe.returncode == 0
            except (OSError, _sp.SubprocessError):
                scoped = False
            if not scoped:
                proc = _sp.Popen(
                    cmd,
                    stdout=stdout,
                    stderr=_sp.STDOUT,
                    stdin=_sp.DEVNULL,
                    env=env,
                    start_new_session=True,
                )
    except (FileNotFoundError, OSError):
        proc = _sp.Popen(
            cmd,
            stdout=stdout,
            stderr=_sp.STDOUT,
            stdin=_sp.DEVNULL,
            env=env,
            start_new_session=True,
        )
    return proc


def _launch_background(
    subcommand,
    path,
    hostname,
    index_suffix="",
    time_field="",
    delimiter="",
    recursive=False,
    auto_hosts="",
    active=None,
):
    """Launch a generic ingest as background subprocess with concurrency control.
    `active`: the calling tool's one `_active_case()` read."""
    import os as _os
    import sys as _sys
    import uuid as _uuid
    from datetime import datetime, timezone

    # Defensive breaker reset — covers idx_ingest_json/delimited/accesslog.
    from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb
    from opensearch_mcp.ingest_status import write_status

    _reset_cb()
    if active is None:
        active = _active_case()
    active_case = active[0]

    # Pre-flight shard capacity check — single insertion point covers
    # json / delimited / accesslog subcommands routed through here.
    # (idx_ingest and idx_ingest_memory have their own pre-flight
    # before their specific subprocess launches.)
    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    ok, reason = check_shard_headroom(
        get_client(),
        expected_new_shards=_estimate_new_shards(subcommand),
        min_headroom_pct=10.0,
    )
    if not ok:
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.ingest_status import (
            HALT_SHARD_CAPACITY,
            write_status,
        )

        if active_case:
            write_status(
                case_id=active_case,
                pid=os.getpid(),
                run_id="",
                status="failed",
                hosts=[],
                totals={},
                started=_dt.now(_tz.utc).isoformat(),
                error=f"{HALT_SHARD_CAPACITY}: {reason}",
            )
        return {"status": "failed", "error": "shard_capacity", "message": reason}

    if not active_case:
        return {"error": "No active case. Run 'vhir case activate' first."}

    # Concurrency gate — prevent OpenSearch OOM from unbounded parallelism
    if refused := _admission_refusal():
        return refused

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["VHIR_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-I",
        "-m",
        "opensearch_mcp.ingest_cli",
        subcommand,
        path,
        "--case",
        active_case,
    ]
    if hostname:
        cmd.extend(["--hostname", hostname])
    if index_suffix:
        cmd.extend(["--index-suffix", index_suffix])
    if time_field:
        cmd.extend(["--time-field", time_field])
    if delimiter:
        cmd.extend(["--delimiter", delimiter])
    if recursive:
        cmd.append("--recursive")
    if auto_hosts:
        cmd.extend(["--auto-hosts", auto_hosts])

    # Log to file instead of DEVNULL so errors are visible
    from opensearch_mcp.paths import vhir_dir

    log_dir = vhir_dir() / "ingest-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.log"
    log_fh = open(log_file, "w")

    # Write placeholder status BEFORE spawn to close TOCTOU window
    started_ts = datetime.now(timezone.utc).isoformat()
    write_status(
        case_id=active_case,
        pid=0,
        run_id=run_id,
        status="starting",
        hosts=[{"hostname": hostname, "artifacts": [{"name": subcommand, "status": "starting"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    proc = _spawn_ingest(cmd, env, log_fh, run_id)
    log_fh.close()  # Safe: Popen dup2'd the fd, subprocess has its own copy
    # Remove orphaned PID-0 placeholder
    from opensearch_mcp.ingest_status import _status_path_safe

    _status_path_safe(active_case, 0, run_id).unlink(missing_ok=True)
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

    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "log_file": str(log_file),
        "message": (
            f"Ingest started. Call idx_ingest_status() to monitor progress. Log file: {log_file}"
        ),
    }
    resp = _answer_after_gate(resp, active_case, proc.pid, run_id)
    aid = audit.log(
        tool=f"idx_ingest_{subcommand}",
        params={"path": path, "hostname": hostname},
        result_summary=_launch_summary(resp, f"Background ingest started (pid={proc.pid})"),
        input_files=[path],
        **_audit_case(active),
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def _launch_enrich_background(
    case_id: str, force: bool = False, include_filesystem: bool = False
) -> dict:
    """Launch idx_enrich_intel as a background subprocess.

    Mirrors `_launch_background` but shaped for enrichment: no path
    positional, no hostname, no shard-capacity preflight (enrichment
    doesn't create new indices — it stamps existing docs). Returns
    immediately with `{status: "started", pid, run_id, log_file}` so
    the gateway's 300s synchronous tool timeout cannot kill a real
    enrichment run (UAT 2026-04-23 B79: 5,426-IOC corpus × rate-limited
    OpenCTI = 15–60 min, 3×–12× the timeout).

    Status records use `artifact_name="intel"` so the sweep + monotonic
    transition protection in `ingest_status` apply equally; operators
    watch progress via `idx_ingest_status` (intel and ingest runs
    interleave there — disambiguate on `artifact_name`).
    """
    import os as _os
    import sys as _sys
    import uuid as _uuid
    from datetime import datetime, timezone

    from opensearch_mcp.ingest_status import read_active_ingests, write_status

    active_case = _get_active_case()
    if not active_case:
        return {"error": "No active case. Run 'vhir case activate' first."}
    # An explicit case_id arg (not the active case) is respected: pass
    # it through to the worker and use it for status-file keying.
    status_case = case_id or active_case

    # Concurrency gate — same cap as ingest. Enrichment is one-per-case
    # and typically long; running multiple simultaneously would starve
    # the rate limiter. Places are counted by process, as at admission.
    active = read_active_ingests()
    running = [i for i in active if i.get("status") in ("running", "starting")]
    holding = {r.get("pid") for r in running}
    if len(holding) >= _MAX_CONCURRENT_INGESTS:
        return {
            "error": (
                f"Too many concurrent ingest/enrich runs ({len(holding)} "
                f"running, max {_MAX_CONCURRENT_INGESTS}). Wait for "
                "current runs to complete. Use idx_ingest_status() to check."
            ),
            "running": [{"case_id": r.get("case_id"), "pid": r.get("pid")} for r in running],
        }

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["VHIR_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-I",
        "-m",
        "opensearch_mcp.ingest_cli",
        "enrich-intel",
        "--case",
        status_case,
    ]
    if force:
        cmd.append("--force")
    if include_filesystem:
        cmd.append("--include-filesystem")

    from opensearch_mcp.paths import vhir_dir

    log_dir = vhir_dir() / "ingest-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.log"
    log_fh = open(log_file, "w")

    # Pre-spawn placeholder status so the TOCTOU window is closed.
    started_ts = datetime.now(timezone.utc).isoformat()
    write_status(
        case_id=status_case,
        pid=0,
        run_id=run_id,
        status="starting",
        hosts=[{"hostname": "(enrich)", "artifacts": [{"name": "intel", "status": "starting"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    proc = _spawn_ingest(cmd, env, log_fh, run_id)
    log_fh.close()
    # Remove orphaned PID-0 placeholder.
    from opensearch_mcp.ingest_status import _status_path_safe

    _status_path_safe(status_case, 0, run_id).unlink(missing_ok=True)
    write_status(
        case_id=status_case,
        pid=proc.pid,
        run_id=run_id,
        status="running",
        hosts=[{"hostname": "(enrich)", "artifacts": [{"name": "intel", "status": "running"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "case_id": status_case,
        "log_file": str(log_file),
        "message": (
            "Intel enrichment started. Call idx_ingest_status() to monitor "
            f"progress (artifact_name='intel'). Log file: {log_file}"
        ),
    }
    aid = audit.log(
        tool="idx_enrich_intel",
        params={"case_id": status_case, "force": force},
        result_summary=f"Background enrichment started (pid={proc.pid})",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def idx_ingest_memory(
    path: str,
    hostname: str = "",
    tier: int = 1,
    plugins: list[str] | None = None,
    dry_run: bool = True,
) -> dict:
    """Parse a memory image with Volatility 3 and index results.

    Args:
        path: Path to memory image (.raw, .vmem, .dmp, etc.)
        hostname: Source hostname for the memory image, if known. A name
            given here is the AI's: it never confirms a machine. With none,
            the examiner names the image's machine in the Hosts tab.
        tier: Analysis depth (1=fast/essential, 2=moderate, 3=deep).
        plugins: Override tier — run only these specific plugins.
        dry_run: Preview plugins (default True). Set False to execute.
    """
    active = _active_case()  # one read: the input's folder and the run's case
    path, path_err = _case_path(path, active)
    path_err = path_err or _validate_path(path)
    if path_err:
        return {"error": path_err}
    from opensearch_mcp.memory_tiers import TIERS

    # The worker is always passed --tier, so a tier it refuses fails even
    # with plugins named.
    if tier not in TIERS:
        return {"error": f"tier must be one of {sorted(TIERS)}, got {tier!r}"}
    plugin_list = plugins or TIERS[tier]

    if dry_run:
        resp = {
            "status": "preview",
            "tier": tier,
            "plugins": plugin_list,
            "plugin_count": len(plugin_list),
            "scan": _memory_scan(Path(path), hostname, active[0] or ""),
        }
        _with_host_list_hint(resp, active[0] or "")
        aid = audit.log(
            tool="idx_ingest_memory",
            params={"path": path, "dry_run": True, "tier": tier},
            result_summary=f"preview: {len(plugin_list)} plugins",
            **_audit_case(active),
        )
        if aid:
            resp["audit_id"] = aid
        return resp

    # dry_run=False: defensive reset, pre-flight, then launch subprocess.
    from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb

    _reset_cb()

    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    ok, reason = check_shard_headroom(
        get_client(),
        expected_new_shards=_estimate_new_shards("memory"),
        min_headroom_pct=10.0,
    )
    if not ok:
        aid = audit.log(
            tool="idx_ingest_memory",
            params={"path": path, "dry_run": False, "tier": tier},
            result_summary=f"aborted: {reason[:120]}",
            **_audit_case(active),
        )
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.ingest_status import (
            HALT_SHARD_CAPACITY,
            write_status,
        )

        _active = active[0] or ""
        if _active:
            write_status(
                case_id=_active,
                pid=os.getpid(),
                run_id="",
                status="failed",
                hosts=[],
                totals={},
                started=_dt.now(_tz.utc).isoformat(),
                error=f"{HALT_SHARD_CAPACITY}: {reason}",
            )
        resp = {"status": "failed", "error": "shard_capacity", "message": reason}
        if aid:
            resp["audit_id"] = aid
        return resp

    import os as _os
    import sys as _sys
    import uuid as _uuid

    active_case = active[0]
    if not active_case:
        return {"error": "No active case. Run 'vhir case activate' first."}

    # Concurrency gate (same as _launch_background)
    if refused := _admission_refusal():
        return refused

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["VHIR_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-I",
        "-m",
        "opensearch_mcp.ingest_cli",
        "memory",
        path,
        *(["--hostname", hostname] if hostname else []),
        "--case",
        active_case,
        "--tier",
        str(tier),
        "--yes",
    ]
    if plugins:
        cmd.extend(["--plugins", ",".join(plugins)])

    from opensearch_mcp.paths import vhir_dir as _vd

    _ld = _vd() / "ingest-logs"
    _ld.mkdir(parents=True, exist_ok=True)
    _lf = _ld / f"{run_id}.log"
    _lfh = open(_lf, "w")

    # Write placeholder status BEFORE spawn (same TOCTOU fix as _launch_background)
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from opensearch_mcp.ingest_status import write_status as _ws_mem

    _started_ts = _dt.now(_tz.utc).isoformat()
    _ws_mem(
        case_id=active_case,
        pid=0,
        run_id=run_id,
        status="starting",
        hosts=[
            {
                "hostname": hostname or Path(path).name,
                "artifacts": [{"name": "memory", "status": "starting"}],
            }
        ],
        totals={"indexed": 0, "artifacts_total": len(plugin_list), "artifacts_complete": 0},
        started=_started_ts,
        log_file=str(_lf),
    )

    proc = _spawn_ingest(cmd, env, _lfh, run_id)
    _lfh.close()  # Safe: Popen dup2'd the fd, subprocess has its own copy
    # Remove orphaned PID-0 placeholder
    from opensearch_mcp.ingest_status import _status_path_safe

    _status_path_safe(active_case, 0, run_id).unlink(missing_ok=True)
    # The same record under the worker's pid, which the reader checks.
    _ws_mem(
        case_id=active_case,
        pid=proc.pid,
        run_id=run_id,
        status="starting",
        hosts=[
            {
                "hostname": hostname or Path(path).name,
                "artifacts": [{"name": "memory", "status": "starting"}],
            }
        ],
        totals={"indexed": 0, "artifacts_total": len(plugin_list), "artifacts_complete": 0},
        started=_started_ts,
        log_file=str(_lf),
    )

    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "tier": tier,
        "plugins": plugin_list,
        "log_file": str(_lf),
        "message": (
            f"Memory analysis started ({len(plugin_list)} plugins). "
            "This may take several minutes. Use idx_ingest_status() to monitor."
        ),
    }
    resp = _answer_after_gate(resp, active_case, proc.pid, run_id)
    aid = audit.log(
        tool="idx_ingest_memory",
        params={"path": path, "tier": tier, "pid": proc.pid, "run_id": run_id},
        result_summary=_launch_summary(resp, f"started tier {tier} ({len(plugin_list)} plugins)"),
        input_files=[path],
        **_audit_case(active),
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def _get_active_case() -> str | None:
    """Read active case ID."""
    return _active_case()[0]


def _active_case() -> tuple[str | None, Path | None]:
    """The active case's id and folder, from one read of its pointer; the
    folder as case-mcp resolves it: an absolute path is the folder itself, a
    bare id is VHIR_CASES_DIR/<id>. (None, None) when no case is active."""
    from opensearch_mcp.paths import vhir_dir

    pointer = vhir_dir() / "active_case"
    raw = pointer.read_text().strip() if pointer.exists() else ""
    if not raw:
        return None, None
    name = Path(raw).name
    if os.path.isabs(raw):
        return name, Path(raw)
    return name, Path(os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases"))) / name


def _audit_case(active) -> dict:
    """audit.log's case for a call's one `_active_case()` read: its entry goes
    into that case, with its id, even if the examiner switches meanwhile."""
    case_id, case_dir = active
    return {"case_id": case_id, "case_dir": str(case_dir)} if case_id else {}


# Hayabusa's CSV abbreviates Level: crit, high, med, low, info, and emer on a
# configured critical system. With -b (--disable-abbreviations) they're in full.
_HAYABUSA_TOP_QUERY = "Level:(emer OR crit OR critical OR high)"

# Zero Hayabusa alerts because the engine isn't there, not because nothing matched.
_HAYABUSA_ABSENT = (
    "Hayabusa not installed: evtx ingests ran no detections, so 0 alerts is not "
    "a finding. Install it with `sudo cast install teamdfir/sift` (Hayabusa 3.8.1 "
    "with the rest of SIFT) or `vhir setup hayabusa` (the current Hayabusa only), "
    "then re-run the evtx ingest."
)


@server.tool()
def idx_list_detections(
    severity: str = "",
    detector_type: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Hayabusa detection alerts: the count, and an idx_search call for high and critical ones.

    Args:
        severity: Filter by severity (critical, high, medium, low).
                  Empty = all severities.
        detector_type: Filter by detector type (windows, linux, dns, etc.).
                  Empty = all detectors.
        limit: Max results (default 50).
        offset: Starting position for pagination (default 0).
    """
    limit = min(limit, 500)
    client = _get_os()
    hb_index = _hayabusa_index(client=client)

    # Fetch more than requested when filtering by severity (API doesn't support it)
    fetch_size = limit * 3 if severity else limit
    params: dict = {
        "size": fetch_size,
        "startIndex": offset,
        "sortOrder": "desc",
    }
    if detector_type:
        params["detectorType"] = detector_type

    try:
        response = _os_call(
            client.transport.perform_request,
            "GET",
            "/_plugins/_security_analytics/findings/_search",
            params=params,
        )
    except (RuntimeError, ValueError, Exception) as e:
        if "security_analytics" in str(e).lower() or "400" in str(e) or "404" in str(e):
            resp = {"error": "Security Analytics plugin not available", "findings": []}
            # Still suggest Hayabusa when SA is unavailable
            try:
                hb_count = client.count(index=hb_index)["count"] if hb_index else 0
                if hb_count:
                    resp["suggestion"] = (
                        f"Sigma detectors unavailable. {hb_count:,} Hayabusa alerts available. "
                        f"Query: {_hayabusa_query(_HAYABUSA_TOP_QUERY, hb_index, client=client)}"
                    )
                else:
                    resp["suggestion"] = "Sigma detectors unavailable on OpenSearch 3.5. " + (
                        _HAYABUSA_ABSENT
                        if shutil.which("hayabusa") is None
                        else "Hayabusa runs during evtx ingest if installed."
                    )
            except Exception:
                resp["suggestion"] = (
                    "Sigma detectors unavailable. Check Hayabusa: "
                    f"{_hayabusa_query('Level:*', hb_index, client=client)}"
                )
            return _logged_query(  # the normal answer on OpenSearch 3.5: recorded too
                resp,
                tool="idx_list_detections",
                params={"severity": severity, "detector_type": detector_type,
                        "limit": limit, "offset": offset},
                result_summary="Security Analytics plugin not available",
            )  # fmt: skip
        raise

    sev_filter = severity.lower() if severity else ""
    findings = []
    related: list[dict] = []  # each finding's documents, for its audit entry
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
        doc_ids = list(finding.get("related_doc_ids") or [])
        related.append({"id": finding.get("id"), "index": finding.get("index"),
                        "related_doc_ids": doc_ids})  # fmt: skip

        if len(findings) >= limit:
            break

    # Suggest Hayabusa when Sigma returns empty
    hayabusa_hint = ""
    if not findings:
        try:
            hb_count = client.count(index=hb_index)["count"] if hb_index else 0
            if hb_count:
                hayabusa_hint = (
                    f"No Sigma detections. {hb_count:,} Hayabusa alerts available. "
                    f"Query: {_hayabusa_query(_HAYABUSA_TOP_QUERY, hb_index, client=client)}"
                )
            else:
                hayabusa_hint = "No Sigma detections (disabled on OpenSearch 3.5). " + (
                    _HAYABUSA_ABSENT
                    if shutil.which("hayabusa") is None
                    else "Hayabusa runs during evtx ingest if installed."
                )
        except Exception:
            hayabusa_hint = "No Sigma detections."

    resp = {
        "findings": findings,
        "total": response.get("total_findings", 0),
        "returned": len(findings),
        "offset": offset,
    }
    if hayabusa_hint:
        resp["suggestion"] = hayabusa_hint
    return _logged_query(
        resp,
        tool="idx_list_detections",
        params={
            "severity": severity,
            "detector_type": detector_type,
            "limit": limit,
            "offset": offset,
            "result_findings": related,
            **_related_doc_params(client, related),
        },
        result_summary=f"{len(findings)} findings",
    )


@server.tool()
def idx_host_inventory(case_id: str = "", offset: int = 0, limit: int = 50) -> dict:
    """The case's machines as the examiner and the evidence have named them,
    for reading only: each machine (host.id) with its state, the raw names
    its records carry (host.name) with their evidence and flags, the units
    (evidence sources) they came from and its document count; the names no
    machine holds yet; your suggestions (case_host_fix); and the ingest runs
    awaiting host confirmation (they write nothing until the examiner
    confirms their hosts in the portal's Hosts tab). Changes nothing: the
    examiner confirms, names and merges machines.

    These lists are paged by offset and limit and carry their total: the
    machines, the names without a machine, the suggestions, and each waiting
    run's units, its count per unit and its held names (each run also counts
    its held names by reason). Each machine's own names list is returned
    whole. A name shows its first 5 evidence items and their total.

    Args:
        case_id: The case (default: the active case).
        offset: The first item of each list to return, in its order (default
            0).
        limit: Items of each list per page (default 50, max 200).
    """
    from sift_common import host_gate
    from sift_common import host_identity as hi

    case_dir = _scan_case_dir(case_id)
    if case_dir is None:
        return {"error": "No case: give case_id, or activate a case first."}
    try:
        state = hi.load(case_dir)
        op = hi.unfinished_op(case_dir)
    except hi.HostLogError as e:
        return {"error": f"host logs unreadable: {e}"}
    offset, limit = max(0, int(offset)), max(1, min(int(limit), 200))
    machines = sorted(state.machines.values(), key=lambda m: (hi.spelling(m.canonical), m.id))
    page = machines[offset : offset + limit]

    def name(p) -> dict:
        info = state.names.get(p) or {}
        evidence = list(info.get("evidence") or [])
        return {"unit": p[0], "raw": p[1], "evidence": evidence[:_INVENTORY_EVIDENCE],
                "evidence_total": len(evidence),
                "origins": list(info.get("origins") or []),
                "flags": list(state.pair_flags.get(p) or [])}  # fmt: skip

    from opensearch_mcp.write_context import case_identity

    ingested: dict = {}
    try:
        c12 = case_identity(case_dir)[0]
    except Exception as e:
        docs, docs_note = None, f"document counts unavailable: the case's identity: {e}"
    else:
        docs, docs_note = _docs_per_key(c12, [k for m in page for k in m.keys], ingested)
    units = sorted({p[0] for m in page for p in m.pairs})
    unbound = [p for p in state.names if p not in state.bindings]
    pending = []
    for run, run_units in sorted(state.waits.items()):
        if run in state.cancelled:
            continue
        held = host_gate.unresolved(state, run_units)
        if held:
            pending.append(_held_page(run, list(run_units), held, offset, limit))
    states: dict[str, int] = {}
    for m in machines:
        states[m.state] = states.get(m.state, 0) + 1
    resp = {
        "case_id": _case_id_of(case_dir),
        "machines_total": len(machines),
        "machines_by_state": states,
        "offset": offset,
        "limit": limit,
        "machines": [
            {
                "host.id": m.canonical,
                "id": m.id,
                "state": m.state,
                "flags": list(m.flags),
                "former_names": list(m.former),
                "names": [name(p) for p in m.pairs],
                "units": sorted({p[0] for p in m.pairs}),
                "docs": None if docs is None else sum(docs.get(k, 0) for k in m.keys),
            }
            for m in page
        ],  # fmt: skip
        "units": {u: state.units.get(u) or {} for u in units},
        "names_without_machine_total": len(unbound),
        "names_without_machine": [name(p) for p in unbound[offset : offset + limit]],
        "suggestions_total": len(state.suggestions),
        "suggestions": list(state.suggestions)[offset : offset + limit],
        "awaiting_host_confirmation": pending,
        **(
            {"host_note": f"host operation {op.get('id', '?')} is {op.get('state')}"} if op else {}
        ),
        **({"docs_note": docs_note} if docs_note else {}),
    }
    return _logged_query(
        resp,
        tool="idx_host_inventory",
        params={"case_id": resp["case_id"], "offset": offset, "limit": limit,
                **_ingest_params(ingested)},
        result_summary=f"{len(machines)} machines, {len(page)} listed",
    )  # fmt: skip


_INVENTORY_EVIDENCE = 5  # evidence items shown per name; the total is given


def _held_page(run: str, units: list, held: list[dict], offset: int, limit: int) -> dict:
    """One run awaiting host confirmation, a page long: its totals, its held
    names counted by reason, a row per unit (count, first reason), and
    `limit` of its units, unit rows and held names from `offset`."""
    by_reason: dict[str, int] = {}
    by_unit: dict[str, dict] = {}
    for h in held:
        by_reason[h["reason"]] = by_reason.get(h["reason"], 0) + 1
        row = by_unit.setdefault(h["unit"], {"unit": h["unit"], "count": 0,
                                             "first_reason": h["reason"]})  # fmt: skip
        row["count"] += 1
    rows = list(by_unit.values())
    return {
        "run_id": run,
        "units_total": len(units),
        "units": units[offset : offset + limit],
        "unresolved_total": len(held),
        "unresolved_by_reason": by_reason,
        "unresolved_units_total": len(rows),
        "unresolved_by_unit": rows[offset : offset + limit],
        "unresolved": held[offset : offset + limit],
    }


def _docs_per_key(c12, keys: list[str], ingested: dict | None = None) -> tuple[dict | None, str]:
    """(documents per machine key in the case's indices, a note): None and why
    when the cluster can't be asked; the counts and a note when they're
    incomplete (timed out, or shards that didn't answer). `ingested` gets the
    response, for the ingests the counted records came from."""
    if not keys:
        return {}, ""
    try:
        resp = _get_os().search(
            index=f"case-{c12}-*",
            body={"size": 0, "query": {"terms": {"vhir.host_key": keys}},
                  "aggs": {"k": {"terms": {"field": "vhir.host_key", "size": len(keys)}},
                           **_ingest_aggs()}},
            allow_no_indices=True, ignore_unavailable=True,
        )  # fmt: skip
    except Exception:
        return None, "document counts unavailable: the cluster didn't answer"
    if ingested is not None:
        ingested.update(resp)
    counts = {b["key"]: b["doc_count"] for b in resp["aggregations"]["k"]["buckets"]}
    failed = int((resp.get("_shards") or {}).get("failed") or 0)
    if resp.get("timed_out") or failed:
        why = "the count timed out" if resp.get("timed_out") else f"{failed} shard(s) failed"
        return counts, f"document counts incomplete: {why}; they may be low"
    return counts, ""


def _case_id_of(case_dir) -> str:
    """The case's id as its CASE.yaml gives it, else its folder's name."""
    import yaml

    try:
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
    except Exception:
        meta = {}
    cid = meta.get("case_id") if isinstance(meta, dict) else None
    return str(cid) if cid else case_dir.name


@server.tool()
def case_host_fix(raw: str, new_canonical: str) -> dict:
    """Suggest that a host name belongs to another machine. Records the
    suggestion for the examiner and changes no document: host.id values
    change only when the examiner renames, merges or splits machines in the
    portal's Hosts tab.

    Args:
        raw: The host name as found in the evidence (host.name).
        new_canonical: The machine (host.id) you think it belongs to.
    """
    from opensearch_mcp.host_dictionary import InvalidHostnameValue

    try:
        return _case_host_fix_impl(raw, new_canonical)
    except InvalidHostnameValue as e:
        return {
            "status": "rejected",
            "error": f"InvalidHostnameValue: {e}",
            "raw": raw,
            "new_canonical": new_canonical,
            "dict_saved": False,
            "isError": True,
        }
    except Exception as e:
        # Last-resort envelope — any unexpected exception still returns
        # a structured response with isError: True rather than bubbling
        # to FastMCP as a generic ToolError.
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "raw": raw,
            "new_canonical": new_canonical,
            "isError": True,
        }


def _case_host_fix_impl(raw: str, new_canonical: str) -> dict:
    """Record the suggestion; change nothing else."""
    from sift_common import host_identity

    from opensearch_mcp.case_scope import CaseScopeError, scope_of
    from opensearch_mcp.host_dictionary import _validate_hostname_for_storage

    _validate_hostname_for_storage(raw, "case_host_fix raw")
    _validate_hostname_for_storage(new_canonical, "case_host_fix new_canonical")
    try:
        scope = scope_of(_get_active_case() or "")
    except CaseScopeError as e:
        return {"error": str(e)}
    host_identity.append_observations(
        scope.case_dir,
        [
            {
                "kind": "suggestion",
                "origin": "ai",
                "tool": "case_host_fix",
                "raw": raw,
                "canonical": new_canonical,
            }
        ],
    )
    aid = audit.log(
        tool="case_host_fix",
        params={"raw": raw, "new_canonical": new_canonical},
        result_summary="suggestion recorded; no document or host decision changed",
    )
    resp = {
        "status": "suggested",
        "raw": raw,
        "new_canonical": new_canonical,
        "docs_updated": 0,
        "message": (
            f"Recorded for the examiner: host name {raw!r} may belong to {new_canonical!r}. "
            "Nothing was changed. Only the examiner confirms, renames, merges or splits "
            "machines, in the portal's Hosts tab: ask them to review it there."
        ),
    }
    if aid:
        resp["audit_id"] = aid
    return resp


def main():
    """Run the MCP server."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
