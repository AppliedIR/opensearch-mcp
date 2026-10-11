"""Post-ingest triage enrichment — batch gateway calls + registry persistence rules.

Gateway-dependent: check_file/check_service via windows-triage-mcp.
Gateway-independent: registry persistence R1-R17 via update_by_query.
"""

from __future__ import annotations

import logging
import re
import sys
import time

from opensearchpy import OpenSearch

from opensearch_mcp.gateway import call_tool, gateway_available

logger = logging.getLogger(__name__)


def _search_outcome(e: Exception) -> dict:
    """What a triage search that raised leaves: `skipped` (with the error's
    own text) only when the index isn't there; any other error means the
    artifact wasn't enriched, so `failed`."""
    from opensearchpy.exceptions import NotFoundError

    if isinstance(e, NotFoundError):
        return {"status": "skipped", "reason": str(e)}
    return {"status": "failed", "reason": f"search failed: {e}"}


_MAX_CONSECUTIVE_FAILURES = 3


class _WriteFailed(Exception):
    """A verdict write failed after a successful triage lookup."""


def _ubq(client, **kw):
    try:
        return client.update_by_query(**kw)
    except Exception as e:
        print(f"  WARNING: update_by_query failed: {e}", file=sys.stderr)
        raise _WriteFailed from e


def _loop_result(
    consecutive_failures: int,
    succeeded: bool,
    write_failures: int = 0,
    unchecked_docs: int = 0,
    **counts,
) -> dict:
    """Not 'complete' when a gateway loop stopped on consecutive call failures,
    when every call it made failed, when verdict writes failed, or when the
    aggregation left values unread."""
    reasons = []
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES or (
        consecutive_failures and not succeeded
    ):
        reasons.append(
            "consecutive gateway call failures; windows-triage backend or gateway unavailable"
        )
    if write_failures:
        reasons.append(f"{write_failures} verdicts could not be written to the index")
        counts["write_failures"] = write_failures
    if unchecked_docs:
        reasons.append(
            f"{unchecked_docs} documents hold values past the first 5000 and were not checked"
        )
        counts["unchecked_docs"] = unchecked_docs
    if reasons:
        return {"status": "failed", "reason": "; ".join(reasons), **counts}
    return {"status": "complete", **counts}


class _CaseIndices:
    """A case's indices, read through its scope (see case_scope)."""

    def __init__(self, case_id: str, client) -> None:
        self.case_id, self.client = case_id, client


def _index(case_ix: _CaseIndices | str, artifact_type: str = "") -> str:
    """The case's indices of `artifact_type` (all of them when empty); a
    bare case id reads without the client, so no pre-0.6.4 alias members."""
    from opensearch_mcp.case_scope import case_read_scope

    if isinstance(case_ix, str):
        return case_read_scope(case_ix, None, artifact_type=artifact_type)
    return case_read_scope(case_ix.case_id, case_ix.client, artifact_type=artifact_type)


def enrich_remote(
    client: OpenSearch,
    case_id: str,
    on_progress=None,
    audit=None,
) -> dict:
    """Run batch triage enrichment against indexed data.

    The run is a reference step, written before its first write: the rules
    and windows-triage, with their versions. Every triage field group it
    writes carries the step's id (`triage.op_id`).

    Returns dict with counts per artifact type.
    """
    from opensearch_mcp import ops
    from opensearch_mcp.case_scope import CaseScopeError, scope_of

    try:
        scope_of(case_id)
    except CaseScopeError as e:
        return {"error": str(e)}
    from opensearch_mcp.write_context import case_dir_for

    audit = ops.case_writer(audit, case_dir_for(case_id))  # the enriched case's audit
    try:
        ref = ops.reference_step(
            audit, "enrich_triage", "windows-triage and registry persistence rules",
            _triage_versions(), {"case_id": case_id},
        )  # fmt: skip
    except ops.NoEntry as e:
        return {"error": f"Not enriched: {e}"}
    client = ops.StampingClient(client, ref)
    case_ix = _CaseIndices(case_id, client)

    # Refresh indices so aggregations see all recently ingested docs
    try:
        client.indices.refresh(index=_index(case_ix))
    except Exception:
        pass

    results: dict = {"_reference_op": ref}

    # Stamps this version no longer writes are removed (events other than process
    # creation and 7045, and values of a service key other than ImagePath);
    # everything else is re-stamped below.
    results["_cleared"] = _clear_stamps(client, case_ix)

    # --- Gateway-independent: registry persistence R1-R14, R16 ---
    results["registry_persistence"] = _enrich_registry_persistence(client, case_ix, on_progress)

    # --- Gateway-dependent: file + service enrichment ---
    if not gateway_available():
        results["_gateway"] = "not configured — file/service enrichment skipped"
        return results

    # No health pre-check — the first check_file call serves as the
    # availability test. Circuit breaker (3 failures) handles backend down.
    # Removed hardcoded windows-triage-mcp__get_health: the collision-prefixed
    # name only exists when BOTH windows-triage-mcp AND the threat-intel
    # backend are registered. In single-backend configs, bare get_health is
    # the name.

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
            case_ix,
            index_pattern=_index(case_ix, suffix),
            path_field=field,
            artifact_name=name,
            query=query,
            on_progress=on_progress,
            flags_only=(name == "tasks"),
            hash_field="SHA1.keyword" if name == "amcache" else None,
            command_line=(name == "tasks"),
        )

    # Service enrichment (check_service): name plus executable, each doc's own pair
    results["evtx_svc"] = _enrich_services(
        client,
        _index(case_ix, "evtx"),
        {"term": {"event.code": 7045}},
        _svc_from_7045,
        "evtx_svc",
        on_progress,
    )
    results["vol_svcs"] = _enrich_services(
        client,
        _index(case_ix, "vol-svcscan"),
        {"match_all": {}},
        _svc_from_svcscan,
        "vol_svcs",
        on_progress,
    )
    results["registry_svcs"] = _enrich_services(
        client,
        _index(case_ix, "registry"),
        {
            "bool": {
                "must": [
                    {"wildcard": {"KeyPath.keyword": "*\\\\Services\\\\*"}},
                    {"term": {"ValueName.keyword": "ImagePath"}},
                ]
            }
        },
        _svc_from_registry,
        "registry_svcs",
        on_progress,
    )

    # Registry Run keys (check_file on ValueData)
    results["registry_run"] = _enrich_registry_run_keys(client, case_ix, on_progress)

    # R15: Active Setup StubPath (check_file)
    results["registry_activestub"] = _enrich_registry_check_file(
        client,
        case_ix,
        query_body={
            "bool": {
                "filter": [
                    {"wildcard": {"KeyPath.keyword": "*Active Setup\\\\Installed Components*"}},
                    {"term": {"ValueName.keyword": "StubPath"}},
                ]
            }
        },
        value_field="ValueData",
        artifact_name="registry_activestub",
        on_progress=on_progress,
    )

    # R17: NetSh Helper DLLs (check_file)
    results["registry_netsh"] = _enrich_registry_check_file(
        client,
        case_ix,
        query_body={
            "bool": {
                "should": [
                    {"wildcard": {"KeyPath.keyword": "*\\\\NetSh*"}},
                    {"wildcard": {"KeyPath.keyword": "*\\\\NetSh\\\\*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        value_field="ValueData",
        artifact_name="registry_netsh",
        on_progress=on_progress,
        dll_filter=True,
    )

    for name in ("registry_svcs", "registry_activestub", "registry_netsh"):
        if results.get(name, {}).get("status") == "empty":
            results[name]["reason"] = (
                "no registry values to check: the key is absent, or the ingested registry "
                "data doesn't include it"
            )
    return results


# ---------------------------------------------------------------------------
# File enrichment (check_file)
# ---------------------------------------------------------------------------


def _triage_versions() -> str:
    """The rules' version (this package's) and windows-triage's database
    version when the gateway answers; "unknown" for what doesn't."""
    from opensearch_mcp import __version__

    triage = "unknown"
    if gateway_available():
        try:
            stats = call_tool("get_db_stats", {}, timeout=10)
            if isinstance(stats, dict):
                triage = str(stats.get("db_version") or stats.get("version") or "unknown")
        except Exception:
            pass
    return f"rules opensearch-mcp {__version__}; windows-triage db {triage}"


def _enrich_file_artifact(
    client: OpenSearch,
    case_ix: _CaseIndices | str,
    index_pattern: str,
    path_field: str,
    artifact_name: str,
    query: str = "*",
    on_progress=None,
    flags_only: bool = False,
    hash_field: str | None = None,
    command_line: bool = False,
) -> dict:
    """Enrich file-based artifacts in batch via check_file.

    hash_field (Amcache's SHA1): check_file runs once per path and hash, so
    each hash gets its own answer; a missing or empty hash is one more value.
    command_line (a task's command): check_file gets the executable it starts
    and the command itself as before; `checked` counts the values sent and
    `not_checked` those that name no executable."""
    paths_agg: dict = {"terms": {"field": path_field, "size": 5000}}
    if hash_field:
        paths_agg["aggs"] = {
            "hashes": {
                "terms": {"field": hash_field, "size": 100, "missing": ""},
                "aggs": {"sizes": {"terms": {"field": "Size.keyword", "size": 1}}},
            }
        }
    try:
        agg_result = client.search(
            index=index_pattern,
            allow_no_indices=False,
            body={
                "query": {"query_string": {"query": query}},
                "aggs": {"paths": paths_agg},
                "size": 0,
            },
        )
    except Exception as e:
        from opensearchpy.exceptions import NotFoundError

        if isinstance(e, NotFoundError):
            return {"status": "skipped", "reason": "index not found"}
        print(
            f"  WARNING: {artifact_name} aggregation failed: {e}",
            file=sys.stderr,
        )
        return _search_outcome(e)

    paths_agg = agg_result.get("aggregations", {}).get("paths", {})
    buckets = paths_agg.get("buckets", [])
    unchecked = paths_agg.get("sum_other_doc_count", 0)
    hashes_unread = 0
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    verdicts: dict = {}
    consecutive_failures = 0
    succeeded = False
    counts = {"checked": len(buckets)}
    if command_line:  # the values with something to send, and those with none
        sendable = sum(1 for b in buckets if _sends(b["key"], raw=_heads_sent(b["key"])))
        counts = {"checked": sendable, "not_checked": len(buckets) - sendable}
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            print(
                f"  WARNING: {consecutive_failures} consecutive gateway failures "
                f"— stopping {artifact_name}",
                file=sys.stderr,
            )
            break
        path = bucket["key"]
        if command_line:  # its executable, and the command as it was sent before
            sends = _sends(path, raw=_heads_sent(path))
            state = {"failures": consecutive_failures, "ok": succeeded}
            answer = _ask_all(sends, state)
            consecutive_failures, succeeded = state["failures"], state["ok"]
            if answer:
                verdicts[path] = answer
            continue
        # Skip non-path entries (AppX metadata, hex strings, empty)
        if not _heads_sent(path):
            continue
        hashes = bucket.get("hashes", {}).get("buckets") if hash_field else None
        if hash_field:  # a path's hashes past the first 100 aren't read
            hashes_unread += bucket.get("hashes", {}).get("sum_other_doc_count", 0)
        if hashes:  # one answer per hash: {hash: result}
            answers = {}
            for h in hashes:
                if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    break
                size = (h.get("sizes", {}).get("buckets") or [{}])[0].get("key", "")
                args, note = _amcache_args(path, str(h["key"]), str(size))
                try:
                    result = call_tool("check_file", args, timeout=15)
                    consecutive_failures = 0
                    succeeded = True
                except Exception:
                    consecutive_failures += 1
                    continue
                if result.get("verdict"):
                    result = _reference_mismatch(result)
                    if note:
                        result = dict(result, reasons=[*result.get("reasons", []), note])
                    answers[str(h["key"])] = result
            if answers:
                verdicts[path] = answers
            continue
        try:
            result = call_tool("check_file", {"path": path}, timeout=15)
            consecutive_failures = 0
            succeeded = True
            if result.get("verdict"):
                verdicts[path] = _flags_only(result) if flags_only else result
        except Exception:
            consecutive_failures += 1
            continue

    if not verdicts:
        return _hashes_unread(
            _loop_result(consecutive_failures, succeeded, 0, unchecked, **counts, enriched=0),
            hashes_unread,
        )

    by_hash = {p: v for p, v in verdicts.items() if "verdict" not in v}
    plain = {p: v for p, v in verdicts.items() if "verdict" in v}
    enriched, write_failures = _batch_stamp_verdicts(
        client, index_pattern, path_field, plain, query
    )
    if by_hash:
        more, failed = _stamp_by_hash(client, index_pattern, path_field, hash_field, by_hash)
        enriched, write_failures = enriched + more, write_failures + failed

    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=counts["checked"],
            enriched=enriched,
        )

    return _hashes_unread(
        _loop_result(
            consecutive_failures,
            succeeded,
            write_failures,
            unchecked,
            **counts,
            enriched=enriched,
        ),
        hashes_unread,
    )


def _hashes_unread(result: dict, n: int) -> dict:
    """A result that also says how many documents' hashes weren't read."""
    if not n:
        return result
    why = f"{n} documents hold hashes past a path's first 100 and were not checked"
    reason = f"{result['reason']}; {why}" if result.get("reason") else why
    return {**result, "status": "failed", "reason": reason, "unchecked_hash_docs": n}


def _batch_stamp_verdicts(
    client: OpenSearch,
    index_pattern: str,
    path_field: str,
    verdicts: dict,
    scope_query: str = "*",
) -> int:
    """Batch-stamp verdicts by grouping paths with identical verdicts.

    Groups paths by (verdict, confidence, is_lolbin) and issues
    update_by_query per group using terms queries. Chunks to 500 paths
    per batch to avoid timeouts on large cases.
    """
    from collections import defaultdict

    # Group paths by stamp key: (verdict, confidence, lolbin)
    groups: dict[tuple, dict] = defaultdict(lambda: {"paths": [], "reasons": []})
    for path, result in verdicts.items():
        verdict_str = result.get("verdict", "UNKNOWN")
        confidence = result.get("confidence", "low")
        is_lolbin = bool(result.get("is_lolbin"))
        key = (verdict_str, confidence, is_lolbin)
        groups[key]["paths"].append(path)
        reasons = result.get("reasons", [])
        if reasons:
            groups[key]["reasons"].append("; ".join(reasons))

    total_updated = 0
    failed_values = 0
    for (verdict_str, confidence, is_lolbin), group in groups.items():
        script_lines = [
            "ctx._source['triage.verdict'] = params.verdict",
            "ctx._source['triage.checked'] = true",
            "ctx._source['triage.confidence'] = params.confidence",
        ]
        params: dict = {"verdict": verdict_str, "confidence": confidence}
        if is_lolbin:
            script_lines.append("ctx._source['triage.lolbin'] = true")

        # For batched paths, stamp a generic reason (individual reasons
        # vary per path but the verdict is the same for all in this group)
        unique_reasons = sorted(set(group["reasons"]))
        if len(unique_reasons) == 1:
            script_lines.append("ctx._source['triage.reason'] = params.reason")
            params["reason"] = unique_reasons[0]
        elif unique_reasons:
            # Multiple distinct reasons in same verdict group — use per-doc
            # reason from a lookup map in params
            script_lines.append(
                "String p = ctx._source.getOrDefault(params.path_field, ''); "
                "if (params.reason_map.containsKey(p)) { "
                "ctx._source['triage.reason'] = params.reason_map.get(p); }"
            )
            params["path_field"] = path_field.replace(".keyword", "")
            params["reason_map"] = {
                p: "; ".join(verdicts[p].get("reasons", []))
                for p in group["paths"]
                if verdicts[p].get("reasons")
            }

        # Chunk paths to avoid timeouts on large cases
        all_paths = group["paths"]
        for i in range(0, len(all_paths), 500):
            chunk = all_paths[i : i + 500]
            chunk_params = dict(params)
            if "reason_map" in chunk_params:
                chunk_params["reason_map"] = {
                    p: params["reason_map"][p] for p in chunk if p in params["reason_map"]
                }
            paths_query = {"terms": {path_field: chunk}}
            try:
                resp = client.update_by_query(
                    index=index_pattern,
                    body={
                        "query": paths_query
                        if scope_query == "*"
                        else {
                            "bool": {
                                "filter": [paths_query, {"query_string": {"query": scope_query}}]
                            }
                        },
                        "script": {
                            "source": "; ".join(script_lines),
                            "lang": "painless",
                            "params": chunk_params,
                        },
                    },
                    conflicts="proceed",
                    requests_per_second=1000,
                )
                total_updated += resp.get("updated", 0)
            except Exception as e:
                failed_values += len(chunk)
                print(
                    f"  WARNING: batch update_by_query failed for {verdict_str}: {e}",
                    file=sys.stderr,
                )

    return total_updated, failed_values


# ---------------------------------------------------------------------------
# Service enrichment (check_service)
# ---------------------------------------------------------------------------


_TRIAGE_FIELDS = [
    "triage.verdict",
    "triage.reason",
    "triage.checked",
    "triage.confidence",
    "triage.lolbin",
    "triage.expected_paths",
    "triage.op_id",  # the enrichment step that wrote them
]
_AMCACHE_HASH_LIMIT = 31457280  # Amcache's SHA1 covers only the first 30 MiB of a file


def _clear_stamps(client, case_ix):
    script = {
        "source": "for (f in params.f) { ctx._source.remove(f) }",
        "lang": "painless",
        "params": {"f": _TRIAGE_FIELDS},
    }
    stamped = {"exists": {"field": "triage.checked"}}
    scopes = [
        (
            _index(case_ix, "evtx"),
            {
                "bool": {
                    "filter": [stamped],
                    "must_not": [{"terms": {"event.code": [4688, 1, 7045]}}],
                }
            },
        ),
        (
            _index(case_ix, "registry"),
            {
                "bool": {
                    "filter": [stamped, {"wildcard": {"KeyPath.keyword": "*\\\\Services\\\\*"}}],
                    "must_not": [{"term": {"ValueName.keyword": "ImagePath"}}],
                }
            },
        ),
    ]
    from opensearchpy.exceptions import NotFoundError

    cleared = 0
    for index, query in scopes:
        try:
            cleared += _ubq_to_completion(
                client, index=index, body={"query": query, "script": script}
            )
        except NotFoundError:
            continue  # no such index: no stamps in it to clear
        except Exception as e:
            return {"status": "failed", "reason": f"retired stamps could not be cleared: {e}"}
    return {"status": "complete", "cleared": cleared}


_CLEAR_WAIT = 3600  # seconds a clear may take before triage gives up on it


def _ubq_to_completion(client, index, body, wait=_CLEAR_WAIT, poll=1.0) -> int:
    """Run an update_by_query as a task and wait for it, returning its count.

    Called synchronously, a large one outlives the client's 10 s read timeout
    (and its response, with one header per batch, can be misread), so the
    caller would carry on, and stamp, while it still runs. Polling the task
    gives the true count, and nothing after it starts first."""
    resp = client.update_by_query(
        index=index,
        body=body,
        conflicts="proceed",
        allow_no_indices=True,
        wait_for_completion=False,
        request_timeout=60,
    )
    task = resp.get("task")
    if not task:  # nothing matched an index: no task was started
        return resp.get("updated", 0)
    deadline = time.monotonic() + wait
    while True:
        status = client.tasks.get(task_id=task, request_timeout=60)
        if status.get("completed"):
            if status.get("error"):
                raise RuntimeError(status["error"].get("reason", status["error"]))
            response = status.get("response", {})
            if response.get("failures"):
                raise RuntimeError(f"{len(response['failures'])} documents failed")
            return response.get("updated", 0)
        if time.monotonic() > deadline:
            raise TimeoutError(f"still running after {wait} s (task {task})")
        time.sleep(poll)


# What check_file can be given for a command line: the executable it starts
_EXE_EXTS = (".exe", ".com", ".bat", ".cmd", ".scr", ".dll", ".cpl", ".msc", ".ps1",
             ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".pif", ".msi")  # fmt: skip
_EXE_END = re.compile("(" + "|".join(map(re.escape, _EXE_EXTS)) + r")(?=\s)", re.I)


def _heads_sent(value: str) -> bool:
    """A value check_file is given as it is: one starting with \\, / or X:."""
    return bool(value) and (value[0] in "\\/" or (len(value) > 1 and value[1] == ":"))


def _a_path(value: str) -> bool:
    """A path windows-triage can read: rooted, on a drive, or %NAME%-led."""
    return _heads_sent(value) or bool(re.match(r"%[^%\s]+%", value))


def _executable_of(value: str) -> str | None:
    """The executable a command line starts (a RunOnceEx "||cmd" or
    "file|Function", a quoted path, or the shortest prefix ending in an
    executable extension before a space), or None when that isn't a path."""
    s = (value or "").strip()
    if "|" in s:
        s = s.lstrip("|").split("|", 1)[0].strip()
    if s.startswith('"'):
        s = s[1:].split('"', 1)[0]
    elif m := _EXE_END.search(s):
        s = s[: m.end()]
    return s if _a_path(s) else None


def _sends(value: str, raw: bool = True) -> list[str]:
    """What check_file is given for a command line: its executable, and the
    value itself when `raw` (as it was sent before, so no answer is lost)."""
    exe = _executable_of(value)
    return list(dict.fromkeys(([exe] if exe else []) + ([value] if raw else [])))


_WORSE = {"SUSPICIOUS": 2, "UNKNOWN": 1}


def _ask_all(values: list[str], state: dict) -> dict | None:
    """check_file on each value, flags only: the worse answer (SUSPICIOUS,
    then UNKNOWN, then the rest), with the LOLBin flag if any answer had it.
    The values are answered only when every call answered: one that failed
    fails them all, as one call would, and nothing is written for them.
    `state` carries the loop's consecutive call failures and whether any
    value was answered."""
    if not values or state["failures"] >= _MAX_CONSECUTIVE_FAILURES:
        return None
    answers = []
    for value in values:
        try:
            result = call_tool("check_file", {"path": value}, timeout=15)
        except Exception:
            state["failures"] += 1
            return None
        if result.get("verdict"):
            answers.append(_flags_only(result))
    state["failures"], state["ok"] = 0, True
    if not answers:
        return None
    worst = max(answers, key=lambda a: _WORSE.get(a.get("verdict"), 0))
    return dict(worst, is_lolbin=True) if any(a.get("is_lolbin") for a in answers) else worst


def _flags_only(result: dict) -> dict:
    """An entry that only names a file: keep SUSPICIOUS and the LOLBin flag, never EXPECTED."""
    if not str(result.get("verdict", "")).startswith("EXPECTED"):
        return result
    reasons = [
        "Target file: " + "; ".join(result.get("reasons", [])),
        "The entry itself is not compared to a baseline",
    ]
    return dict(result, verdict="UNKNOWN", confidence="low", reasons=reasons)


_REFERENCE_MISMATCH = (
    "hash differs from every reference build; may be a patch level not in the reference"
)


def _amcache_args(path: str, sha1: str, size: str) -> tuple[dict, str | None]:
    """check_file's arguments for one Amcache path and SHA1, and a note when
    the hash isn't passed (none recorded, or past what Amcache hashes)."""
    if len(sha1) != 40 or not all(c in "0123456789abcdefABCDEF" for c in sha1):
        return {"path": path}, "Hash not compared: Amcache recorded no SHA1 for this entry"
    if size.isdigit() and int(size) > _AMCACHE_HASH_LIMIT:
        return {"path": path}, "Hash not compared: Amcache hashes only the first 30 MiB of a file"
    return {"path": path, "hash": sha1}, None


def _reference_mismatch(result: dict) -> dict:
    """A hash that matches no reference build of the path, with nothing else
    critical, is most often a patch level the reference doesn't hold: UNKNOWN
    here, never SUSPICIOUS and never EXPECTED."""
    critical = [f for f in result.get("findings", []) if f.get("severity") == "critical"]
    if [f.get("type") for f in critical] != ["hash_mismatch"]:
        return result
    return dict(result, verdict="UNKNOWN", confidence="low", reasons=[_REFERENCE_MISMATCH])


def _stamp_by_hash(client, index_pattern, path_field, hash_field, by_hash) -> tuple[int, int]:
    """Stamp each doc with the answer for its own path and hash; a doc with
    no hash, or an empty one, takes the "" answer."""
    source_path = path_field.removesuffix(".keyword")
    source_hash = hash_field.removesuffix(".keyword")
    script = (
        "def m = params.m.get(ctx._source[params.pf]); "
        "def h = ctx._source[params.hf]; "
        "def r = m == null ? null : m.get(h == null ? '' : h.toString()); "
        "if (r == null) { ctx.op = 'noop' } else { "
        "ctx._source['triage.verdict'] = r.v; ctx._source['triage.checked'] = true; "
        "ctx._source['triage.confidence'] = r.c; ctx._source['triage.reason'] = r.r; "
        "if (r.l) { ctx._source['triage.lolbin'] = true } }"
    )
    updated = failed = 0
    paths = list(by_hash)
    for i in range(0, len(paths), 500):
        chunk = paths[i : i + 500]
        m = {
            p: {
                h: {
                    "v": r["verdict"],
                    "c": r.get("confidence", "low"),
                    "r": "; ".join(r.get("reasons", [])),
                    "l": bool(r.get("is_lolbin")),
                }
                for h, r in by_hash[p].items()
            }
            for p in chunk
        }
        try:
            resp = _ubq(
                client,
                index=index_pattern,
                body={
                    "query": {"terms": {path_field: chunk}},
                    "script": {
                        "source": script,
                        "lang": "painless",
                        "params": {"m": m, "pf": source_path, "hf": source_hash},
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            updated += resp.get("updated", 0)
        except _WriteFailed:
            failed += len(chunk)
    return updated, failed


def _svc_from_registry(src):
    return src.get("KeyPath", "").replace("/", "\\").rsplit("\\", 1)[-1], src.get("ValueData", "")


def _svc_from_7045(src):
    ed = src.get("winlog.event_data", {})
    return (ed.get("ServiceName"), ed.get("ImagePath", "")) if isinstance(ed, dict) else (None, "")


def _svc_from_svcscan(src):
    """The registry's ImagePath first: the in-memory Binary still shows the old
    executable until a hijacked service restarts. Binary when it's the only one
    and names a file (a driver object isn't one)."""
    registry = (src.get("Binary (Registry)") or "").strip()
    memory = (src.get("Binary") or "").strip()
    is_file = memory and not memory.lower().startswith(("\\driver\\", "\\filesystem\\"))
    return src.get("Name"), registry or (memory if is_file else "")


class _PartialRead(RuntimeError):
    """A scroll failed after its first page: some matching docs were not read."""


def _all_hits(client, index, query):
    """Every hit for the query, read in pages through a scroll. A failure
    after the first page raises _PartialRead."""
    resp = client.search(
        index=index, allow_no_indices=False, scroll="2m", body={"query": query, "size": 1000}
    )
    scroll_id = resp.get("_scroll_id")
    try:
        while resp["hits"]["hits"]:
            yield from resp["hits"]["hits"]
            if not scroll_id:
                break
            try:
                resp = client.scroll(scroll_id=scroll_id, scroll="2m")
            except Exception as e:
                raise _PartialRead(str(e)) from e
            scroll_id = resp.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            try:
                client.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass


def _enrich_services(client, index, query, extract, artifact_name, on_progress=None):
    """check_service once per (name, executable string); the verdict goes only
    to the docs that carry that pair. Every matching doc is read."""
    try:
        hits = list(_all_hits(client, index, query))
    except _PartialRead as e:
        return {"status": "failed", "reason": f"not every matching document could be read: {e}"}
    except Exception as e:
        return _search_outcome(e)
    if not hits:
        return {"status": "empty", "checked": 0}
    groups: dict = {}
    for h in hits:
        name, image_path = extract(h["_source"])
        if name:
            groups.setdefault((name, image_path or ""), []).append(h["_id"])
    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(groups))
    enriched = write_failures = consecutive_failures = unanswered = 0
    succeeded = False
    for (name, image_path), ids in groups.items():
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        args = {"service_name": name}
        if image_path:
            args["binary_path"] = image_path
        try:
            verdict = call_tool("check_service", args, timeout=15)
            consecutive_failures = 0
            succeeded = True
            if not verdict.get("verdict"):  # an error answer, not a verdict
                unanswered += 1
                continue
            params = {
                "verdict": verdict["verdict"],
                "confidence": verdict.get("confidence", "low"),
                "reason": "; ".join(verdict.get("reasons", [])),
            }
            resp = _ubq(
                client,
                index=index,
                body={
                    "query": {"ids": {"values": ids}},
                    "script": {
                        "source": "ctx._source['triage.verdict'] = params.verdict; "
                        "ctx._source['triage.checked'] = true; "
                        "ctx._source['triage.confidence'] = params.confidence; "
                        "ctx._source['triage.reason'] = params.reason",
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            enriched += resp.get("updated", 0)
        except _WriteFailed:
            write_failures += 1
        except Exception:
            consecutive_failures += 1
    if on_progress:
        on_progress("triage_done", artifact=artifact_name, checked=len(groups), enriched=enriched)
    result = _loop_result(
        consecutive_failures, succeeded, write_failures, checked=len(groups), enriched=enriched
    )
    if unanswered:
        why = f"{unanswered} check_service calls returned no verdict"
        reason = f"{result['reason']}; {why}" if result.get("reason") else why
        result = {**result, "status": "failed", "reason": reason, "unanswered": unanswered}
    return result


# ---------------------------------------------------------------------------
# Registry Run keys (check_file on ValueData)
# ---------------------------------------------------------------------------


def _enrich_registry_run_keys(client, case_ix, on_progress=None):
    """Enrich registry Run key entries (Run, RunOnce, RunOnceEx, RunServices,
    RunServicesOnce) with check_file: each value, and the executable it starts.
    A value over 256 characters has no keyword term, so the aggregation can't
    read it: those are counted (`too_long`) and fail the step."""
    index = _index(case_ix, "registry")
    run_keys = [
        {"wildcard": {"KeyPath.keyword": f"*\\\\{key}"}}
        for key in ("Run\\\\*", "Run", "RunOnce", "RunOnce\\\\*", "RunOnceEx\\\\*",
                    "RunServices", "RunServicesOnce")
    ]  # fmt: skip
    try:
        result = client.search(
            index=index,
            allow_no_indices=False,
            body={
                "query": {
                    "bool": {
                        "should": run_keys,
                        "minimum_should_match": 1,
                        "filter": [{"exists": {"field": "ValueData"}}],
                    }
                },
                "size": 0,
                "track_total_hits": True,
                "aggs": {"values": {"terms": {"field": "ValueData.keyword", "size": 5000}}},
            },
        )
    except Exception as e:
        return _search_outcome(e)

    values_agg = result.get("aggregations", {}).get("values", {})
    buckets = values_agg.get("buckets", [])
    unchecked = values_agg.get("sum_other_doc_count", 0)
    total = (result.get("hits") or {}).get("total") or 0
    total = total.get("value", 0) if isinstance(total, dict) else total
    too_long = max(0, total - sum(b.get("doc_count", 0) for b in buckets) - unchecked)
    if not buckets:
        return _too_long({"status": "empty", "checked": 0}, too_long)

    if on_progress:
        on_progress("triage_start", artifact="registry_run", unique_values=len(buckets))

    enriched = 0
    write_failures = 0
    state = {"failures": 0, "ok": False}
    for bucket in buckets:
        if state["failures"] >= _MAX_CONSECUTIVE_FAILURES:
            break
        value_data = bucket["key"]
        if not value_data.strip():
            continue
        verdict = _ask_all(_sends(value_data), state)
        if verdict:
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
                "ctx._source['triage.confidence'] = params.confidence",
            ]
            params: dict = {
                "verdict": verdict["verdict"],
                "confidence": verdict.get("confidence", "low"),
            }
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            if verdict.get("is_lolbin"):
                script_lines.append("ctx._source['triage.lolbin'] = true")
            try:
                resp = client.update_by_query(
                    index=index,
                    body={
                        "query": {
                            "bool": {
                                "should": run_keys,
                                "minimum_should_match": 1,
                                "filter": [{"term": {"ValueData.keyword": value_data}}],
                            }
                        },
                        "script": {
                            "source": "; ".join(script_lines),
                            "lang": "painless",
                            "params": params,
                        },
                    },
                    conflicts="proceed",
                    requests_per_second=1000,
                )
                enriched += resp.get("updated", 0)
            except Exception as e:
                write_failures += 1
                print(
                    f"  WARNING: update_by_query failed for Run key: {e}",
                    file=sys.stderr,
                )

    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_run",
            checked=len(buckets),
            enriched=enriched,
        )
    return _too_long(
        _loop_result(
            state["failures"],
            state["ok"],
            write_failures,
            unchecked,
            checked=len(buckets),
            enriched=enriched,
        ),  # fmt: skip
        too_long,
    )


def _too_long(result: dict, n: int) -> dict:
    """A result that also says how many Run-key values were too long to read."""
    if not n:
        return result
    why = f"{n} Run-key values are over 256 characters and were not checked"
    reason = f"{result['reason']}; {why}" if result.get("reason") else why
    return {**result, "status": "failed", "reason": reason, "too_long": n}


# ---------------------------------------------------------------------------
def _enrich_registry_check_file(
    client,
    case_ix,
    query_body,
    value_field,
    artifact_name,
    on_progress=None,
    dll_filter=False,
):
    """Enrich registry entries by calling check_file on a value field.

    Used for R15 (Active Setup StubPath) and R17 (NetSh helper DLLs).
    """
    index = _index(case_ix, "registry")
    try:
        result = client.search(
            index=index,
            allow_no_indices=False,
            body={
                "query": {
                    "bool": {
                        "must": [query_body, {"exists": {"field": value_field}}],
                    }
                },
                "size": 0,
                "aggs": {"values": {"terms": {"field": f"{value_field}.keyword", "size": 5000}}},
            },
        )
    except Exception as e:
        return _search_outcome(e)

    values_agg = result.get("aggregations", {}).get("values", {})
    buckets = values_agg.get("buckets", [])
    unchecked = values_agg.get("sum_other_doc_count", 0)
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    enriched = 0
    write_failures = 0
    state = {"failures": 0, "ok": False}
    for bucket in buckets:
        if state["failures"] >= _MAX_CONSECUTIVE_FAILURES:
            break
        value = bucket["key"]
        if not value.strip():
            continue
        if dll_filter and not value.lower().endswith(".dll"):
            continue
        # a StubPath is a command line: its executable too; a NetSh value is the DLL
        verdict = _ask_all([value] if dll_filter else _sends(value), state)
        if not verdict:
            continue
        try:
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = _ubq(
                client,
                index=index,
                body={
                    # Only the documents this loop selected: another rule's
                    # verdict on a document holding the same value stays
                    "query": {
                        "bool": {
                            "filter": [query_body, {"term": {f"{value_field}.keyword": value}}]
                        }
                    },
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            enriched += resp.get("updated", 0)
        except _WriteFailed:
            write_failures += 1

    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )
    return _loop_result(
        state["failures"],
        state["ok"],
        write_failures,
        unchecked,
        checked=len(buckets),
        enriched=enriched,
    )


# Registry persistence R1-R17 (no gateway — pure update_by_query)
# ---------------------------------------------------------------------------

# The fields a persistence rule stamps
_RULE_STAMP_FIELDS = ["triage.verdict", "triage.reason", "triage.checked"]
# else-branch of a rule script: remove the rule's own earlier stamp, leave any other alone
_UNSTAMP_OWN = """{
    if (ctx._source['triage.reason'] instanceof String
            && ctx._source['triage.reason'].startsWith(params.prefix)) {
        for (String f : params.fields) { ctx._source.remove(f); }
    } else { ctx.op = 'noop'; }
}"""


def _enrich_registry_persistence(client, case_ix, on_progress=None):
    """Flag registry persistence mechanisms via update_by_query.

    Implements R1-R14, R16. R15 (Active Setup) and R17 (NetSh) use
    check_file gateway calls and are handled in enrich_remote().

    No gateway calls — queries OpenSearch directly. Runs even when
    gateway is unavailable.
    """
    index = _index(case_ix, "registry")
    total_updated = 0
    rules_failed = 0
    no_data: list[str] = []

    def _seen(resp, name):  # a rule whose query matched no row had nothing to check
        if not resp.get("total", 0):
            no_data.append(name)

    try:  # no registry index: say so, not "complete, 0"
        client.search(index=index, body={"size": 0}, allow_no_indices=False)
    except Exception as e:
        return _search_outcome(e)

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
        # NOTE: R8-R10 (LSA packages) handled separately below (need Painless set logic)
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
            # the monitors Windows itself registers (bare names, loaded from System32)
            "known": [
                "localspl.dll",
                "tcpmon.dll",
                "usbmon.dll",
                "apmon.dll",
                "appmon.dll",
                "fxsmon.dll",
            ],
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

    # Simple rules: a non-empty value, not one Windows itself sets → SUSPICIOUS. A value
    # that no longer qualifies loses this rule's earlier stamp (and only this rule's).
    for rule in rules:
        try:
            resp = client.update_by_query(
                index=index,
                body={
                    "query": rule["query"],
                    "script": {
                        "source": """
                            String v = ctx._source['ValueData'].toString().trim();
                            if (v.length() > 0 && !params.known.contains(v.toLowerCase())) {
                                ctx._source['triage.verdict'] = 'SUSPICIOUS';
                                ctx._source['triage.reason'] =
                                    params.prefix + ctx._source['ValueData'];
                                ctx._source['triage.checked'] = true;
                            } else """
                        + _UNSTAMP_OWN,
                        "lang": "painless",
                        "params": {
                            "prefix": rule["reason_prefix"],
                            "known": rule.get("known", []),
                            "fields": _RULE_STAMP_FIELDS,
                        },
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            total_updated += resp.get("updated", 0)
            _seen(resp, rule["reason_prefix"].removesuffix(": "))
        except Exception:
            rules_failed += 1

    # R8-R10: LSA packages — flag non-default entries
    _LSA_DEFAULTS = (
        "msv1_0 kerberos schannel wdigest tspkg pku2u cloudap negoextender scecli rassfm"
    ).split()
    for lsa_value_name, lsa_label in [
        ("Authentication Packages", "Authentication Packages"),
        ("Security Packages", "Security Packages"),
        ("Notification Packages", "Notification Packages"),
    ]:
        try:
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"wildcard": {"KeyPath.keyword": "*Control\\\\Lsa*"}},
                                {"term": {"ValueName.keyword": lsa_value_name}},
                                {"exists": {"field": "ValueData"}},
                            ]
                        }
                    },
                    "script": {
                        "source": """
                            String val = ctx._source['ValueData'].toString().toLowerCase();
                            val = val.replace('"', '').trim();
                            String[] entries = /[\\n| ]+/.split(val);
                            List unknown = new ArrayList();
                            for (String e : entries) {
                                String trimmed = e.trim();
                                if (trimmed.length() > 0 && !params.known.contains(trimmed)) {
                                    unknown.add(trimmed);
                                }
                            }
                            if (unknown.size() > 0) {
                                ctx._source['triage.verdict'] = 'SUSPICIOUS';
                                String r = params.label + ': ' + String.join(', ', unknown);
                                ctx._source['triage.reason'] = r;
                                ctx._source['triage.checked'] = true;
                            } else """
                        + _UNSTAMP_OWN,
                        "lang": "painless",
                        "params": {
                            "known": _LSA_DEFAULTS,
                            "label": f"Non-default {lsa_label}",
                            "prefix": f"Non-default {lsa_label}: ",
                            "fields": _RULE_STAMP_FIELDS,
                        },
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            total_updated += resp.get("updated", 0)
            _seen(resp, lsa_label)
        except Exception as exc:
            rules_failed += 1
            logger.debug("Registry rule failed: %s", exc)

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
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
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
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
        _seen(resp, "Winlogon Shell")
    except Exception as exc:
        rules_failed += 1
        logger.debug("Registry rule failed: %s", exc)

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
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
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
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
        _seen(resp, "Winlogon Userinit")
    except Exception as exc:
        rules_failed += 1
        logger.debug("Registry rule failed: %s", exc)

    # R7: BootExecute — conditional (anything but Windows' own autochk entries → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Session Manager*"}},
                            {"term": {"ValueName.keyword": "BootExecute"}},
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toString().trim();
                        // Windows' own entries, one or more: `autocheck autochk`, its
                        // switches (/q, /k:C, /p), then all volumes (*) or one (\\??\\C:)
                        String[] t = val.length() == 0 ? new String[0]
                            : /\\s+/.split(val.toLowerCase());
                        boolean dflt = true;
                        int i = 0;
                        while (dflt && i < t.length) {
                            dflt = i + 2 < t.length
                                && t[i] == 'autocheck' && t[i + 1] == 'autochk';
                            i += 2;
                            while (dflt && i < t.length && t[i].startsWith('/')) { i++; }
                            dflt = dflt && i < t.length
                                && (t[i] == '*' || (t[i].startsWith('\\\\??\\\\')
                                    && t[i].length() > 4));
                            i++;
                        }
                        if (!dflt) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            ctx._source['triage.reason'] = params.prefix + val;
                            ctx._source['triage.checked'] = true;
                        } else """
                    + _UNSTAMP_OWN,
                    "lang": "painless",
                    "params": {"prefix": "BootExecute: ", "fields": _RULE_STAMP_FIELDS},
                },
            },
            conflicts="proceed",
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
        _seen(resp, "BootExecute")
    except Exception as exc:
        rules_failed += 1
        logger.debug("Registry rule failed: %s", exc)

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
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
        _seen(resp, "Screensaver")
    except Exception as exc:
        rules_failed += 1
        logger.debug("Registry rule failed: %s", exc)

    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_persistence",
            checked=0,
            enriched=total_updated,
        )
    result: dict = {"status": "complete", "enriched": total_updated}
    if no_data:
        result["rules_without_data"] = no_data
        result["note"] = (
            f"{len(no_data)} of 15 rules had no registry values to check "
            f"({', '.join(no_data)}): the value is absent, or the ingested registry data "
            "doesn't include it (the scan doesn't read user hives, NTUSER.DAT)"
        )
    if rules_failed:
        result.update(
            status="failed",
            reason=f"{rules_failed} persistence rules could not be applied",
            rules_failed=rules_failed,
        )
    return result
