"""Shared bulk indexing helper for evtx and CSV ingest."""

from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Iterator, Mapping

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import ConnectionError as OSConnectionError
from opensearchpy.exceptions import ConnectionTimeout, NotFoundError, TransportError

_INITIAL_BACKOFF = 10
_MAX_BACKOFF = 120
_MAX_RETRIES = 10

# Circuit breaker — trip after N consecutive 100%-failure batches
# matching systemic error patterns. Prevents silent data loss when a
# cluster-wide condition (shard limit, cluster block) rejects every
# write indefinitely. Threshold is env-tunable (min 1 — operator
# typo of 0 would defeat the purpose of the breaker).
_SYSTEMIC_ERROR_PATTERNS = (
    "validation_exception",
    "cluster_block_exception",
    "this action would add",
    "maximum shards open",
    "blocked by",
    "illegal_argument_exception",
)
_CIRCUIT_BREAKER_THRESHOLD = max(1, int(os.environ.get("VHIR_SHARD_BREAKER_THRESHOLD", "3")))

# Rev 6: thread-local state. Concurrent in-process MCP tools used to
# share a module-global counter and could cross-halt each other.
# Subprocess-launched ingests still get a fresh state per process.
# Note: if a future MCP handler runs async coroutines with direct
# in-process flush_bulk, migrate to contextvars.ContextVar — today
# every ingest path subprocess-isolates so thread-local is enough.
_tls = threading.local()

# Prefixes the last bulk reason when the transport gave up on a batch, which
# was then never delivered — as opposed to records OpenSearch rejected.
TRANSPORT_REASON_PREFIX = "transport: "


def _get_counter() -> int:
    return getattr(_tls, "consecutive_systemic_failures", 0)


def _set_counter(n: int) -> None:
    _tls.consecutive_systemic_failures = n


def get_last_bulk_reason() -> str:
    """Return the first-error reason from the most recent bulk failure
    (thread-local). Empty string when the last batch succeeded or no
    batches have run yet. Callers that write ingest status read this
    to populate the status file's `bulk_failed_reason` field — gives
    operators the mapping/validation cause without digging in stderr.
    """
    return getattr(_tls, "last_bulk_reason", "")


def clear_last_bulk_reason() -> None:
    """Reset the thread-local last-error tracker. Call at ingest start."""
    _tls.last_bulk_reason = ""


class ShardCapacityExhausted(RuntimeError):
    """Raised when N consecutive bulk batches are fully rejected for
    systemic reasons (shard limit, cluster block). Signals callers to
    halt the ingest — retrying won't help until capacity is restored.
    """


def reset_circuit_breaker() -> None:
    """Call at ingest start to clear thread-local state from prior runs.

    Clears BOTH the circuit-breaker counter AND the last-bulk-reason
    tracker — both live on the same `_tls` and both need to be reset
    per ingest so an in-process MCP tool (idx_ingest_json,
    idx_ingest_delimited, idx_ingest_accesslog, idx_ingest_memory,
    idx_ingest) running a second time in the same thread doesn't
    inherit stale state from the prior call. Subprocess-launched
    ingests get a fresh process regardless — this matters for the
    in-process path.
    """
    _set_counter(0)
    _tls.last_bulk_reason = ""


def _is_systemic_failure(success: int, total: int, errors: list | None) -> tuple[bool, str]:
    """Scan bulk errors for systemic patterns (shard-limit, cluster-block).

    Returns (is_systemic, representative_reason). Scans up to 200
    errors (Rev 6: raised from 50). Systemic failures typically hit
    100% of a batch anyway, but a mixed batch could have 51+
    non-systemic errors before a systemic one — 200 is safe buffer.
    """
    if total == 0 or success > 0:
        return False, ""
    representative = ""
    for err in (errors or [])[:200]:  # Rev 6: raised from 50
        if not isinstance(err, dict):
            continue
        for action_type in ("index", "create", "update"):
            info = err.get(action_type, {})
            if not info.get("error"):
                continue
            e = info["error"]
            reason = e.get("reason", str(e)) if isinstance(e, dict) else str(e)
            reason_lower = reason.lower()
            if any(p in reason_lower for p in _SYSTEMIC_ERROR_PATTERNS):
                return True, reason
            if not representative:
                representative = reason
            break
    return False, representative


def flush_bulk(
    client: OpenSearch, actions: list[dict], depth_limit: bool = False
) -> tuple[int, int]:
    """Bulk index actions with persistent retry on timeout.

    Returns (success_count, failed_count).
    Never gives up on a batch — retries with increasing backoff until
    OpenSearch accepts it or max retries exceeded. Under sustained
    pressure, splits the batch in half and retries smaller chunks.

    Raises ShardCapacityExhausted if N consecutive batches fail for
    systemic reasons (e.g., cluster-wide shard limit).

    `depth_limit=True` refuses, before sending, each record the cluster
    would certainly reject for nesting deeper than its index's
    `index.mapping.depth.limit`. Measured: OpenSearch expands a deep dotted
    key itself before rejecting it — 3 s and an HTTP 500 at 1,000
    segments — and the timeout is then retried as if transient. A refused
    record is counted in `failed` and named in the last bulk reason by
    `_id` and field path; the rest of the batch is sent.
    """
    refused = 0
    if depth_limit and actions:
        actions, refused = _refuse_too_deep(client, actions)
    success, failed = _flush_with_retry(client, actions, attempt=0)
    return success, failed + refused


_DEPTH_SETTING = "index.mapping.depth.limit"
_DEFAULT_DEPTH_LIMIT = 20  # OpenSearch's default


def _as_limit(value: object) -> int | None:
    if isinstance(value, (int, str)) and str(value).isdigit():
        return int(value)
    return None


def _index_depth_limit(client: OpenSearch, index: str) -> int | None:
    """`index.mapping.depth.limit` for `index`: its own settings (defaults
    included) when it exists, the template it would be created from when
    it does not, and OpenSearch's default when neither sets it. For an alias
    over several indices, the largest, so nothing is refused that one of
    them accepts.

    None when the limit could not be READ — a request that failed, or an
    answer that makes no sense. Nothing is then refused for this index and
    the cluster decides: falling back to the default there would refuse
    records that an index with a higher limit accepts.
    """
    try:
        resp = client.indices.get_settings(
            index=index, name=_DEPTH_SETTING, include_defaults=True, flat_settings=True
        )
    except NotFoundError:
        resp = None
    except Exception:
        return None
    if resp is not None:
        if not isinstance(resp, dict):
            return None
        found = [
            _as_limit(entry.get("settings", {}).get(_DEPTH_SETTING))
            or _as_limit(entry.get("defaults", {}).get(_DEPTH_SETTING))
            for entry in resp.values()
            if isinstance(entry, dict)
        ]
        found = [limit for limit in found if limit]
        return max(found) if found else _DEFAULT_DEPTH_LIMIT
    try:
        sim = client.indices.simulate_index_template(name=index)
    except Exception:
        return None
    if not isinstance(sim, dict):
        return None
    depth = (sim.get("template", {}).get("settings", {}).get("index", {}).get("mapping", {})).get(
        "depth", {}
    )
    if not isinstance(depth, dict) or "limit" not in depth:
        return _DEFAULT_DEPTH_LIMIT
    return _as_limit(depth["limit"])


def _too_deep(source: Mapping, limit: int) -> str | None:
    """The field path at which `source` nests past `limit`, or None.

    The rule, measured on OpenSearch 3.5.0 for limits 20 and 5: every object
    on a field's path counts, the root included, and must be at most
    `limit`. A dotted key expands to one object per non-empty segment, so a
    value under `a.b.c` in an object at depth d sits in the object at depth
    d + 2; an object value is itself one level deeper, so an empty object
    counts one more than a scalar. Arrays add nothing. A null under a
    dotted key creates no objects and is accepted at any depth; every other
    value, empty strings and lists included, does. Iterative, and it goes
    no deeper than `limit` + 1, so a 5,000-segment key costs one split.
    Not modelled: an object an index maps `enabled: false` is not parsed, so
    the cluster accepts depth under it that this refuses; no shipped mapping
    declares one and dynamic mapping never creates one.

    Depth-first over iterators: one frame per open object or list on the
    current path, each with a (parent, key) link rather than its path, so
    memory follows nesting, not width, and a path is joined only for the
    record being refused. Building one per child copied a long key once per
    child — a 1 MB key over 1,000 empty objects peaked at 954 MiB (measured)
    before anything was sent — and pushing every child at once kept enough
    tracked objects alive to make the garbage collector's full passes grow
    with the record.
    """
    if limit < 1:
        return ""
    # (is an object, iterator, depth of the objects it yields, link)
    frames: list[tuple[bool, Iterator, int, tuple | None]] = [
        (True, iter(source.items()), 1, None)
    ]
    while frames:
        is_object, items, depth, link = frames[-1]
        child = None
        if is_object:
            for key, value in items:
                if value is None:
                    continue
                key = str(key)
                segments = sum(1 for part in key.split(".") if part)
                if isinstance(value, Mapping):
                    if depth + segments > limit:
                        return _joined((link, key))
                    child = (True, iter(value.items()), depth + segments, (link, key))
                    break
                if depth + segments - 1 > limit:
                    return _joined((link, key))
                if isinstance(value, (list, tuple)):
                    child = (False, iter(value), depth + segments, (link, key))
                    break
        else:
            for item in items:
                if isinstance(item, Mapping):
                    if depth > limit:
                        return _joined(link)
                    child = (True, iter(item.items()), depth, link)
                    break
                if isinstance(item, (list, tuple)):
                    child = (False, iter(item), depth, link)
                    break
        if child is None:
            frames.pop()
        else:
            frames.append(child)
    return None


def _joined(link: tuple | None) -> str:
    """The dotted field path a (parent, key) link chain names."""
    keys: list[str] = []
    while link is not None:
        link, key = link
        keys.append(key)
    return ".".join(reversed(keys))


def _refuse_too_deep(client: OpenSearch, actions: list[dict]) -> tuple[list[dict], int]:
    """`actions` without the records their index would reject for depth,
    and how many were refused."""
    limits: dict[str, int | None] = {}
    kept: list[dict] = []
    refused: list[tuple[dict, str, int]] = []
    for action in actions:
        index = action.get("_index", "")
        if index not in limits:
            limits[index] = _index_depth_limit(client, index)
        limit = limits[index]
        source = action.get("_source")
        path = (
            _too_deep(source, limit) if limit is not None and isinstance(source, Mapping) else None
        )
        if path is None:
            kept.append(action)
        else:
            refused.append((action, path, limit))
    if refused:
        action, path, limit = refused[0]
        shown = path if len(path) <= 200 else f"{path[:200]}…"
        # Cause first: status readers clip the reason, and a field path can
        # be long.
        reason = (
            f"refused before sending: nests deeper than {_DEPTH_SETTING} [{limit}] "
            f"— record {action.get('_id', '?')} field [{shown}]"
        )
        print(f"WARNING: {len(refused)}/{len(actions)} docs {reason}", file=sys.stderr)
        _tls.last_bulk_reason = reason[:500]
    return kept, len(refused)


def _flush_with_retry(client: OpenSearch, actions: list[dict], attempt: int) -> tuple[int, int]:
    """Recursive retry with backoff and batch splitting."""
    if not actions:
        return 0, 0

    try:
        success, errors = helpers.bulk(
            client,
            actions,
            max_retries=2,
            raise_on_error=False,
            request_timeout=60,
        )
        failed = len(actions) - success

        # Circuit breaker: detect systemic (cluster-wide) failures and
        # halt ingest if they persist across multiple batches. State is
        # thread-local (Rev 6) so concurrent in-process tools don't
        # cross-halt each other.
        is_sys, sys_reason = _is_systemic_failure(
            success, len(actions), errors if isinstance(errors, list) else None
        )
        if is_sys:
            _set_counter(_get_counter() + 1)
            if _get_counter() >= _CIRCUIT_BREAKER_THRESHOLD:
                raise ShardCapacityExhausted(
                    f"Halting ingest: {_get_counter()} "
                    f"consecutive batches fully rejected. Last reason: "
                    f"{sys_reason[:200]}. Likely cause: cluster shard "
                    f"limit or cluster block. Raise "
                    f"cluster.max_shards_per_node or archive old cases."
                )
        else:
            _set_counter(0)  # reset on partial success

        if failed:
            # Extract first error reason to help diagnose mapping
            # conflicts. Written to stderr AND stored in thread-local
            # state so ingest-status writers can surface it via
            # get_last_bulk_reason() — operators see the cause in the
            # status file, not only in the log.
            reason = ""
            if isinstance(errors, list) and errors:
                first = errors[0]
                if isinstance(first, dict):
                    for action_type in ("index", "create", "update"):
                        info = first.get(action_type, {})
                        if info.get("error"):
                            err = info["error"]
                            reason = (
                                err.get("reason", str(err)) if isinstance(err, dict) else str(err)
                            )
                            break
            msg = f"WARNING: {failed}/{len(actions)} docs failed in bulk batch"
            if reason:
                msg += f" — {reason[:200]}"
                # Preserve the first reason across the ingest run —
                # later batches without failures shouldn't clobber it
                # with "". Only overwrite when this batch has its own
                # non-empty reason.
                _tls.last_bulk_reason = reason[:500]
            print(msg, file=sys.stderr)
        return success, failed

    except (ConnectionTimeout, OSConnectionError) as e:
        if attempt >= _MAX_RETRIES:
            index = actions[0].get("_index", "") if actions else ""
            print(
                f"\n*** DATA LOSS: {len(actions)} events not indexed after "
                f"{_MAX_RETRIES} retries (timeout) — {index} ***\n"
                f"  Recovery: re-run ingest on the same evidence (dedup is safe)\n",
                file=sys.stderr,
            )
            _tls.last_bulk_reason = f"{TRANSPORT_REASON_PREFIX}{type(e).__name__}: {e}"[:500]
            return 0, len(actions)

        # If batch is large enough, split and retry smaller chunks
        if len(actions) > 200 and 3 <= attempt <= 5:  # cap split depth
            mid = len(actions) // 2
            print(
                f"WARNING: Bulk timeout (attempt {attempt + 1}), "
                f"splitting batch {len(actions)} -> 2x{mid}",
                file=sys.stderr,
            )
            s1, f1 = _flush_with_retry(client, actions[:mid], attempt + 1)
            s2, f2 = _flush_with_retry(client, actions[mid:], attempt + 1)
            return s1 + s2, f1 + f2

        wait = min(_INITIAL_BACKOFF * (2**attempt), _MAX_BACKOFF)
        print(
            f"WARNING: Bulk timeout (attempt {attempt + 1}/{_MAX_RETRIES}), "
            f"retrying {len(actions)} docs in {wait}s...",
            file=sys.stderr,
        )
        time.sleep(wait)
        return _flush_with_retry(client, actions, attempt + 1)

    except TransportError as e:
        if attempt >= _MAX_RETRIES:
            index = actions[0].get("_index", "") if actions else ""
            print(
                f"\n*** DATA LOSS: {len(actions)} events not indexed after "
                f"{_MAX_RETRIES} retries ({e}) — {index} ***\n"
                f"  Recovery: re-run ingest on the same evidence (dedup is safe)\n",
                file=sys.stderr,
            )
            _tls.last_bulk_reason = f"{TRANSPORT_REASON_PREFIX}{type(e).__name__}: {e}"[:500]
            return 0, len(actions)

        wait = min(_INITIAL_BACKOFF * (2**attempt), _MAX_BACKOFF)
        print(
            f"WARNING: Bulk error ({e}), retrying in {wait}s...",
            file=sys.stderr,
        )
        time.sleep(wait)
        return _flush_with_retry(client, actions, attempt + 1)
