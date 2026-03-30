"""Shared bulk indexing helper for evtx and CSV ingest."""

from __future__ import annotations

import sys
import time

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import ConnectionTimeout, TransportError

_INITIAL_BACKOFF = 10
_MAX_BACKOFF = 120
_MAX_RETRIES = 10


def flush_bulk(client: OpenSearch, actions: list[dict]) -> tuple[int, int]:
    """Bulk index actions with persistent retry on timeout.

    Returns (success_count, failed_count).
    Never gives up on a batch — retries with increasing backoff until
    OpenSearch accepts it or max retries exceeded. Under sustained
    pressure, splits the batch in half and retries smaller chunks.
    """
    return _flush_with_retry(client, actions, attempt=0)


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
        if failed:
            print(
                f"WARNING: {failed}/{len(actions)} docs failed in bulk batch",
                file=sys.stderr,
            )
        return success, failed

    except ConnectionTimeout:
        if attempt >= _MAX_RETRIES:
            index = actions[0].get("_index", "") if actions else ""
            print(
                f"\n*** DATA LOSS: {len(actions)} events not indexed after "
                f"{_MAX_RETRIES} retries (timeout) — {index} ***\n"
                f"  Recovery: re-run ingest on the same evidence (dedup is safe)\n",
                file=sys.stderr,
            )
            return 0, len(actions)

        # If batch is large enough, split and retry smaller chunks
        if len(actions) > 200 and attempt >= 3:
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
            return 0, len(actions)

        wait = min(_INITIAL_BACKOFF * (2**attempt), _MAX_BACKOFF)
        print(
            f"WARNING: Bulk error ({e}), retrying in {wait}s...",
            file=sys.stderr,
        )
        time.sleep(wait)
        return _flush_with_retry(client, actions, attempt + 1)
