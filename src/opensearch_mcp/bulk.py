"""Shared bulk indexing helper for evtx and CSV ingest."""

from __future__ import annotations

import sys
import time

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import ConnectionTimeout, TransportError

_BACKOFF_SECONDS = 10


def flush_bulk(client: OpenSearch, actions: list[dict]) -> tuple[int, int]:
    """Bulk index actions with timeout resilience.

    Returns (success_count, failed_count).
    Retries on ConnectionTimeout with exponential backoff.
    """
    for attempt in range(3):
        try:
            success, errors = helpers.bulk(
                client,
                actions,
                max_retries=3,
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
            if attempt < 2:
                wait = _BACKOFF_SECONDS * (attempt + 1)
                print(
                    f"WARNING: Bulk timeout (attempt {attempt + 1}/3), retrying in {wait}s...",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            print(
                f"WARNING: Bulk timeout after 3 attempts, {len(actions)} events lost",
                file=sys.stderr,
            )
            return 0, len(actions)
        except TransportError as e:
            print(
                f"WARNING: Bulk index failed ({e}), {len(actions)} events lost",
                file=sys.stderr,
            )
            return 0, len(actions)
    return 0, len(actions)
