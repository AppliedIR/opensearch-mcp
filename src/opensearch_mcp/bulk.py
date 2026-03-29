"""Shared bulk indexing helper for evtx and CSV ingest."""

from __future__ import annotations

import sys

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import TransportError


def flush_bulk(client: OpenSearch, actions: list[dict]) -> tuple[int, int]:
    """Bulk index actions. Returns (success_count, failed_count)."""
    try:
        success, errors = helpers.bulk(client, actions, max_retries=3, raise_on_error=False)
        failed = len(actions) - success
        if failed:
            print(
                f"WARNING: {failed}/{len(actions)} docs failed in bulk batch",
                file=sys.stderr,
            )
        return success, failed
    except TransportError as e:
        print(
            f"WARNING: Bulk index failed ({e}), {len(actions)} events lost",
            file=sys.stderr,
        )
        return 0, len(actions)
