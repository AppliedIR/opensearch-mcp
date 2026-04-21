"""Shard capacity pre-flight check and budget estimation.

Prevents silent data loss when OpenSearch cluster reaches
max_shards_per_node ceiling. Called before ingest starts — if
capacity is exhausted, refuse with an actionable error instead of
launching into hundreds of silently-rejecting bulk writes.
"""

from __future__ import annotations

import logging
from typing import Any

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


def _resolve_setting(settings: dict[str, Any], key: str, default: Any = None) -> Any:
    """Resolve a cluster setting from transient/persistent/defaults.

    Precedence: transient > persistent > defaults > default.
    Handles both nested form (dotted key split into path) and flat
    form (dotted key as single string). Called with flat_settings=False
    by default since that form works with filter_path; the flat form
    is retained for backwards compatibility if the caller ever changes.
    """
    for tier in ("transient", "persistent", "defaults"):
        tier_dict = settings.get(tier) or {}
        # Flat form first: "cluster.max_shards_per_node" as one key.
        if key in tier_dict:
            return tier_dict[key]
        # Nested form: navigate tier_dict["cluster"]["max_shards_per_node"].
        nested = tier_dict
        for part in key.split("."):
            if not isinstance(nested, dict):
                nested = None
                break
            nested = nested.get(part)
        if nested not in (None, {}):
            return nested
    return default


def check_shard_headroom(
    client: OpenSearch,
    expected_new_shards: int = 1,
    min_headroom_pct: float = 10.0,
) -> tuple[bool, str]:
    """Return (ok, reason). False means abort ingest with reason.

    Budget model: OpenSearch enforces max_shards_per_node per node.
    Effective cluster-wide budget = max_per_node × num_data_nodes.
    Using the cluster-wide product is conservative when shard
    distribution is balanced; exact on single-node clusters.
    """
    try:
        stats = client.cluster.stats(
            filter_path=["indices.shards.total", "nodes.count.data"],
            request_timeout=10,
        )
        # NOTE: flat_settings=True + filter_path with dotted key-paths
        # is incompatible: in flat mode, keys are single dotted strings
        # ("cluster.max_shards_per_node" as one key), and filter_path
        # treats dots as path separators, so it navigates to a
        # non-existent "cluster" sub-object and returns {}. Drop
        # flat_settings so filter_path works on nested structure;
        # _resolve_setting handles nested form.
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
        # Fail open on transient stats hiccups — better than blocking
        # legitimate operations.
        return True, f"shard-headroom check unavailable: {e}"

    current_shards = (stats.get("indices") or {}).get("shards", {}).get("total")
    num_data_nodes = (stats.get("nodes") or {}).get("count", {}).get("data")

    # Explicit fail-open on malformed stats response — a trivial
    # .get() chain returning 0/None passes headroom trivially, which
    # would silently re-introduce the bug this fix is preventing.
    if current_shards is None or num_data_nodes is None or num_data_nodes < 1:
        return True, (
            "shard-headroom check skipped — cluster.stats response "
            f"missing indices.shards.total or nodes.count.data "
            f"(got current={current_shards!r}, nodes={num_data_nodes!r})"
        )

    max_per_node = _resolve_setting(settings, "cluster.max_shards_per_node", default=1000)
    try:
        max_per_node = int(max_per_node)
    except (TypeError, ValueError):
        max_per_node = 1000
    max_total = max_per_node * int(num_data_nodes)

    available = max_total - int(current_shards)
    headroom_pct = (available / max_total) * 100 if max_total else 0.0

    if available < expected_new_shards:
        return False, (
            f"Shard capacity exhausted: {current_shards}/{max_total} "
            f"shards used across {num_data_nodes} data node(s) "
            f"(max_shards_per_node={max_per_node}). "
            f"Cannot create {expected_new_shards} new shard(s). "
            f"Raise cluster.max_shards_per_node or archive old cases "
            f"before retrying."
        )
    if headroom_pct < min_headroom_pct:
        return False, (
            f"Shard capacity near limit: {current_shards}/{max_total} "
            f"shards used ({headroom_pct:.1f}% headroom, need "
            f"{min_headroom_pct}%). Raise cluster.max_shards_per_node "
            f"or archive old cases before retrying."
        )
    return True, ""


def _estimate_new_shards(ingest_type: str, host_count: int = 1) -> int:
    """Rough upper bound on shards created for a new ingest.

    Used for pre-flight headroom check. Errs high. Actual shard
    creation depends on index templates and whether the host's index
    already exists — this is a budget check, not an allocation
    reservation.

    Post-2026-04-22: all 15 Valhuntir templates declare
    index.number_of_replicas: 0, so per-index shard cost is 1 primary
    (no replica). Estimates halved from the pre-replicas-0 era — the
    prior 2 × host_count for evtx/generic assumed 1 primary + 1 replica
    and was refusing ingests operators could actually handle.
    """
    estimates = {
        "evtx": 1 * host_count,
        "memory": 5,
        "delimited": 1 * host_count,
        "json": 1 * host_count,
        "accesslog": 1 * host_count,
        "generic": 1 * host_count,
    }
    return estimates.get(ingest_type, estimates["generic"]) + 1
