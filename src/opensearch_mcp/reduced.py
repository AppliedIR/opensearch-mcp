"""Load the reduced Event ID set for --reduced mode."""

from __future__ import annotations

from pathlib import Path

import yaml

_YAML_PATH = Path(__file__).parent / "reduced_event_ids.yaml"
_cached: set[int] | None = None


def load_reduced_ids() -> set[int]:
    """Load and cache the set of high-value Event IDs."""
    global _cached
    if _cached is not None:
        return _cached
    data = yaml.safe_load(_YAML_PATH.read_text())
    ids: set[int] = set()
    for category_ids in data.values():
        if isinstance(category_ids, list):
            ids.update(int(i) for i in category_ids)
    _cached = ids
    return _cached
