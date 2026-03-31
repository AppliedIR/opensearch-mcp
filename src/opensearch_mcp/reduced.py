"""Load reduced Event ID and log file sets for filtering modes."""

from __future__ import annotations

from pathlib import Path

import yaml

_DATA_DIR = Path(__file__).parent

_cached_ids: set[int] | None = None
_cached_logs: set[str] | None = None


def load_reduced_ids() -> set[int]:
    """Load and cache the set of high-value Event IDs for --reduced-ids."""
    global _cached_ids
    if _cached_ids is not None:
        return _cached_ids
    data = yaml.safe_load((_DATA_DIR / "reduced_event_ids.yaml").read_text())
    ids: set[int] = set()
    for category_ids in data.values():
        if isinstance(category_ids, list):
            ids.update(int(i) for i in category_ids)
    _cached_ids = ids
    return _cached_ids


def load_reduced_logs() -> set[str]:
    """Load and cache forensic log filenames for --reduced-logs.

    Returns lowercase stems (no .evtx extension) for case-insensitive matching.
    """
    global _cached_logs
    if _cached_logs is not None:
        return _cached_logs
    data = yaml.safe_load((_DATA_DIR / "reduced_logs.yaml").read_text())
    names: set[str] = set()
    for category_names in data.values():
        if isinstance(category_names, list):
            for name in category_names:
                names.add(name.lower())
    _cached_logs = names
    return _cached_logs
