"""Unit tests for parse_memory TIER lists + plugin-availability filter.

UAT 2026-04-23 BUG 4 regression coverage. Pins:

1. TIER_3 does NOT include `windows.registry.hashdump` (not in Vol3
   2.26.2's argparse choice list → errors on every invocation) or
   `windows.vadinfo` (compute-heavy, forensic value overlaps cheaper
   plugins). Both were removed based on live-UAT evidence.

2. `_filter_available_plugins` drops plugins absent from the installed
   Vol3 binary's plugin set and warns once about the skip. Empty
   `available` (Vol3 --help unparseable) falls through to preserve
   the input list unchanged.
"""

from __future__ import annotations

import logging


class TestTier3PluginList:
    def test_hashdump_removed_from_tier_3(self):
        """`windows.registry.hashdump` isn't in Vol3 2.26.2's argparse
        choice list; keeping it in TIER_3 produced per-plugin errors
        on every memory host. Pin removal."""
        from opensearch_mcp.parse_memory import TIER_3

        assert "windows.registry.hashdump" not in TIER_3

    def test_vadinfo_removed_from_tier_3(self):
        """`windows.vadinfo` compute-heavy (>60s on 5GB images, times
        out); forensic value overlaps malfind + dlllist + ldrmodules +
        handles already in the tier. Pin removal."""
        from opensearch_mcp.parse_memory import TIER_3

        assert "windows.vadinfo" not in TIER_3

    def test_tier_3_still_contains_retained_plugins(self):
        """Regression guard: the pair-removal must NOT have dropped
        anything else. Pin the remaining TIER_3 additions beyond
        TIER_2."""
        from opensearch_mcp.parse_memory import TIER_2, TIER_3

        tier_3_only = set(TIER_3) - set(TIER_2)
        assert "windows.handles" in tier_3_only
        assert "windows.filescan" in tier_3_only
        assert "windows.malfind" in tier_3_only
        assert "windows.shimcachemem" in tier_3_only
        assert "windows.driverscan" in tier_3_only
        assert "windows.mutantscan" in tier_3_only
        assert "timeliner" in tier_3_only

    def test_natural_keys_and_timestamp_map_in_sync_with_tier_3(self):
        """Both `_NATURAL_KEYS` and `_TIMESTAMP_FIELD` must not
        reference removed plugins — otherwise dead entries accumulate
        and future readers can't tell what's live."""
        from opensearch_mcp.parse_memory import _NATURAL_KEYS, _TIMESTAMP_FIELD

        assert "windows.registry.hashdump" not in _NATURAL_KEYS
        assert "windows.registry.hashdump" not in _TIMESTAMP_FIELD
        assert "windows.vadinfo" not in _TIMESTAMP_FIELD


class TestFilterAvailablePlugins:
    def test_drops_plugins_absent_from_available_set(self, caplog):
        """Primary contract: a TIER plugin not in the installed
        binary's plugin set must be dropped, with a warning naming
        the skip."""
        from opensearch_mcp.parse_memory import _filter_available_plugins

        requested = [
            "windows.pslist",
            "windows.registry.hashdump",  # not installed
            "windows.malfind",
        ]
        available = {"windows.pslist", "windows.malfind"}

        with caplog.at_level(logging.WARNING, logger="opensearch_mcp.parse_memory"):
            kept = _filter_available_plugins(requested, available)

        assert kept == ["windows.pslist", "windows.malfind"]
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("windows.registry.hashdump" in m for m in warning_msgs), (
            f"warning must name the skipped plugin; got: {warning_msgs}"
        )

    def test_empty_available_falls_through(self):
        """When Vol3 --help can't be parsed (`available` is empty),
        pass the input list through unchanged. Preserves existing
        behavior for test harnesses / unusual Vol3 builds."""
        from opensearch_mcp.parse_memory import _filter_available_plugins

        requested = ["windows.pslist", "windows.pstree", "windows.malfind"]
        assert _filter_available_plugins(requested, set()) == requested

    def test_all_available_passes_through_silently(self, caplog):
        """When every requested plugin is in `available`, no warning
        is emitted (avoids log-spam on every clean memory ingest)."""
        from opensearch_mcp.parse_memory import _filter_available_plugins

        requested = ["windows.pslist", "windows.malfind"]
        available = {"windows.pslist", "windows.malfind", "windows.netstat"}

        with caplog.at_level(logging.WARNING, logger="opensearch_mcp.parse_memory"):
            kept = _filter_available_plugins(requested, available)

        assert kept == requested
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert not warnings, (
            f"no warning expected when all plugins are available; got: "
            f"{[r.getMessage() for r in warnings]}"
        )

    def test_empty_input_returns_empty(self):
        """Edge case: empty requested list returns empty list."""
        from opensearch_mcp.parse_memory import _filter_available_plugins

        assert _filter_available_plugins([], {"windows.pslist"}) == []


class TestAvailableVol3Plugins:
    def test_parses_choose_from_block(self, monkeypatch):
        """`_available_vol3_plugins` must correctly parse the
        `(choose from X.Y.Class, A.B.Class, ...)` block from
        argparse-formatted Vol3 --help output."""
        from opensearch_mcp import parse_memory

        fake_help = (
            "usage: vol [-h] ...\n"
            "positional arguments:\n"
            "  PLUGIN    Which plugin to run\n"
            "            (choose from banners.Banners, windows.pslist.PsList, "
            "windows.malfind.Malfind, windows.registry.hivelist.HiveList)\n"
            "\n"
            "optional arguments:\n"
            "  -h, --help  show this help message and exit\n"
        )

        class FakeCompletedProcess:
            stdout = fake_help
            stderr = ""
            returncode = 0

        monkeypatch.setattr(parse_memory, "_find_vol3", lambda: "vol")
        monkeypatch.setattr(
            parse_memory.subprocess, "run", lambda *a, **kw: FakeCompletedProcess()
        )

        plugins = parse_memory._available_vol3_plugins()
        # Class suffix stripped (Malfind, PsList, HiveList, Banners).
        assert "windows.pslist" in plugins
        assert "windows.malfind" in plugins
        assert "windows.registry.hivelist" in plugins
        assert "banners" in plugins

    def test_returns_empty_on_unparseable_help(self, monkeypatch):
        """When Vol3 --help doesn't contain a `(choose from ...)`
        block, return empty set — caller falls through to pass-all
        semantics."""
        from opensearch_mcp import parse_memory

        class FakeCompletedProcess:
            stdout = "no choose-from block here\n"
            stderr = ""
            returncode = 0

        monkeypatch.setattr(parse_memory, "_find_vol3", lambda: "vol")
        monkeypatch.setattr(
            parse_memory.subprocess, "run", lambda *a, **kw: FakeCompletedProcess()
        )

        assert parse_memory._available_vol3_plugins() == set()

    def test_returns_empty_on_vol3_not_found(self, monkeypatch):
        """When `_find_vol3` raises (Vol3 not installed), return empty
        set — don't propagate the exception up through `ingest_memory`
        startup."""
        from opensearch_mcp import parse_memory

        def _raise(*_a, **_kw):
            raise RuntimeError("Volatility 3 not found")

        monkeypatch.setattr(parse_memory, "_find_vol3", _raise)

        assert parse_memory._available_vol3_plugins() == set()
