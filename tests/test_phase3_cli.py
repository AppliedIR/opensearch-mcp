"""Tests for Phase 3 CLI additions (config, --full, --reduced)."""

from __future__ import annotations

import argparse

from opensearch_mcp.ingest_cli import _load_config, _merge_config
from opensearch_mcp.tools import get_active_tools


class TestLoadConfig:
    def test_none_returns_empty(self):
        assert _load_config(None) == {}

    def test_valid_yaml(self, tmp_path):
        cfg = tmp_path / "ingest.yaml"
        cfg.write_text("include:\n  - evtx\n  - amcache\npassword: infected\n")
        result = _load_config(str(cfg))
        assert result["include"] == ["evtx", "amcache"]
        assert result["password"] == "infected"


class TestMergeConfig:
    def test_config_values_set_on_args(self):
        args = argparse.Namespace(
            include=None,
            exclude=None,
            time_from=None,
            time_to=None,
            reduced=False,
            password=None,
        )
        config = {
            "include": ["evtx", "amcache"],
            "exclude": ["mft"],
            "time_range": {"from": "2023-01-15", "to": "2023-01-20"},
            "evtx": {"reduced": True},
            "password": "infected",
        }
        _merge_config(args, config)
        assert args.include == "evtx,amcache"
        assert args.exclude == "mft"
        assert args.time_from == "2023-01-15"
        assert args.time_to == "2023-01-20"
        assert args.reduced is True
        assert args.password == "infected"

    def test_cli_takes_precedence(self):
        """CLI values override config file."""
        args = argparse.Namespace(
            include="evtx",
            exclude=None,
            time_from=None,
            time_to=None,
            reduced=True,
            password="secret",
        )
        config = {
            "include": ["amcache", "shimcache"],
            "password": "infected",
        }
        _merge_config(args, config)
        # CLI value should not be overwritten
        assert args.include == "evtx"
        assert args.password == "secret"

    def test_empty_config(self):
        args = argparse.Namespace(
            include=None,
            exclude=None,
            time_from=None,
            time_to=None,
            reduced=False,
            password=None,
        )
        _merge_config(args, {})
        assert args.include is None


class TestGetActiveToolsFull:
    def test_full_includes_all_tiers(self):
        tools = get_active_tools(full=True)
        names = {t.cli_name for t in tools}
        assert "mft" in names
        assert "usn" in names
        assert "timeline" in names
        assert "amcache" in names

    def test_full_respects_exclude(self):
        tools = get_active_tools(full=True, exclude={"mft"})
        names = {t.cli_name for t in tools}
        assert "mft" not in names
        assert "usn" in names

    def test_default_excludes_tier3(self):
        tools = get_active_tools()
        names = {t.cli_name for t in tools}
        assert "mft" not in names
        assert "usn" not in names
        assert "amcache" in names
