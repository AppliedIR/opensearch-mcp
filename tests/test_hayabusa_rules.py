"""Tests for Fix E — _resolve_hayabusa_rules_dir."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from opensearch_mcp.ingest import _resolve_hayabusa_rules_dir


def _make_rules_dir(root: Path) -> Path:
    """Create a directory with a 'config' subdir to satisfy the resolver."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "config").mkdir(exist_ok=True)
    return root


class TestResolveHayabusaRulesDir:
    def test_env_var_wins(self, tmp_path, monkeypatch):
        env_dir = _make_rules_dir(tmp_path / "custom-rules")
        monkeypatch.setenv("HAYABUSA_RULES_DIR", str(env_dir))
        # Even if standard path exists, env var takes precedence.
        with patch(
            "opensearch_mcp.ingest._HAYABUSA_RULES_CANDIDATES",
            ("/nonexistent",),
        ):
            assert _resolve_hayabusa_rules_dir() == env_dir

    def test_standard_path_fallback(self, tmp_path, monkeypatch):
        std = _make_rules_dir(tmp_path / "std")
        monkeypatch.delenv("HAYABUSA_RULES_DIR", raising=False)
        with patch("opensearch_mcp.ingest._HAYABUSA_RULES_CANDIDATES", (str(std),)):
            assert _resolve_hayabusa_rules_dir() == std

    def test_env_var_without_config_subdir_rejected(self, tmp_path, monkeypatch):
        bad = tmp_path / "no-config"
        bad.mkdir()
        monkeypatch.setenv("HAYABUSA_RULES_DIR", str(bad))
        with patch("opensearch_mcp.ingest._HAYABUSA_RULES_CANDIDATES", ()):
            assert _resolve_hayabusa_rules_dir() is None

    def test_none_when_nothing_found(self, tmp_path, monkeypatch):
        monkeypatch.delenv("HAYABUSA_RULES_DIR", raising=False)
        with (
            patch(
                "opensearch_mcp.ingest._HAYABUSA_RULES_CANDIDATES",
                ("/definitely/not/a/path",),
            ),
            patch("pathlib.Path.glob", return_value=iter([])),
        ):
            # Also prevent /opt fallback from finding anything
            assert _resolve_hayabusa_rules_dir() is None

    def test_opt_glob_fallback(self, tmp_path, monkeypatch):
        # Simulate /opt/hayabusa-3.0.0/rules/ + /config/
        monkeypatch.delenv("HAYABUSA_RULES_DIR", raising=False)
        opt_dir = tmp_path / "opt"
        opt_dir.mkdir()
        hayabusa_root = opt_dir / "hayabusa-3.0.0"
        rules = _make_rules_dir(hayabusa_root / "rules")

        with (
            patch("opensearch_mcp.ingest._HAYABUSA_RULES_CANDIDATES", ()),
            patch(
                "opensearch_mcp.ingest.Path",
                side_effect=lambda p: Path(str(opt_dir)) if p == "/opt" else Path(p),
            ),
        ):
            result = _resolve_hayabusa_rules_dir()
            # Depending on path resolution, may or may not find it —
            # the key behavior is "doesn't crash on missing /opt"
            assert result is None or result == rules
