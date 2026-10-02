"""Hayabusa's rules are found beside the binary its PATH entry links to.

SIFT installs hayabusa as ~/.local/bin/hayabusa, a link into its own install
directory, whose rules/ is at no fixed path; the resolver only knew fixed
paths and /opt/hayabusa*. The fixed candidates and the /opt globs are
patched out, so this box's own /opt/hayabusa/rules can't answer for them.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from opensearch_mcp.ingest import _resolve_hayabusa_rules_dir


def _install(root: Path, rules=True, config=True) -> Path:
    """A SIFT-like layout: bin/hayabusa -> assets/hayabusa/hb (+ rules/config)."""
    real = root / "assets" / "hayabusa"
    real.mkdir(parents=True)
    (real / "hb").write_text("#!/bin/sh\nexit 0\n")
    (real / "hb").chmod(0o755)
    if rules:
        (real / "rules").mkdir()
        if config:
            (real / "rules" / "config").mkdir()
    (root / "bin").mkdir()
    (root / "bin" / "hayabusa").symlink_to(real / "hb")
    return real / "rules"


@pytest.fixture
def resolve(monkeypatch, tmp_path):
    monkeypatch.delenv("HAYABUSA_RULES_DIR", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))

    def run(candidates=()):
        with (
            patch("opensearch_mcp.ingest._HAYABUSA_RULES_CANDIDATES", candidates),
            patch("pathlib.Path.glob", return_value=iter([])),
        ):
            return _resolve_hayabusa_rules_dir()

    return run


def test_rules_beside_the_linked_binary(resolve, tmp_path):
    rules = _install(tmp_path)
    assert resolve() == rules.resolve()


@pytest.mark.parametrize("rules,config", [(False, False), (True, False)])
def test_no_rules_or_no_config_beside_it(resolve, tmp_path, rules, config):
    _install(tmp_path, rules=rules, config=config)
    assert resolve() is None


def test_a_fixed_candidate_still_wins(resolve, tmp_path):
    _install(tmp_path)
    fixed = tmp_path / "share" / "hayabusa-rules"
    (fixed / "config").mkdir(parents=True)
    assert resolve(candidates=(str(fixed),)) == fixed
