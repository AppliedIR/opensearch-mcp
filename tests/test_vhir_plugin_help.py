"""The vhir ingest-memory help names the tier that runs by default."""

from __future__ import annotations

import argparse

from opensearch_mcp.vhir_plugin import register


def _tier():
    parser = argparse.ArgumentParser()
    register(parser.add_subparsers(), set())
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    (tier,) = [a for a in sub.choices["ingest-memory"]._actions if "--tier" in a.option_strings]
    return tier


def test_the_tier_help_names_the_default_the_option_has():
    tier = _tier()
    assert tier.default == 1
    assert "1=fast, the default" in tier.help
    assert "2=default" not in tier.help
