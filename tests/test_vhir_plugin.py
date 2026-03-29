"""Tests for vhir plugin registration."""

from __future__ import annotations

import argparse

from opensearch_mcp.vhir_plugin import register


class TestRegister:
    def test_registers_ingest_command(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        registered = set()
        register(subparsers, registered)
        assert "ingest" in registered

    def test_skips_if_already_registered(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        registered = {"ingest"}
        register(subparsers, registered)
        # Should not raise or add duplicate
        assert "ingest" in registered

    def test_ingest_parser_has_expected_args(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        registered = set()
        register(subparsers, registered)
        # Parse known args to verify they exist
        args = parser.parse_args(
            [
                "ingest",
                "/evidence",
                "--hostname",
                "HOST1",
                "--case",
                "INC001",
                "--password",
                "infected",
                "--reduced",
                "--full",
                "--vss",
                "--parallel",
                "8",
                "--yes",
            ]
        )
        assert args.path == "/evidence"
        assert args.hostname == "HOST1"
        assert args.case == "INC001"
        assert args.password == "infected"
        assert args.reduced is True
        assert args.full is True
        assert args.vss is True
        assert args.parallel == 8
        assert args.yes is True
