"""Unit tests for parse_transcripts — registry-hive reads and timezone
resolution.

UAT 2026-04-23 BUG 1+3 regression coverage. Lives in its own file (not
test_all_parsers.py) because that module is gated on a local fixture
directory (`/tmp/opensearch-test-data`) and CI would skip everything in
it — these tests must actually run.

These tests pin the two contracts surfaced by the audit:

- `regipy.RegistryHive.get_key()` requires a leading backslash on every
  fully-qualified path. Without it, regipy 6.2.1 raises
  `RegistryKeyNotFoundException` even for paths that exist. Pre-fix,
  every call in `_read_transcript_config` dropped that exception
  silently via `except Exception: pass`, producing `(None, None)` on
  every host. Downstream: parse_transcripts + parse_defender both
  skipped every row on the "no timezone" branch → 0 docs across
  30 SRL hosts.

- Silent-swallow (`except Exception: pass`) is split by severity.
  Hive-open failures emit at `logger.warning` so they surface at
  default log level; key-not-found failures (policy absent, alternate
  ControlSet missing) stay at `logger.debug` because they're expected
  on most hosts and warning-spamming every stock Windows install would
  drown out real hive-level diagnostics.

All tests here build their own fixture (tmp_path + mocked regipy) and
do NOT depend on `/tmp/opensearch-test-data`.
"""

from __future__ import annotations

import logging
import sys
import types


def _make_volume(tmp_path):
    """Build the minimal volume layout `_read_transcript_config` probes."""
    cfg = tmp_path / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    # Content doesn't matter — we mock RegistryHive. We only need the
    # files to exist so `resolve_case_insensitive` finds their paths.
    (cfg / "SOFTWARE").write_bytes(b"regf-placeholder")
    (cfg / "SYSTEM").write_bytes(b"regf-placeholder")
    return tmp_path


def _fake_val(name, value):
    """Minimal stand-in for regipy's value object (exposes .name / .value)."""

    class _V:
        pass

    v = _V()
    v.name = name
    v.value = value
    return v


def _install_fake_regipy(monkeypatch, fake_hive_cls):
    """Register a synthetic `regipy.registry.RegistryHive` via sys.modules."""
    fake_regipy = types.ModuleType("regipy.registry")
    fake_regipy.RegistryHive = fake_hive_cls
    monkeypatch.setitem(sys.modules, "regipy", types.ModuleType("regipy"))
    monkeypatch.setitem(sys.modules, "regipy.registry", fake_regipy)


class TestReadTranscriptConfigRegipyPathFormat:
    def test_get_key_called_with_leading_backslash(self, tmp_path, monkeypatch):
        """BUG 1 pin: every path handed to regipy.get_key MUST start
        with a backslash. Without it regipy 6.2.1 raises
        RegistryKeyNotFoundException even for paths that exist in the
        hive."""
        from opensearch_mcp import parse_transcripts

        captured_paths: list[str] = []

        class FakeHive:
            def __init__(self, path):
                self._path = path

            def get_key(self, path):
                captured_paths.append(path)
                fake = type("FakeKey", (), {})()
                fake.iter_values = lambda: iter(
                    [_fake_val("TimeZoneKeyName", "Eastern Standard Time")]
                )
                return fake

        _install_fake_regipy(monkeypatch, FakeHive)

        volume = _make_volume(tmp_path)
        _gp, tz = parse_transcripts._read_transcript_config(volume)

        assert captured_paths, "get_key was never called — fixture setup broken"
        for p in captured_paths:
            assert p.startswith("\\"), f"regipy.get_key path must start with backslash; got {p!r}"
        # Sanity: the timezone the fake emitted round-trips.
        assert tz == "Eastern Standard Time"

    def test_standard_name_fallback(self, tmp_path, monkeypatch):
        """BUG 1 fix part 2: on older Windows installs without
        TimeZoneKeyName, fall back to StandardName."""
        from opensearch_mcp import parse_transcripts

        class FakeHive:
            def __init__(self, path):
                pass

            def get_key(self, path):
                if "TimeZoneInformation" not in path:
                    # Simulate "no Transcription policy" on the SOFTWARE
                    # hive so the test stays narrow.
                    raise RuntimeError("not found")
                fake = type("FakeKey", (), {})()
                # No TimeZoneKeyName — only StandardName present.
                fake.iter_values = lambda: iter(
                    [
                        _fake_val("StandardName", "Pacific Standard Time"),
                        _fake_val("Bias", 480),
                    ]
                )
                return fake

        _install_fake_regipy(monkeypatch, FakeHive)

        volume = _make_volume(tmp_path)
        _gp, tz = parse_transcripts._read_transcript_config(volume)
        assert tz == "Pacific Standard Time"

    def test_hive_open_failure_logs_at_warning_level(self, tmp_path, monkeypatch, caplog):
        """BUG 3 pin — hive-open split: when `RegistryHive(...)` itself
        raises (corrupt / missing / locked hive), this is a
        system-level diagnostic that operators must see at default log
        level. Pre-fix it was `except Exception: pass`. Post-fix it
        emits at `logger.warning` — NOT `logger.debug` — because this
        class of failure cascades to zero-docs-everywhere and the next
        silent-regression needs to be visible without flipping
        `--log-level DEBUG`."""
        from opensearch_mcp import parse_transcripts

        class FakeHive:
            def __init__(self, path):
                raise RuntimeError("corrupt hive (synthetic)")

        _install_fake_regipy(monkeypatch, FakeHive)

        volume = _make_volume(tmp_path)
        with caplog.at_level(logging.DEBUG, logger="opensearch_mcp.parse_transcripts"):
            gp, tz = parse_transcripts._read_transcript_config(volume)

        # Graceful failure: returns (None, None), no raise.
        assert (gp, tz) == (None, None)

        # The failure must land at WARNING (not DEBUG) so operators
        # see it at default log level. Both the SOFTWARE and SYSTEM
        # hive opens fail here; at least one WARNING-level record
        # must name the synthetic failure.
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings, (
            f"expected at least one WARNING-level record, got: "
            f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )
        assert any("corrupt hive (synthetic)" in r.getMessage() for r in warnings), (
            f"WARNING-level record must name the failure; got: "
            f"{[r.getMessage() for r in warnings]}"
        )

    def test_key_not_found_stays_at_debug_not_warning(self, tmp_path, monkeypatch, caplog):
        """Complementary pin to the previous test: key-not-found
        (policy not set, ControlSet variant absent) MUST stay at
        `logger.debug`. Most stock Windows hosts don't have PS
        Transcription GPO configured; warning-spamming every host
        would drown out real hive-open diagnostics. This test feeds a
        FakeHive where the constructor succeeds but every get_key
        call raises — asserts ZERO warning-level records, and at
        least one debug-level record per branch."""
        from opensearch_mcp import parse_transcripts

        class FakeHive:
            def __init__(self, path):
                # Constructor succeeds — hive is "openable".
                pass

            def get_key(self, path):
                # Every key lookup fails — Transcription policy absent,
                # both ControlSet variants absent.
                raise RuntimeError(f"key-not-found for {path}")

        _install_fake_regipy(monkeypatch, FakeHive)

        volume = _make_volume(tmp_path)
        with caplog.at_level(logging.DEBUG, logger="opensearch_mcp.parse_transcripts"):
            gp, tz = parse_transcripts._read_transcript_config(volume)

        # Graceful failure: returns (None, None) — no hive-level error.
        assert (gp, tz) == (None, None)

        # CRITICAL: zero warning records — this is the "most hosts"
        # path and must stay quiet at default log level.
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert not warnings, (
            f"key-not-found must NOT warn (would spam every stock host); "
            f"got: {[r.getMessage() for r in warnings]}"
        )

        # But debug records MUST exist — the diagnostic is still
        # captured, just at debug level.
        debug_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("key-not-found for" in m for m in debug_msgs), (
            f"expected debug records naming the failure; got: {debug_msgs}"
        )

    def test_missing_hives_returns_none_none(self, tmp_path):
        """Negative test: a volume root with no config hives returns
        (None, None) without raising. Does not touch regipy — short-
        circuits on `resolve_case_insensitive` returning None."""
        from opensearch_mcp import parse_transcripts

        # tmp_path has no Windows/System32/config subtree.
        assert parse_transcripts._read_transcript_config(tmp_path) == (None, None)

    def test_transcription_policy_extraction(self, tmp_path, monkeypatch):
        """BUG 1 side: the SOFTWARE-hive path
        (Policies\\Microsoft\\Windows\\PowerShell\\Transcription) also
        required the leading-backslash fix. Assert the
        OutputDirectory value is read correctly when the policy key is
        present with a backslash-prefixed path."""
        from opensearch_mcp import parse_transcripts

        captured_paths: list[str] = []

        class FakeHive:
            def __init__(self, path):
                self._path = path

            def get_key(self, path):
                captured_paths.append(path)
                fake = type("FakeKey", (), {})()
                if "Transcription" in path:
                    fake.iter_values = lambda: iter(
                        [
                            _fake_val("OutputDirectory", "C:\\Transcripts"),
                            _fake_val("EnableInvocationHeader", 1),
                        ]
                    )
                elif "TimeZoneInformation" in path:
                    fake.iter_values = lambda: iter([_fake_val("TimeZoneKeyName", "UTC")])
                else:
                    raise RuntimeError("unexpected path")
                return fake

        _install_fake_regipy(monkeypatch, FakeHive)

        volume = _make_volume(tmp_path)
        gp, tz = parse_transcripts._read_transcript_config(volume)

        assert gp == "C:\\Transcripts"
        assert tz == "UTC"
        # Transcription path must also carry the leading backslash.
        transcription_calls = [p for p in captured_paths if "Transcription" in p]
        assert transcription_calls
        for p in transcription_calls:
            assert p.startswith("\\"), (
                f"Transcription path must also carry leading backslash; got {p!r}"
            )
