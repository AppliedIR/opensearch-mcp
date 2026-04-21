"""Tests for Fix F — intel enrichment rate-limit backoff."""

from __future__ import annotations

import pytest

from opensearch_mcp.threat_intel import (
    _is_rate_limit,
    _parse_wait_hint,
)


class TestParseWaitHint:
    # Rev 6: jitter is +0.5s (was +2s). Clamp to [0.5, 120].
    def test_standard_hint(self):
        assert _parse_wait_hint("Rate limit exceeded. Wait 18.2s.") == pytest.approx(18.7)

    def test_integer_hint(self):
        assert _parse_wait_hint("Wait 30s") == 30.5

    def test_case_insensitive(self):
        assert _parse_wait_hint("rate limit, wait 5s please") == 5.5

    def test_uppercase_ignorecase(self):
        # Rev 6: re.IGNORECASE — uppercase WAIT also matches.
        assert _parse_wait_hint("WAIT 7s") == 7.5

    def test_malformed_falls_back_to_default(self):
        assert _parse_wait_hint("Rate limit exceeded, no number") == 20.0

    def test_empty_string_default(self):
        assert _parse_wait_hint("") == 20.0

    def test_none_default(self):
        assert _parse_wait_hint(None) == 20.0

    def test_upper_bound(self):
        assert _parse_wait_hint("Wait 500s") == 120.0

    def test_lower_bound(self):
        # 0s hint → 0 + 0.5 = 0.5 (minimum floor).
        assert _parse_wait_hint("Wait 0s") == 0.5


class TestIsRateLimit:
    @pytest.mark.parametrize(
        "msg",
        [
            "Rate limit exceeded",
            "rate limit for query",
            "Too Many Requests",
            "too many requests received",
            "RATE LIMIT",
        ],
    )
    def test_detects_rate_limit(self, msg):
        assert _is_rate_limit(msg) is True

    @pytest.mark.parametrize(
        "msg",
        [
            "Internal server error",
            "QueryError: invalid ioc",
            "",
            "Connection refused",
        ],
    )
    def test_non_rate_limit(self, msg):
        assert _is_rate_limit(msg) is False


class TestEnrichmentRateLimitFlow:
    """Integration-style tests for the Rev 6 retry + pacing loop in
    threat_intel.batch_lookup. Shared fixture patches gateway + time +
    pacing + coverage-path.
    """

    @pytest.fixture
    def _patched(self, monkeypatch, tmp_path):
        from opensearch_mcp import threat_intel

        monkeypatch.setattr("opensearch_mcp.gateway.gateway_available", lambda: True)
        monkeypatch.setattr(threat_intel.time, "sleep", lambda s: None)
        monkeypatch.setattr(threat_intel, "_min_interval_sec", lambda: 0.0)
        monkeypatch.setattr(
            threat_intel,
            "_coverage_path_for_run",
            lambda run_id: tmp_path / f"coverage-{run_id}.json",
        )
        return monkeypatch, tmp_path

    def test_rate_limit_sleeps_and_retries_without_tripping(self, _patched):
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        call_count = {"n": 0}
        sleep_calls: list[float] = []

        def fake_call_tool(tool, params, timeout=15):
            call_count["n"] += 1
            if call_count["n"] <= 3:
                return {
                    "error": "RateLimitError",
                    "message": "Rate limit exceeded. Wait 1s.",
                }
            return {"found": True, "confidence": 85}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)
        monkeypatch.setattr(threat_intel.time, "sleep", lambda s: sleep_calls.append(s))

        iocs = {"ip": ["1.2.3.4"]}
        results = threat_intel.batch_lookup(iocs)

        assert len(sleep_calls) == 3
        assert "1.2.3.4" in results
        assert results["1.2.3.4"]["threat_intel.verdict"] == "MALICIOUS"

    def test_genuine_errors_trip_at_threshold(self, _patched):
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        monkeypatch.setenv("VHIR_INTEL_BREAKER_THRESHOLD", "3")

        def fake_call_tool(tool, params, timeout=15):
            return {"error": "QueryError", "message": "OpenCTI down"}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)

        iocs = {"ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]}
        results = threat_intel.batch_lookup(iocs)

        assert "_intel_coverage" in results
        assert "circuit_breaker_halt" in str(results["_intel_coverage"]["skipped"])

    def test_coverage_map_records_enriched_and_skipped(self, _patched):
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        monkeypatch.delenv("VHIR_INTEL_BREAKER_THRESHOLD", raising=False)

        call_seq = iter(
            [
                {"found": True, "confidence": 90},
                {"error": "QueryError", "message": "bad"},
                {"found": False},
            ]
        )

        def fake_call_tool(tool, params, timeout=15):
            return next(call_seq)

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)

        iocs = {"ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}
        results = threat_intel.batch_lookup(iocs)

        cov = results["_intel_coverage"]
        assert "1.1.1.1" in cov["enriched"]
        assert "3.3.3.3" in cov["enriched"]
        assert "2.2.2.2" in cov["skipped"]

    def test_env_configurable_thresholds(self, _patched):
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        monkeypatch.setenv("VHIR_INTEL_BREAKER_THRESHOLD", "2")

        def fake_call_tool(tool, params, timeout=15):
            return {"error": "QueryError", "message": "down"}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)

        iocs = {"ip": ["a", "b", "c", "d"]}
        results = threat_intel.batch_lookup(iocs)

        # With threshold=2, 3rd and 4th IOCs should be breaker-halted.
        skipped = results["_intel_coverage"]["skipped"]
        halt_count = sum(1 for r in skipped.values() if r == "circuit_breaker_halt")
        assert halt_count >= 1  # at least one got the breaker-halt marker
