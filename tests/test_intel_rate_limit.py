"""Tests for Fix F — intel enrichment rate-limit backoff."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opensearch_mcp.threat_intel import (
    _is_rate_limit,
    _is_valid_domain,
    _is_valid_hash,
    _parse_wait_hint,
    extract_unique_iocs,
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

    # -------------------------------------------------------------------
    # B79 follow-on (2026-04-23): cascade resilience at batch_lookup
    # level. Existing tests above prove 3 rate-limit retries eventually
    # succeed; these prove retry *exhaustion* for one IOC (and an
    # unhandled exception from a lower layer) do NOT take the loop
    # down. Original B78 failure: opensearch-mcp stopped when the
    # gateway cancelled its synchronous call after repeated rate
    # limits — async worker + per-IOC isolation + breaker-reset-on-
    # rate-limit together close that path. Worker-level coverage
    # lives below in TestEnrichWorkerResilience.
    # -------------------------------------------------------------------

    def test_rate_limit_exhaustion_skips_ioc_and_continues(self, _patched):
        """When retries exhaust for one IOC, record rate_limit_exhausted
        and continue to the next IOC — do NOT propagate or trip the
        non-rate-limit breaker."""
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        # Low retry cap keeps the test fast; real default is 5.
        monkeypatch.setenv("VHIR_INTEL_RATE_LIMIT_RETRIES", "3")

        def fake_call_tool(tool, params, timeout=15):
            if params.get("ioc") == "exhaust.me":
                return {"error": "RateLimitError", "message": "Rate limit exceeded. Wait 1s"}
            return {"found": True, "confidence": 75}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)

        iocs = {"ip": ["exhaust.me", "ok1.example", "ok2.example"]}
        results = threat_intel.batch_lookup(iocs)

        cov = results["_intel_coverage"]
        assert cov["skipped"].get("exhaust.me") == "rate_limit_exhausted"
        assert "ok1.example" in cov["enriched"]
        assert "ok2.example" in cov["enriched"]
        # Rate-limit exhaustion is transient — must NOT trip the
        # non-rate-limit circuit breaker. If it did, ok1/ok2 would be
        # marked circuit_breaker_halt instead of enriched.
        halt_markers = [v for v in cov["skipped"].values() if v == "circuit_breaker_halt"]
        assert halt_markers == []

    def test_cascade_of_rate_limit_exhaustions_does_not_trip_breaker(self, _patched):
        """B78 worst case: 10+ consecutive IOCs all exhaust their retries.
        Per the `consecutive_failures = 0` reset on rate-limit (implicit
        via the `continue` path in threat_intel.py:326-328 — the
        non-rate-limit branch at :330-339 is the only one that
        increments), the non-rate-limit breaker must stay at 0. If a
        regression ever started counting rate-limit exhaustions toward
        the breaker, the entire enrichment would halt after N IOCs
        rather than skip each individually."""
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        monkeypatch.setenv("VHIR_INTEL_RATE_LIMIT_RETRIES", "2")
        monkeypatch.setenv("VHIR_INTEL_BREAKER_THRESHOLD", "3")

        def fake_call_tool(tool, params, timeout=15):
            # Every IOC rate-limited, retries exhausted. Message must
            # contain "rate limit" (or "too many requests") for
            # _is_rate_limit to match — otherwise the error branch at
            # threat_intel.py:330-339 runs and trips the breaker.
            return {"error": "RateLimitError", "message": "Rate limit exceeded. Wait 1s"}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)

        # 12 IOCs — 4× the breaker threshold. If rate-limit exhaustion
        # counted toward the breaker, we'd see circuit_breaker_halt
        # markers; it must not.
        iocs = {"ip": [f"ip-{i}.example" for i in range(12)]}
        results = threat_intel.batch_lookup(iocs)

        cov = results["_intel_coverage"]
        skipped = cov["skipped"]
        # All 12 should be rate_limit_exhausted — none breaker-halted.
        assert len(skipped) == 12
        assert all(v == "rate_limit_exhausted" for v in skipped.values())
        assert cov["enriched"] == []

    def test_call_tool_exception_isolated_per_ioc(self, _patched):
        """The original B78 symptom was the backend crashing after
        ~10 calls — not a clean rate-limit skip but an unhandled
        exception escaping call_tool. Per-IOC try/except at
        threat_intel.py:305-313 must contain any exception and mark
        the IOC skipped with the `exception:` prefix."""
        from opensearch_mcp import threat_intel

        monkeypatch, _ = _patched
        call_count = {"n": 0}

        def fake_call_tool(tool, params, timeout=15):
            call_count["n"] += 1
            if call_count["n"] == 2:
                # Mimic gateway disconnect / subprocess transport failure.
                raise ConnectionError("gateway dropped connection mid-call")
            return {"found": False}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", fake_call_tool)

        iocs = {"ip": ["a.example", "b.example", "c.example"]}
        # Critical: no exception escapes. If this line raises, the test
        # fails in the way B78 originally did in production.
        results = threat_intel.batch_lookup(iocs)

        cov = results["_intel_coverage"]
        assert "b.example" in cov["skipped"]
        assert cov["skipped"]["b.example"].startswith("exception:")
        assert "gateway dropped connection" in cov["skipped"]["b.example"]
        # Surrounding IOCs processed normally.
        assert "a.example" in cov["enriched"]
        assert "c.example" in cov["enriched"]


# ---------------------------------------------------------------------------
# CR follow-ons (B79 v0.6.x patch) — worker-level resilience coverage for
# idx_enrich_intel's async path. The batch_lookup-level tests above prove
# per-IOC isolation survives rate-limit cascades; these exercise the
# cmd_enrich_intel worker on top of that, confirming:
#   1. A rate-limit storm does NOT crash the worker — terminal "complete"
#      still written via the intel status path.
#   2. The intel fast-exit race is covered by the same monotonic guard
#      that protects ingest, using artifact_name="intel" routing.
# ---------------------------------------------------------------------------


class TestEnrichWorkerResilience:
    """B79 follow-ons: cmd_enrich_intel worker-level regression coverage."""

    def test_rate_limit_storm_does_not_crash_worker(self, monkeypatch, tmp_path):
        """Every lookup returns RATE_LIMITED for several attempts, then
        succeeds. cmd_enrich_intel must complete normally (no raise, no
        unhandled exception, worker would write terminal 'complete') —
        the original bug mode where opensearch-mcp toppled during an
        intel cascade must not recur at the worker layer."""
        import argparse

        from opensearch_mcp import ingest_cli, threat_intel

        # Nail down the environment: no pacing, no real sleeps, no
        # gateway call-outs. Coverage path to tmp so no host dir writes.
        monkeypatch.setattr("opensearch_mcp.gateway.gateway_available", lambda: True)
        monkeypatch.setattr(threat_intel.time, "sleep", lambda s: None)
        monkeypatch.setattr(threat_intel, "_min_interval_sec", lambda: 0.0)
        monkeypatch.setattr(
            threat_intel,
            "_coverage_path_for_run",
            lambda run_id: tmp_path / f"coverage-{run_id}.json",
        )

        # Rate-limit on the first 2 attempts per IOC, then success.
        attempt_counters: dict[str, int] = {}

        def rate_limit_then_success(tool, params, timeout=15):
            ioc = params.get("ioc", "")
            attempt_counters[ioc] = attempt_counters.get(ioc, 0) + 1
            if attempt_counters[ioc] <= 2:
                return {"error": "RateLimitError", "message": "Rate limit exceeded. Wait 0s."}
            return {"found": True, "confidence": 90}

        monkeypatch.setattr("opensearch_mcp.gateway.call_tool", rate_limit_then_success)

        # Stub OpenSearch-side helpers so the worker only exercises the
        # rate-limit retry path (which is the regression target).
        monkeypatch.setattr(
            threat_intel,
            "extract_unique_iocs",
            lambda client, pattern, force=False: {
                "ip": {"1.2.3.4", "5.6.7.8"},
                "hash": set(),
                "domain": set(),
            },
        )
        monkeypatch.setattr(threat_intel, "stamp_documents", lambda *a, **kw: 2)

        # Minimal plumbing so cmd_enrich_intel can run without a real
        # OpenSearch connection or case system.
        monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: "TEST-CASE")
        monkeypatch.setattr(ingest_cli, "get_client", lambda: object())

        args = argparse.Namespace(case="TEST-CASE", force=False, dry_run=False)
        # Without VHIR_INGEST_RUN_ID set, the _write_bg_status path
        # short-circuits (no-op). That's fine for this test — we only
        # need to prove the worker doesn't raise during a rate-limit
        # cascade.
        ingest_cli.cmd_enrich_intel(args)  # must NOT raise

        # Every IOC should have been retried past the rate-limit wall.
        assert attempt_counters["1.2.3.4"] >= 3
        assert attempt_counters["5.6.7.8"] >= 3

    # Note: the intel fast-exit race (terminal complete/failed
    # survives a later running/starting write) is covered more
    # comprehensively in tests/test_ingest_status.py::TestWriteStatus
    # ("test_monotonic_intel_*") since those tests sit next to the
    # sibling monotonic tests and exercise all three regress paths
    # (running→complete, running→failed, starting→complete).


# ---------------------------------------------------------------------------
# IOC extractor structural validation (UAT 2026-04-23 follow-up to
# rate-limit raise). The original B78 runtime observation was that
# extractor shipped non-hash text fragments to OpenCTI as
# ioc_type=hash, OpenCTI fuzzy-matched them against label substrings,
# and ~845K docs got stamped SUSPICIOUS + 8 MALICIOUS with real-looking
# labels (malware-bazaar, rat, loader). Validators must reject any
# value that doesn't parse as its claimed type BEFORE it leaves the
# extractor — without this, raising the rate limit just makes the
# garbage pipeline faster. Fast + noisy is worse than slow + noisy.
# ---------------------------------------------------------------------------


class TestIsValidHash:
    """Accept every STIX file-hash type OpenCTI's stix_cyber_observable
    schema recognises. Reject anything else — length mismatch, non-hex,
    text fragments, empty, None."""

    # Accept: hex hashes at every recognised cryptographic length.
    @pytest.mark.parametrize(
        "length,example",
        [
            (32, "d41d8cd98f00b204e9800998ecf8427e"),  # MD5 of empty string
            (40, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),  # SHA-1 of empty
            (56, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),  # SHA-224
            (64, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),  # SHA-256
            (
                96,
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),  # noqa: E501 SHA-384  # noqa: E501
            (
                128,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),  # noqa: E501 SHA-512  # noqa: E501
        ],
    )
    def test_accepts_all_stix_hex_lengths(self, length, example):
        assert len(example) == length  # sanity
        assert _is_valid_hash(example) is True

    def test_accepts_tlsh(self):
        # T1 prefix + 70 hex = 72 total chars
        assert _is_valid_hash("T1" + "a" * 70) is True
        assert _is_valid_hash("T2" + "F" * 70) is True

    def test_accepts_telfhash(self):
        # 70 lowercase alphanumeric
        assert _is_valid_hash("a" * 70) is True
        assert _is_valid_hash("abc123" + "z" * 64) is True

    def test_accepts_ssdeep(self):
        assert (
            _is_valid_hash(
                "24576:Sh1lHDmFAFg4zIQ7nkCqWXB1cxh5mNNjsh3iOmHWVg+M/GknT3:SPFn4ISqWRAMsh3c2Vg+M/GUT3"
            )
            is True
        )  # noqa: E501
        assert _is_valid_hash("3:aaX:aX") is True  # trivial SSDEEP

    # Reject: the exact bug repro from the B79 runtime observation.
    def test_rejects_text_fragment_from_amcache_field(self):
        """The exact false-positive input from UAT 2026-04-23: an
        amcache text fragment wrongly mapped to a hash field. Pre-fix
        code shipped this to OpenCTI, which fuzzy-matched and stamped
        MALICIOUS. Post-fix: rejected before it leaves the extractor."""
        garbage = "astloggedonuser:[(-1,1)]deviceusers:[(-1,"
        assert _is_valid_hash(garbage) is False

    @pytest.mark.parametrize(
        "bad",
        [
            "",  # empty
            "a" * 33,  # off-by-one: 33 chars, not a valid length
            "a" * 63,  # off-by-one: 63 chars
            "g" * 32,  # 32 chars, NOT hex (g is not 0-9a-f)
            "   d41d8cd98f00b204e9800998ecf8427e",  # whitespace
            "d41d8cd98f00b204e9800998ecf8427e ",  # trailing space
            "d41d8cd9-8f00-b204-e980-0998ecf8427e",  # dashes
            "http://example.com/hash/abc",  # URL-shaped
            "a" * 71,  # 71 chars is not a valid length
            "Z1" + "a" * 70,  # TLSH prefix wrong (Z not T)
            "T1" + "g" * 70,  # TLSH bad-hex (g)
            "A" * 70,  # TELFHASH uppercase (rejected — it's lowercase-only)  # noqa: E501
        ],
    )
    def test_rejects_invalid_shapes(self, bad):
        assert _is_valid_hash(bad) is False


class TestIsValidDomain:
    """RFC 1035 labels, ≥2 labels (reject NetBIOS single-label), reject
    whitespace / control chars / path separators / IP literals."""

    @pytest.mark.parametrize(
        "domain",
        [
            "example.com",
            "sub.example.com",
            "deeply.nested.subdomain.example.co.uk",
            "_dmarc.example.com",  # underscores OK in non-TLD labels (DMARC/DKIM)
            "mail.google.com",
            "a.co",  # minimal valid TLD
        ],
    )
    def test_accepts_real_domains(self, domain):
        assert _is_valid_domain(domain) is True

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "hostname",  # single label — NetBIOS, not a DNS observable
            "1.2.3.4",  # IPv4 literal — belongs on ip path
            "::1",  # IPv6 literal
            "example.com/path",  # path separator
            "example.com\\foo",  # backslash
            "example com",  # whitespace
            "example.com\x00",  # control char (null)
            "example.1",  # numeric TLD
            "example.",  # trailing dot (creates empty label)
            ".example.com",  # leading dot
            "-example.com",  # label starting with dash
            "example-.com",  # label ending with dash
            "a" * 254,  # total length >253
            "astloggedonuser:[(-1,1)]",  # B79 garbage fragment
        ],
    )
    def test_rejects_invalid_shapes(self, bad):
        assert _is_valid_domain(bad) is False


class TestExtractorRejectsGarbageAndSurfacesFieldAttribution:
    """End-to-end extractor test: given a mock client that returns a
    mix of valid + garbage aggregation buckets, the extractor must
    drop the garbage, keep the valid, AND surface per-field rejection
    counts to stderr so operators can tune the field list.

    This is the regression test that would fail on pre-fix code — the
    `astloggedonuser:[(-1,1)]` sample used here is the exact
    observation from the UAT run that drove 845K false-positive
    SUSPICIOUS stamps."""

    def _mock_client(self, buckets_by_field: dict[str, list[str]]) -> MagicMock:
        """Build a MagicMock OpenSearch client whose `search()` returns
        a different agg-values bucket list based on the `field` aggs
        key in the query body. The extractor's agg key is `values`
        (see threat_intel.py:329)."""
        client = MagicMock()

        def _search(*, index, body, **kwargs):
            field = body["aggs"]["values"]["terms"]["field"]
            vals = buckets_by_field.get(field, [])
            return {
                "aggregations": {
                    "values": {
                        "sum_other_doc_count": 0,
                        "buckets": [{"key": v, "doc_count": 1} for v in vals],
                    }
                }
            }

        client.search.side_effect = _search
        return client

    def test_garbage_hash_fragment_rejected(self, capsys):
        """The canonical bug input: `astloggedonuser:[(-1,1)]...` was
        surfacing as ioc_type=hash on pre-fix code. Post-fix: dropped,
        counted, attributed to source field."""
        # Put the garbage on a hash-typed field so the hash validator runs.
        # Pair with a VALID hash on the same field so we prove positive
        # extraction still works.
        from opensearch_mcp.threat_intel import _HASH_FIELDS

        first_hash_field = next(iter(_HASH_FIELDS))
        buckets = {
            first_hash_field: [
                "d41d8cd98f00b204e9800998ecf8427e",  # valid MD5
                "astloggedonuser:[(-1,1)]deviceusers:[(-1,",  # garbage
                "T1" + "a" * 70,  # valid TLSH
                "not a hash at all",  # garbage
            ],
        }
        client = self._mock_client(buckets)
        iocs = extract_unique_iocs(client, "case-test-*")

        # Valid hashes kept.
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hash"]
        assert "T1" + "a" * 70 in iocs["hash"]
        # Garbage dropped.
        assert "astloggedonuser:[(-1,1)]deviceusers:[(-1," not in iocs["hash"]
        assert "not a hash at all" not in iocs["hash"]
        # And every ioc_type should NOT have leaked through as "hash".
        assert all("astloggedonuser" not in v for v in iocs["hash"] | iocs["ip"] | iocs["domain"])

        # Field attribution surfaced to stderr.
        captured = capsys.readouterr()
        assert "dropped 2 malformed values" in captured.err
        assert first_hash_field in captured.err

    def test_per_field_rejects_sorted_high_to_low(self, capsys):
        """When multiple fields produce garbage, the top offender must
        appear first in the stderr INFO output so operators can tune
        the noisiest field first."""
        from opensearch_mcp.threat_intel import _HASH_FIELDS

        fields = list(_HASH_FIELDS)[:2]
        buckets = {
            # Field 0: 3 garbage entries
            fields[0]: ["garbage1", "garbage2", "garbage3"],
            # Field 1: 1 garbage entry
            fields[1]: ["garbage_other"],
        }
        client = self._mock_client(buckets)
        extract_unique_iocs(client, "case-test-*")

        captured = capsys.readouterr().err
        # Field 0 has more rejects; it must appear before Field 1.
        idx0 = captured.find(fields[0])
        idx1 = captured.find(fields[1])
        assert idx0 != -1 and idx1 != -1
        assert idx0 < idx1, (
            f"top-offender field ({fields[0]}) must appear before "
            f"the lower-count field ({fields[1]}) in stderr output:\n{captured}"
        )
