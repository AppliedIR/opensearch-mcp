"""Tests for shard capacity pre-flight, circuit breaker, and
idx_shard_status tool.

Covers:
- check_shard_headroom: ample / exhausted / low-headroom / stats-error
  fail-open / malformed-stats fail-open / multi-node budget / filter_path.
- _is_systemic_failure: scans all errors, pattern matrix.
- Circuit breaker: trips at threshold, resets on partial success,
  doesn't trip on mapping-conflict-only batches.
- _estimate_new_shards: per-type estimates.
- write_status: new bulk_failed / bulk_failed_reason fields.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import bulk as bulk_mod
from opensearch_mcp.bulk import (
    ShardCapacityExhausted,
    _is_systemic_failure,
    reset_circuit_breaker,
)
from opensearch_mcp.shard_capacity import (
    _estimate_new_shards,
    _resolve_setting,
    check_shard_headroom,
)

# --- check_shard_headroom ---


class TestCheckShardHeadroom:
    def _mock_client(self, shards=None, nodes=None, max_per_node=None):
        client = MagicMock()
        client.cluster.stats.return_value = {
            "indices": {"shards": {"total": shards}} if shards is not None else {},
            "nodes": {"count": {"data": nodes}} if nodes is not None else {},
        }
        settings = {"persistent": {}, "transient": {}, "defaults": {}}
        if max_per_node is not None:
            settings["persistent"]["cluster.max_shards_per_node"] = str(max_per_node)
        client.cluster.get_settings.return_value = settings
        return client

    def test_ample_capacity(self):
        client = self._mock_client(shards=100, nodes=1, max_per_node=10000)
        ok, reason = check_shard_headroom(client, expected_new_shards=5)
        assert ok is True
        assert reason == ""

    def test_exhausted(self):
        client = self._mock_client(shards=9999, nodes=1, max_per_node=10000)
        ok, reason = check_shard_headroom(client, expected_new_shards=5)
        assert ok is False
        assert "shard capacity exhausted" in reason.lower()
        assert "9999/10000" in reason

    def test_low_headroom_but_ample_slots(self):
        # 9500/10000 used — 500 slots free, but only 5% headroom with
        # default 10% min → refuse.
        client = self._mock_client(shards=9500, nodes=1, max_per_node=10000)
        ok, reason = check_shard_headroom(client, expected_new_shards=1, min_headroom_pct=10.0)
        assert ok is False
        assert "near limit" in reason.lower()
        assert "9500/10000" in reason

    def test_stats_query_raises_fail_open(self):
        client = MagicMock()
        client.cluster.stats.side_effect = RuntimeError("connection refused")
        ok, reason = check_shard_headroom(client)
        assert ok is True  # fail open
        assert "unavailable" in reason.lower()

    def test_malformed_stats_fail_open_explicit(self):
        # Missing indices.shards.total AND nodes.count.data — must
        # fail open with explicit "malformed" reason, NOT pass
        # trivially with 0/0 arithmetic.
        client = MagicMock()
        client.cluster.stats.return_value = {}
        client.cluster.get_settings.return_value = {}
        ok, reason = check_shard_headroom(client)
        assert ok is True
        assert "malformed" in reason.lower() or "missing" in reason.lower()

    def test_multi_node_budget(self):
        # 2 data nodes × 2000 per-node = 4000 effective budget.
        # 3000 used = 1000 free = 25% headroom → ok.
        client = self._mock_client(shards=3000, nodes=2, max_per_node=2000)
        ok, reason = check_shard_headroom(client, expected_new_shards=1, min_headroom_pct=10.0)
        assert ok is True
        assert reason == ""

    def test_filter_path_plumbed(self):
        client = self._mock_client(shards=100, nodes=1, max_per_node=1000)
        check_shard_headroom(client)
        # Assert cluster.stats was called with the narrow filter_path
        call_kwargs = client.cluster.stats.call_args.kwargs
        assert call_kwargs.get("filter_path") == [
            "indices.shards.total",
            "nodes.count.data",
        ]
        # Assert get_settings uses filter_path for max_shards_per_node.
        # flat_settings MUST NOT be True: the flat form stores dotted
        # keys as single strings ("cluster.max_shards_per_node"), and
        # filter_path treats dots as path separators, so the two
        # combined return an empty payload. Rev 6 dropped flat_settings
        # after live-cluster validation caught the fail-open bug.
        call_kwargs = client.cluster.get_settings.call_args.kwargs
        assert call_kwargs.get("flat_settings") is not True, (
            "flat_settings=True conflicts with dotted filter_path — "
            "check_shard_headroom must not pass it"
        )
        assert "filter_path" in call_kwargs
        assert any("max_shards_per_node" in p for p in call_kwargs["filter_path"])

    def test_request_timeout_is_int_not_string(self):
        """opensearch-py 3.1.0 rejects string timeout values; the
        string raises ConnectionError, which is caught by the outer
        exception handler and fails the check open. Must be int seconds
        via request_timeout, not string via timeout.
        """
        client = self._mock_client(shards=100, nodes=1, max_per_node=1000)
        check_shard_headroom(client)
        stats_kwargs = client.cluster.stats.call_args.kwargs
        settings_kwargs = client.cluster.get_settings.call_args.kwargs
        # Forbidden: timeout="10s" (string)
        assert not isinstance(stats_kwargs.get("timeout"), str)
        assert not isinstance(settings_kwargs.get("timeout"), str)
        # Required: request_timeout=int
        assert isinstance(stats_kwargs.get("request_timeout"), int)
        assert isinstance(settings_kwargs.get("request_timeout"), int)


# --- _is_systemic_failure ---


def _error_entry(reason: str) -> dict:
    return {"index": {"error": {"reason": reason}}}


class TestIsSystemicFailure:
    def test_partial_success_is_not_systemic(self):
        assert _is_systemic_failure(5, 10, [_error_entry("foo")]) == (False, "")

    def test_scans_all_errors_not_just_first(self):
        # Mapping conflict first, shard-limit second — must detect
        # systemic on the later entry.
        errors = [
            _error_entry("mapper_parsing_exception: failed on field X"),
            _error_entry("mapper_parsing_exception: failed on field Y"),
            _error_entry("validation_exception: this action would add too many shards"),
        ]
        is_sys, reason = _is_systemic_failure(0, 3, errors)
        assert is_sys is True
        assert "validation_exception" in reason.lower()

    @pytest.mark.parametrize(
        "reason",
        [
            "validation_exception: bad schema",
            "cluster_block_exception: index read-only",
            "this action would add [5] total shards",
            "maximum shards open in cluster",
            "blocked by: [FORBIDDEN/12/index read-only / allow delete (api)]",
            "illegal_argument_exception: shard limit",
        ],
    )
    def test_systemic_pattern_matrix(self, reason):
        is_sys, ret_reason = _is_systemic_failure(0, 1, [_error_entry(reason)])
        assert is_sys is True
        assert ret_reason == reason

    def test_mapping_conflict_is_not_systemic(self):
        errors = [_error_entry("mapper_parsing_exception: failed on field x")]
        is_sys, reason = _is_systemic_failure(0, 1, errors)
        assert is_sys is False
        assert "mapper" in reason.lower()


# --- Circuit breaker (_flush_with_retry) ---


class TestCircuitBreaker:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuit_breaker()
        yield
        reset_circuit_breaker()

    def test_trips_at_threshold(self, monkeypatch):
        # Mock helpers.bulk to always return all-failures with systemic reason.
        errors = [_error_entry("validation_exception: too many shards") for _ in range(10)]

        def fake_bulk(*a, **kw):
            # Signature returns (success, errors_list)
            return 0, errors

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        # 1st and 2nd calls bump the counter; 3rd trips.
        actions = [{"_index": "x", "foo": "bar"} for _ in range(10)]
        bulk_mod.flush_bulk(MagicMock(), actions)
        bulk_mod.flush_bulk(MagicMock(), actions)
        with pytest.raises(ShardCapacityExhausted) as exc:
            bulk_mod.flush_bulk(MagicMock(), actions)
        assert "validation_exception" in str(exc.value).lower()

    def test_resets_on_partial_success(self, monkeypatch):
        errors = [_error_entry("validation_exception: too many shards") for _ in range(10)]

        call_count = {"n": 0}

        def fake_bulk(*a, **kw):
            call_count["n"] += 1
            # 1st call: all fail systemic. 2nd call: partial success (reset counter).
            # 3rd and 4th: all fail systemic — should NOT trip because counter reset.
            if call_count["n"] == 2:
                return 5, []  # partial success
            return 0, errors

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        actions = [{"_index": "x"} for _ in range(10)]

        bulk_mod.flush_bulk(MagicMock(), actions)  # counter = 1
        bulk_mod.flush_bulk(MagicMock(), actions)  # partial → reset to 0
        bulk_mod.flush_bulk(MagicMock(), actions)  # counter = 1
        # Should NOT raise yet — only 1 systemic failure since reset
        bulk_mod.flush_bulk(MagicMock(), actions)  # counter = 2

    def test_does_not_trip_on_mapping_conflicts(self, monkeypatch):
        # Per-doc mapping errors, not systemic — should never trip
        # no matter how many batches fail.
        errors = [_error_entry("mapper_parsing_exception: bad field") for _ in range(5)]

        def fake_bulk(*a, **kw):
            return 0, errors

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        actions = [{"_index": "x"} for _ in range(5)]
        # 10 consecutive all-failure batches with non-systemic reason
        for _ in range(10):
            bulk_mod.flush_bulk(MagicMock(), actions)

    def test_reset_circuit_breaker_clears_state(self, monkeypatch):
        # Explicit behavior: reset_circuit_breaker() zeroes counter.
        errors = [_error_entry("validation_exception: too many shards")]

        def fake_bulk(*a, **kw):
            return 0, errors

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        actions = [{"_index": "x"}]

        # Two systemic failures — one away from threshold.
        bulk_mod.flush_bulk(MagicMock(), actions)
        bulk_mod.flush_bulk(MagicMock(), actions)
        assert bulk_mod._get_counter() == 2

        reset_circuit_breaker()
        assert bulk_mod._get_counter() == 0

        # After reset, 2 more systemic failures should NOT trip
        # (counter starts fresh at 0).
        bulk_mod.flush_bulk(MagicMock(), actions)
        bulk_mod.flush_bulk(MagicMock(), actions)  # counter = 2, no raise


# --- bulk_failed_reason thread-local capture (operator visibility) ---


class TestLastBulkReasonCapture:
    """Thread-local last-error reason is populated on bulk failure so
    ingest-status writers can surface it via the `bulk_failed_reason`
    status field. Previously the reason only went to stderr."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        from opensearch_mcp.bulk import clear_last_bulk_reason, reset_circuit_breaker

        reset_circuit_breaker()
        clear_last_bulk_reason()
        yield
        reset_circuit_breaker()
        clear_last_bulk_reason()

    def test_empty_reason_before_any_bulk(self):
        from opensearch_mcp.bulk import get_last_bulk_reason

        assert get_last_bulk_reason() == ""

    def test_captures_first_error_reason_on_partial_failure(self, monkeypatch):
        """Mapping conflict error (non-systemic) populates the tracker
        so the status file shows the cause, not just a count."""
        from opensearch_mcp.bulk import get_last_bulk_reason

        errors = [
            _error_entry(
                "mapper [winlog.event_data.Data.#text] cannot be changed "
                "from type [keyword] to [date]"
            )
        ]

        def fake_bulk(*a, **kw):
            return 4, errors  # 4 succeeded, 1 failed

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        actions = [{"_index": "x"} for _ in range(5)]
        bulk_mod.flush_bulk(MagicMock(), actions)
        reason = get_last_bulk_reason()
        assert "mapper" in reason
        assert "Data.#text" in reason

    def test_preserves_first_reason_when_later_batch_succeeds(self, monkeypatch):
        """Operator cares about the FIRST failure cause; a subsequent
        all-success batch must NOT clobber the reason with empty."""
        from opensearch_mcp.bulk import get_last_bulk_reason

        call_count = {"n": 0}

        def fake_bulk(*a, **kw):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return 4, [_error_entry("mapper conflict")]
            return 5, []  # all success

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        actions = [{"_index": "x"} for _ in range(5)]
        bulk_mod.flush_bulk(MagicMock(), actions)
        bulk_mod.flush_bulk(MagicMock(), actions)  # all success
        assert get_last_bulk_reason() == "mapper conflict"

    def test_clear_last_bulk_reason_resets(self, monkeypatch):
        from opensearch_mcp.bulk import clear_last_bulk_reason, get_last_bulk_reason

        def fake_bulk(*a, **kw):
            return 0, [_error_entry("some reason")]

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        bulk_mod.flush_bulk(MagicMock(), [{"_index": "x"}])
        assert get_last_bulk_reason() == "some reason"
        clear_last_bulk_reason()
        assert get_last_bulk_reason() == ""

    def test_reset_circuit_breaker_also_clears_last_bulk_reason(self, monkeypatch):
        """Leak-prevention guard: in-process MCP tools share a thread
        across successive invocations. Without this clear in
        reset_circuit_breaker, Call 2 (clean run, 0 failures) sees the
        stale reason from Call 1 and surfaces it in the status file
        as if the current run had an error. CR flagged this after the
        initial wiring pass.
        """
        from opensearch_mcp.bulk import get_last_bulk_reason

        def fake_bulk(*a, **kw):
            return 0, [_error_entry("call-1 mapping error")]

        monkeypatch.setattr(bulk_mod.helpers, "bulk", fake_bulk)
        bulk_mod.flush_bulk(MagicMock(), [{"_index": "x"}])
        assert "call-1" in get_last_bulk_reason()
        reset_circuit_breaker()
        assert get_last_bulk_reason() == ""


# --- bulk_failed accumulation across batches (Fix C integration) ---


class TestBulkFailedAccumulation:
    def test_totals_aggregate_bulk_failed_across_artifacts(self):
        """_compute_totals sums bulk_failed across all hosts/artifacts."""
        from opensearch_mcp.ingest import _compute_totals

        status_hosts = [
            {
                "hostname": "h1",
                "artifacts": [
                    {"name": "evtx", "status": "complete", "indexed": 100, "bulk_failed": 10},
                    {"name": "mft", "status": "complete", "indexed": 50, "bulk_failed": 5},
                ],
            },
            {
                "hostname": "h2",
                "artifacts": [
                    {"name": "evtx", "status": "complete", "indexed": 200, "bulk_failed": 15},
                ],
            },
        ]
        totals = _compute_totals(status_hosts)
        assert totals["indexed"] == 350
        assert totals["bulk_failed"] == 30
        assert totals["artifacts_complete"] == 3
        assert totals["hosts_complete"] == 2


# --- idx_shard_status tool ---


class TestIdxShardStatus:
    def _mock_client_ok(self, shards=100, nodes=1, max_per_node=1000):
        client = MagicMock()
        client.cluster.stats.return_value = {
            "indices": {"shards": {"total": shards}},
            "nodes": {"count": {"data": nodes}},
        }
        client.cluster.get_settings.return_value = {
            "persistent": {"cluster.max_shards_per_node": str(max_per_node)},
        }
        client.cat.indices.return_value = [
            {
                "index": "case-inc-evtx-host01",
                "pri": "1",
                "rep": "0",
                "docs.count": "1000",
                "store.size": "5mb",
            },
            {
                "index": ".opendistro_security",
                "pri": "1",
                "rep": "1",
                "docs.count": "50",
                "store.size": "100kb",
            },
        ]
        return client

    def test_nominal(self, monkeypatch):
        from opensearch_mcp import server as srv

        client = self._mock_client_ok(shards=100, max_per_node=1000)
        monkeypatch.setattr(srv, "_get_os", lambda: client)
        monkeypatch.setattr(srv.audit, "log", lambda **kw: "test-aid")

        resp = srv.idx_shard_status()
        assert resp["status"] == "ok"
        assert resp["current_shards"] == 100
        assert resp["max_total"] == 1000
        assert resp["headroom_pct"] == 90.0

    def test_critical(self, monkeypatch):
        from opensearch_mcp import server as srv

        client = self._mock_client_ok(shards=9999, max_per_node=10000)
        monkeypatch.setattr(srv, "_get_os", lambda: client)
        monkeypatch.setattr(srv.audit, "log", lambda **kw: "test-aid")

        resp = srv.idx_shard_status()
        assert resp["status"] == "critical"
        assert resp["current_shards"] == 9999

    def test_writes_audit_entry(self, monkeypatch):
        from opensearch_mcp import server as srv

        client = self._mock_client_ok()
        monkeypatch.setattr(srv, "_get_os", lambda: client)
        captured = {}

        def fake_log(**kw):
            captured.update(kw)
            return "test-aid"

        monkeypatch.setattr(srv.audit, "log", fake_log)
        resp = srv.idx_shard_status()
        assert captured["tool"] == "idx_shard_status"
        assert resp["audit_id"] == "test-aid"

    def test_filter_path_plumbed(self, monkeypatch):
        from opensearch_mcp import server as srv

        client = self._mock_client_ok()
        monkeypatch.setattr(srv, "_get_os", lambda: client)
        monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
        srv.idx_shard_status()
        assert client.cluster.stats.call_args.kwargs.get("filter_path") == [
            "indices.shards.total",
            "nodes.count.data",
        ]
        # flat_settings MUST NOT be True — see note in
        # test_filter_path_plumbed for TestCheckShardHeadroom.
        gs_kwargs = client.cluster.get_settings.call_args.kwargs
        assert gs_kwargs.get("flat_settings") is not True
        assert "filter_path" in gs_kwargs
        # Must use request_timeout=int, not timeout=string.
        assert isinstance(gs_kwargs.get("request_timeout"), int)

    def test_system_indices_filtered_from_top(self, monkeypatch):
        from opensearch_mcp import server as srv

        client = self._mock_client_ok()
        monkeypatch.setattr(srv, "_get_os", lambda: client)
        monkeypatch.setattr(srv.audit, "log", lambda **kw: None)
        resp = srv.idx_shard_status()
        top_names = [i["index"] for i in resp["top_indices_by_shard_count"]]
        assert ".opendistro_security" not in top_names
        assert "case-inc-evtx-host01" in top_names


# --- _estimate_new_shards ---


class TestEstimateNewShards:
    @pytest.mark.parametrize(
        "ingest_type,host_count,expected_min",
        [
            # Post-2026-04-22: estimates halved to match replicas=0
            # across all templates. evtx was 2*host+1 (primary+replica
            # per host); now 1*host+1 (primary only). memory was 10+1
            # (5 plugins × 2 for replica); now 5+1.
            ("evtx", 1, 2),
            ("evtx", 5, 6),
            ("memory", 1, 6),
            ("delimited", 1, 2),
            ("json", 1, 2),
            ("accesslog", 1, 2),
            ("generic", 1, 2),
            ("unknown-type", 1, 2),  # falls back to generic
        ],
    )
    def test_returns_positive_upper_bound(self, ingest_type, host_count, expected_min):
        result = _estimate_new_shards(ingest_type, host_count=host_count)
        assert result >= expected_min
        assert result > 0


# --- _resolve_setting ---


class TestResolveSetting:
    def test_transient_wins(self):
        settings = {
            "transient": {"cluster.max_shards_per_node": "5000"},
            "persistent": {"cluster.max_shards_per_node": "2000"},
            "defaults": {"cluster.max_shards_per_node": "1000"},
        }
        assert _resolve_setting(settings, "cluster.max_shards_per_node") == "5000"

    def test_falls_back_to_default(self):
        assert _resolve_setting({}, "cluster.max_shards_per_node", default=777) == 777


# --- ingest_status.write_status schema extension ---


class TestWriteStatusSchema:
    def test_bulk_failed_fields_in_output(self, tmp_path, monkeypatch):
        from opensearch_mcp import ingest_status as ist

        monkeypatch.setattr(ist, "_STATUS_DIR", tmp_path)

        ist.write_status(
            case_id="CASE-TEST",
            pid=12345,
            run_id="run-abc",
            status="running",
            hosts=[],
            totals={"indexed": 0},
            started="2026-04-20T00:00:00+00:00",
            bulk_failed=42,
            bulk_failed_reason="validation_exception",
        )

        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["bulk_failed"] == 42
        assert data["bulk_failed_reason"] == "validation_exception"

    def test_bulk_failed_defaults(self, tmp_path, monkeypatch):
        from opensearch_mcp import ingest_status as ist

        monkeypatch.setattr(ist, "_STATUS_DIR", tmp_path)

        ist.write_status(
            case_id="CASE-TEST",
            pid=1,
            run_id="run-1",
            status="running",
            hosts=[],
            totals={},
            started="2026-04-20T00:00:00+00:00",
        )
        data = json.loads(next(tmp_path.glob("*.json")).read_text())
        assert data["bulk_failed"] == 0
        assert data["bulk_failed_reason"] == ""
