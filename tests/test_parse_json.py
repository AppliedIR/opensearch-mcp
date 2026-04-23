"""Unit tests for parse_json — pretty-printed single-object JSON support
and empty-file-list walker diagnostic.

UAT 2026-04-24 A.5 regression coverage. Lives in its own file (not
test_all_parsers.py) because that module is gated on a local fixture
directory (`/tmp/opensearch-test-data`) and CI would skip everything in
it — these tests must actually run.

Contract pinned:

- `_detect_json_format` recognises a pretty-printed single-object JSON
  file (line 1 is bare `{`) as `json_single` and `_iter_json_records`
  yields it as exactly one record. Pre-fix, such files failed format
  detection and raised `ValueError("Cannot detect JSON format")` —
  blocking Velociraptor `collection_context.json`, `client_info.json`,
  `requests.json`, and any other producer that pretty-prints a single
  object.

- Empty-file-list walker diagnostic: when `idx_ingest_json` is pointed
  at a directory with zero matching `.json/.jsonl/.ndjson` files, a
  stderr diagnostic surfaces the reason (non-recursive walker, count
  of entries / subdirectories) instead of the prior silent
  `Done. 0 indexed, 0 skipped, 0 bulk failed.` output that hid the
  walker's one-level-only semantics.
"""

from __future__ import annotations

import json


class TestDetectJsonFormatSingleObject:
    def test_pretty_printed_single_object_detected_as_json_single(self, tmp_path):
        """Pre-fix this was the primary Velociraptor parser-fail mode:
        files like client_info.json (pretty-printed dict) returned
        'unknown' because line 1 was bare `{`."""
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "client_info.json"
        f.write_text(
            json.dumps(
                {"hostname": "testhost-1", "fqdn": "testhost-1.example.test"},
                indent=2,
            )
        )
        assert _detect_json_format(f) == "json_single"

    def test_single_object_iterates_as_one_record(self, tmp_path):
        """`_iter_json_records` must yield the single-object file as
        exactly one dict record — not try to iterate keys or flatten."""
        from opensearch_mcp.parse_json import _iter_json_records

        f = tmp_path / "collection_context.json"
        payload = {
            "session_id": "F.0000000000000001",
            "artifacts": ["Windows.Registry.Test"],
            "start_ts": 1698765432,
        }
        f.write_text(json.dumps(payload, indent=2))

        records = list(_iter_json_records(f, "json_single"))
        assert len(records) == 1
        assert records[0] == payload

    def test_single_line_ndjson_still_detected_as_jsonl(self, tmp_path):
        """Regression guard: the single-object fix must NOT change how
        single-line NDJSON files classify. Line 1 is a complete JSON
        object → still 'jsonl'."""
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "ndjson.json"
        f.write_text('{"key": "value"}\n')
        assert _detect_json_format(f) == "jsonl"

    def test_json_array_still_detected(self, tmp_path):
        """Regression guard: pretty-printed array (line 1 = `[`) still
        routes to 'json_array', not 'json_single'."""
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "array.json"
        f.write_text("[\n  {},\n  {}\n]\n")
        assert _detect_json_format(f) == "json_array"

    def test_malformed_single_object_returns_unknown(self, tmp_path):
        """Bare `{` followed by garbage must still return 'unknown'
        (the full-file parse fallback catches JSONDecodeError)."""
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "bad.json"
        f.write_text("{\n  not-valid-json\n")
        assert _detect_json_format(f) == "unknown"

    def test_oversize_single_object_returns_unknown(self, tmp_path):
        """Single-object files >200MB return 'unknown' so the walker
        rejects them rather than trying to load into memory. Matches
        the existing json_array size cap posture."""
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "huge.json"
        # Write a bare `{` on line 1 + enough filler to exceed the
        # 200MB cap. We don't need to make it parseable — the size
        # check fires before the full-file parse.
        with open(f, "w") as fh:
            fh.write("{\n")
            chunk = "x" * (10 * 1024 * 1024)  # 10MB
            for _ in range(21):  # 210MB total, comfortably over cap
                fh.write(chunk)
        assert _detect_json_format(f) == "unknown"

    def test_single_object_ingest_full_pipeline(self, tmp_path):
        """End-to-end: a pretty-printed single-object file is now
        ingestable via `ingest_json` without raising ValueError.
        Before A.5 this path raised 'Cannot detect JSON format'."""
        from unittest.mock import MagicMock

        from opensearch_mcp.parse_json import ingest_json

        f = tmp_path / "client_info.json"
        f.write_text(
            json.dumps(
                {
                    "hostname": "testhost-1",
                    "client_id": "C.0000000000000001",
                    "last_seen_at": 1698765432,
                },
                indent=2,
            )
        )

        captured = []

        def fake_flush(client, actions):
            captured.extend(actions)
            return len(actions), 0

        from unittest.mock import patch

        with patch("opensearch_mcp.parse_json.flush_bulk", side_effect=fake_flush):
            cnt, sk, bf, _ = ingest_json(f, MagicMock(), "test-idx", "testhost-1")

        assert cnt == 1, "pretty-printed single-object file must ingest as 1 doc"
        assert bf == 0
        assert len(captured) == 1
        source = captured[0]["_source"]
        assert source["hostname"] == "testhost-1"
        assert source["host.name"] == "testhost-1"
