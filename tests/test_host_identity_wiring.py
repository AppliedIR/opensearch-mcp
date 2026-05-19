"""End-to-end wiring tests for host-identity v1.

Covers:
  parse_csv per-row host.name + host.id stamping
  parse_json per-doc host.name + host.id stamping
  Preflight auto-apply (always-proceed, never block)
  case_host_fix correctness invariants
  Parser resolve-miss → stamp host.id = raw
  Deletion regression guard for the old fail-loud surface
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

# ---------------------------------------------------------------------------
# parse_csv wiring — per-row host.name (Test 6)
# ---------------------------------------------------------------------------


class TestParseCsvPerRowHostName:
    def _write_csv(self, path: Path, rows: list[dict]) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _capture_actions(self):
        """Install flush_bulk stub that records the bulk actions written."""
        captured: list[dict] = []

        def _stub(client, actions):
            captured.extend(actions)
            return len(actions), 0

        return captured, _stub

    def test_row_with_host_column_overrides_ingest_hostname(self, tmp_path):
        from opensearch_mcp.parse_csv import ingest_csv

        csv_path = tmp_path / "kansa.csv"
        self._write_csv(
            csv_path,
            [
                {"Host": "admin01.shieldbase.com", "data": "x"},
                {"Host": "rd01", "data": "y"},
            ],
        )

        captured, stub = self._capture_actions()
        with patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=stub):
            ingest_csv(
                csv_path=csv_path,
                client=MagicMock(),
                index_name="case-test-csv-kansa",
                hostname="UNUSED_DEFAULT",
            )

        hosts = [a["_source"]["host.name"] for a in captured]
        assert "admin01.shieldbase.com" in hosts
        assert "rd01" in hosts
        assert "UNUSED_DEFAULT" not in hosts

    def test_row_without_priority_field_falls_back_to_ingest_hostname(self, tmp_path):
        from opensearch_mcp.parse_csv import ingest_csv

        csv_path = tmp_path / "generic.csv"
        self._write_csv(csv_path, [{"col1": "x"}, {"col1": "y"}])

        captured, stub = self._capture_actions()
        with patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=stub):
            ingest_csv(
                csv_path=csv_path,
                client=MagicMock(),
                index_name="case-test-csv-generic",
                hostname="admin01",
            )

        hosts = {a["_source"]["host.name"] for a in captured}
        assert hosts == {"admin01"}


# ---------------------------------------------------------------------------
# parse_json wiring — per-doc host.name (Test 5 / Test 13 doc-level)
# ---------------------------------------------------------------------------


class TestParseJsonPerDocHostName:
    def test_doc_with_hostname_field_overrides_ingest_hostname(self, tmp_path):
        from opensearch_mcp.parse_json import ingest_json

        json_path = tmp_path / "v.jsonl"
        json_path.write_text(
            json.dumps({"Hostname": "admin01", "field": "x"})
            + "\n"
            + json.dumps({"ClientInfo": {"Hostname": "rd01"}, "field": "y"})
            + "\n"
        )

        captured: list[dict] = []

        def _stub(client, actions):
            captured.extend(actions)
            return len(actions), 0

        with patch("opensearch_mcp.parse_json.flush_bulk", side_effect=_stub):
            ingest_json(
                path=json_path,
                client=MagicMock(),
                index_name="case-test-json-v",
                hostname="UNUSED_DEFAULT",
            )

        hosts = {a["_source"]["host.name"] for a in captured}
        assert hosts == {"admin01", "rd01"}
        assert "UNUSED_DEFAULT" not in hosts

    def test_doc_without_priority_field_falls_back_to_ingest_hostname(self, tmp_path):
        from opensearch_mcp.parse_json import ingest_json

        json_path = tmp_path / "no_host.jsonl"
        json_path.write_text(json.dumps({"random": "value"}) + "\n")

        captured: list[dict] = []

        def _stub(client, actions):
            captured.extend(actions)
            return len(actions), 0

        with patch("opensearch_mcp.parse_json.flush_bulk", side_effect=_stub):
            ingest_json(
                path=json_path,
                client=MagicMock(),
                index_name="case-test-json-plain",
                hostname="admin01",
            )

        hosts = {a["_source"]["host.name"] for a in captured}
        assert hosts == {"admin01"}


# ---------------------------------------------------------------------------
# v1 Tests 4 / 5 / 6 — host_discovery.discover_hosts
# ---------------------------------------------------------------------------


class TestDiscoverHosts:
    def test_discover_unions_sources_per_host(self, tmp_path):
        """Test 4 — same host found via path-pattern AND content-peek:
        ONE entry, BOTH sources captured (no double-entry, no source-drop)."""
        import re

        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.host_discovery import discover_hosts

        host_dir = tmp_path / "admin01"
        host_dir.mkdir()
        with open(host_dir / "kansa.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Host", "data"])
            w.writerow(["admin01", "x"])

        dict_obj = HostDictionary()
        report = discover_hosts(
            tmp_path,
            dict_obj,
            hostname_from_path_re=re.compile(r"/([^/]+)/kansa\.csv"),
        )
        # Exactly one entry for admin01 (no duplicates across sources).
        entries_admin01 = [e for e in report.entries if e.raw == "admin01"]
        assert len(entries_admin01) == 1, (
            f"expected single entry for admin01, got {len(entries_admin01)}: "
            f"{[e.raw for e in entries_admin01]}"
        )
        entry = entries_admin01[0]
        methods = {s["method"] for s in entry.sources}
        # BOTH from_path AND csv_peek must be captured — proves the
        # orchestrator unions sources rather than first-wins.
        assert "from_path" in methods, f"missing from_path in sources: {methods}"
        assert "csv_peek" in methods, f"missing csv_peek in sources: {methods}"

    def test_discover_classifies_per_dict_state(self, tmp_path):
        """Test 5 — three hosts: mapped, near-match, novel."""
        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.host_discovery import HostEntry, _classify

        dict_obj = HostDictionary(
            hosts={"admin01": {"aliases": ["admin01"]}, "wkstn01": {"aliases": ["wkstn01"]}}
        )
        e_mapped = HostEntry(raw="admin01")
        e_near = HostEntry(raw="wksn01")
        e_novel = HostEntry(raw="WIN-3BVS460J98U")
        _classify(e_mapped, dict_obj)
        _classify(e_near, dict_obj)
        _classify(e_novel, dict_obj)

        assert e_mapped.status == "mapped"
        assert e_mapped.proposed_canonical == "admin01"
        assert e_near.status == "propose_with_match"
        assert e_near.proposed_canonical == "wkstn01"
        assert e_near.confidence >= 0.85
        assert e_novel.status == "propose_no_match"
        assert e_novel.proposed_canonical == "WIN-3BVS460J98U"

    def test_discover_empty_returns_empty_report(self, tmp_path):
        """Test 6 — empty evidence root returns empty report (no crash)."""
        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.host_discovery import discover_hosts

        report = discover_hosts(tmp_path, HostDictionary())
        assert report.entries == []


# ---------------------------------------------------------------------------
# v1 Tests 7 / 8 / 9 — preflight auto-apply (always-proceed)
# ---------------------------------------------------------------------------


def _seed_case_v1(cases_dir: Path, case_id: str, dict_hosts: dict | None = None) -> Path:
    case_dir = cases_dir / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\n")
    payload = {
        "version": 1,
        "auto_accept_high_confidence": True,
        "domains": ["shieldbase.com"],
        "hosts": dict_hosts if dict_hosts is not None else {},
        "unmapped": [],
    }
    (case_dir / "host-dictionary.yaml").write_text(yaml.safe_dump(payload))
    return case_dir


class TestPreflightAutoApply:
    def test_preflight_auto_alias_on_exact_strip(self, tmp_path, monkeypatch):
        """Test 7 — exact-strip confidence-1.00 → add_alias."""
        from opensearch_mcp.ingest_cli import _preflight_host_discovery

        _seed_case_v1(
            tmp_path,
            "INC-7",
            dict_hosts={"admin01": {"aliases": ["admin01"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        host_dir = tmp_path / "evidence" / "admin01.shieldbase.com"
        host_dir.mkdir(parents=True)

        hosts = [MagicMock(hostname="admin01.shieldbase.com")]
        report, _host_dict = _preflight_host_discovery("INC-7", host_dir, hosts)
        applied = report["decisions_applied"]
        assert any(
            d["raw"] == "admin01.shieldbase.com"
            and d["decision"] == "auto_alias"
            and d["applied_canonical"] == "admin01"
            and d["confidence"] == 1.00
            for d in applied
        )
        from opensearch_mcp.host_dictionary import HostDictionary

        d = HostDictionary.load(tmp_path / "INC-7" / "host-dictionary.yaml")
        assert d.resolve("admin01.shieldbase.com") == "admin01"

    def test_preflight_auto_new_canonical_on_no_match(self, tmp_path, monkeypatch):
        """Test 8 — no close match → new canonical created from raw."""
        from opensearch_mcp.ingest_cli import _preflight_host_discovery

        _seed_case_v1(
            tmp_path,
            "INC-8",
            dict_hosts={"admin01": {"aliases": ["admin01"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        host_dir = tmp_path / "evidence"
        host_dir.mkdir()
        hosts = [MagicMock(hostname="WIN-3BVS460J98U")]
        report, _host_dict = _preflight_host_discovery("INC-8", host_dir, hosts)
        applied = report["decisions_applied"]
        assert any(
            d["raw"] == "WIN-3BVS460J98U"
            and d["decision"] == "auto_new_canonical"
            and d["applied_canonical"] == "WIN-3BVS460J98U"
            for d in applied
        )
        from opensearch_mcp.host_dictionary import HostDictionary

        d = HostDictionary.load(tmp_path / "INC-8" / "host-dictionary.yaml")
        assert "WIN-3BVS460J98U" in d.hosts

    def test_preflight_decisions_appear_in_response(self, tmp_path, monkeypatch):
        """Test 9 — every applied decision is in decisions_applied[]."""
        from opensearch_mcp.ingest_cli import _preflight_host_discovery

        _seed_case_v1(
            tmp_path,
            "INC-9",
            dict_hosts={"admin01": {"aliases": ["admin01", "admin01.shieldbase.com"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        host_dir = tmp_path / "evidence"
        host_dir.mkdir()
        hosts = [
            MagicMock(hostname="admin01"),
            MagicMock(hostname="rd01"),
        ]
        report, _host_dict = _preflight_host_discovery("INC-9", host_dir, hosts)
        raws = {d["raw"] for d in report["decisions_applied"]}
        assert raws == {"admin01", "rd01"}

    def test_preflight_creates_dict_when_absent(self, tmp_path, monkeypatch):
        """Issue #2 fix — first-ever ingest on a case with no dict on disk
        creates one with auto-applied decisions."""
        from opensearch_mcp.ingest_cli import _preflight_host_discovery

        case_dir = tmp_path / "INC-NEW"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: INC-NEW\n")
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        host_dir = tmp_path / "evidence"
        host_dir.mkdir()
        hosts = [MagicMock(hostname="admin01")]

        report, host_dict = _preflight_host_discovery("INC-NEW", host_dir, hosts)
        # Dict file was created on disk.
        dict_path = case_dir / "host-dictionary.yaml"
        assert dict_path.exists(), "preflight must create dict when absent"
        # Decision was auto-applied.
        raws = {d["raw"] for d in report["decisions_applied"]}
        assert "admin01" in raws
        # Returned host_dict resolves the new canonical.
        assert host_dict is not None
        assert host_dict.resolve("admin01") == "admin01"


# ---------------------------------------------------------------------------
# v1 Integration — preflight → ingest_csv → host.id (Issue #3 guard)
# ---------------------------------------------------------------------------


class TestPreflightToParserIntegration:
    """End-to-end: preflight populates dict, ingest_csv receives it via the
    call chain, indexed docs carry host.id == canonical.

    This guards Issue #3 — that parsers receive host_dict at runtime, not
    just in unit tests. If a future refactor drops host_dict from any
    intermediate call site, this test fails.
    """

    def test_plaso_fallback_prefetch_receives_host_dict(self, tmp_path, monkeypatch):
        """Test Finding 1 (HIGH) — Plaso fallback path for prefetch must
        forward host_dict. Pre-fix, parse_prefetch._parse_prefetch_plaso
        dropped host_dict and prefetch docs got host.id=raw on wintools-
        down systems."""
        import inspect

        from opensearch_mcp.parse_prefetch import _parse_prefetch_plaso

        # The shape-level guard: the fallback function MUST accept host_dict
        # and MUST forward it to parse_plaso. Source-text check catches a
        # silent regression where host_dict is dropped on dispatch.
        sig = inspect.signature(_parse_prefetch_plaso)
        assert "host_dict" in sig.parameters, (
            "_parse_prefetch_plaso must accept host_dict — Plaso fallback bypasses dict otherwise"
        )
        src = inspect.getsource(_parse_prefetch_plaso)
        assert "host_dict=host_dict" in src, (
            "_parse_prefetch_plaso must forward host_dict to parse_plaso"
        )

    def test_plaso_fallback_srum_receives_host_dict(self):
        """Test Finding 1 (HIGH) — same for SRUM."""
        import inspect

        from opensearch_mcp.parse_srum import _parse_srum_plaso

        sig = inspect.signature(_parse_srum_plaso)
        assert "host_dict" in sig.parameters
        src = inspect.getsource(_parse_srum_plaso)
        assert "host_dict=host_dict" in src

    def test_discover_hosts_drops_null_byte_via_fixture(self, tmp_path):
        """CR follow-up 1 — drive the NULL-byte gate through discover_hosts
        end-to-end with a fixture containing an adversarial raw. Proves
        the `del raws[raw]` gate at host_discovery.py fires in production
        flow, not just the helper unit test.
        """
        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.host_discovery import discover_hosts

        host_dir = tmp_path / "evidence"
        host_dir.mkdir()
        # CSV with one row whose Host column carries a NULL byte —
        # csv_peek will pull this raw, the gate must reject it.
        (host_dir / "kansa.csv").write_text(
            "Host,data\nadmin\x0001,x\n",
            encoding="utf-8",
        )

        report = discover_hosts(host_dir, HostDictionary())
        raws = [e.raw for e in report.entries]
        assert "admin\x0001" not in raws, (
            f"adversarial raw must be filtered out before classification; got {raws!r}"
        )

    def test_discover_hosts_rejects_null_byte_raws(self, tmp_path):
        """Test Finding 3 (MEDIUM) — adversarial NULL byte / control char
        raws are rejected at discover_hosts boundary, never reach the
        dict. yaml.safe_dump escape-encodes them rather than raising, so
        the only safe gate is at input."""
        from opensearch_mcp.host_discovery import _is_safe_raw_hostname

        # NULL byte rejected.
        assert _is_safe_raw_hostname("admin\x0001") is False
        # ASCII control char rejected.
        assert _is_safe_raw_hostname("admin\x0101") is False
        # Tab is allowed (covered by upstream strip()).
        assert _is_safe_raw_hostname("admin\t01") is True
        # Empty string rejected.
        assert _is_safe_raw_hostname("") is False
        # Lucene metacharacters NOT rejected (term-DSL filter handles).
        assert _is_safe_raw_hostname('admin" OR *') is True
        # Normal hostname accepted.
        assert _is_safe_raw_hostname("admin01.shieldbase.com") is True

    def test_add_canonical_dedups_case_variants(self):
        """Arch Obs 3 — ADMIN01 and admin01 must not coexist as separate
        canonicals; second add is a no-op."""
        from opensearch_mcp.host_dictionary import HostDictionary

        d = HostDictionary(hosts={"admin01": {"aliases": ["admin01"]}})
        d.add_canonical("ADMIN01")
        assert "ADMIN01" not in d.hosts, (
            "ADMIN01 (case variant) must not create a second canonical when admin01 already exists"
        )
        assert d.resolve("ADMIN01") == "admin01"

    def test_h1_detection_handles_nested_mapping_form(self):
        """WSL2 Round-3 H1 detection bug — host.id can be stored in two
        shapes: flat-dotted (v1 template) or nested under host.properties
        (default dynamic mapping for pre-v1 docs). Detection must catch
        both forms; the old code only checked flat and missed nested,
        then PUT _mapping silently failed.
        """
        from opensearch_mcp.ingest_cli import _detect_host_id_mapping_type

        # Flat-dotted form (v1 template).
        flat = {"host.id": {"type": "keyword"}}
        assert _detect_host_id_mapping_type(flat) == "keyword"

        # Nested form (default dynamic mapping for pre-v1 docs).
        nested_text = {
            "host": {
                "properties": {
                    "id": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "name": {"type": "keyword"},
                }
            }
        }
        assert _detect_host_id_mapping_type(nested_text) == "text"

        # Genuinely absent — neither form has host.id.
        absent = {"host": {"properties": {"name": {"type": "keyword"}}}}
        assert _detect_host_id_mapping_type(absent) is None

        # Flat form wins if both present (template overrides).
        both = {
            "host.id": {"type": "keyword"},
            "host": {"properties": {"id": {"type": "text"}}},
        }
        assert _detect_host_id_mapping_type(both) == "keyword"

    def test_case_host_fix_passes_request_timeout(self):
        """WSL2 R4 Test 3 — case_host_fix must pass request_timeout to
        update_by_query so the default client read_timeout doesn't fire
        false-negative on hundred-thousand-doc reindex calls. Verified
        via source-text (test-mocking the timeout would over-fit)."""
        import inspect

        from opensearch_mcp import server

        src = inspect.getsource(server._case_host_fix_impl)
        assert "request_timeout=600" in src, (
            "case_host_fix must pass request_timeout=600 to update_by_query "
            "to avoid client-side ConnectionTimeout on multi-100K-doc hosts."
        )

    def test_standalone_entries_run_h1_back_patch(self):
        """CR R4b — standalone entries (cmd_ingest_delimited/json/
        accesslog/memory) skip preflight. The H1 mapping back-patch
        must still fire from those entries so pre-v1 cases get
        host.id=keyword on existing indices before parsers write."""
        import inspect

        from opensearch_mcp import ingest_cli

        for entry_name in [
            "cmd_csv",
            "cmd_ingest_json",
            "cmd_ingest_delimited",
            "cmd_ingest_accesslog",
            "cmd_ingest_memory",
        ]:
            fn = getattr(ingest_cli, entry_name, None)
            assert fn is not None, f"{entry_name} missing from ingest_cli"
            src = inspect.getsource(fn)
            assert "_warn_if_mapping_upgrade_required" in src, (
                f"{entry_name} must call _warn_if_mapping_upgrade_required "
                f"after dict load so the H1 back-patch fires uniformly. "
                f"Without it, the first v1 ingest into a pre-v1 case via "
                f"this entry leaves text-mapped host.id silently."
            )

    def test_case_host_fix_script_noop_guards_already_flipped(self):
        """WSL2 R5 — must_not bool filter alone is not sufficient because
        on a text-mapped (pre-v1) host.id, the term query doesn't behave
        as exact-match. Defense-in-depth: the painless script also
        checks `ctx._source['host.id'] == params.id` and sets ctx.op =
        'noop', so retry-after-timeout doesn't re-touch already-flipped
        docs regardless of mapping type.
        """
        import inspect

        from opensearch_mcp import server

        src = inspect.getsource(server._case_host_fix_impl)
        assert "ctx.op = 'noop'" in src, (
            "case_host_fix painless script must include ctx.op = 'noop' "
            "guard so retry-after-timeout doesn't re-touch already-flipped "
            "docs on text-mapped indices."
        )
        assert "ctx._source['host.id'] == params.id" in src

    def test_case_host_fix_outer_envelope_catches_unexpected_exception(self):
        """WSL2 R5 — case_host_fix entry has an outer try/except that
        catches InvalidHostnameValue + generic Exception and returns
        isError envelope. Without this guard, FastMCP wraps exceptions
        with isError:false envelopes."""
        import inspect

        from opensearch_mcp import server

        src = inspect.getsource(server.case_host_fix)
        assert "except InvalidHostnameValue" in src
        assert "except Exception" in src
        assert '"isError": True' in src

    def test_case_host_fix_retry_skips_already_flipped(self):
        """WSL2 Round-3 Test 3 — case_host_fix on 188K docs hit a
        ConnectionTimeout after 174K flipped. Retry must skip the
        already-flipped 174K and only touch the remaining 14K.

        Verified via source-text: query body has must + must_not, where
        must_not excludes docs already at new_canonical.
        """
        import inspect

        from opensearch_mcp import server

        src = inspect.getsource(server._case_host_fix_impl)
        # Must clause: term host.name == raw
        assert '"must": [{"term": {"host.name": raw}}]' in src, (
            "case_host_fix must use bool/must term filter on host.name"
        )
        # Must-not clause: host.id already at new_canonical → skip
        assert '"must_not": [{"term": {"host.id": new_canonical}}]' in src, (
            "case_host_fix must skip already-flipped docs on retry "
            "to bound the cost of retry-after-ConnectionTimeout"
        )

    def test_case_host_fix_refuses_text_mapped_index(self, tmp_path, monkeypatch):
        """H1 defensive — refuse case_host_fix when any case index has
        host.id mapped as text (pre-v1 upgrade path). update_by_query
        would succeed but host.id queries would silently miss."""
        from unittest.mock import patch

        _seed_case_v1(tmp_path, "INC-H1", dict_hosts={"admin01": {"aliases": ["admin01"]}})
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        fake_vhir = tmp_path / "vhir"
        fake_vhir.mkdir()
        (fake_vhir / "active_case").write_text("INC-H1\n")
        monkeypatch.setattr("opensearch_mcp.paths.vhir_dir", lambda: fake_vhir)
        monkeypatch.setattr("opensearch_mcp.server.vhir_dir", lambda: fake_vhir, raising=False)

        with patch("opensearch_mcp.server._get_os") as mock_get_os:
            mock_client = MagicMock()
            # Simulate a pre-v1 index where host.id is text.
            mock_client.indices.get_mapping.return_value = {
                "case-inc-h1-evtx-stale": {
                    "mappings": {
                        "properties": {
                            "host.id": {
                                "type": "text",
                                "fields": {"keyword": {"type": "keyword"}},
                            },
                        }
                    }
                },
            }
            mock_get_os.return_value = mock_client

            from opensearch_mcp.server import case_host_fix

            result = case_host_fix(raw="admin01", new_canonical="admin01-new")

        assert result.get("status") == "mapping_upgrade_required"
        assert result.get("isError") is True
        assert "case-inc-h1-evtx-stale" in result.get("indices_text", [])
        # update_by_query must NOT have been called.
        assert not mock_client.update_by_query.called

    def test_case_id_path_traversal_rejected(self):
        """M1 — case_id with path components rejected."""
        from opensearch_mcp.ingest_cli import _case_dir_for

        assert _case_dir_for("../etc") is None
        assert _case_dir_for("/abs/path") is None
        assert _case_dir_for("foo/bar") is None
        assert _case_dir_for("") is None

    def test_merge_preserves_disk_only_role(self, tmp_path):
        """M3 — _merge_from_disk preserves disk-only non-list fields.

        Process A sets role/notes on canonical. Process B saves
        (merge=True) without those fields. After merge, the disk file
        retains Process A's role/notes."""
        from opensearch_mcp.host_dictionary import HostDictionary

        p = tmp_path / "host-dictionary.yaml"
        # Process A's state: admin01 with role and notes
        HostDictionary(
            hosts={
                "admin01": {
                    "aliases": ["admin01"],
                    "role": "workstation",
                    "notes": "operator-set",
                }
            },
            path=p,
        ).save()

        # Process B loads, adds a new canonical, saves merge=True
        b = HostDictionary.load(p)
        b.add_canonical("rd01")
        # B has admin01 but without role/notes (it loaded them, so they're there)
        # Simulate a stale in-memory: drop the operator-set fields
        b.hosts["admin01"].pop("role", None)
        b.hosts["admin01"].pop("notes", None)
        b.save(merge=True)

        reloaded = HostDictionary.load(p)
        assert reloaded.hosts["admin01"].get("role") == "workstation", (
            "M3: disk's operator-set role was clobbered by Process B's save"
        )
        assert reloaded.hosts["admin01"].get("notes") == "operator-set"
        assert "rd01" in reloaded.hosts  # B's add survived too

    def test_case_host_fix_rejection_response_shape(self, tmp_path, monkeypatch):
        """WSL2 minor — case_host_fix rejection returns a structured error
        response with `status: rejected`, `isError: true`, and operator-
        readable context. Avoids confusing the AI/operator with a bare
        ToolError when the cause is operator input."""
        from unittest.mock import patch

        _seed_case_v1(tmp_path, "INC-REJ", dict_hosts={"admin01": {"aliases": ["admin01"]}})
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        fake_vhir = tmp_path / "vhir"
        fake_vhir.mkdir()
        (fake_vhir / "active_case").write_text("INC-REJ\n")
        monkeypatch.setattr("opensearch_mcp.paths.vhir_dir", lambda: fake_vhir)
        monkeypatch.setattr("opensearch_mcp.server.vhir_dir", lambda: fake_vhir, raising=False)

        with patch("opensearch_mcp.server._get_os") as mock_get_os:
            mock_get_os.return_value = MagicMock()
            from opensearch_mcp.server import case_host_fix

            result = case_host_fix(raw="admin\x0001", new_canonical="admin01")

        assert result.get("status") == "rejected"
        assert result.get("isError") is True
        assert "NULL byte" in result.get("error", "")
        assert result.get("dict_saved") is False

    def test_dict_primitives_reject_adversarial_input(self):
        """Fresh-eyes Issue 3 — gate is at the dict primitive, not just at
        discover_hosts. Covers preflight + case_host_fix + future CLI paths."""
        import pytest

        from opensearch_mcp.host_dictionary import (
            HostDictionary,
            InvalidHostnameValue,
        )

        d = HostDictionary(hosts={"admin01": {"aliases": ["admin01"]}})

        with pytest.raises(InvalidHostnameValue, match="NULL byte"):
            d.add_alias("admin\x0001", "admin01")
        with pytest.raises(InvalidHostnameValue, match="NULL byte"):
            d.add_canonical("admin\x0002")
        with pytest.raises(InvalidHostnameValue, match="control char"):
            d.add_alias("admin\x0101", "admin01")
        with pytest.raises(InvalidHostnameValue, match="empty"):
            d.add_canonical("")
        with pytest.raises(InvalidHostnameValue, match="must be a string"):
            d.add_canonical(None)
        # Lucene metacharacters pass through — handled by term-DSL filter.
        d.add_canonical('admin01" OR *')
        assert 'admin01" OR *' in d.hosts

    def test_case_host_fix_writes_audit_log(self, tmp_path, monkeypatch):
        """Fresh-eyes Issue 2 — every other server.py tool calls audit.log;
        case_host_fix must too. Forensic audit trail for dict mutation +
        reindex must not be silent."""
        from unittest.mock import patch

        _seed_case_v1(tmp_path, "INC-AUDIT", dict_hosts={"admin01": {"aliases": ["admin01"]}})
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        fake_vhir = tmp_path / "vhir"
        fake_vhir.mkdir()
        (fake_vhir / "active_case").write_text("INC-AUDIT\n")
        monkeypatch.setattr("opensearch_mcp.paths.vhir_dir", lambda: fake_vhir)
        monkeypatch.setattr("opensearch_mcp.server.vhir_dir", lambda: fake_vhir, raising=False)

        with (
            patch("opensearch_mcp.server._get_os") as mock_get_os,
            patch("opensearch_mcp.server.audit") as mock_audit,
        ):
            mock_client = MagicMock()
            mock_client.update_by_query.return_value = {"updated": 7, "took": 50}
            mock_get_os.return_value = mock_client
            mock_audit.log.return_value = "audit-123"

            from opensearch_mcp.server import case_host_fix

            result = case_host_fix(raw="wksn01", new_canonical="admin01")

        assert mock_audit.log.called, "case_host_fix must call audit.log"
        call_kwargs = mock_audit.log.call_args.kwargs
        assert call_kwargs.get("tool") == "case_host_fix"
        assert call_kwargs.get("params", {}).get("raw") == "wksn01"
        assert call_kwargs.get("params", {}).get("new_canonical") == "admin01"
        assert result.get("audit_id") == "audit-123"

    def test_ingest_function_forwards_host_dict_end_to_end(self, tmp_path, monkeypatch):
        """Arch Obs 2 — Invoke ingest() directly with a seeded host_dict
        and minimal evtx evidence. Assert the parser call site receives
        host_dict (not None). Catches wiring-omission on any of the 6
        forwarding points: ingest → _ingest_hosts → parse_and_index.

        Pre-fix shape: ingest() accepted host_dict but didn't forward to
        _ingest_hosts; _ingest_hosts accepted but didn't forward to
        parse_and_index. Silent fallback to host.id=raw.
        """
        from unittest.mock import patch

        from opensearch_mcp.discover import DiscoveredHost
        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.ingest import ingest

        # Seeded dict that would resolve admin01.shieldbase.com → admin01
        # if host_dict reaches the parser.
        seeded = HostDictionary(
            hosts={"admin01": {"aliases": ["admin01", "admin01.shieldbase.com"]}},
        )

        # Minimal evidence: one host with no evtx_dir / artifacts. ingest()
        # short-circuits the per-host loop but still hits the forwarding
        # chain. We patch parse_and_index to capture host_dict at the
        # production call site (line 568 of ingest.py).
        host = DiscoveredHost(
            hostname="admin01.shieldbase.com",
            volume_root=tmp_path,
        )
        # Give the host one evtx file so parse_and_index is reached.
        evtx_dir = tmp_path / "evtx"
        evtx_dir.mkdir()
        (evtx_dir / "fake.evtx").write_bytes(b"x" * 100000)  # >= _MIN_EVTX_SIZE
        host.evtx_dir = evtx_dir

        captured: list[object] = []

        def _stub_parse(**kwargs):
            captured.append(kwargs.get("host_dict"))
            return (0, 0, 0)

        with (
            patch("opensearch_mcp.ingest.parse_and_index", side_effect=_stub_parse),
            patch("opensearch_mcp.ingest.AuditWriter"),
            patch("opensearch_mcp.ingest._build_idx", return_value="case-test-evtx-x"),
            patch("opensearch_mcp.ingest._safe_count", return_value=0),
            patch("opensearch_mcp.ingest.sha256_file", return_value="abcd"),
            patch("opensearch_mcp.ingest._write_ingest_manifest"),
            patch("opensearch_mcp.ingest._build_status_hosts", return_value=[]),
            patch("opensearch_mcp.ingest._find_artifact_status", return_value=None),
        ):
            try:
                ingest(
                    hosts=[host],
                    client=MagicMock(),
                    audit=MagicMock(),
                    case_id="INC-WIRE",
                    host_dict=seeded,
                )
            except Exception:
                # Other downstream paths (plaso/custom artifacts) may fail
                # on fixtures we didn't set up — we only care that
                # parse_and_index was reached with host_dict.
                pass

        # parse_and_index must have been invoked with the seeded dict —
        # NOT None. If any forwarding point dropped host_dict, captured[0]
        # would be None.
        assert captured, "parse_and_index was never called — fixture problem"
        assert captured[0] is seeded, (
            f"parse_and_index received host_dict={captured[0]!r}; expected "
            f"the seeded dict to flow through ingest() → _ingest_hosts → "
            f"parse_and_index. A forwarding point is dropping host_dict."
        )

    def test_csv_resolve_canonical_after_preflight(self, tmp_path, monkeypatch):
        from opensearch_mcp.ingest_cli import _preflight_host_discovery
        from opensearch_mcp.parse_csv import ingest_csv

        # Seed case with an existing canonical so preflight produces an
        # auto_alias decision (raw FQDN strips to bare canonical).
        _seed_case_v1(
            tmp_path,
            "INC-INT",
            dict_hosts={"admin01": {"aliases": ["admin01"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        host_dir = tmp_path / "evidence"
        host_dir.mkdir()

        # Discovered host carries the FQDN form.
        hosts = [MagicMock(hostname="admin01.shieldbase.com")]
        _report, case_host_dict = _preflight_host_discovery("INC-INT", host_dir, hosts)

        # case_host_dict is what cmd_scan plumbs through ingest() →
        # parse_and_index / ingest_csv. Pass it now via the same kwarg
        # the production call sites use.
        csv_path = tmp_path / "kansa.csv"
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Host", "data"])
            w.writerow(["admin01.shieldbase.com", "x"])

        captured: list[dict] = []

        def _stub(client, actions):
            captured.extend(actions)
            return len(actions), 0

        with patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=_stub):
            ingest_csv(
                csv_path=csv_path,
                client=MagicMock(),
                index_name="case-int-csv",
                hostname="admin01.shieldbase.com",  # ingest-level fallback
                host_dict=case_host_dict,
            )

        # The indexed doc must carry host.id = "admin01" (the canonical),
        # NOT "admin01.shieldbase.com" (the raw). If host_dict didn't
        # reach the parser, host.id would be the raw and this test fails.
        assert captured, "no actions captured — bulk stub never called"
        src = captured[0]["_source"]
        assert src["host.name"] == "admin01.shieldbase.com"
        assert src["host.id"] == "admin01", (
            f"host.id must resolve to canonical 'admin01', got {src['host.id']!r}. "
            "If equal to host.name, host_dict isn't reaching ingest_csv."
        )


# ---------------------------------------------------------------------------
# v1 Tests 10 / 11 / 12 / 18 — case_host_fix correctness
# ---------------------------------------------------------------------------


class TestCaseHostFix:
    def test_fix_changes_dictionary(self, tmp_path):
        """Test 10 — alias moves from old canonical to new canonical.

        Exercises the in-memory dict-edit half of case_host_fix.
        """
        from opensearch_mcp.host_dictionary import HostDictionary

        p = tmp_path / "host-dictionary.yaml"
        p.write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "domains": [],
                    "hosts": {
                        "wkstn01": {"aliases": ["wkstn01", "wksn01"]},
                    },
                    "unmapped": [],
                }
            )
        )
        d = HostDictionary.load(p)
        for canonical, entry in d.hosts.items():
            if "wksn01" in (entry.get("aliases") or []) and canonical != "wksn01":
                entry["aliases"].remove("wksn01")
        d.add_canonical("wksn01")
        d._rebuild_alias_map()
        d.save()

        reloaded = HostDictionary.load(p)
        assert "wksn01" in reloaded.hosts
        assert "wksn01" not in reloaded.hosts["wkstn01"]["aliases"]
        assert reloaded.resolve("wksn01") == "wksn01"

    def test_fix_when_raw_is_itself_a_canonical(self, tmp_path, monkeypatch):
        """Issue #4 — operator collapses an existing canonical into another.

        Pre-fix: case_host_fix("wkstn01", "admin01") with wkstn01 as a
        canonical would leave wkstn01.hosts entry orphaned. After
        _rebuild_alias_map, the canonical self-mapping (wkstn01 → wkstn01)
        wins over the new alias mapping (wkstn01 → admin01), so resolve
        still returns "wkstn01". The fix deletes the canonical entry.
        """
        from unittest.mock import patch

        _seed_case_v1(
            tmp_path,
            "INC-EDGE",
            dict_hosts={
                "admin01": {"aliases": ["admin01"]},
                "wkstn01": {"aliases": ["wkstn01"]},  # collapsed-from
            },
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        fake_vhir = tmp_path / "vhir"
        fake_vhir.mkdir()
        (fake_vhir / "active_case").write_text("INC-EDGE\n")
        monkeypatch.setattr("opensearch_mcp.paths.vhir_dir", lambda: fake_vhir)
        monkeypatch.setattr("opensearch_mcp.server.vhir_dir", lambda: fake_vhir, raising=False)

        with patch("opensearch_mcp.server._get_os") as mock_get_os:
            mock_client = MagicMock()
            mock_client.update_by_query.return_value = {"updated": 0, "took": 1}
            mock_get_os.return_value = mock_client

            from opensearch_mcp.server import case_host_fix

            result = case_host_fix(raw="wkstn01", new_canonical="admin01")

        assert "error" not in result, f"unexpected error: {result.get('error')}"

        # Reload the persisted dict and verify the collapse actually took.
        from opensearch_mcp.host_dictionary import HostDictionary

        d = HostDictionary.load(tmp_path / "INC-EDGE" / "host-dictionary.yaml")
        assert "wkstn01" not in d.hosts, (
            "wkstn01 canonical entry must be deleted when collapsed into admin01"
        )
        assert "wkstn01" in d.hosts["admin01"]["aliases"]
        assert d.resolve("wkstn01") == "admin01", (
            f"resolve('wkstn01') must return 'admin01', got {d.resolve('wkstn01')!r}"
        )

    def test_fix_uses_term_filter_not_query_string(self):
        """Test 12 — case_host_fix builds a term-DSL query, NEVER query_string.

        Source-text guard against Lucene-injection regression.
        """
        import inspect

        from opensearch_mcp import server

        src = inspect.getsource(server._case_host_fix_impl)
        assert '"term": {"host.name": raw}' in src, (
            "case_host_fix must use term-DSL filter; raw values may contain Lucene metacharacters."
        )
        # The quoted-string `"query_string"` is how the DSL key would appear
        # if used as a filter. Plain-text references in comments are fine.
        assert '"query_string"' not in src, "case_host_fix must NOT use query_string DSL clause."

    def test_fix_saves_dict_before_reindex(self, tmp_path, monkeypatch):
        """Test 18 — save() is invoked BEFORE update_by_query.

        Order matters: a crash mid-call must leave the dict reflecting
        operator intent, not the stale state.
        """
        from unittest.mock import patch

        from opensearch_mcp.host_dictionary import HostDictionary

        _seed_case_v1(tmp_path, "INC-18", dict_hosts={"admin01": {"aliases": ["admin01"]}})
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        # Redirect vhir_dir() to tmp_path so active_case can be written.
        fake_vhir = tmp_path / "vhir"
        fake_vhir.mkdir()
        (fake_vhir / "active_case").write_text("INC-18\n")
        monkeypatch.setattr("opensearch_mcp.paths.vhir_dir", lambda: fake_vhir)
        monkeypatch.setattr("opensearch_mcp.server.vhir_dir", lambda: fake_vhir, raising=False)

        call_order: list[str] = []
        original_save = HostDictionary.save

        def tracking_save(self):
            call_order.append("save")
            return original_save(self)

        def fake_update_by_query(*args, **kwargs):
            call_order.append("update_by_query")
            return {"updated": 5, "took": 100}

        with (
            patch.object(HostDictionary, "save", tracking_save),
            patch("opensearch_mcp.server._get_os") as mock_get_os,
        ):
            mock_client = MagicMock()
            mock_client.update_by_query.side_effect = fake_update_by_query
            mock_get_os.return_value = mock_client

            from opensearch_mcp.server import case_host_fix

            case_host_fix(raw="wksn01", new_canonical="wkstn01-new")

        assert call_order == ["save", "update_by_query"], (
            f"Expected save before update_by_query, got {call_order}"
        )


# ---------------------------------------------------------------------------
# v1 Test 16 — parser resolve-miss stamps host.id = raw
# ---------------------------------------------------------------------------


class TestParserResolveMiss:
    def test_csv_resolve_miss_stamps_host_id_from_raw(self, tmp_path):
        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.parse_csv import ingest_csv

        csv_path = tmp_path / "miss.csv"
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Host", "data"])
            w.writerow(["UNKNOWN_HOST", "x"])

        captured: list[dict] = []

        def _stub(client, actions):
            captured.extend(actions)
            return len(actions), 0

        d = HostDictionary(hosts={"admin01": {"aliases": ["admin01"]}})

        with patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=_stub):
            ingest_csv(
                csv_path=csv_path,
                client=MagicMock(),
                index_name="case-test-miss",
                hostname="fallback",
                host_dict=d,
            )

        assert captured[0]["_source"]["host.id"] == "UNKNOWN_HOST"
        assert captured[0]["_source"]["host.name"] == "UNKNOWN_HOST"

    def test_csv_resolve_hit_stamps_canonical(self, tmp_path):
        """Companion: resolve hit → host.id is canonical, not raw."""
        from opensearch_mcp.host_dictionary import HostDictionary
        from opensearch_mcp.parse_csv import ingest_csv

        csv_path = tmp_path / "hit.csv"
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Host", "data"])
            w.writerow(["ADMIN01", "x"])

        captured: list[dict] = []

        def _stub(client, actions):
            captured.extend(actions)
            return len(actions), 0

        d = HostDictionary(hosts={"admin01": {"aliases": ["admin01", "ADMIN01"]}})

        with patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=_stub):
            ingest_csv(
                csv_path=csv_path,
                client=MagicMock(),
                index_name="case-test-hit",
                hostname="fallback",
                host_dict=d,
            )

        assert captured[0]["_source"]["host.id"] == "admin01"
        assert captured[0]["_source"]["host.name"] == "ADMIN01"


# ---------------------------------------------------------------------------
# v1 Test 17 — deletion regression guard
# ---------------------------------------------------------------------------


class TestDeletionGuard:
    """One combined guard. Catches: definition removal, call-site
    removal (line 633 of ingest_cli.py before deletion), AND
    rename-and-keep refactor via the sys.exit(2) semantic marker.
    """

    def test_classify_or_fail_and_yaml_writers_deleted(self):
        from opensearch_mcp import hostname as hostname_mod
        from opensearch_mcp import ingest_cli

        assert not hasattr(ingest_cli, "_classify_or_fail"), (
            "_classify_or_fail must remain deleted. v1 always-proceeds; fail-loud is gone."
        )
        assert not hasattr(hostname_mod, "write_host_unmapped_yaml")
        assert not hasattr(hostname_mod, "archive_resolved_unmapped_yaml")

        src_path = Path(ingest_cli.__file__)
        src = src_path.read_text()
        assert "_classify_or_fail(" not in src, (
            "ingest_cli.py contains a _classify_or_fail call site; "
            "even renamed, fail-loud is forbidden in v1."
        )
        # Semantic marker for the OLD fail-loud-on-unmapped-host path:
        # the print message was "Error: hostname_unmapped — N host(s)...".
        # Refined from a bare `sys.exit(2)` marker (M1 path-traversal
        # rejection legitimately exits 2 with a different message).
        assert "hostname_unmapped" not in src, (
            "ingest_cli.py references hostname_unmapped — the semantic "
            "marker of the old fail-loud-on-unmapped-host path. "
            "v1 always-proceeds; that flow is forbidden."
        )
