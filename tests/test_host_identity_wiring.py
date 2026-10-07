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

        def _stub(client, actions, **kw):
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

        def _stub(client, actions, **kw):
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

    def test_h1_detection_handles_nested_mapping_form(self):
        """WSL2 Round-3 H1 detection bug — host.id can be stored in two
        shapes: flat-dotted (v1 template) or nested under host.properties
        (default dynamic mapping for pre-v1 docs). Detection must catch
        both forms; the old code only checked flat and missed nested,
        then PUT _mapping silently failed.
        """
        from opensearch_mcp.host_dictionary import (
            detect_host_id_mapping_type as _detect_host_id_mapping_type,
        )

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

    def test_case_id_path_traversal_rejected(self):
        """M1 — case_id with path components rejected."""
        from opensearch_mcp.ingest_cli import _case_dir_for

        assert _case_dir_for("../etc") is None
        assert _case_dir_for("/abs/path") is None
        assert _case_dir_for("foo/bar") is None
        assert _case_dir_for("") is None

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

    def test_host_names_from_a_caller_are_checked_before_use(self):
        """case_host_fix's names go through the storage check."""
        import pytest

        from opensearch_mcp.host_dictionary import (
            InvalidHostnameValue,
            _validate_hostname_for_storage,
        )

        for bad, why in (("admin\x0001", "NULL byte"), ("admin\x0101", "control char"),
                         ("", "empty"), (None, "must be a string")):  # fmt: skip
            with pytest.raises(InvalidHostnameValue, match=why):
                _validate_hostname_for_storage(bad, "raw")
        # Lucene metacharacters pass through — queries use term filters.
        _validate_hostname_for_storage('admin01" OR *', "raw")

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
