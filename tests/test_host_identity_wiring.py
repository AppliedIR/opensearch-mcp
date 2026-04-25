"""End-to-end wiring tests for host-identity Rev 1.5 Commit B.

Closes the spec-vs-code delta flagged by Arch review 2026-04-24 —
primitives were shipped in 6c6b698 but not wired; this follow-up
commit wires them into parse_csv, parse_json, and cmd_scan.

Covers:
  Test 6  — parse_csv per-row host.name from priority list
  Test 5  — parse_json per-doc host.name from priority list
            (spec's test 13 assertion shape at the doc-level)
  Test 14 — cmd_scan blocks on unmapped hosts by writing
            host-unmapped.yaml + exiting with hostname_unmapped
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
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
# cmd_scan batch-discovery + fail-loud (Test 14)
# ---------------------------------------------------------------------------


class TestCmdScanFailLoud:
    """Spec Test 14 — ingest must NOT start when host-dictionary binds
    and any discovered host is unmapped. host-unmapped.yaml is written
    to the case dir; exit code distinguishes from other errors."""

    def _seed_case_with_dict(self, cases_dir: Path, dict_hosts: dict) -> Path:
        case_dir = cases_dir / "INC-TEST"
        case_dir.mkdir(parents=True)
        (case_dir / "CASE.yaml").write_text("case_id: INC-TEST\n")
        (case_dir / "host-dictionary.yaml").write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "auto_accept_high_confidence": True,
                    "domains": ["shieldbase.com"],
                    "hosts": dict_hosts,
                    "unmapped": [],
                }
            )
        )
        return case_dir

    def _mock_hosts(self, hostnames):
        """Build minimal DiscoveredHost-shaped mocks for the classifier."""
        return [MagicMock(hostname=h) for h in hostnames]

    def test_unmapped_host_blocks_ingest_and_writes_yaml(self, tmp_path, monkeypatch):
        from opensearch_mcp.ingest_cli import _load_case_host_dict

        case_dir = self._seed_case_with_dict(
            tmp_path,
            {"admin01": {"aliases": ["admin01", "ADMIN01", "admin01.shieldbase.com"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        # Verify dict loads correctly via the helper under test
        d = _load_case_host_dict("INC-TEST")
        assert d is not None
        assert d.resolve("admin01") == "admin01"

        # Classify the unmapped host like cmd_scan will
        from opensearch_mcp.hostname import classify_host, write_host_unmapped_yaml

        discovered = self._mock_hosts(["wksn01"])  # not in dict
        unmapped = []
        for h in discovered:
            status, raw, proposed, conf = classify_host(h.hostname, d)
            if status.startswith("unmapped"):
                unmapped.append(
                    {
                        "raw": raw,
                        "first_seen": "2026-04-24T00:00:00Z",
                        "sources": ["test"],
                        "proposed_canonical": proposed,
                        "confidence": conf,
                        "action_required": "vhir case host add wksn01 --new-canonical",
                    }
                )

        assert len(unmapped) == 1
        yaml_path = write_host_unmapped_yaml(case_dir, unmapped)
        assert yaml_path.exists()
        payload = yaml.safe_load(yaml_path.read_text())
        assert len(payload["entries"]) == 1
        assert payload["entries"][0]["raw"] == "wksn01"

    def test_all_mapped_does_not_write_yaml(self, tmp_path, monkeypatch):
        from opensearch_mcp.hostname import classify_host

        self._seed_case_with_dict(
            tmp_path,
            {
                "admin01": {"aliases": ["admin01", "ADMIN01"]},
                "rd01": {"aliases": ["rd01", "RD01"]},
            },
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        from opensearch_mcp.ingest_cli import _load_case_host_dict

        d = _load_case_host_dict("INC-TEST")
        assert d is not None

        discovered = self._mock_hosts(["admin01", "rd01"])
        unmapped = [
            h for h in discovered if classify_host(h.hostname, d)[0].startswith("unmapped")
        ]
        assert unmapped == []

    def test_no_case_dict_falls_back_to_legacy_behavior(self, tmp_path, monkeypatch):
        """Pre-C1 cases have no host-dictionary.yaml yet — ingest must
        proceed with the pre-existing behavior, not fail-loud."""
        from opensearch_mcp.ingest_cli import _load_case_host_dict

        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))
        assert _load_case_host_dict("NONEXISTENT_CASE") is None

    def test_malformed_dict_warns_and_returns_none(self, tmp_path, monkeypatch, capsys):
        """If the dictionary file exists but fails to load (bad version,
        corrupt YAML), fall back to legacy behavior with a warning
        rather than aborting."""
        from opensearch_mcp.ingest_cli import _load_case_host_dict

        case_dir = tmp_path / "BAD-CASE"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: BAD-CASE\n")
        # version=2 triggers UnsupportedHostDictVersion
        (case_dir / "host-dictionary.yaml").write_text(yaml.safe_dump({"version": 2, "hosts": {}}))
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        result = _load_case_host_dict("BAD-CASE")
        assert result is None
        err = capsys.readouterr().err
        assert "proceeding without host-dictionary validation" in err


# ---------------------------------------------------------------------------
# End-to-end cmd_scan wiring — Test 14 elevated + Test 4 archive-basename
# ---------------------------------------------------------------------------


def _seed_case(cases_dir: Path, case_id: str, dict_hosts: dict | None = None) -> Path:
    case_dir = cases_dir / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\n")
    if dict_hosts is not None:
        (case_dir / "host-dictionary.yaml").write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "auto_accept_high_confidence": True,
                    "domains": ["shieldbase.com"],
                    "hosts": dict_hosts,
                    "unmapped": [],
                }
            )
        )
    return case_dir


def _run_batch_discovery(hosts, case_id):
    """Invoke the EXACT function cmd_scan calls — no harness drift.

    Per CR review 2026-04-25, the previous version of this helper
    re-implemented cmd_scan's batch-discovery block, which would silently
    pass even if cmd_scan's call site got refactored away. The
    `_classify_or_fail` helper extracted into ingest_cli.py is now the
    single shared call site; this test wrapper just thins-passes through
    so failures on the production code path always surface here.
    """
    from opensearch_mcp.ingest_cli import _classify_or_fail

    _classify_or_fail(case_id, hosts, "test")


class TestCmdScanEndToEnd:
    """Spec Test 14 end-to-end + Test 4 archive-basename rejection."""

    def test_14_unmapped_blocks_then_rerun_succeeds_and_cleans_up(
        self, tmp_path, monkeypatch
    ):
        case_dir = _seed_case(
            tmp_path,
            "INC-14",
            dict_hosts={
                "admin01": {"aliases": ["admin01", "ADMIN01"]},
                "rd01": {"aliases": ["rd01", "RD01"]},
            },
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        # Run 1: 2 mapped + 1 unmapped → block with SystemExit(2)
        discovered_v1 = [
            MagicMock(hostname="admin01"),
            MagicMock(hostname="rd01"),
            MagicMock(hostname="wksn01"),
        ]
        with pytest.raises(SystemExit) as exc:
            _run_batch_discovery(discovered_v1, "INC-14")
        assert exc.value.code == 2

        yaml_path = case_dir / "host-unmapped.yaml"
        assert yaml_path.exists()
        payload = yaml.safe_load(yaml_path.read_text())
        assert len(payload["entries"]) == 1
        assert payload["entries"][0]["raw"] == "wksn01"

        # Operator resolves (add wksn01 → dict)
        dict_file = case_dir / "host-dictionary.yaml"
        dict_data = yaml.safe_load(dict_file.read_text())
        dict_data["hosts"]["wksn01"] = {"aliases": ["wksn01"]}
        dict_file.write_text(yaml.safe_dump(dict_data))

        # Run 2: all mapped → proceeds + cleanup rename
        _run_batch_discovery(discovered_v1, "INC-14")

        assert not yaml_path.exists(), "stale host-unmapped.yaml should be renamed"
        renamed = list(case_dir.glob("host-unmapped.yaml.resolved.*"))
        assert len(renamed) == 1
        assert renamed[0].name.endswith("Z")

    def test_4_archive_basename_style_name_rejected(self, tmp_path, monkeypatch):
        """Rev 1.5 criterion 1 bullet 3: archive-basename names (like
        `foo-triage` from the removed fallback) must fail-loud when
        they don't resolve against the dictionary, not silent-stamp.
        """
        _seed_case(
            tmp_path,
            "INC-4",
            dict_hosts={"admin01": {"aliases": ["admin01", "ADMIN01"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        discovered = [MagicMock(hostname="foo-triage")]
        with pytest.raises(SystemExit) as exc:
            _run_batch_discovery(discovered, "INC-4")
        assert exc.value.code == 2

        payload = yaml.safe_load(
            (tmp_path / "INC-4" / "host-unmapped.yaml").read_text()
        )
        assert payload["entries"][0]["raw"] == "foo-triage"

    def test_peek_rescues_junk_hostname_flow(self, tmp_path, monkeypatch):
        """Fix C step 3 fallback: when discover() produces junk names
        (registry detect failed), peek_hostname_from_evidence pulls a
        real name from the first CSV/JSON so host-unmapped.yaml carries
        actionable raw data instead of `_mnt_1` directory-scan junk.
        """
        import csv as _csv

        from opensearch_mcp.hostname import peek_hostname_from_evidence

        _seed_case(
            tmp_path,
            "INC-PEEK",
            dict_hosts={"admin01": {"aliases": ["admin01"]}},
        )
        monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path))

        scan_root = tmp_path / "scan"
        scan_root.mkdir()
        with open(scan_root / "kansa.csv", "w", newline="") as f:
            w = _csv.writer(f)
            w.writerow(["Host", "data"])
            w.writerow(["rd01.shieldbase.com", "x"])

        peeked = peek_hostname_from_evidence(scan_root)
        assert peeked == "rd01.shieldbase.com"

        discovered = [MagicMock(hostname=peeked)]
        with pytest.raises(SystemExit):
            _run_batch_discovery(discovered, "INC-PEEK")
        payload = yaml.safe_load(
            (tmp_path / "INC-PEEK" / "host-unmapped.yaml").read_text()
        )
        assert payload["entries"][0]["raw"] == "rd01.shieldbase.com"
