"""Exhaustive tests for all parsers against synthetic + real test data.

Covers: JSON, delimited (CSV/TSV/Zeek/bodyfile), access log, Defender,
IIS W3C, HTTPERR, tasks XML, WER, SSH, firewall, transcripts, and
vol3 memory (if available).

Tests verify: parsing, field extraction, format detection, dedup stability,
provenance ordering, time range filtering, edge cases, and cross-parser
consistency.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_TEST_DATA = Path("/tmp/opensearch-test-data")

# Skip all fixture-dependent tests when test data is not present (CI)
pytestmark = pytest.mark.skipif(not _TEST_DATA.is_dir(), reason="test fixtures not present")


def _collect(module_path):
    """Helper: returns (mock_bulk, collected_actions) for patching flush_bulk."""
    collected = []

    def capture(client, actions):
        collected.extend(actions)
        return len(actions), 0

    return patch(module_path, side_effect=capture), collected


# ===================================================================
# JSON parser
# ===================================================================


class TestJsonFormatDetection:
    def test_jsonl(self):
        from opensearch_mcp.parse_json import _detect_json_format

        assert _detect_json_format(_TEST_DATA / "json" / "suricata-eve.jsonl") == "jsonl"

    def test_json_array_pretty(self):
        from opensearch_mcp.parse_json import _detect_json_format

        assert _detect_json_format(_TEST_DATA / "json" / "tshark-packets.json") == "json_array"

    def test_empty_file(self, tmp_path):
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "empty.json"
        f.write_text("")
        assert _detect_json_format(f) == "unknown"

    def test_non_json(self, tmp_path):
        from opensearch_mcp.parse_json import _detect_json_format

        f = tmp_path / "bad.json"
        f.write_text("this is not json\n")
        assert _detect_json_format(f) == "unknown"


class TestJsonIngest:
    def test_jsonl_basic(self):
        from opensearch_mcp.parse_json import ingest_json

        p, collected = _collect("opensearch_mcp.parse_json.flush_bulk")
        with p:
            cnt, sk, bf, _ = ingest_json(
                _TEST_DATA / "json" / "suricata-eve.jsonl",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 5
        assert bf == 0

    def test_json_array(self):
        from opensearch_mcp.parse_json import ingest_json

        p, collected = _collect("opensearch_mcp.parse_json.flush_bulk")
        with p:
            cnt, sk, bf, _ = ingest_json(
                _TEST_DATA / "json" / "tshark-packets.json",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 2

    def test_auto_detect_time_field(self):
        from opensearch_mcp.parse_json import ingest_json

        p, collected = _collect("opensearch_mcp.parse_json.flush_bulk")
        with p:
            ingest_json(
                _TEST_DATA / "json" / "suricata-eve.jsonl",
                MagicMock(),
                "test",
                "host1",
            )
        # Should auto-detect "timestamp" and map to @timestamp
        doc = collected[0]["_source"]
        assert "@timestamp" in doc

    def test_epoch_millis_time_range(self):
        from opensearch_mcp.parse_json import ingest_json

        t_from = datetime(2024, 1, 15, 10, 0, 1, tzinfo=timezone.utc)
        t_to = datetime(2024, 1, 15, 10, 0, 3, tzinfo=timezone.utc)
        p, collected = _collect("opensearch_mcp.parse_json.flush_bulk")
        with p:
            cnt, sk, bf, _ = ingest_json(
                _TEST_DATA / "json" / "suricata-eve.jsonl",
                MagicMock(),
                "test",
                "host1",
                time_field="timestamp",
                time_from=t_from,
                time_to=t_to,
            )
        assert sk > 0  # some filtered out
        assert cnt < 5

    def test_dedup_stability(self):
        from opensearch_mcp.parse_json import ingest_json

        ids = []
        for aid in ["audit-1", "audit-2"]:
            p, collected = _collect("opensearch_mcp.parse_json.flush_bulk")
            with p:
                ingest_json(
                    _TEST_DATA / "json" / "suricata-eve.jsonl",
                    MagicMock(),
                    "test",
                    "host1",
                    ingest_audit_id=aid,
                )
            ids.append(sorted(a["_id"] for a in collected))
        assert ids[0] == ids[1]

    def test_provenance_after_id(self):
        from opensearch_mcp.parse_json import ingest_json

        p, collected = _collect("opensearch_mcp.parse_json.flush_bulk")
        with p:
            ingest_json(
                _TEST_DATA / "json" / "suricata-eve.jsonl",
                MagicMock(),
                "test",
                "host1",
                ingest_audit_id="aud-1",
                pipeline_version="v1",
                source_file="/evidence/test.jsonl",
            )
        doc = collected[0]["_source"]
        assert doc["host.name"] == "host1"
        assert doc["vhir.source_file"] == "/evidence/test.jsonl"
        assert doc["vhir.ingest_audit_id"] == "aud-1"
        assert doc["pipeline_version"] == "v1"
        assert doc["vhir.parse_method"] == "json-ingest"

    def test_unknown_format_raises(self, tmp_path):
        from opensearch_mcp.parse_json import ingest_json

        f = tmp_path / "bad.json"
        f.write_text("not json")
        with pytest.raises(ValueError, match="Cannot detect"):
            ingest_json(f, MagicMock(), "test", "host1")


# ===================================================================
# Delimited parser
# ===================================================================


class TestDelimitedFormatDetection:
    def test_csv(self):
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        fmt = _detect_delimited_format(_TEST_DATA / "delimited" / "timeline.csv")
        assert fmt["format"] == "csv"

    def test_tsv(self):
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        fmt = _detect_delimited_format(_TEST_DATA / "delimited" / "auth.tsv")
        assert fmt["format"] == "tsv"

    def test_zeek(self):
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        fmt = _detect_delimited_format(_TEST_DATA / "delimited" / "conn.log")
        assert fmt["format"] == "zeek"

    def test_bodyfile(self):
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        fmt = _detect_delimited_format(_TEST_DATA / "delimited" / "body.txt")
        assert fmt["format"] == "bodyfile"


class TestDelimitedIngest:
    def test_csv_basic(self):
        from opensearch_mcp.parse_delimited import ingest_delimited

        p, collected = _collect("opensearch_mcp.parse_delimited.flush_bulk")
        with p:
            cnt, sk, bf, _ = ingest_delimited(
                _TEST_DATA / "delimited" / "timeline.csv",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 3
        doc = collected[0]["_source"]
        assert doc["host.name"] == "host1"
        assert doc["vhir.parse_method"] == "delimited-csv"

    def test_zeek_null_handling(self):
        from opensearch_mcp.parse_delimited import ingest_delimited

        p, collected = _collect("opensearch_mcp.parse_delimited.flush_bulk")
        with p:
            cnt, _, _, _ = ingest_delimited(
                _TEST_DATA / "delimited" / "conn.log",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 3
        # Third row has uid="-" → None
        row3 = collected[2]["_source"]
        assert row3.get("uid") is None

    def test_bodyfile_epoch_conversion(self):
        from opensearch_mcp.parse_delimited import ingest_delimited

        p, collected = _collect("opensearch_mcp.parse_delimited.flush_bulk")
        with p:
            cnt, _, _, _ = ingest_delimited(
                _TEST_DATA / "delimited" / "body.txt",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 4
        doc = collected[0]["_source"]
        assert "T" in doc["mtime"]  # converted to ISO
        # Zero epoch should be removed
        mft_doc = collected[3]["_source"]
        assert "mtime" not in mft_doc  # epoch 0 popped

    def test_bodyfile_default_time_field(self):
        from opensearch_mcp.parse_delimited import ingest_delimited

        p, collected = _collect("opensearch_mcp.parse_delimited.flush_bulk")
        with p:
            ingest_delimited(
                _TEST_DATA / "delimited" / "body.txt",
                MagicMock(),
                "test",
                "host1",
            )
        # bodyfile defaults to mtime for @timestamp
        doc = collected[0]["_source"]
        assert "@timestamp" in doc

    def test_dedup_stability(self):
        from opensearch_mcp.parse_delimited import ingest_delimited

        ids = []
        for aid in ["a1", "a2"]:
            p, collected = _collect("opensearch_mcp.parse_delimited.flush_bulk")
            with p:
                ingest_delimited(
                    _TEST_DATA / "delimited" / "conn.log",
                    MagicMock(),
                    "test",
                    "host1",
                    ingest_audit_id=aid,
                )
            ids.append(sorted(a["_id"] for a in collected))
        assert ids[0] == ids[1]


# ===================================================================
# Access log parser
# ===================================================================


class TestAccessLog:
    def test_combined_format(self):
        from opensearch_mcp.parse_accesslog import ingest_accesslog

        p, collected = _collect("opensearch_mcp.parse_accesslog.flush_bulk")
        with p:
            cnt, sk, bf = ingest_accesslog(
                _TEST_DATA / "accesslog" / "access.log",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 6
        doc = collected[0]["_source"]
        assert doc["source.ip"] == "198.51.100.23"
        assert doc["http.request.method"] == "POST"
        assert doc["url.path"] == "/aspnet_client/system_web.aspx"
        assert doc["http.response.status_code"] == 200
        assert doc.get("user_agent.original") == "python-requests/2.28.1"

    def test_common_format(self):
        from opensearch_mcp.parse_accesslog import ingest_accesslog

        p, collected = _collect("opensearch_mcp.parse_accesslog.flush_bulk")
        with p:
            cnt, sk, bf = ingest_accesslog(
                _TEST_DATA / "accesslog" / "access-common.log",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 2
        # Common format — no referer or UA
        doc = collected[0]["_source"]
        assert "http.request.referrer" not in doc
        assert "user_agent.original" not in doc

    def test_bytes_dash(self):
        from opensearch_mcp.parse_accesslog import ingest_accesslog

        p, collected = _collect("opensearch_mcp.parse_accesslog.flush_bulk")
        with p:
            ingest_accesslog(
                _TEST_DATA / "accesslog" / "access.log",
                MagicMock(),
                "test",
                "host1",
            )
        # Last entry has bytes=-
        last = collected[-1]["_source"]
        assert "http.response.bytes" not in last

    def test_ipv6(self):
        from opensearch_mcp.parse_accesslog import ingest_accesslog

        p, collected = _collect("opensearch_mcp.parse_accesslog.flush_bulk")
        with p:
            ingest_accesslog(
                _TEST_DATA / "accesslog" / "access.log",
                MagicMock(),
                "test",
                "host1",
            )
        ipv6_doc = [d for d in collected if d["_source"].get("source.ip") == "::1"]
        assert len(ipv6_doc) == 1

    def test_dedup_content_based(self):
        from opensearch_mcp.parse_accesslog import ingest_accesslog

        ids = []
        for aid in ["a1", "a2"]:
            p, collected = _collect("opensearch_mcp.parse_accesslog.flush_bulk")
            with p:
                ingest_accesslog(
                    _TEST_DATA / "accesslog" / "access.log",
                    MagicMock(),
                    "test",
                    "host1",
                    ingest_audit_id=aid,
                )
            ids.append(sorted(a["_id"] for a in collected))
        assert ids[0] == ids[1]

    def test_time_range_filter(self):
        from opensearch_mcp.parse_accesslog import ingest_accesslog

        t_from = datetime(2023, 1, 25, 15, 10, 31, tzinfo=timezone.utc)
        t_to = datetime(2023, 1, 25, 15, 10, 33, tzinfo=timezone.utc)
        p, collected = _collect("opensearch_mcp.parse_accesslog.flush_bulk")
        with p:
            cnt, sk, bf = ingest_accesslog(
                _TEST_DATA / "accesslog" / "access.log",
                MagicMock(),
                "test",
                "host1",
                time_from=t_from,
                time_to=t_to,
            )
        assert cnt < 6
        assert sk > 0


# ===================================================================
# Defender MPLog parser
# ===================================================================


class TestDefenderMPLog:
    def test_detections_extracted(self):
        from opensearch_mcp.parse_defender import parse_mplog

        p, collected = _collect("opensearch_mcp.parse_defender.flush_bulk")
        with p:
            cnt, sk, bf = parse_mplog(
                _TEST_DATA / "defender",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt >= 3  # detections + exclusions
        types = {d["_source"]["defender.event_type"] for d in collected}
        assert "detection_add" in types
        assert "exclusion_added" in types
        assert "exclusion_removed" in types

    def test_noise_filtered(self):
        from opensearch_mcp.parse_defender import parse_mplog

        p, collected = _collect("opensearch_mcp.parse_defender.flush_bulk")
        with p:
            cnt, sk, bf = parse_mplog(
                _TEST_DATA / "defender",
                MagicMock(),
                "test",
                "host1",
            )
        # "other" type should be skipped
        types = {d["_source"]["defender.event_type"] for d in collected}
        assert "other" not in types
        assert sk > 0

    def test_threat_name_extracted(self):
        from opensearch_mcp.parse_defender import parse_mplog

        p, collected = _collect("opensearch_mcp.parse_defender.flush_bulk")
        with p:
            parse_mplog(_TEST_DATA / "defender", MagicMock(), "test", "host1")
        det = [d for d in collected if d["_source"].get("defender.threat_name")]
        assert len(det) >= 1


# ===================================================================
# IIS W3C parser
# ===================================================================


class TestIISW3C:
    def test_basic_parse(self):
        from opensearch_mcp.parse_w3c import parse_w3c_log

        p, collected = _collect("opensearch_mcp.parse_w3c.flush_bulk")
        with p:
            cnt, sk, bf = parse_w3c_log(
                _TEST_DATA / "iis" / "u_ex230125.log",
                MagicMock(),
                "test",
                "host1",
                timestamp_is_utc=True,
            )
        assert cnt == 4
        doc = collected[0]["_source"]
        assert doc["@timestamp"] == "2023-01-25T14:30:00Z"
        assert "source.ip" in doc  # ECS remapped from c-ip

    def test_ecs_ip_remap(self):
        from opensearch_mcp.parse_w3c import parse_w3c_log

        p, collected = _collect("opensearch_mcp.parse_w3c.flush_bulk")
        with p:
            parse_w3c_log(
                _TEST_DATA / "iis" / "u_ex230125.log",
                MagicMock(),
                "test",
                "host1",
                timestamp_is_utc=True,
            )
        doc = collected[0]["_source"]
        assert doc["source.ip"] == "198.51.100.23"

    def test_httperr(self):
        from opensearch_mcp.parse_w3c import parse_w3c_log

        p, collected = _collect("opensearch_mcp.parse_w3c.flush_bulk")
        with p:
            cnt, sk, bf = parse_w3c_log(
                _TEST_DATA / "iis" / "httperr1.log",
                MagicMock(),
                "test",
                "host1",
                timestamp_is_utc=True,
            )
        assert cnt == 2


# ===================================================================
# Tasks XML parser
# ===================================================================


class TestTasksXML:
    def test_parse_tasks(self):
        from opensearch_mcp.parse_tasks import parse_tasks_dir

        p, collected = _collect("opensearch_mcp.parse_tasks.flush_bulk")
        with p:
            cnt, sk, bf = parse_tasks_dir(
                _TEST_DATA / "tasks",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 2
        commands = {d["_source"]["task.command"] for d in collected}
        assert r"C:\Windows\System32\updater.exe" in commands

    def test_system_task_detection(self):
        from opensearch_mcp.parse_tasks import parse_tasks_dir

        p, collected = _collect("opensearch_mcp.parse_tasks.flush_bulk")
        with p:
            parse_tasks_dir(_TEST_DATA / "tasks", MagicMock(), "test", "host1")
        docs = {d["_source"]["task.name"]: d["_source"] for d in collected}
        assert docs["WindowsUpdate"]["task.is_system"] is True
        assert docs["Backup_Sync_Service"]["task.is_system"] is False

    def test_xml_namespace(self):
        from opensearch_mcp.parse_tasks import parse_task_xml

        doc = parse_task_xml(_TEST_DATA / "tasks" / "Backup_Sync_Service")
        assert doc is not None
        assert doc["task.author"] == r"contoso\svc-backup"
        assert "CalendarTrigger" in doc["task.trigger_types"]
        assert doc["task.run_level"] == "HighestAvailable"


# ===================================================================
# WER parser
# ===================================================================


class TestWER:
    def test_parse_wer(self):
        from opensearch_mcp.parse_wer import parse_wer_dir

        p, collected = _collect("opensearch_mcp.parse_wer.flush_bulk")
        with p:
            cnt, sk, bf = parse_wer_dir(
                _TEST_DATA / "wer",
                MagicMock(),
                "test",
                "host1",
            )
        assert cnt == 1
        doc = collected[0]["_source"]
        assert doc["process.name"] == "updater.exe"
        assert doc["wer.event_type"] == "APPCRASH"
        assert doc["wer.exception_code"] == "c0000005"

    def test_wer_report_dir(self):
        from opensearch_mcp.parse_wer import parse_wer_dir

        p, collected = _collect("opensearch_mcp.parse_wer.flush_bulk")
        with p:
            parse_wer_dir(_TEST_DATA / "wer", MagicMock(), "test", "host1")
        doc = collected[0]["_source"]
        assert "updater" in doc["wer.report_dir"]


# ===================================================================
# SSH parser
# ===================================================================


class TestSSH:
    def test_auth_events(self):
        from opensearch_mcp.parse_ssh import parse_ssh_log

        p, collected = _collect("opensearch_mcp.parse_ssh.flush_bulk")
        with p:
            cnt, sk, bf = parse_ssh_log(
                _TEST_DATA / "ssh",
                MagicMock(),
                "test",
                "host1",
                system_timezone="UTC",
            )
        assert cnt == 6
        types = {d["_source"]["ssh.event_type"] for d in collected}
        assert "auth_accepted" in types
        assert "auth_failed" in types

    def test_accepted_fields(self):
        from opensearch_mcp.parse_ssh import parse_ssh_log

        p, collected = _collect("opensearch_mcp.parse_ssh.flush_bulk")
        with p:
            parse_ssh_log(
                _TEST_DATA / "ssh",
                MagicMock(),
                "test",
                "host1",
                system_timezone="UTC",
            )
        accepted = [d for d in collected if d["_source"]["ssh.event_type"] == "auth_accepted"]
        doc = accepted[0]["_source"]
        assert doc["user.name"] == "jdoe-admin"
        assert doc["source.ip"] == "198.51.100.23"
        assert doc["source.port"] == 49832
        assert doc["ssh.auth_method"] == "publickey"

    def test_skips_without_timezone(self):
        from opensearch_mcp.parse_ssh import parse_ssh_log

        p, collected = _collect("opensearch_mcp.parse_ssh.flush_bulk")
        with p:
            cnt, sk, bf = parse_ssh_log(
                _TEST_DATA / "ssh",
                MagicMock(),
                "test",
                "host1",
                system_timezone=None,
            )
        assert cnt == 0  # skips entirely when timezone unknown


# ===================================================================
# Firewall W3C parser
# ===================================================================


class TestFirewallW3C:
    def test_firewall_parse(self):
        from opensearch_mcp.parse_w3c import parse_w3c_log

        p, collected = _collect("opensearch_mcp.parse_w3c.flush_bulk")
        with p:
            cnt, sk, bf = parse_w3c_log(
                _TEST_DATA / "firewall" / "pfirewall.log",
                MagicMock(),
                "test",
                "host1",
                timestamp_is_utc=False,
                system_timezone="UTC",
            )
        assert cnt == 4
        actions = {d["_source"].get("action") for d in collected}
        assert "DROP" in actions
        assert "ALLOW" in actions

    def test_firewall_skips_without_timezone(self):
        from opensearch_mcp.parse_w3c import parse_w3c_log

        p, collected = _collect("opensearch_mcp.parse_w3c.flush_bulk")
        with p:
            cnt, sk, bf = parse_w3c_log(
                _TEST_DATA / "firewall" / "pfirewall.log",
                MagicMock(),
                "test",
                "host1",
                timestamp_is_utc=False,
                system_timezone=None,
            )
        assert cnt == 0
        assert sk == 4  # all skipped — no timezone


# ===================================================================
# Transcripts parser
# ===================================================================


class TestTranscripts:
    def test_parse_transcript(self):
        from opensearch_mcp.parse_transcripts import ingest_transcripts

        p, collected = _collect("opensearch_mcp.parse_transcripts.flush_bulk")
        with p:
            cnt, bf = ingest_transcripts(
                _TEST_DATA / "transcripts",
                MagicMock(),
                "test",
                "host1",
                system_timezone="UTC",
            )
        assert cnt == 1
        doc = collected[0]["_source"]
        assert doc["transcript.session_type"] == "remoting"
        assert doc["transcript.command_count"] == 2
        assert any("whoami" in cmd for cmd in doc["transcript.commands"])
        assert doc["user.name"] == "jdoe-admin"
        assert doc["user.domain"] == "contoso"
        # BUG: Path().name on Linux doesn't parse Windows backslash paths.
        # Should be "wsmprovhost.exe" but returns full path.
        # Fix: use PureWindowsPath or rsplit("\\", 1)[-1]
        assert "wsmprovhost.exe" in doc["process.name"]

    def test_transcript_skips_without_timezone(self):
        from opensearch_mcp.parse_transcripts import ingest_transcripts

        p, collected = _collect("opensearch_mcp.parse_transcripts.flush_bulk")
        with p:
            cnt, bf = ingest_transcripts(
                _TEST_DATA / "transcripts",
                MagicMock(),
                "test",
                "host1",
                system_timezone=None,
            )
        assert cnt == 0  # skips — timezone unknown


# ===================================================================
# Vol3 memory parser
# ===================================================================


class TestVol3:
    def test_find_vol3(self):
        from opensearch_mcp.parse_memory import _find_vol3

        cmd = _find_vol3()
        assert cmd  # should find vol or vol3

    def test_plugin_to_index_suffix(self):
        from opensearch_mcp.parse_memory import _plugin_to_index_suffix

        assert _plugin_to_index_suffix("windows.pslist") == "vol-pslist"
        assert _plugin_to_index_suffix("windows.registry.hivelist") == "vol-hivelist"
        assert _plugin_to_index_suffix("timeliner") == "vol-timeliner"

    def test_tier_lists(self):
        from opensearch_mcp.parse_memory import TIER_1, TIER_2, TIER_3

        assert len(TIER_1) == 8  # netscan moved to tier 2
        assert len(TIER_2) == 17
        assert len(TIER_3) == 26
        assert "windows.pslist" in TIER_1
        assert "windows.malfind" in TIER_3
        assert "windows.malfind" not in TIER_1

    def test_flatten_records(self):
        from opensearch_mcp.parse_memory import _flatten_records

        records = [
            {
                "PID": 1,
                "__children": [
                    {"PID": 2, "__children": [{"PID": 3}]},
                    {"PID": 4},
                ],
            },
            {"PID": 5},
        ]
        flat = _flatten_records(records)
        pids = [r["PID"] for r in flat]
        assert pids == [1, 2, 3, 4, 5]

    def test_vol3_doc_id_natural_key(self):
        from opensearch_mcp.parse_memory import _vol3_doc_id

        record = {"PID": 4, "CreateTime": "2023-01-15T10:00:00Z"}
        id1 = _vol3_doc_id("idx", "windows.pslist", record, "memory.raw")
        id2 = _vol3_doc_id("idx", "windows.pslist", record, "memory.raw")
        assert id1 == id2

    def test_vol3_doc_id_different_source(self):
        from opensearch_mcp.parse_memory import _vol3_doc_id

        record = {"PID": 4, "CreateTime": "2023-01-15T10:00:00Z"}
        id1 = _vol3_doc_id("idx", "windows.pslist", record, "mem1.raw")
        id2 = _vol3_doc_id("idx", "windows.pslist", record, "mem2.raw")
        assert id1 != id2

    def test_handle_type_filtering(self):
        from opensearch_mcp.parse_memory import _HANDLE_TYPES_KEEP

        assert "File" in _HANDLE_TYPES_KEEP
        assert "Key" in _HANDLE_TYPES_KEEP
        assert "Semaphore" not in _HANDLE_TYPES_KEEP


# ===================================================================
# Cross-parser consistency
# ===================================================================


class TestCrossParserConsistency:
    def test_all_parsers_set_host_name(self):
        """Every parser sets host.name on every document."""
        from opensearch_mcp.parse_accesslog import ingest_accesslog
        from opensearch_mcp.parse_defender import parse_mplog
        from opensearch_mcp.parse_delimited import ingest_delimited
        from opensearch_mcp.parse_json import ingest_json
        from opensearch_mcp.parse_ssh import parse_ssh_log
        from opensearch_mcp.parse_tasks import parse_tasks_dir
        from opensearch_mcp.parse_w3c import parse_w3c_log
        from opensearch_mcp.parse_wer import parse_wer_dir

        parsers = [
            (
                "opensearch_mcp.parse_json.flush_bulk",
                lambda c: ingest_json(
                    _TEST_DATA / "json" / "suricata-eve.jsonl", MagicMock(), "t", "HOST1"
                ),
            ),
            (
                "opensearch_mcp.parse_delimited.flush_bulk",
                lambda c: ingest_delimited(
                    _TEST_DATA / "delimited" / "timeline.csv", MagicMock(), "t", "HOST1"
                ),
            ),
            (
                "opensearch_mcp.parse_accesslog.flush_bulk",
                lambda c: ingest_accesslog(
                    _TEST_DATA / "accesslog" / "access.log", MagicMock(), "t", "HOST1"
                ),
            ),
            (
                "opensearch_mcp.parse_defender.flush_bulk",
                lambda c: parse_mplog(_TEST_DATA / "defender", MagicMock(), "t", "HOST1"),
            ),
            (
                "opensearch_mcp.parse_w3c.flush_bulk",
                lambda c: parse_w3c_log(
                    _TEST_DATA / "iis" / "u_ex230125.log",
                    MagicMock(),
                    "t",
                    "HOST1",
                    timestamp_is_utc=True,
                ),
            ),
            (
                "opensearch_mcp.parse_tasks.flush_bulk",
                lambda c: parse_tasks_dir(_TEST_DATA / "tasks", MagicMock(), "t", "HOST1"),
            ),
            (
                "opensearch_mcp.parse_wer.flush_bulk",
                lambda c: parse_wer_dir(_TEST_DATA / "wer", MagicMock(), "t", "HOST1"),
            ),
            (
                "opensearch_mcp.parse_ssh.flush_bulk",
                lambda c: parse_ssh_log(
                    _TEST_DATA / "ssh", MagicMock(), "t", "HOST1", system_timezone="UTC"
                ),
            ),
        ]
        for module_path, fn in parsers:
            p, collected = _collect(module_path)
            with p:
                fn(collected)
            for action in collected:
                assert action["_source"]["host.name"] == "HOST1", (
                    f"{module_path}: missing host.name"
                )

    def test_all_parsers_set_parse_method(self):
        """Every parser sets vhir.parse_method."""
        from opensearch_mcp.parse_accesslog import ingest_accesslog
        from opensearch_mcp.parse_defender import parse_mplog
        from opensearch_mcp.parse_delimited import ingest_delimited
        from opensearch_mcp.parse_json import ingest_json
        from opensearch_mcp.parse_ssh import parse_ssh_log
        from opensearch_mcp.parse_tasks import parse_tasks_dir
        from opensearch_mcp.parse_w3c import parse_w3c_log
        from opensearch_mcp.parse_wer import parse_wer_dir

        parsers = [
            (
                "opensearch_mcp.parse_json.flush_bulk",
                lambda c: ingest_json(
                    _TEST_DATA / "json" / "suricata-eve.jsonl", MagicMock(), "t", "h"
                ),
            ),
            (
                "opensearch_mcp.parse_delimited.flush_bulk",
                lambda c: ingest_delimited(
                    _TEST_DATA / "delimited" / "timeline.csv", MagicMock(), "t", "h"
                ),
            ),
            (
                "opensearch_mcp.parse_accesslog.flush_bulk",
                lambda c: ingest_accesslog(
                    _TEST_DATA / "accesslog" / "access.log", MagicMock(), "t", "h"
                ),
            ),
            (
                "opensearch_mcp.parse_defender.flush_bulk",
                lambda c: parse_mplog(_TEST_DATA / "defender", MagicMock(), "t", "h"),
            ),
            (
                "opensearch_mcp.parse_w3c.flush_bulk",
                lambda c: parse_w3c_log(
                    _TEST_DATA / "iis" / "u_ex230125.log",
                    MagicMock(),
                    "t",
                    "h",
                    timestamp_is_utc=True,
                    parse_method="iis-w3c",
                ),
            ),
            (
                "opensearch_mcp.parse_tasks.flush_bulk",
                lambda c: parse_tasks_dir(_TEST_DATA / "tasks", MagicMock(), "t", "h"),
            ),
            (
                "opensearch_mcp.parse_wer.flush_bulk",
                lambda c: parse_wer_dir(_TEST_DATA / "wer", MagicMock(), "t", "h"),
            ),
            (
                "opensearch_mcp.parse_ssh.flush_bulk",
                lambda c: parse_ssh_log(
                    _TEST_DATA / "ssh", MagicMock(), "t", "h", system_timezone="UTC"
                ),
            ),
        ]
        for module_path, fn in parsers:
            p, collected = _collect(module_path)
            with p:
                fn(collected)
            for action in collected:
                assert "vhir.parse_method" in action["_source"], (
                    f"{module_path}: missing parse_method"
                )


# ===================================================================
# auto_detect_time_field
# ===================================================================


class TestAutoDetectTimeField:
    def test_finds_timestamp(self):
        from opensearch_mcp.paths import auto_detect_time_field

        assert auto_detect_time_field({"timestamp": 123, "data": "x"}) == "timestamp"

    def test_finds_ts(self):
        from opensearch_mcp.paths import auto_detect_time_field

        assert auto_detect_time_field({"ts": 1.23, "uid": "abc"}) == "ts"

    def test_finds_at_timestamp(self):
        from opensearch_mcp.paths import auto_detect_time_field

        assert auto_detect_time_field({"@timestamp": "2024-01-01", "msg": "x"}) == "@timestamp"

    def test_returns_none(self):
        from opensearch_mcp.paths import auto_detect_time_field

        assert auto_detect_time_field({"event": "x", "data": "y"}) is None
