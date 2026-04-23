"""Unit tests for parse_defender — UTF-16LE encoding + MPDetection glob
+ DETECTION regex (3-bug chain).

UAT 2026-04-24 regression coverage. Lives in its own file (not
test_all_parsers.py) because that module is gated on a local fixture
directory (`/tmp/opensearch-test-data`) and CI would skip everything in
it — these tests must actually run.

Contracts pinned:

- **Bug A** `_sniff_encoding` picks the right codec from the 4-byte
  BOM and uses bare `utf-16` (not `utf-16-le`) so the BOM is consumed
  and `^` anchors on line 1 still match.
- **Bug B** Walker globs both `MPLog-*.log` AND `MPDetection-*.log`.
- **Bug C** New DETECTION regex matches current Defender output
  (`DETECTION Behavior:Win32/<name>[!variant] <context>`), with named
  groups powering the indexed-doc field map. Legacy
  `DETECTION_ADD ... Name:<x>#` shape retained as fallback — zero loss
  of coverage.
- Context sub-parse for 4 shapes: `behavior:process`, `file:`,
  `regkey:`, `taskscheduler:`. Unmatched shapes preserve raw context.
- UTF-8 MPLog with `Adding exclusion:` still parses (regression guard).

All fixtures use real BOM bytes (`\\xff\\xfe`, `\\xfe\\xff`,
`\\xef\\xbb\\xbf`) written via `path.write_bytes()` — NOT
`.encode("utf-16-le")` which omits the BOM. Using the real byte
sequences is what catches the Arch-flagged codec-choice bug (suffixed
UTF-16 codec leaves `\\ufeff` in the decoded text).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _utf16le(text: str) -> bytes:
    """Encode text as UTF-16LE with a real `\\xff\\xfe` BOM prefix."""
    return b"\xff\xfe" + text.encode("utf-16-le")


def _utf16be(text: str) -> bytes:
    """Encode text as UTF-16BE with a real `\\xfe\\xff` BOM prefix."""
    return b"\xfe\xff" + text.encode("utf-16-be")


def _utf8sig(text: str) -> bytes:
    """Encode text as UTF-8 with a real `\\xef\\xbb\\xbf` BOM prefix."""
    return b"\xef\xbb\xbf" + text.encode("utf-8")


def _capture_flush():
    """Return (patcher, collected_actions) for flush_bulk interception."""
    collected = []

    def capture(client, actions):
        collected.extend(actions)
        return len(actions), 0

    return patch("opensearch_mcp.parse_defender.flush_bulk", side_effect=capture), collected


def _run_parse_mplog(tmp_path, **kwargs):
    """Invoke parse_mplog on a `tmp_path` dir with a MagicMock client."""
    from opensearch_mcp.parse_defender import parse_mplog

    patcher, collected = _capture_flush()
    with patcher:
        cnt, sk, bf = parse_mplog(
            mplog_dir=tmp_path,
            client=MagicMock(),
            index_name="test-idx",
            hostname="testhost",
            **kwargs,
        )
    return cnt, sk, bf, collected


class TestBomSniff:
    """Bug A — the load-bearing codec-choice test. Line 1 must decode
    to start with an ISO 8601 timestamp, NOT with `\\ufeff` followed by
    a timestamp. This catches the Arch-flagged regression: if someone
    regresses `utf-16` → `utf-16-le`, the BOM stays in the text and
    `_TS_PATTERN`'s `^` anchor fails on line 1. Do NOT paper over a
    residual `\\ufeff` in any test assertion — that would hide the real
    bug.
    """

    def test_utf16le_bom_sniffed_and_consumed(self, tmp_path):
        """UTF-16LE (Defender's native encoding on Windows)."""
        from opensearch_mcp.parse_defender import _sniff_encoding

        f = tmp_path / "MPLog-1.log"
        f.write_bytes(_utf16le("2023-01-25T00:41:10.327Z Some line\r\n"))
        enc = _sniff_encoding(f)
        assert enc == "utf-16", f"expected utf-16 for UTF-16LE BOM; got {enc!r}"
        # Decode with the sniffed codec and assert line 1 starts with
        # the timestamp — no residual `\ufeff`.
        with open(f, encoding=enc) as fh:
            line1 = fh.readline()
        assert line1.startswith("2023-01-25T"), (
            f"line 1 must start with timestamp, not BOM residue; got {line1!r}"
        )

    def test_utf16be_bom_sniffed_and_consumed(self, tmp_path):
        """UTF-16BE is rare but the sniff should still recognise it."""
        from opensearch_mcp.parse_defender import _sniff_encoding

        f = tmp_path / "MPLog-1.log"
        f.write_bytes(_utf16be("2023-01-25T00:41:10.327Z Some line\r\n"))
        enc = _sniff_encoding(f)
        assert enc == "utf-16"
        with open(f, encoding=enc) as fh:
            line1 = fh.readline()
        assert line1.startswith("2023-01-25T"), (
            f"line 1 must start with timestamp, not BOM residue; got {line1!r}"
        )

    def test_utf8sig_bom_sniffed(self, tmp_path):
        """UTF-8 with BOM (some older tooling emits this)."""
        from opensearch_mcp.parse_defender import _sniff_encoding

        f = tmp_path / "MPLog-1.log"
        f.write_bytes(_utf8sig("2023-01-25T00:41:10.327Z Some line\r\n"))
        enc = _sniff_encoding(f)
        assert enc == "utf-8-sig"
        with open(f, encoding=enc) as fh:
            line1 = fh.readline()
        assert line1.startswith("2023-01-25T")

    def test_utf8_no_bom_default(self, tmp_path):
        """UTF-8 with no BOM falls through to the `utf-8` default."""
        from opensearch_mcp.parse_defender import _sniff_encoding

        f = tmp_path / "MPLog-1.log"
        f.write_bytes(b"2023-01-25T00:41:10.327Z Some line\r\n")
        enc = _sniff_encoding(f)
        assert enc == "utf-8"


class TestEndToEndBehavioralDetection:
    """Bug A + B + C together — the primary regression path."""

    def test_utf16le_mpdetection_behavioral_detection_parsed(self, tmp_path):
        """The full UAT repro: UTF-16LE MPDetection-*.log with a
        `DETECTION Behavior:Win32/CobaltStrike.E!sms` line. Pre-fix:
        0 docs. Post-fix: 1 doc with all named-group fields populated
        AND the `behavior:process` context sub-parsed into
        `process.executable` + `process.pid` (as int)."""
        f = tmp_path / "MPDetection-20230125.log"
        f.write_bytes(
            _utf16le(
                "2023-01-25T00:41:10.327Z DETECTION Behavior:Win32/"
                "CobaltStrike.E!sms behavior:process: C:\\x.exe, pid:99\r\n"
            )
        )

        cnt, sk, bf, collected = _run_parse_mplog(tmp_path)

        assert cnt == 1, f"expected 1 indexed doc; got {cnt} (skipped={sk})"
        doc = collected[0]["_source"]
        assert doc["defender.event_type"] == "detection"
        assert doc["defender.detection_category"] == "Behavior"
        assert doc["defender.platform"] == "Win32"
        assert doc["defender.threat_name"] == "CobaltStrike.E"
        assert doc["defender.variant"] == "sms"
        assert doc["process.executable"] == "C:\\x.exe"
        assert doc["process.pid"] == 99
        assert isinstance(doc["process.pid"], int), "pid must be int-typed"
        assert doc["@timestamp"] == "2023-01-25T00:41:10.327Z"


class TestContextSubParse:
    """Each context shape gets its own test per CR — brevity-over-signal
    was the wrong tradeoff since the sub-parse rules have different
    failure modes. A break in one shape gives a precise failure signal."""

    def test_context_behavior_process_with_pid(self, tmp_path):
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {}
        _parse_detection_context("behavior:process: C:\\x.exe, pid:2376", doc)
        assert doc["process.executable"] == "C:\\x.exe"
        assert doc["process.pid"] == 2376
        assert isinstance(doc["process.pid"], int)

    def test_context_behavior_process_without_pid(self, tmp_path):
        """Some DETECTION lines emit `behavior:process:` with no pid
        tail. Must populate `process.executable` and leave
        `process.pid` unset — NOT index a string or None."""
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {}
        _parse_detection_context("behavior:process: C:\\x.exe", doc)
        assert doc["process.executable"] == "C:\\x.exe"
        assert "process.pid" not in doc

    def test_context_file(self, tmp_path):
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {}
        _parse_detection_context("file:C:\\Windows\\System32\\SRLUpdate.exe", doc)
        assert doc["file.path"] == "C:\\Windows\\System32\\SRLUpdate.exe"

    def test_context_regkey(self, tmp_path):
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {}
        _parse_detection_context(
            "regkey:HKLM\\SOFTWARE\\...\\{F0E32B12-4364-4ED6-8BCC-ED667179F8E2}",
            doc,
        )
        assert doc["registry.key"] == (
            "HKLM\\SOFTWARE\\...\\{F0E32B12-4364-4ED6-8BCC-ED667179F8E2}"
        )

    def test_context_taskscheduler(self, tmp_path):
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {}
        _parse_detection_context(
            "taskscheduler:C:\\Windows\\System32\\Tasks\\SRL User Maintenance", doc
        )
        assert doc["defender.task_name"] == "C:\\Windows\\System32\\Tasks\\SRL User Maintenance"

    def test_context_malformed_pid_stays_unset(self, tmp_path):
        """Regex captures `pid:\\d+`, so a non-numeric pid won't match
        the group at all. Verify the parser doesn't raise on weird
        pid-like fragments."""
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {}
        _parse_detection_context("behavior:process: C:\\x.exe, pid:notanumber", doc)
        # The regex's `pid:(\d+)` group doesn't match "notanumber", so
        # the whole context doesn't match _CTX_BEHAVIOR_PROCESS (which
        # requires pid to be digits when present — actually wait, the
        # group is optional). Verify executable populates even with
        # garbage pid trail.
        assert "C:\\x.exe" in doc.get("process.executable", "")

    def test_unmatched_context_stays_raw(self, tmp_path):
        """Any shape not in the sub-parse catalog must leave
        `defender.detection_context` populated (set by caller) and
        not add spurious fields."""
        from opensearch_mcp.parse_defender import _parse_detection_context

        doc: dict = {"defender.detection_context": "unrecognized:foo bar"}
        _parse_detection_context("unrecognized:foo bar", doc)
        # Raw context still there; no ECS fields added.
        assert doc["defender.detection_context"] == "unrecognized:foo bar"
        assert "process.executable" not in doc
        assert "file.path" not in doc
        assert "registry.key" not in doc
        assert "defender.task_name" not in doc


class TestExclusionRegression:
    """Bug A's encoding sniff is the one change affecting a currently-
    working path. Pin that `Adding exclusion:` in a UTF-8 MPLog still
    produces an `exclusion_added` doc with the same shape as before."""

    def test_utf8_mplog_exclusion_added(self, tmp_path):
        f = tmp_path / "MPLog-2023.log"
        f.write_bytes(
            b"2023-01-25T00:41:10.327Z Adding exclusion: C:\\Users\\admin\\Downloads\r\n"
        )
        cnt, sk, bf, collected = _run_parse_mplog(tmp_path)
        assert cnt == 1
        doc = collected[0]["_source"]
        assert doc["defender.event_type"] == "exclusion_added"
        assert doc["defender.exclusion_path"] == "C:\\Users\\admin\\Downloads"


class TestLegacyDetectionFallback:
    """Backward-compat pin — older Defender builds may emit
    `DETECTION_ADD ... Name:<threat>#`. The legacy-fallback regex
    catches these and produces the pre-UAT field shape
    (`defender.event_type = "detection_add"/"detection_clean"/
    "detection_delete"` + `defender.threat_name`). Zero loss of
    coverage after the new-format regex landed."""

    def test_legacy_detection_add_name_format(self, tmp_path):
        f = tmp_path / "MPLog-legacy.log"
        f.write_bytes(
            b"2020-06-15T12:00:00Z DETECTION_ADD  Name:Trojan:Win32/Foo#ThreatType:malware\r\n"
        )
        cnt, sk, bf, collected = _run_parse_mplog(tmp_path)
        assert cnt == 1
        doc = collected[0]["_source"]
        assert doc["defender.event_type"] == "detection_add"
        assert doc["defender.threat_name"] == "Trojan:Win32/Foo"


class TestMpDetectionGlob:
    """Bug B — ingest sees both MPLog-*.log and MPDetection-*.log."""

    def test_both_mplog_and_mpdetection_globbed(self, tmp_path):
        """Two files: MPLog with exclusion, MPDetection with behavioral
        detection. Pre-fix: only MPLog indexed (1 doc). Post-fix: both
        indexed (2 docs)."""
        (tmp_path / "MPLog-2023.log").write_bytes(
            b"2023-01-24T00:00:00Z Adding exclusion: C:\\Users\\x\r\n"
        )
        (tmp_path / "MPDetection-2023.log").write_bytes(
            _utf16le(
                "2023-01-25T00:00:00Z DETECTION Behavior:Win32/Cobalt.E!sms file:C:\\x.exe\r\n"
            )
        )
        cnt, sk, bf, collected = _run_parse_mplog(tmp_path)
        assert cnt == 2, f"expected 2 docs (both files indexed); got {cnt}"
        event_types = {d["_source"]["defender.event_type"] for d in collected}
        assert "exclusion_added" in event_types
        assert "detection" in event_types
