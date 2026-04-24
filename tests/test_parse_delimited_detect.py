"""Tests for `_detect_delimited_format` quote-aware variance check.

Regression pin for the Hayabusa silent-drop bug: pre-fix, the variance
check counted raw delimiter characters per line, so a 142 MB Hayabusa
CSV with 89k+ detection rows got classified `unknown` and the walker
skipped it — dropping WMI Persistence + 88,999 other hits. The fix
swaps raw char counting for `csv.reader`-based field-count variance,
which is quote-aware.
"""

from __future__ import annotations

from pathlib import Path

from opensearch_mcp.parse_delimited import _detect_delimited_format


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class TestHayabusaShapedCsv:
    """Heavily-quoted CSV with inline commas in quoted fields must
    parse as csv — this is what the old check silently rejected."""

    def test_detects_csv_with_inline_commas_in_quoted_fields(self, tmp_path):
        path = _write(
            tmp_path / "hayabusa.csv",
            (
                'Timestamp,Level,Computer,RuleTitle,Details,ExtraFieldInfo\n'
                # Row 1 — short details
                '2026-04-24T10:00:00Z,high,admin01,"WMI Persist","Created","src=7,dst=8"\n'
                # Row 2 — LONG details with 8 inline commas (exactly the
                # shape that makes raw-character variance blow past the
                # threshold)
                '2026-04-24T10:01:00Z,high,admin01,"Suspicious Proc",'
                '"cmd=powershell,args=-enc,aB,cD,payload=yes,stage=1,user=alice,host=x",'
                '"k1=v1,k2=v2,k3=v3"\n'
                # Row 3 — empty details (min-extreme)
                '2026-04-24T10:02:00Z,info,admin01,"RDP Login","Logon",""\n'
                # Row 4 — medium details
                '2026-04-24T10:03:00Z,high,rd01,"T1546.003","WMI subscription triggered",'
                '"provider=MSFT,binding=EventFilter"\n'
                # Row 5 — another long with 5 inline commas
                '2026-04-24T10:04:00Z,med,rd01,"Disk Activity",'
                '"path=C:\\Windows\\Temp\\x.tmp,size=1024,accessed=yes,created=yes,ro=0",""\n'
            ),
        )
        result = _detect_delimited_format(path)
        assert result["format"] == "csv", (
            f"Hayabusa-shaped CSV wrongly classified as {result['format']!r}"
        )
        assert result["delimiter"] == ","
        assert result["header"] == "first_line"

    def test_rejects_pure_prose_as_unknown(self, tmp_path):
        """Random commas in prose must still classify as unknown."""
        path = _write(
            tmp_path / "license.txt",
            (
                "This software is provided as is, without warranty.\n"
                "The author, copyright holder, and contributors disclaim liability.\n"
                "Redistribution permitted.\n"
                "See documentation for details.\n"
                "No commas here at all either\n"
                "Some, comma, here, for variance.\n"
            ),
        )
        result = _detect_delimited_format(path)
        assert result["format"] == "unknown", (
            f"Prose with random commas wrongly classified as {result['format']!r}"
        )

    def test_simple_unquoted_csv_still_detects(self, tmp_path):
        """Regression — plain CSV without quoting continues to work."""
        path = _write(
            tmp_path / "simple.csv",
            (
                "id,name,value\n"
                "1,alpha,10\n"
                "2,beta,20\n"
                "3,gamma,30\n"
                "4,delta,40\n"
            ),
        )
        result = _detect_delimited_format(path)
        assert result["format"] == "csv"
        assert result["delimiter"] == ","

    def test_multiline_quoted_field_detects_as_csv(self, tmp_path):
        """A CSV field that contains newlines inside quotes must not
        throw off the variance check. Joining lines with \\n before
        csv.reader lets the reader reconstruct the multi-line row
        as a single logical row.
        """
        path = _write(
            tmp_path / "multiline.csv",
            (
                'id,description,tail\n'
                '1,"line one\nline two\nline three",end\n'
                '2,"single line",end\n'
                '3,"another\nsplit",end\n'
                '4,"ok",end\n'
            ),
        )
        result = _detect_delimited_format(path)
        assert result["format"] == "csv"
        assert result["delimiter"] == ","
