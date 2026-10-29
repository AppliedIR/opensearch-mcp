"""Only a failed call marks wintools down: a reply, whatever its error says
(WxTCmd's own text can say SQLiteConnection), proves wintools answered."""

from __future__ import annotations

import contextlib
import urllib.error

import pytest
import sift_common

from opensearch_mcp import ops
from opensearch_mcp import parse_prefetch as pp
from opensearch_mcp import parse_srum as ps
from opensearch_mcp import parse_timeline as pt
from opensearch_mcp import wintools as wt

ERR = "WxTCmd.exe wrote no file to extractions/wt-r (exit code 0). What it printed: at SQLiteConnection.Open()"  # noqa: E501
ANSWER = {"success": False, "audit_id": "wt-r", "error": ERR}
REFUSED = urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
GW_TIMEOUT = RuntimeError("gateway timeout")
HTTP500 = urllib.error.HTTPError("http://gw/api/v1/tools/run_windows_command", 500, "", {}, None)
ROWS = [("timeline", ANSWER, False), ("timeline", REFUSED, True), ("prefetch", ANSWER, False),
        ("prefetch", REFUSED, True), ("srum", ANSWER, False), ("srum", REFUSED, True),
        ("timeline", HTTP500, False), ("timeline", GW_TIMEOUT, True)]  # fmt: skip
EVIDENCE = {"timeline": ("u/ActivitiesCache.db", b"SQLite format 3\x00x", pt.parse_timeline),
            "prefetch": ("Prefetch/A.EXE-12345678.pf", b"MAM\x04x", pp.parse_prefetch),
            "srum": ("sru/SRUDB.dat", b"x", ps.parse_srum)}  # fmt: skip


@pytest.mark.parametrize("parser, result, down", ROWS, ids=[f"O{i}" for i in range(1, 9)])
def test_only_a_failed_call_marks_wintools_down(tmp_path, monkeypatch, parser, result, down):
    rel, data, run = EVIDENCE[parser]
    f = tmp_path / "case" / "evidence" / rel
    f.parent.mkdir(parents=True)
    f.write_bytes(data)
    for mod, name, value in ((wt, "gateway_available", True), (wt, "_wintools_configured", True),
                             (ops, "staging_step", "sid-1"), (pp, "_parse_prefetch_plaso", (0, 0)),
                             (sift_common, "resolve_case_dir", str(tmp_path / "case")),
                             (ps, "_parse_srum_plaso", (0, 0))):  # fmt: skip
        monkeypatch.setattr(mod, name, lambda *a, _v=value, **k: _v)
    monkeypatch.setattr(wt, "_to_unc_path", lambda rel: "\\\\sift\\cases\\" + rel)
    monkeypatch.setattr(wt, "_wintools_down", False)
    calls = []  # the parser reached wintools

    def call(*a, **k):
        calls.append(1)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(wt, "call_tool", call)
    with contextlib.suppress(Exception):  # the timeline raises; the others fall back to Plaso
        run(f.parent if parser == "prefetch" else f, None, f"case-{parser}", "host-a")
    assert calls and wt._wintools_down is down
