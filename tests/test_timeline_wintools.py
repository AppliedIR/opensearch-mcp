"""The Windows 10 Timeline: each ActivitiesCache.db is parsed by WxTCmd on
wintools-mcp, the database FILE at -f, with its SQLite companions.

Discovery yielded the ConnectedDevicesPlatform folder, and WxTCmd given a
folder reads nothing; one account can hold several databases (rd01's
tdungan has L.tdungan and a device id). Now each database is found, staged
with its -wal and -shm (the rows still in the WAL are in no other file),
and the staged file reaches -f. Without wintools-mcp the run names why; an
empty result is a named failure. wintools is stubbed here; the real guest
leg is test's.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from _helpers import make_windows_tree
from sift_common.audit import AuditWriter
from test_ingest_steps import C12, _fake_wintools, case  # noqa: F401

from opensearch_mcp import ingest
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost, discover_artifacts
from opensearch_mcp.results import HostResult

# rd01's databases, from its file listing (rsrc/fls.txt)
RD01 = [
    "Users/Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator",
    "Users/tdungan/AppData/Local/ConnectedDevicesPlatform/8869d58b59727812",
    "Users/tdungan/AppData/Local/ConnectedDevicesPlatform/L.tdungan",
    "Users/wacsvc/AppData/Local/ConnectedDevicesPlatform/L.wacsvc",
]


def _rd01(root: Path) -> Path:
    make_windows_tree(root, users=["Administrator", "tdungan", "wacsvc"])
    for folder in RD01:
        d = root / folder
        d.mkdir(parents=True, exist_ok=True)
        for name in ("ActivitiesCache.db", "ActivitiesCache.db-wal", "ActivitiesCache.db-shm"):
            (d / name).write_bytes(name.encode())
    return root


def test_each_database_is_found_as_a_file_in_any_subfolder(tmp_path):
    host = DiscoveredHost(hostname="RD01", volume_root=_rd01(tmp_path / "C"))
    discover_artifacts(host)
    found = sorted(p for n, p in host.artifacts if n == "timeline")
    assert found == sorted(tmp_path / "C" / f / "ActivitiesCache.db" for f in RD01)


def _run(case, db, monkeypatch, available=True):  # noqa: F811
    monkeypatch.setattr("opensearch_mcp.wintools.wintools_available", lambda: available)
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)
    monkeypatch.setattr(ingest, "_safe_count", lambda *a, **k: 0)
    monkeypatch.setattr(wc, "index_name", lambda t: f"case-{C12}-{t}-0")
    monkeypatch.setattr(wc, "current", lambda: MagicMock(unit="u1"))
    result = HostResult(hostname="RD01")
    host = DiscoveredHost(hostname="RD01", volume_root=db.parents[6])
    ingest._ingest_plaso_artifact(
        "timeline", db, MagicMock(), AuditWriter(mcp_name="opensearch-ingest-1"), "acme",
        host, 0, result, [], lambda *a, **k: None, lambda: None,
    )  # fmt: skip
    return result.artifacts[0]


def test_the_database_file_reaches_f_with_its_companions_staged(case, monkeypatch):  # noqa: F811
    db = _rd01(case / "evidence" / "C") / RD01[1] / "ActivitiesCache.db"
    _fake_wintools(case, monkeypatch, "20261013_ActivitiesCache_Activity.csv")
    commands = []
    from opensearch_mcp import parse_csv, wintools

    real = wintools.run_windows_tool

    def run(command, *a, **k):
        commands.append(command)
        return real(command, *a, **k)

    monkeypatch.setattr(wintools, "run_windows_tool", run)
    monkeypatch.setattr(parse_csv, "ingest_csv", lambda **kw: (3, 0, 0))
    ar = _run(case, db, monkeypatch)
    assert ar.error in ("", None) and ar.indexed == 3, ar
    (command,) = commands
    target = command[command.index("-f") + 1]
    # the staged file, not its folder
    assert target.replace("\\", "/").endswith("/8869d58b59727812/ActivitiesCache.db"), command
    staged = case / "extractions" / "timeline" / "RD01" / "tdungan" / "8869d58b59727812"
    assert sorted(f.name for f in staged.iterdir()) == [
        "ActivitiesCache.db", "ActivitiesCache.db-shm", "ActivitiesCache.db-wal"]  # fmt: skip


def test_without_wintools_each_database_names_why(case, monkeypatch):  # noqa: F811
    db = _rd01(case / "evidence" / "C") / RD01[0] / "ActivitiesCache.db"
    from opensearch_mcp.parse_timeline import NO_WINTOOLS

    ar = _run(case, db, monkeypatch, available=False)
    assert ar.error == NO_WINTOOLS


def test_a_connection_error_marks_wintools_down_and_is_raised(case, monkeypatch, tmp_path):  # noqa: F811
    from opensearch_mcp import wintools

    db = _rd01(tmp_path / "C") / RD01[0] / "ActivitiesCache.db"
    monkeypatch.setattr(wintools, "wintools_available", lambda: True)
    down = []
    monkeypatch.setattr(wintools, "mark_wintools_down", lambda: down.append(1))

    def refused(**kw):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(wintools, "run_tool_and_get_csv", refused)
    from opensearch_mcp import ops, parse_timeline

    with ops.recording(AuditWriter(mcp_name="opensearch-ingest-1"), case, "ingest_timeline", {}):
        with pytest.raises(ConnectionError):
            parse_timeline.parse_timeline(db, MagicMock(), "idx", "RD01")
    assert down == [1]


def test_an_empty_result_is_a_named_failure(case, monkeypatch):  # noqa: F811
    db = _rd01(case / "evidence" / "C") / RD01[3] / "ActivitiesCache.db"
    _fake_wintools(case, monkeypatch, "20261013_ActivitiesCache_Activity.csv")
    from opensearch_mcp import parse_csv

    monkeypatch.setattr(parse_csv, "ingest_csv", lambda **kw: (0, 0, 0))
    ar = _run(case, db, monkeypatch)
    assert ar.error.startswith("no records read from ActivitiesCache.db"), ar.error


def test_the_timeline_stays_opt_in():
    from opensearch_mcp.tools import get_active_tools

    assert "timeline" not in {t.cli_name for t in get_active_tools()}
    assert "timeline" in {t.cli_name for t in get_active_tools(include={"timeline"})}


def test_the_account_is_the_folder_after_the_last_users():
    from opensearch_mcp.parse_timeline import _staging

    db = Path(
        "/mnt/users/img/C/Users/tdungan/AppData/Local/ConnectedDevicesPlatform/L.x/ActivitiesCache.db"
    )
    assert _staging(Path("/cases/c1"), "RD01", db) == Path(
        "/cases/c1/extractions/timeline/RD01/tdungan/L.x"
    )


@pytest.mark.parametrize(
    "hostname", ["a/../../../outside/victim", "../../../../../tmp/x", "..", "C:\\..\\x"],
    ids=["climbs in the case", "climbs out of it", "dot-dot", "a Windows path"],
)  # fmt: skip
def test_a_hostname_that_climbs_stages_nothing_outside_extractions(
    case,  # noqa: F811
    monkeypatch,
    tmp_path,
    hostname,
):
    """The host name is evidence: it names one folder under extractions/,
    whatever it holds, and nothing is written outside extractions/."""
    db = _rd01(tmp_path / "C") / RD01[0] / "ActivitiesCache.db"
    _fake_wintools(case, monkeypatch, "20261013_ActivitiesCache_Activity.csv")
    from opensearch_mcp import ops, parse_csv, parse_timeline

    monkeypatch.setattr("opensearch_mcp.wintools.wintools_available", lambda: True)
    monkeypatch.setattr(parse_csv, "ingest_csv", lambda **kw: (1, 0, 0))
    before = {p for p in tmp_path.rglob("*")}
    with ops.recording(AuditWriter(mcp_name="opensearch-ingest-1"), case, "ingest_timeline", {}):
        parse_timeline.parse_timeline(db, MagicMock(), "idx", hostname)
    written = {p for p in tmp_path.rglob("*")} - before
    extractions = case / "extractions"
    # the run's own audit line aside, everything it wrote is under extractions/
    inside = (extractions, case / "audit")
    stray = [p for p in written if p not in inside and not any(d in p.parents for d in inside)]
    assert not stray, sorted(stray)
    assert any(p.name == "ActivitiesCache.db" for p in written)
    (host_dir,) = (extractions / "timeline").iterdir()
    assert "/" not in host_dir.name and host_dir.name not in (".", "..")


def test_a_database_without_companions_is_staged_without_an_earlier_runs(
    case,  # noqa: F811
    monkeypatch,
    tmp_path,
):
    """A snapshot's database often has no -wal; the live one's, staged first in
    the same folder, must not be applied to it."""
    from opensearch_mcp import ops, parse_csv, parse_timeline, wintools

    monkeypatch.setattr(wintools, "wintools_available", lambda: True)
    monkeypatch.setattr(wintools, "run_tool_and_get_csv", lambda **kw: [tmp_path / "out.csv"])
    monkeypatch.setattr(parse_csv, "ingest_csv", lambda **kw: (1, 0, 0))
    live = _rd01(tmp_path / "live") / RD01[2] / "ActivitiesCache.db"
    snap = tmp_path / "vss1" / RD01[2] / "ActivitiesCache.db"
    snap.parent.mkdir(parents=True)
    snap.write_bytes(b"snapshot")
    with ops.recording(AuditWriter(mcp_name="opensearch-ingest-1"), case, "ingest_timeline", {}):
        parse_timeline.parse_timeline(live, MagicMock(), "idx", "RD01")
        parse_timeline.parse_timeline(snap, MagicMock(), "idx", "RD01")
    staged = case / "extractions" / "timeline" / "RD01" / "tdungan" / "L.tdungan"
    assert sorted(f.name for f in staged.iterdir()) == ["ActivitiesCache.db"]
    assert (staged / "ActivitiesCache.db").read_bytes() == b"snapshot"
