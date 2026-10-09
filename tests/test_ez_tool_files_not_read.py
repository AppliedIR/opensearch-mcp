"""A file or folder an EZ tool could not read is named in the ingest status.

LECmd, JLECmd and RBCmd exit 0 when they cannot open or parse an input file,
and list it under "Failed files" in their console output. An unreadable folder
reads exactly like an empty one ("Found 0 files"). Both used to end `done` with
no warning. Everything here is synthetic: the tool run is a stub that returns
console output in the tools' own format.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest
from opensearch_mcp.ingest_cli import _rebuilt_status_host

RECENT = "AppData/Roaming/Microsoft/Windows/Recent"
DENIED = "Access to the path '{p}' is denied."
NOT_LNK = "File ({p}) has an invalid signature! Is it a valid LNK file?"
# What LECmd --all always lists for a real Recent folder, in its own order.
NOISE = [
    ("AutomaticDestinations", DENIED),
    ("desktop.ini", NOT_LNK),
    ("CustomDestinations", DENIED),
    ("AutomaticDestinations/0123456789abcdef.automaticDestinations-ms", NOT_LNK),
    ("Feedback.website", NOT_LNK),
]


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _console(folder: Path, rows: int, failed: list[tuple[str, str]], after=()) -> str:
    """Console output shaped like the tools' own; `after` is printed past the list."""
    n = rows + len(failed)
    out = [f"Looking for files in {folder}", "", f"Found {n} files", ""]
    out.append(f"Processed {rows} out of {n} files in 0.0700 seconds")
    if failed:
        out += ["", "Failed files"]
        for name, why in failed:
            p = f"{folder}/{name}"
            out.append(f"  {p} ==> ({why.format(p=p)})")
    out += [line.format(folder=folder) for line in after]
    out += ["", "CSV output will be saved to /tmp/x.csv"]
    return "\n".join(out)


def _host(tmp_path, artifact, plan, name="HOST1"):
    """plan: {user: (rows, [(file, reason), ...])}"""
    root = tmp_path / name
    h = DiscoveredHost(hostname=name, volume_root=root)
    for user in plan:
        d = root / "Users" / user / RECENT
        d.mkdir(parents=True)
        h.artifacts.append((artifact, d))
    return h


def _ingest(hosts, plan, final_status="complete", ingest_error=None):
    def run_tool(cmd, label):
        folder = Path(cmd[cmd.index("-d") + 1])
        user = folder.parts[folder.parts.index("Users") + 1]
        rows, failed, *after = plan[user]
        if rows:
            out = Path(cmd[cmd.index("--csv") + 1])
            (out / "20260101000000_Output.csv").write_text("SourceFile\n" + "x\n" * rows)
        return _console(folder, rows, failed, *after), ""

    def ingest_csv(csv_path, **kw):
        if ingest_error:
            raise ingest_error
        return len(csv_path.read_text().splitlines()) - 1, 0, 0

    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
        patch("opensearch_mcp.tools._run_tool", side_effect=run_tool),
        patch("opensearch_mcp.tools.ingest_csv", side_effect=ingest_csv),
    ):
        result = ingest(
            hosts=hosts,
            client=client,
            audit=audit,
            case_id="c1",
            include={"lnk", "jumplists"},
            status_pid=os.getpid(),
            status_run_id="run-unread",
            final_status=final_status,
        )
    return result, audit


def _status():
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status


def _warnings(status, word):
    return [w for w in status.get("warnings", []) if word in w]


@pytest.mark.parametrize(
    "name, why",
    [("Budget.lnk", DENIED), ("NOTES.LNK", NOT_LNK)],
    ids=["unreadable", "corrupt-upper-case-extension"],
)
def test_an_lnk_the_tool_could_not_read_is_named(tmp_path, status_dir, name, why):
    plan = {"alice": (3, NOISE[:2] + [(name, why)] + NOISE[2:])}
    _ingest([_host(tmp_path, "lnk", plan)], plan)
    status = _status()
    (w,) = _warnings(status, name)
    assert w.startswith("HOST1: lnk: 1 file(s) or folder(s) were not ingested, or only in part (")
    assert why.split("{p}")[-1].strip(" .)'") in w  # the tool's reason
    (row,) = [c for c in status["checklist"] if c["artifact"] == "lnk"]
    assert row["detail"].startswith("3 docs submitted")


def test_files_lecmd_tries_that_are_not_lnk_do_not_warn(tmp_path, status_dir):
    # LECmd runs with --all, so a real Recent folder's desktop.ini, its
    # jump-list subfolders and their files are always in its failed list.
    plan = {"alice": (8, NOISE)}
    _ingest([_host(tmp_path, "lnk", plan)], plan)
    assert _status().get("warnings", []) == []


def test_a_jump_list_the_tool_could_not_read_is_named(tmp_path, status_dir):
    bad = "AutomaticDestinations/0123456789abcdef.automaticDestinations-ms"
    plan = {"alice": (17, [(bad, "Invalid signature (footer missing)")])}
    _ingest([_host(tmp_path, "jumplists", plan)], plan)
    (w,) = _warnings(_status(), "0123456789abcdef")
    assert "jumplists" in w


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 folder")
@pytest.mark.parametrize("artifact", ["lnk", "jumplists"])
def test_an_unreadable_folder_is_named(tmp_path, status_dir, artifact):
    plan = {"alice": (0, [])}  # the tool reports an unreadable folder as empty
    host = _host(tmp_path, artifact, plan)
    folder = host.artifacts[0][1]
    folder.chmod(0)
    try:
        _ingest([host], plan)
    finally:
        folder.chmod(0o755)
    (w,) = _warnings(_status(), str(folder))
    assert w.startswith(f"HOST1: {artifact}: 1 file(s) or folder(s)")


def test_indented_lines_after_the_failed_files_list_are_not_named(tmp_path, status_dir):
    after = ["", "Summary", "  {folder}/Later.lnk ==> (processed)"]
    plan = {"alice": (3, [("Budget.lnk", DENIED)], after)}
    _ingest([_host(tmp_path, "lnk", plan)], plan)
    (w,) = _warnings(_status(), "Budget.lnk")
    assert "Later.lnk" not in w
    assert w.startswith("HOST1: lnk: 1 file(s) or folder(s)")


def test_files_not_read_are_named_when_indexing_then_fails(tmp_path, status_dir):
    plan = {"alice": (3, [("Budget.lnk", DENIED)])}
    error = RuntimeError("circuit_breaking_exception")
    result, audit = _ingest([_host(tmp_path, "lnk", plan)], plan, ingest_error=error)
    status = _status()
    (row,) = [c for c in status["checklist"] if c["artifact"] == "lnk"]
    assert row["status"] == "failed"
    (w,) = _warnings(status, "Budget.lnk")
    assert w.startswith("HOST1: lnk: 1 file(s) or folder(s)")
    (summary,) = [
        c.kwargs["result_summary"]
        for c in audit.log.call_args_list
        if c.kwargs["tool"] == "ingest_lnk" and (c.kwargs.get("extra") or {}).get("about")
    ]  # what became of the artifact: the entry about its step
    assert summary == "FAILED: circuit_breaking_exception, 1 not read"
    hosts = [_rebuilt_status_host(h) for h in result.hosts]
    ingest_status.write_status("c1", os.getpid(), "run-unread", "complete", hosts, {}, "")
    assert _warnings(_status(), "Budget.lnk")


def test_an_empty_folder_does_not_warn(tmp_path, status_dir):
    plan = {"alice": (0, [])}
    _ingest([_host(tmp_path, "lnk", plan)], plan)
    assert _status().get("warnings", []) == []


def test_files_not_read_in_two_profiles_add_up(tmp_path, status_dir):
    plan = {
        "alice": (2, [("Budget.lnk", DENIED), ("desktop.ini", NOT_LNK), ("Old.lnk", NOT_LNK)]),
        "bob": (5, [("Plan.lnk", NOT_LNK)]),
    }
    _ingest([_host(tmp_path, "lnk", plan)], plan)
    status = _status()
    (w,) = _warnings(status, "Budget.lnk")
    assert "Old.lnk" in w and "Plan.lnk" in w and "3 file" in w


def test_the_warning_survives_the_detection_phase_rewrite(tmp_path, status_dir):
    plan = {"alice": (3, [("Budget.lnk", DENIED)])}
    result, _ = _ingest([_host(tmp_path, "lnk", plan)], plan, final_status="running")
    # what the scan writes when Hayabusa runs after the artifacts
    hosts = [_rebuilt_status_host(h) for h in result.hosts]
    ingest_status.write_status("c1", os.getpid(), "run-unread", "complete", hosts, {}, "")
    assert _warnings(_status(), "Budget.lnk")


def test_the_audit_entry_counts_the_files_not_read(tmp_path, status_dir):
    plan = {"alice": (3, [("Budget.lnk", DENIED)])}
    _, audit = _ingest([_host(tmp_path, "lnk", plan)], plan)
    (summary,) = [
        c.kwargs["result_summary"]
        for c in audit.log.call_args_list
        if c.kwargs["tool"] == "ingest_lnk" and (c.kwargs.get("extra") or {}).get("about")
    ]  # what became of the artifact: the entry about its step
    assert "1 not read" in summary
