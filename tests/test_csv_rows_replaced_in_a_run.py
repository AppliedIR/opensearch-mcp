"""Rows one file of a scan replaces in another are named, not lost silently.

A content-hash tool's row id leaves out the file it came from, so two
profiles whose shellbags are identical write the same ids, and the later
profile's rows replace the earlier one's: every row reads as the later
profile's, and nothing said so. Each such loss is now counted against the
file that lost its rows, in the artifact's status note (an idx_ingest_status
warning) and its audit line. The same file seen again (a shadow copy and the
live volume) is the intended dedup and stays silent. SBECmd is a stand-in;
the profiles are synthetic.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

COLUMNS = ["BagPath", "Slot", "AbsolutePath", "ShellType", "SourceFile"]


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _volume(tmp_path, profiles) -> Path:
    root = tmp_path / "evidence" / "RD01" / "C"
    for name in profiles:
        (root / "Users" / name).mkdir(parents=True)
    return root


def _sbecmd(rows_for):
    """SBECmd: one CSV of `rows_for(profile name)` rows, SourceFile its own."""

    def run(cmd, label):
        profile = Path(cmd[cmd.index("-d") + 1])
        out = Path(cmd[cmd.index("--csv") + 1])
        with (out / "UsrClass.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            for i in rows_for(profile.name):
                hive = profile / "AppData/Local/Microsoft/Windows/UsrClass.dat"
                w.writerow([f"Bag{i}", i, f"My Computer\\C:\\dir{i}", "Directory", str(hive)])
        return "", ""

    return run


def _scan(hosts, rows_for, case_id="c1"):
    audit = MagicMock()
    ids = iter(f"aid-{n:03d}" for n in range(1, 100))
    audit._next_audit_id.side_effect = lambda: next(ids)
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.tools._run_tool", side_effect=_sbecmd(rows_for)),
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=lambda c, a, **k: (len(a), 0)),
        patch("opensearch_mcp.ingest._write_ingest_manifest"),
    ):
        ingest(
            hosts=hosts,
            client=client,
            audit=audit,
            case_id=case_id,
            include={"shellbags"},
            status_pid=os.getpid(),
            status_run_id="run-replaced",
        )
    lines = {
        c.kwargs["params"]["file"]: c.kwargs["result_summary"]
        for c in audit.log.call_args_list
        if c.kwargs.get("tool") == "ingest_shellbags"
    }
    (status,) = srv.idx_ingest_status(case_id=case_id)["ingests"]
    return lines, status.get("warnings", [])


def _host(root, profiles, vss_id="", hostname="RD01"):
    host = DiscoveredHost(hostname=hostname, volume_root=root, vss_id=vss_id)
    host.artifacts = [("shellbags", root / "Users" / p) for p in profiles]
    return host


def test_identical_profiles_name_the_profile_that_lost_its_rows(tmp_path, status_dir, capsys):
    """rd01's shape: SRLAdmin and rsydow-a hold the same 37 shellbags."""
    profiles = ["SRLAdmin", "rsydow-a", "tdungan"]
    root = _volume(tmp_path, profiles)
    lines, warnings = _scan(
        [_host(root, profiles)],
        lambda p: range(100, 120) if p == "tdungan" else range(37),
    )
    message = (
        "37 rows of Users/SRLAdmin were replaced by identical rows from a later file "
        "in this run (Users/rsydow-a)"
    )
    assert [w for w in warnings if "replaced" in w] == [f"RD01: {message}"]
    assert lines[str(root / "Users/rsydow-a")] == f"37 indexed; {message}"
    assert lines[str(root / "Users/SRLAdmin")] == "37 indexed"
    assert lines[str(root / "Users/tdungan")] == "20 indexed"
    assert "replaced" not in capsys.readouterr().out  # no console line


def test_three_identical_profiles_count_each_loss_against_its_own_file(tmp_path, status_dir):
    profiles = ["a", "b", "c"]
    root = _volume(tmp_path, profiles)
    _, warnings = _scan([_host(root, profiles)], lambda p: range(5))
    lost = "rows from a later file in this run"
    assert [w for w in warnings if "replaced" in w] == [
        f"RD01: 5 rows of Users/a were replaced by identical {lost} (Users/b); "
        f"5 rows of Users/b were replaced by identical {lost} (Users/c)"
    ]


def test_anchor_a_shadow_copy_of_the_same_profile_is_silent(tmp_path, status_dir):
    root = _volume(tmp_path, ["SRLAdmin", "rsydow-a"])
    hosts = [
        _host(root, ["SRLAdmin", "rsydow-a"], vss_id="live"),
        _host(root, ["SRLAdmin"], vss_id="vss1"),  # the same files, from a shadow copy
    ]
    _, warnings = _scan(hosts, lambda p: range(10) if p == "SRLAdmin" else range(50, 60))
    assert [w for w in warnings if "replaced" in w] == []


def test_one_recmd_run_over_four_hives_isn_t_tracked(tmp_path):
    from opensearch_mcp.ingest import _indices_filled_by_several_files

    root = tmp_path / "evidence" / "RD01" / "C"
    config = root / "Windows/System32/config"
    host = DiscoveredHost(hostname="RD01", volume_root=root)
    host.artifacts = [
        (f"registry_{h.lower()}", config / h) for h in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")
    ] + [("shellbags", root / "Users/one")]
    assert _indices_filled_by_several_files([host], {"registry", "shellbags"}) == set()
    host.artifacts.append(("shellbags", root / "Users/two"))
    assert _indices_filled_by_several_files([host], {"registry", "shellbags"}) == {"shellbags"}


def test_two_machines_with_identical_rows_keep_both_and_say_nothing(tmp_path, status_dir):
    """Every machine's rows share one case index; a row's stored id carries its
    machine, so the same shellbags on two machines are two documents."""
    profiles = {"RD01": "alice", "RD02": "bob"}  # different files, identical rows
    roots = {}
    for name, profile in profiles.items():
        roots[name] = tmp_path / "evidence" / name / "C"
        (roots[name] / "Users" / profile).mkdir(parents=True)
    hosts = [_host(roots[n], [profiles[n]], hostname=n) for n in roots]
    _, warnings = _scan(hosts, lambda p: range(37), case_id="c2-two-machines")
    assert [w for w in warnings if "replaced" in w] == []
