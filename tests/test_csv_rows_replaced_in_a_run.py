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
import json
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
    root = tmp_path / "evidence" / "WS01" / "C"
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


def _scan(hosts, rows_for, case_id="c1", client=None, written=None, stored=None):
    """A scan whose writes are stamped as the real write stamps them (the
    machine key, and the pre-0.7 import before the first name binds)."""
    from opensearch_mcp import write_context as wc

    audit = MagicMock()
    ids = iter(f"aid-{n:03d}" for n in range(1, 100))
    audit._next_audit_id.side_effect = lambda: next(ids)
    if client is None:
        client = MagicMock()
        client.indices.get.return_value = {}  # no pre-0.7 indices
    client.count.side_effect = Exception("no index")

    def write(c, actions, **k):
        wc.stamp_or_refuse(actions, c)
        if written is not None:
            written.extend(a["_source"] for a in actions)
        for a in actions if stored is not None else ():
            stored[a["_id"]] = a["_source"].get("vhir.source_file", "")
        return len(actions), 0

    with (
        patch("opensearch_mcp.tools._run_tool", side_effect=_sbecmd(rows_for)),
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=write),
        patch("opensearch_mcp.write_context.note_second_copy"),  # not this file's subject
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


def _host(root, profiles, vss_id="", hostname="WS01"):
    host = DiscoveredHost(hostname=hostname, volume_root=root, vss_id=vss_id)
    host.artifacts = [("shellbags", root / "Users" / p) for p in profiles]
    return host


def test_identical_profiles_name_the_profile_that_lost_its_rows(tmp_path, status_dir, capsys):
    """Two profiles hold the same 37 shellbags; a third holds its own."""
    profiles = ["alice", "bob-admin", "carol"]
    root = _volume(tmp_path, profiles)
    lines, warnings = _scan(
        [_host(root, profiles)],
        lambda p: range(100, 120) if p == "carol" else range(37),
    )
    message = (
        "37 shellbag rows from Users/alice are identical to rows from Users/bob-admin "
        "(a later file in this run) and are stored once, under the last file that has "
        "them; a search for Users/alice won't find them"
    )
    assert [w for w in warnings if "stored once" in w] == [f"WS01: {message}"]
    assert lines[str(root / "Users/bob-admin")] == f"37 indexed; {message}"
    assert lines[str(root / "Users/alice")] == "37 indexed"
    assert lines[str(root / "Users/carol")] == "20 indexed"
    assert "stored once" not in capsys.readouterr().out  # no console line


def test_three_identical_profiles_count_each_loss_against_its_own_file(tmp_path, status_dir):
    profiles = ["a", "b", "c"]
    root = _volume(tmp_path, profiles)
    _, warnings = _scan([_host(root, profiles)], lambda p: range(5))
    once = ("(a later file in this run) and are stored once, under the last file that "
            "has them")  # fmt: skip
    assert [w for w in warnings if "stored once" in w] == [
        f"WS01: 5 shellbag rows from Users/a are identical to rows from Users/b {once}; "
        "a search for Users/a won't find them; "
        f"5 shellbag rows from Users/b are identical to rows from Users/c {once}; "
        "a search for Users/b won't find them"
    ]


def test_rows_three_files_hold_are_stored_under_the_last(tmp_path, status_dir):
    profiles = ["a", "b", "c"]
    root = _volume(tmp_path, profiles)
    stored: dict = {}
    _scan([_host(root, profiles)], lambda p: range(5), stored=stored)
    assert len(stored) == 5  # one document per row
    assert {Path(src).parent.name + "/" + Path(src).name for src in stored.values()} == {"Users/c"}


def test_anchor_a_shadow_copy_of_the_same_profile_is_silent(tmp_path, status_dir):
    root = _volume(tmp_path, ["alice", "bob-admin"])
    hosts = [
        _host(root, ["alice", "bob-admin"], vss_id="live"),
        _host(root, ["alice"], vss_id="vss1"),  # the same files, from a shadow copy
    ]
    _, warnings = _scan(hosts, lambda p: range(10) if p == "alice" else range(50, 60))
    assert [w for w in warnings if "stored once" in w] == []


def test_one_recmd_run_over_four_hives_isn_t_tracked(tmp_path):
    from opensearch_mcp.ingest import _indices_filled_by_several_files

    root = tmp_path / "evidence" / "WS01" / "C"
    config = root / "Windows/System32/config"
    host = DiscoveredHost(hostname="WS01", volume_root=root)
    host.artifacts = [
        (f"registry_{h.lower()}", config / h) for h in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY")
    ] + [("shellbags", root / "Users/one")]
    assert _indices_filled_by_several_files([host], {"registry", "shellbags"}) == set()
    host.artifacts.append(("shellbags", root / "Users/two"))
    assert _indices_filled_by_several_files([host], {"registry", "shellbags"}) == {"shellbags"}


def test_two_machines_with_identical_rows_keep_both_and_say_nothing(tmp_path, status_dir):
    """Every machine's rows share one case index; a row's stored id carries its
    machine, so the same shellbags on two machines are two documents."""
    profiles = {"WS01": "alice", "WS02": "bob"}  # different files, identical rows
    roots = {}
    for name, profile in profiles.items():
        roots[name] = tmp_path / "evidence" / name / "C"
        (roots[name] / "Users" / profile).mkdir(parents=True)
    hosts = [_host(roots[n], [profiles[n]], hostname=n) for n in roots]
    _, warnings = _scan(hosts, lambda p: range(37), case_id="c2-two-machines")
    assert [w for w in warnings if "stored once" in w] == []


def test_one_host_name_on_two_units_that_are_two_machines_says_nothing(tmp_path, status_dir):
    """Machines are told apart by the key the write stamps, not the raw name."""
    roots = {}
    for folder, profile in (("WS01-a", "alice"), ("WS01-b", "bob")):
        roots[folder] = tmp_path / "evidence" / folder / "C"
        (roots[folder] / "Users" / profile).mkdir(parents=True)
    hosts = [
        _host(roots["WS01-a"], ["alice"], hostname="WS01"),
        _host(roots["WS01-b"], ["bob"], hostname="WS01"),
    ]
    written = []
    _, warnings = _scan(hosts, lambda p: range(37), case_id="c4-one-name", written=written)
    assert len({d["vhir.host_key"] for d in written}) == 2  # two machines
    assert [w for w in warnings if "stored once" in w] == []


def test_counting_binds_no_host_before_a_pre_0_7_case_s_hosts_are_imported(tmp_path, status_dir):
    """A pre-0.7 case holds WS02 as WS02-CANON: its hosts are imported before
    any name of the scan binds, so counting replaced rows binds nothing first.
    The scan's own WS02 is a name it holds: it waits for the examiner, who can
    join it to WS02-CANON at the gate."""
    from sift_common import host_identity

    from opensearch_mcp import write_context as wc

    case_id = "c5-pre-0-7"
    old = f"case-{case_id}-shellbags-ws02"
    client = MagicMock()
    client.indices.get.return_value = {old: {}}
    props = {"host": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}}}
    client.indices.get_mapping.side_effect = lambda index: {
        index: {"mappings": {"properties": props}}
    }
    client.search.return_value = {
        "aggregations": {"p": {"buckets": [{"key": {"name": "WS02", "id": "WS02-CANON"}}]}}
    }
    root = tmp_path / "evidence" / "WS02" / "C"
    for profile in ("alice", "bob"):
        (root / "Users" / profile).mkdir(parents=True)
    written = []
    _scan(
        [_host(root, ["alice", "bob"], hostname="WS02")],
        lambda p: range(2),
        case_id=case_id,
        client=client,
        written=written,
    )
    case_dir = wc.case_dir_for(case_id)
    log = [
        json.loads(ln) for ln in (case_dir / host_identity.OBSERVATIONS).read_text().splitlines()
    ]
    kinds = [e["kind"] for e in log]
    first_new = next(i for i, e in enumerate(log) if e["kind"] == "bind" and e["state"] == "new")
    assert kinds.index("v1-import") < first_new  # nothing bound before the import
    machines = host_identity.load(case_dir).machines.values()
    assert sorted((m.canonical, m.state) for m in machines) == [
        ("WS02", "new"),
        ("WS02-CANON", "confirmed"),
    ]
