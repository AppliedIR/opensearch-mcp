# ruff: noqa: F811 - `cluster`, `cases` and `new_process` are the fixtures imported below
"""A per-profile tool's rows get the same id from the pre-parsed csv route as
from the scan route, so the same evidence ingested both ways is one record.

The scan route puts the profile folder it ran the tool on in each id (the
folder discovery hands it: `Users/<name>/` and the tool's own folder, as on
disk). The csv route reads that folder from each row's SourceFile, the file
the tool read: the `Users` nearest the file, as when the image was mounted
under the examiner's own profile. Both routes case-fold it, as Windows paths
are case-insensitive. A row whose SourceFile names no such folder (none, or a profile
discovery skips) can't be given it: those rows are counted and named, because
the same profile ingested by scan as well would be stored twice.

The routes are real: `tools.run_and_ingest` with the EZ stand-in, and
`ingest_cli.cmd_csv`; OpenSearch is the record-id stand-in.
"""

from __future__ import annotations

import argparse
import contextlib
import io
from unittest import mock

import pytest
from test_record_ids import (  # noqa: F401
    COLS,
    FILL_STATE,
    MACHINE,
    PAIRS,
    STORED_064,
    VALS,
    cases,
    cluster,
    ez_stub,
    new_process,
    new_run,
    open_run,
    profile,
)

from opensearch_mcp import ingest_cli
from opensearch_mcp import write_context as wc

RECENT = "AppData\\Roaming\\Microsoft\\Windows\\Recent"
ALICE = (
    f"C:\\Users\\alice\\{RECENT}\\AutomaticDestinations\\5d696d521de238c3.automaticDestinations-ms"
)
BOB = ALICE.replace("\\alice\\", "\\bob\\")


def csv_route(cluster, cases, monkeypatch, sources, tool="jumplists") -> list[str]:
    """`opensearch-ingest csv --tool <tool>` over one CSV holding the
    stand-in's row once per SourceFile in `sources` (None: the column empty).
    What it printed."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    csv = cases / "prof" / "evidence" / "jlecmd" / "20260102030405_AutomaticDestinations.csv"
    csv.parent.mkdir(parents=True, exist_ok=True)
    lines = [",".join(COLS[tool])]
    for source in sources:
        values = list(VALS[tool])
        values.insert(COLS[tool].index("SourceFile"), source or "")
        lines.append(",".join(f'"{v}"' for v in values))
    csv.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(ingest_cli, "get_client", cluster.client)
    for name in ("_preflight_shard_capacity", "_ensure_case_active"):
        monkeypatch.setattr(ingest_cli, name, mock.MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "prof")
    audit = cases.parent / "audit"
    audit.mkdir(exist_ok=True)
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(audit))
    args = argparse.Namespace(tool_name=tool, csv_path=str(csv), hostname="HOST-S", case="prof")
    out = io.StringIO()
    with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
        ingest_cli.cmd_csv(args)
    wc.set_current(None)
    return out.getvalue().splitlines()


def scan_route(cluster, cases, monkeypatch, ez, rels, tool="jumplists") -> None:
    open_run(cases, "prof", "evidence/HOST-S", "HOST-S", "evidence folder")
    for rel in rels:
        profile(cluster, ez, tool, rel)
    wc.set_current(None)


def records(cluster, tool="jumplists"):
    return sorted(d for (i, d) in cluster.store if tool in i)


@pytest.fixture
def ez(cases, monkeypatch):
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    return ez_stub(cases, monkeypatch)


LOWER = "Users/alice/appdata/roaming/microsoft/windows/recent"  # a disk in other case
ROUTES = {
    "lower-case folders, scan then csv": (
        ["scan", "csv"],
        [LOWER],
        [ALICE.replace(RECENT, RECENT.lower())],
    ),
    "alice, scan then csv": (["scan", "csv"], [PAIRS["jumplists"][0]], [ALICE]),
    "alice, csv then scan": (["csv", "scan"], [PAIRS["jumplists"][0]], [ALICE]),
    "alice and bob, scan then csv": (["scan", "csv"], list(PAIRS["jumplists"]), [ALICE, BOB]),
    "alice and bob, csv then scan": (["csv", "scan"], list(PAIRS["jumplists"]), [ALICE, BOB]),
}


@pytest.mark.parametrize("name", list(ROUTES))
def test_the_same_jumplist_by_both_routes_is_one_record(cluster, cases, monkeypatch, ez, name):
    order, rels, sources = ROUTES[name]
    for route in order:
        new_run(*FILL_STATE)
        if route == "scan":
            scan_route(cluster, cases, monkeypatch, ez, rels)
        else:
            out = csv_route(cluster, cases, monkeypatch, sources)
            assert not [line for line in out if "stored twice" in line], out
    assert len(records(cluster)) == len(rels), records(cluster)


def test_csv_rows_from_two_profiles_get_each_profiles_scan_id(cluster, cases, monkeypatch, ez):
    """Identical rows from alice and bob are two records, under the ids the
    scan route gives them."""
    scan_route(cluster, cases, monkeypatch, ez, list(PAIRS["jumplists"]))
    by_scan = records(cluster)
    cluster.store.clear()
    new_run(*FILL_STATE)
    csv_route(cluster, cases, monkeypatch, [ALICE, BOB])
    assert records(cluster) == by_scan and len(by_scan) == 2


NO_SCAN_ID = {
    "no SourceFile": None,
    "a profile discovery skips": ALICE.replace("\\alice\\", "\\Public\\"),
    "outside the tool's folder": ALICE.replace(RECENT + "\\AutomaticDestinations", "Desktop"),
}


@pytest.mark.parametrize("name", list(NO_SCAN_ID))
def test_a_row_that_cant_get_the_scan_id_is_counted_and_named(
    cluster, cases, monkeypatch, ez, name
):
    out = csv_route(cluster, cases, monkeypatch, [NO_SCAN_ID[name], ALICE])
    assert (
        "1 rows of jumplists couldn't be given the scan route's id; if the same profile is "
        "also ingested by scan, they're stored twice"
    ) in out
    assert len(records(cluster)) == 2  # each stored once


MOUNTED = "C:\\Users\\examiner\\case\\C\\Users\\{}\\NTUSER.DAT"  # an image mounted in a profile
BOTH = {
    "a jumplist path spelled in other case": (
        "jumplists",
        [PAIRS["jumplists"][0]],
        [ALICE.replace("C:\\Users\\alice", "C:\\users\\ALICE").replace(RECENT, RECENT.upper())],
    ),
    "shellbags of an image mounted in the examiner's profile": (
        "shellbags",
        [PAIRS["shellbags"][0]],
        [MOUNTED.format("alice")],
    ),
    "two profiles' shellbags of an image mounted in the examiner's profile": (
        "shellbags",
        list(PAIRS["shellbags"]),
        [MOUNTED.format("alice"), MOUNTED.format("bob")],
    ),
}


@pytest.mark.parametrize("name", list(BOTH))
def test_the_csv_route_gives_the_profile_the_scan_route_ran_on(
    cluster, cases, monkeypatch, ez, name
):
    tool, rels, sources = BOTH[name]
    scan_route(cluster, cases, monkeypatch, ez, rels, tool)
    by_scan = records(cluster, tool)
    new_run(*FILL_STATE)
    out = csv_route(cluster, cases, monkeypatch, sources, tool)
    assert not [line for line in out if "stored twice" in line], out
    assert records(cluster, tool) == by_scan and len(by_scan) == len(rels)


# The scan route's id of the stand-in's jumplist row from a folder already
# spelled in lower case, as before ids were case-folded
LOWER_ID = "42b4afba01bed23a151a"  # measured at the commit before the fold


def test_case_folding_keeps_the_scan_ids_of_lower_case_folders(cluster, cases, monkeypatch, ez):
    scan_route(cluster, cases, monkeypatch, ez, [LOWER.lower()])
    assert records(cluster) == [LOWER_ID]
    new_run(*FILL_STATE)
    scan_route(cluster, cases, monkeypatch, ez, [PAIRS["jumplists"][0]])  # the on-disk case
    assert records(cluster) == [LOWER_ID]


def test_case_folding_leaves_the_id_0_6_4_stored_it_under(cluster, cases, monkeypatch, ez):
    """The fill-in looks a record up by 0.6.4's id, which has no id source:
    the same whichever case the path is spelled in."""
    carried = []
    real = wc.stamp_or_refuse

    def stamp_or_refuse(actions, client=None):
        real(actions, client)
        carried.extend(a.get("_vhir_old_id") for a in actions)  # bulk.OLD_ID_KEY

    monkeypatch.setattr(wc, "stamp_or_refuse", stamp_or_refuse)
    cluster.created.add("case-000000000000-jumplists-0")  # 0.6.4 made it: no marker
    upper = ALICE.replace("C:\\Users\\alice", "C:\\USERS\\ALICE")
    csv_route(cluster, cases, monkeypatch, [ALICE, upper])
    assert carried == [STORED_064["jumplists"]] * 2
    assert len(records(cluster)) == 1
