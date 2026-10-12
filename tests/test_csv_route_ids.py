# ruff: noqa: F811 - `cluster`, `cases` and `new_process` are the fixtures imported below
"""A per-profile tool's rows get the same id from the pre-parsed csv route as
from the scan route, so the same evidence ingested both ways is one record.

The scan route puts the profile folder it ran the tool on in each id (the
folder discovery hands it: `Users/<name>/` and the tool's own folder, as on
disk). The csv route reads that folder from each row's SourceFile, the file
the tool read. A row whose SourceFile names no such folder (none, or a profile
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


def csv_route(cluster, cases, monkeypatch, sources) -> list[str]:
    """`opensearch-ingest csv --tool jumplists` over one CSV holding the
    stand-in's jumplist row once per SourceFile in `sources` (None: the
    column empty). What it printed."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    csv = cases / "prof" / "evidence" / "jlecmd" / "20260102030405_AutomaticDestinations.csv"
    csv.parent.mkdir(parents=True, exist_ok=True)
    lines = [",".join(COLS["jumplists"])]
    for source in sources:
        values = list(VALS["jumplists"])
        values.insert(COLS["jumplists"].index("SourceFile"), source or "")
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
    args = argparse.Namespace(
        tool_name="jumplists", csv_path=str(csv), hostname="HOST-S", case="prof"
    )
    out = io.StringIO()
    with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
        ingest_cli.cmd_csv(args)
    wc.set_current(None)
    return out.getvalue().splitlines()


def scan_route(cluster, cases, monkeypatch, ez, rels) -> None:
    open_run(cases, "prof", "evidence/HOST-S", "HOST-S", "evidence folder")
    for rel in rels:
        profile(cluster, ez, "jumplists", rel)
    wc.set_current(None)


def records(cluster):
    return sorted(d for (i, d) in cluster.store if "jumplists" in i)


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
