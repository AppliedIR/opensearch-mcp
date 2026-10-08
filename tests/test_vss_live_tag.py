"""A shadow copy's records never replace one already in the case.

A store's records are written with `create`, so a record on the live volume
keeps `vhir.vss_id: live` and a store-only record keeps the tag of the first
store to write it. The cluster's 409 for a record already there counts as
already present: not a failure, no warning, no banner, and it never halts the
run. Values are synthetic.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import bulk, ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

# -- the stamp


def _case():
    cid = f"vss-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    return d


def _ctx(d, vss_id):
    host = DiscoveredHost(
        hostname="WKS01", volume_root=d / "mnt", vss_id=vss_id, unit_locator="evidence/img.e01"
    )
    return wc.host_context(d, d.name, host)


def _actions(ctx, op=None):
    a = {"_index": f"case-{ctx.c12}-amcache-x", "_id": "r1", "_source": {"k": "v"}}
    if op:
        a["_op_type"] = op
    return [a]


@pytest.mark.parametrize("store", ["vss1", "p2-vss3"])
def test_a_shadow_copys_records_are_created_never_overwritten(store):
    d = _case()
    ctx = _ctx(d, store)
    for op in (None, "index"):
        (a,) = _actions(ctx, op)
        wc.stamp(ctx, [a])
        assert a["_op_type"] == "create"


@pytest.mark.parametrize("vss_id", ["live", ""])
def test_live_and_plain_records_still_overwrite(vss_id):
    d = _case()
    ctx = _ctx(d, vss_id)
    (a,) = _actions(ctx)
    wc.stamp(ctx, [a])
    assert a.get("_op_type", "index") == "index"


def test_another_op_type_is_left_alone():
    d = _case()
    ctx = _ctx(d, "vss1")
    for op in ("update", "delete", "create"):
        (a,) = _actions(ctx, op)
        wc.stamp(ctx, [a])
        assert a["_op_type"] == op


# -- bulk: a 409 on create is already present


def _err(op, status, reason):
    return {op: {"_id": "e1", "status": status, "error": {"type": "x", "reason": reason}}}


CONFLICT = _err("create", 409, "[e1]: version conflict, document already exists")


def _flush(success, errors, n):
    actions = [{"_index": "scratch", "_id": f"e{i}", "_source": {}} for i in range(n)]
    with patch.object(bulk.helpers, "bulk", return_value=(success, errors)):
        return bulk.flush_bulk(MagicMock(), actions)


def _keep(n):
    """A flush whose n records are all in the case already."""
    if n:
        assert _flush(0, [CONFLICT] * n, n) == (0, 0)


def test_a_record_already_in_the_case_is_present_not_failed(capsys):
    bulk.reset_circuit_breaker()
    assert _flush(0, [CONFLICT], 1) == (0, 0)
    assert bulk.get_already_present() == 1
    assert bulk.get_last_bulk_reason() == ""
    assert "WARNING" not in capsys.readouterr().err


def test_other_errors_in_the_batch_still_fail(capsys):
    bulk.reset_circuit_breaker()
    errors = [CONFLICT, _err("index", 409, "conflict on index"), _err("create", 400, "mapper")]
    assert _flush(1, errors, 4) == (1, 2)
    assert bulk.get_already_present() == 1
    assert "version conflict" not in bulk.get_last_bulk_reason()
    assert "WARNING: 2/4 docs failed" in capsys.readouterr().err


def test_a_run_of_batches_all_already_present_never_halts():
    bulk.reset_circuit_breaker()
    for _ in range(bulk._CIRCUIT_BREAKER_THRESHOLD + 2):
        assert _flush(0, [CONFLICT, CONFLICT], 2) == (0, 0)
    assert bulk._get_counter() == 0
    assert bulk.get_already_present() == 2 * (bulk._CIRCUIT_BREAKER_THRESHOLD + 2)


def test_a_systemic_failure_beside_present_records_still_counts():
    bulk.reset_circuit_breaker()
    systemic = _err("create", 400, "this action would add [2] shards")
    _flush(0, [CONFLICT, systemic], 2)
    assert bulk._get_counter() == 1


def test_a_new_run_starts_its_count_at_zero():
    _flush(0, [CONFLICT], 1)
    bulk.reset_circuit_breaker()
    assert bulk.get_already_present() == 0


def test_the_run_summary_says_how_many_were_kept():
    from opensearch_mcp.ingest_cli import _run_summary
    from opensearch_mcp.results import HostResult, IngestResult

    result = IngestResult(hosts=[HostResult(hostname="WKS01", volume_root="/x")])
    assert _run_summary(result) == "1 host(s), 0 entries indexed."
    result.already_present = 1234
    assert _run_summary(result) == (
        "1 host(s), 0 entries indexed. 1,234 shadow-copy entries were already in the "
        "case (live or an earlier copy) and kept their tag."
    )


# -- the scan: an artifact whose records are all present is read, and the total is said


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _scan(tmp_path, present, vss_id="vss1", before=0):
    root = tmp_path / "HOST1"
    srum = root / "Windows/System32/sru/SRUDB.dat"
    srum.parent.mkdir(parents=True)
    srum.write_bytes(b"x")
    host = DiscoveredHost(hostname="HOST1", volume_root=root, vss_id=vss_id)
    host.artifacts.append(("srum", srum))

    def plaso(*a, **k):  # every row it read was in the case already
        _keep(present)
        return 0, 0

    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    bulk.reset_circuit_breaker()
    bulk._tls.already_present = before  # what the thread counted before this run
    with (
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
        patch("opensearch_mcp.wintools.wintools_available", return_value=False),
        patch("opensearch_mcp.parse_srum._parse_srum_plaso", side_effect=plaso),
    ):
        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            include={"srum"},
            status_pid=os.getpid(),
            status_run_id=f"run-{uuid.uuid4().hex[:6]}",
        )
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return result, status


def test_a_store_artifact_whose_rows_are_all_live_is_not_failed(tmp_path, status_dir):
    result, status = _scan(tmp_path, present=12)
    (row,) = status["checklist"]
    assert row["status"] == "done", row
    assert result.already_present == 12


def test_an_artifact_that_read_nothing_still_fails(tmp_path, status_dir):
    _, status = _scan(tmp_path, present=0)
    (row,) = status["checklist"]
    assert row["status"] == "failed"
    assert "no records read" in row["detail"]


def test_the_status_says_how_many_were_already_in_the_case(tmp_path, status_dir):
    _, status = _scan(tmp_path, present=8)
    assert status["already_present"] == 8
    assert status["message"].endswith(
        " 8 shadow-copy records were already in the case (live or an earlier copy) "
        "and kept their tag."
    )
    raw = ingest_status.read_active_ingests()
    assert [r["totals"]["already_present"] for r in raw] == [8]


def test_a_run_counts_only_its_own(tmp_path, status_dir):
    result, status = _scan(tmp_path, present=4, before=30)
    assert result.already_present == 4
    assert status["already_present"] == 4


def test_a_run_with_nothing_present_says_nothing_of_it(tmp_path, status_dir, monkeypatch):
    monkeypatch.setattr(
        "opensearch_mcp.parse_srum.parse_srum",
        lambda **kw: (3, 0, "", "completed", 3),
        raising=True,
    )
    root = tmp_path / "H"
    srum = root / "SRUDB.dat"
    root.mkdir()
    srum.write_bytes(b"x")
    host = DiscoveredHost(hostname="H", volume_root=root, vss_id="live")
    host.artifacts.append(("srum", srum))
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    bulk.reset_circuit_breaker()
    with patch("opensearch_mcp.ingest.sha256_file", return_value="h"):
        ingest(hosts=[host], client=client, audit=audit, case_id="c2", include={"srum"},
               status_pid=os.getpid(), status_run_id="run-none")  # fmt: skip
    (status,) = srv.idx_ingest_status(case_id="c2")["ingests"]
    assert "already_present" not in status
    assert "shadow-copy" not in status["message"]


# -- a whole scan: the console and the status, through the hayabusa phase


@pytest.mark.parametrize("no_hayabusa", [False, True], ids=["hayabusa", "no hayabusa"])
def test_a_scan_says_how_many_were_kept_on_screen_and_in_its_status(
    tmp_path, monkeypatch, capsys, no_hayabusa
):
    import argparse
    import shutil

    from opensearch_mcp import ingest as ing
    from opensearch_mcp import ingest_cli as cli

    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-kept")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    evtx = tmp_path / "ev" / "evtx"
    evtx.mkdir(parents=True)
    (evtx / "Security.evtx").write_bytes(b"\0" * 70000)
    host = DiscoveredHost(hostname="HOST1", volume_root=tmp_path / "ev", vss_id="vss1")
    host.evtx_dir = evtx
    monkeypatch.setattr(cli, "discover", lambda *a, **k: [host])
    monkeypatch.setattr(
        cli, "_preflight_host_discovery", lambda *a, **k: ({"decisions_applied": []}, None)
    )
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")

    def parse(*a, **k):  # 2 written, 7 already in the case
        bulk._tls.already_present = getattr(bulk._tls, "already_present", 0) + 7
        return 2, 0, 0

    monkeypatch.setattr(ing, "parse_and_index", parse)
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")
    monkeypatch.setattr(ing, "run_hayabusa_batch", lambda *a, **k: {})
    monkeypatch.setattr(shutil, "which", lambda n: "/x/hayabusa")
    cli.cmd_scan(argparse.Namespace(
        path=str(tmp_path / "ev"), case="c1", yes=True, hostname="HOST1", all_logs=False,
        no_hayabusa=no_hayabusa, skip_triage=True))  # fmt: skip
    assert (
        "1 host(s), 2 entries indexed. 7 shadow-copy entries were already in the case "
        "(live or an earlier copy) and kept their tag."
    ) in capsys.readouterr().out
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    assert status["status"] == "complete"
    assert status["already_present"] == 7


# -- the parser decides: rows already in the case never hide a parser that failed


def _failing_parser(monkeypatch, module, primary, fallback):
    """The wintools parser writes rows that are all in the case already, then
    raises; the Plaso fallback fails too."""
    import subprocess

    from opensearch_mcp import wintools

    def wrote_then_raised(*a, **k):
        _keep(5)
        raise RuntimeError("PECmd crashed mid-run")

    def plaso_failed(*a, **k):
        raise subprocess.CalledProcessError(1, ["log2timeline.py"])

    monkeypatch.setattr(wintools, "wintools_available", lambda: True)
    monkeypatch.setattr(module, primary, wrote_then_raised)
    monkeypatch.setattr(module, fallback, plaso_failed)


def _scan_artifact(tmp_path, artifact):
    root = tmp_path / "HOST1"
    if artifact == "prefetch":
        path = root / "Windows/Prefetch"
        path.mkdir(parents=True)
        (path / "CALC.EXE-1234.pf").write_bytes(b"x")
    else:
        path = root / "Windows/System32/sru/SRUDB.dat"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"x")
    host = DiscoveredHost(hostname="HOST1", volume_root=root, vss_id="vss1")
    host.artifacts.append((artifact, path))
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    bulk.reset_circuit_breaker()
    with patch("opensearch_mcp.ingest.sha256_file", return_value="h"):
        ingest(hosts=[host], client=client, audit=audit, case_id="c1", include={artifact},
               status_pid=os.getpid(), status_run_id=f"run-{uuid.uuid4().hex[:6]}")  # fmt: skip
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    (row,) = status["checklist"]
    return row


@pytest.mark.parametrize(
    "artifact, module, primary, fallback",
    [
        ("prefetch", "parse_prefetch", "_parse_prefetch_wintools", "_parse_prefetch_plaso"),
        ("srum", "parse_srum", "_parse_srum_wintools", "_parse_srum_plaso"),
    ],
)
def test_a_parser_that_failed_is_failed_whatever_was_already_present(
    tmp_path, status_dir, monkeypatch, artifact, module, primary, fallback
):
    import importlib

    _failing_parser(monkeypatch, importlib.import_module(f"opensearch_mcp.{module}"),
                    primary, fallback)  # fmt: skip
    row = _scan_artifact(tmp_path, artifact)
    assert row["status"] == "failed" and "no records read" in row["detail"], row


@pytest.mark.parametrize(
    "artifact, module, primary, fallback",
    [
        ("prefetch", "parse_prefetch", "_parse_prefetch_wintools", "_parse_prefetch_plaso"),
        ("srum", "parse_srum", "_parse_srum_wintools", "_parse_srum_plaso"),
    ],
)
def test_a_fallback_that_worked_with_every_row_already_present_is_done(
    tmp_path, status_dir, monkeypatch, artifact, module, primary, fallback
):
    """No wintools: Plaso parses the shadow copy's artifact, and every row it
    wrote was in the case already. Its reduced-fidelity note doesn't fail it."""
    import importlib

    from opensearch_mcp import wintools

    mod = importlib.import_module(f"opensearch_mcp.{module}")

    def plaso_all_present(*a, **k):
        _keep(12)
        return 0, 0

    monkeypatch.setattr(wintools, "wintools_available", lambda: False)
    monkeypatch.setattr(mod, primary, lambda *a, **k: pytest.fail("no wintools here"))
    monkeypatch.setattr(mod, fallback, plaso_all_present)
    row = _scan_artifact(tmp_path, artifact)
    assert row["status"] == "done", row


@pytest.mark.parametrize(
    "artifact, module, primary, fallback",
    [
        ("prefetch", "parse_prefetch", "_parse_prefetch_wintools", "_parse_prefetch_plaso"),
        ("srum", "parse_srum", "_parse_srum_wintools", "_parse_srum_plaso"),
    ],
)
def test_rows_an_earlier_attempt_kept_never_count_for_the_final_one(
    tmp_path, status_dir, monkeypatch, artifact, module, primary, fallback
):
    """PECmd keeps 3 rows already in the case, then raises; Plaso then runs
    and produces nothing."""
    import importlib

    from opensearch_mcp import wintools

    mod = importlib.import_module(f"opensearch_mcp.{module}")

    def wrote_then_raised(*a, **k):
        _keep(3)
        raise RuntimeError("PECmd crashed mid-run")

    monkeypatch.setattr(wintools, "wintools_available", lambda: True)
    monkeypatch.setattr(mod, primary, wrote_then_raised)
    monkeypatch.setattr(mod, fallback, lambda *a, **k: (0, 0))
    row = _scan_artifact(tmp_path, artifact)
    assert row["status"] == "failed" and "no records read" in row["detail"], row


def test_a_count_of_kept_records_covers_its_block_only():
    bulk.reset_circuit_breaker()
    _keep(2)
    with bulk.counting_present() as outer:
        _keep(3)
        with bulk.counting_present() as inner:
            _keep(4)
        _keep(1)
    _keep(5)
    assert (outer[0], inner[0]) == (8, 4)


@pytest.mark.parametrize(
    "artifact, module, primary",
    [("prefetch", "parse_prefetch", "_parse_prefetch_wintools"),
     ("srum", "parse_srum", "_parse_srum_wintools")],
)  # fmt: skip
def test_a_wintools_parser_whose_rows_are_all_in_the_case_is_done(
    tmp_path, status_dir, monkeypatch, artifact, module, primary
):
    import importlib

    from opensearch_mcp import wintools

    def all_present(*a, **k):
        _keep(7)
        return 0, 0

    monkeypatch.setattr(wintools, "wintools_available", lambda: True)
    monkeypatch.setattr(importlib.import_module(f"opensearch_mcp.{module}"), primary, all_present)
    row = _scan_artifact(tmp_path, artifact)
    assert row["status"] == "done", row


def test_a_final_attempt_that_failed_fails_whatever_rows_it_reports(
    tmp_path, status_dir, monkeypatch
):
    monkeypatch.setattr(
        "opensearch_mcp.parse_srum.parse_srum", lambda **kw: (2, 0, "", "failed", 2)
    )
    row = _scan_artifact(tmp_path, "srum")
    assert row["status"] == "failed", row
