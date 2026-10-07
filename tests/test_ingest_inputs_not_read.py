"""An ingest names the inputs it didn't read, in the status the examiner reads.

A JSON or delimited file that failed to parse, a delimited file of no
recognised format, a memory archive holding more than one image, and a
Prefetch or SRUM source that gave no records all ended as a clean `complete`,
with nothing in the status to say so. The JSON, delimited, Plaso and memory
status rows run in-process with the parsers' writes stubbed; the memory
cleanup rows run real workers in a scratch HOME. No cluster is used, and every
value is synthetic.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest

from opensearch_mcp import ingest_status, shard_capacity
from opensearch_mcp import server as srv

NOT_JSON = "user=alice action=logon\n"  # a .jsonl that holds no JSON
GOOD = "".join(json.dumps({"ts": f"2024-01-0{i + 1}T10:00:00Z", "n": i}) + "\n" for i in range(3))
TWO_COLS = "user,ts\nalice,2024-01-01T09:00:00Z\nbob,2024-01-02T10:00:00Z\n"
ONE_COL = "sha256\n" + "".join(f"{i:064x}\n" for i in range(1, 4))


@pytest.fixture
def bg(tmp_path, monkeypatch):
    """cmd_ingest_json / cmd_ingest_delimited as a background run: its status
    file in tmp_path, a stub client, case c1."""
    from opensearch_mcp import ingest_cli as cli

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    (tmp_path / "audit").mkdir()
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-1")
    monkeypatch.setattr(cli, "get_client", lambda: mock.MagicMock())
    for n in (
        "_preflight_shard_capacity",
        "_ensure_case_active",
    ):
        monkeypatch.setattr(cli, n, mock.MagicMock())
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(cli, "stored_counts", lambda *a, **k: {})
    monkeypatch.setattr(
        "opensearch_mcp.parse_json.flush_bulk", lambda client, actions, **k: (len(actions), 0)
    )
    return cli


def _status() -> dict:
    (st,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return st


def _not_read(st: dict) -> list[str]:
    return [w for w in st.get("warnings", []) if "not ingested, or only in part" in w]


def _files(root: Path, files: dict) -> Path:
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    return root


# --- JSON -------------------------------------------------------------------


def test_json_files_that_fail_to_parse_are_named(bg, tmp_path):
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD, "a.jsonl": NOT_JSON, "b.jsonl": NOT_JSON})
    bg.cmd_ingest_json(argparse.Namespace(path=str(d), case="c1", hostname="h1"))
    st = _status()
    (w,) = _not_read(st)
    assert "h1: json: 2 file(s)" in w, w
    assert str(d / "a.jsonl") in w and str(d / "b.jsonl") in w, w
    assert "Cannot detect JSON format" in w, w  # the reason is shown
    (row,) = st["checklist"]
    assert row["status"] == "done" and row["detail"].startswith("3 docs submitted"), row


def test_a_single_json_file_that_fails_is_named(bg, tmp_path):
    f = _files(tmp_path / "ev", {"only.jsonl": NOT_JSON}) / "only.jsonl"
    bg.cmd_ingest_json(argparse.Namespace(path=str(f), case="c1", hostname="h1"))
    (w,) = _not_read(_status())
    assert "1 file(s)" in w and str(f) in w, w


def test_a_halt_keeps_the_json_files_already_not_read(bg, tmp_path, monkeypatch):
    from opensearch_mcp.bulk import ShardCapacityExhausted

    def full(client, actions, **k):
        raise ShardCapacityExhausted("shard limit reached")

    monkeypatch.setattr("opensearch_mcp.parse_json.flush_bulk", full)
    d = _files(tmp_path / "ev", {"a.jsonl": NOT_JSON, "b.jsonl": GOOD})
    with pytest.raises(ShardCapacityExhausted):
        bg.cmd_ingest_json(argparse.Namespace(path=str(d), case="c1", hostname="h1"))
    st = _status()
    assert st["status"] == "failed" and st["checklist"] == [], st
    (w,) = _not_read(st)
    assert w.startswith("h1: json: 1 file(s)") and str(d / "a.jsonl") in w, w


def test_json_that_all_parses_carries_no_warning(bg, tmp_path):
    d = _files(tmp_path / "ev", {"good.jsonl": GOOD, "more.jsonl": GOOD})
    bg.cmd_ingest_json(argparse.Namespace(path=str(d), case="c1", hostname="h1"))
    st = _status()
    assert _not_read(st) == [] and st["total_indexed"] == 6, st


# --- delimited --------------------------------------------------------------


@pytest.fixture
def delim(bg, monkeypatch):
    """ingest_delimited stubbed: 2 rows a file, or raises for a name with
    'broken'; format detection is real, and raises for a name with 'locked'."""
    from opensearch_mcp import parse_delimited as pd

    def fake(path, *a, **k):
        if "broken" in path.name:
            raise ValueError("bad row at line 2")
        return 2, 0, 0, 0

    real_detect = pd._detect_delimited_format

    def detect(path):
        if "locked" in path.name:
            raise PermissionError(13, "Permission denied", str(path))
        return real_detect(path)

    monkeypatch.setattr(pd, "ingest_delimited", fake)
    monkeypatch.setattr(pd, "_detect_delimited_format", detect)
    return bg


def _delim_args(path, **kw):
    return argparse.Namespace(path=str(path), case="c1", hostname=kw.pop("hostname", "h1"), **kw)


def test_a_one_column_file_is_named(delim, tmp_path):
    d = _files(tmp_path / "ev", {"logons.csv": TWO_COLS, "hashes.csv": ONE_COL})
    delim.cmd_ingest_delimited(_delim_args(d))
    st = _status()
    (w,) = _not_read(st)
    assert "h1: delimited: 1 file(s)" in w and f"{d / 'hashes.csv'} (unrecognized format)" in w
    assert st["total_indexed"] == 2, st


def test_a_delimited_file_that_fails_to_parse_is_named(delim, tmp_path):
    d = _files(tmp_path / "ev", {"logons.csv": TWO_COLS, "broken.csv": TWO_COLS})
    delim.cmd_ingest_delimited(_delim_args(d))
    (w,) = _not_read(_status())
    assert f"{d / 'broken.csv'} (bad row at line 2)" in w, w


def test_a_recursive_walk_names_what_each_host_left_out(delim, tmp_path):
    d = _files(
        tmp_path / "ev",
        {
            "h1/logons.csv": TWO_COLS,
            "h1/hashes.csv": ONE_COL,
            "h2/a-locked.csv": TWO_COLS,
            "h2/logons.csv": TWO_COLS,
        },
    )
    delim.cmd_ingest_delimited(_delim_args(d, hostname="", recursive=True))
    st = _status()
    (w,) = _not_read(st)
    assert "2 file(s)" in w, w
    assert f"{d / 'h1' / 'hashes.csv'} (unrecognized format)" in w, w
    assert f"{d / 'h2'} (" in w and "Permission denied" in w, w


def test_auto_hosts_names_a_hosts_one_column_file(delim, tmp_path):
    d = _files(
        tmp_path / "ev",
        {"logons-h1.csv": TWO_COLS, "hashes-h1.csv": ONE_COL, "logons-h2.csv": TWO_COLS},
    )
    delim.cmd_ingest_delimited(_delim_args(d, hostname="", auto_hosts="h1,h2"))
    st = _status()
    (w,) = _not_read(st)
    assert "1 file(s)" in w and str(d / "hashes-h1.csv") in w, w
    assert st["total_indexed"] == 4, st


def test_a_halt_keeps_the_delimited_files_already_not_read(delim, tmp_path, monkeypatch):
    from opensearch_mcp import parse_delimited as pd
    from opensearch_mcp.bulk import ShardCapacityExhausted

    stub = pd.ingest_delimited

    def fake(path, *a, **k):
        if "full" in path.name:
            raise ShardCapacityExhausted("shard limit reached")
        return stub(path, *a, **k)

    monkeypatch.setattr(pd, "ingest_delimited", fake)
    d = _files(tmp_path / "ev", {"a-broken.csv": TWO_COLS, "b-full.csv": TWO_COLS})
    with pytest.raises(ShardCapacityExhausted):
        delim.cmd_ingest_delimited(_delim_args(d))
    st = _status()
    assert st["status"] == "failed" and st["checklist"] == [], st
    (w,) = _not_read(st)
    assert w.startswith("h1: delimited: 1 file(s)"), w
    assert f"{d / 'a-broken.csv'} (bad row at line 2)" in w, w


def test_a_halt_with_nothing_not_read_carries_no_warning(delim, tmp_path, monkeypatch):
    from opensearch_mcp import parse_delimited as pd
    from opensearch_mcp.bulk import ShardCapacityExhausted

    def full(path, *a, **k):
        raise ShardCapacityExhausted("shard limit reached")

    monkeypatch.setattr(pd, "ingest_delimited", full)
    d = _files(tmp_path / "ev", {"logons.csv": TWO_COLS})
    with pytest.raises(ShardCapacityExhausted):
        delim.cmd_ingest_delimited(_delim_args(d))
    st = _status()
    assert st["status"] == "failed" and _not_read(st) == [] and st["checklist"] == [], st


def test_delimited_files_that_all_parse_carry_no_warning(delim, tmp_path):
    d = _files(tmp_path / "ev", {"logons.csv": TWO_COLS, "more.csv": TWO_COLS})
    delim.cmd_ingest_delimited(_delim_args(d))
    st = _status()
    assert _not_read(st) == [] and st["total_indexed"] == 4, st


# --- memory archives (real workers) ------------------------------------------


def _exited(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return True


@pytest.fixture
def mem(tmp_path, monkeypatch):
    """A scratch HOME with case c1 and no OpenSearch config, so a worker that
    gets past extraction fails at its first cluster call. The stand-in 7z
    writes one empty file per name listed in the archive."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / ".vhir" / "ingest-status")
    case_dir = tmp_path / "cases" / "c1"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: c1\n")
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "active_case").write_text(str(case_dir))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "7z").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; last="$a"; done\n'
        'for n in $(cat "$last"); do : > "$out/$n"; done\n'
    )
    (bindir / "7z").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    (tmp_path / "tmp").mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    monkeypatch.setattr(srv, "get_client", lambda: mock.MagicMock())
    monkeypatch.setattr(srv, "_get_os", lambda: mock.MagicMock())

    def run(*members: str) -> dict:
        archive = tmp_path / "mem.zip"
        archive.write_text("\n".join(members) + "\n")
        resp = srv.idx_ingest_memory(path=str(archive), hostname="hostA", dry_run=False)
        # a worker that already ended (no cluster here) is answered as it ended
        assert resp["status"] in ("started", "failed"), resp
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ingests = srv.idx_ingest_status(case_id="c1").get("ingests", [])
            if ingests and ingests[0]["status"] in ("failed", "complete"):
                break
            time.sleep(0.25)
        while time.monotonic() < deadline and not _exited(resp["pid"]):
            time.sleep(0.1)  # the status is written before the worker's exit cleans up
        ingests[0]["log"] = Path(resp["log_file"]).read_text()
        return ingests[0]

    run.tmp = tmp_path / "tmp"
    return run


def test_an_archive_with_two_memory_images_ingests_both(mem):
    st = mem("hostA.raw", "hostB.vmem")
    assert "Memory image: hostA.raw" in st["log"], st
    assert "Memory image: hostB.vmem" in st["log"], st
    assert "not ingested" not in st["log"], st
    assert list(mem.tmp.glob("vhir-mem-*")) == []


def test_an_extracted_image_is_removed_when_the_run_fails(mem):
    st = mem("hostA.raw")
    assert st["status"] == "failed", st  # no OpenSearch config in this HOME
    assert "Memory image: hostA.raw" in st["log"], st
    assert list(mem.tmp.glob("vhir-mem-*")) == []


def test_an_archive_with_one_memory_image_goes_on_to_ingest_it(mem):
    st = mem("hostA.raw")
    assert "Memory image: hostA.raw" in st["log"] and "not ingested" not in st["log"], st


@pytest.fixture
def mem_status(bg, mem, tmp_path, monkeypatch):
    """cmd_ingest_memory in-process: the stand-in 7z, Volatility stubbed to
    index one record from whichever image it is given."""
    from opensearch_mcp import parse_memory

    monkeypatch.setattr(bg, "AuditWriter", mock.MagicMock())
    seen = []

    def ingest_memory(image_path, on_progress, **kw):
        seen.append(image_path.name)
        on_progress("plugin_start", plugin="windows.info")
        on_progress("plugin_done", plugin="windows.info", indexed=1)
        return {"windows.info": {"indexed": 1, "status": "done"}}

    monkeypatch.setattr(parse_memory, "ingest_memory", ingest_memory)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")

    def run(*members):
        archive = tmp_path / "mem.zip"
        archive.write_text("\n".join(members) + "\n")
        args = argparse.Namespace(
            path=str(archive),
            case="c1",
            hostname="hostA",
            tier=1,
            plugins="windows.info",
            yes=True,
            timeout=60,
        )
        bg.cmd_ingest_memory(args)
        if len(members) > 1:  # each image's run, and the archive's
            return srv.idx_ingest_status(case_id="c1")["ingests"], seen[0]
        return _status(), seen[0]

    run.seen = seen
    return run


def test_every_image_an_archive_holds_is_ingested_as_its_own_unit(mem_status):
    from sift_common import host_identity

    from opensearch_mcp import write_context as wc

    statuses, _ = mem_status("hostA.raw", "hostB.vmem", "hostC.mem")
    assert len(statuses) == 4
    assert sorted(mem_status.seen) == ["hostA.raw", "hostB.vmem", "hostC.mem"]
    units = host_identity.load(wc.case_dir_for("c1")).units.values()
    locators = sorted(u["locator"] for u in units if u.get("source") == "memory image")
    assert [loc.rsplit("!", 1)[1] for loc in locators] == ["hostA.raw", "hostB.vmem", "hostC.mem"]
    assert len({loc.rsplit("!", 1)[0] for loc in locators}) == 1  # one archive


def test_a_one_image_archive_carries_no_warning(mem_status):
    st, ingested = mem_status("hostA.raw")
    assert ingested == "hostA.raw"
    assert _not_read(st) == [] and [c["artifact"] for c in st["checklist"]] == ["windows.info"]


# --- Prefetch and SRUM --------------------------------------------------------


@pytest.fixture
def plaso(tmp_path, monkeypatch):
    """ingest() over one host, Plaso's result stubbed, no wintools; the status
    is written for case c1 and read back through idx_ingest_status."""
    import os

    from opensearch_mcp import parse_plaso, wintools
    from opensearch_mcp.discover import DiscoveredHost
    from opensearch_mcp.ingest import ingest

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(wintools, "wintools_available", lambda: False)
    vr = tmp_path / "vr"

    def run(tool: str, files: dict, result) -> tuple:
        _files(vr, files)
        if tool == "prefetch":
            path = vr / "Windows/Prefetch"
            path.mkdir(parents=True, exist_ok=True)
        else:
            path = vr / "Windows/System32/SRU/SRUDB.dat"

        def fake(*a, **k):
            if isinstance(result, Exception):
                raise result
            return result

        monkeypatch.setattr(parse_plaso, f"parse_{tool}", fake)
        host = DiscoveredHost(hostname="h1", volume_root=vr)
        host.artifacts = [(tool, path)]
        client = mock.MagicMock()
        client.count.side_effect = Exception("no index")
        audit = mock.MagicMock()
        audit._next_audit_id.return_value = "aid-1"
        res = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            include={tool},
            status_pid=os.getpid(),
            status_run_id="run-1",
        )
        summaries = [c.kwargs.get("result_summary", "") for c in audit.log.call_args_list]
        return res.hosts[0], _status(), summaries

    return run


PF = {"Windows/Prefetch/AAA.EXE-0000AAAA.pf": "x" * 64, "Windows/Prefetch/BBB.EXE-0000BBBB.pf": ""}


def test_prefetch_files_that_give_no_records_fail(plaso):
    host, st, audit = plaso("prefetch", PF, (0, 0))
    (row,) = st["checklist"]
    assert row["status"] == "failed" and "2 .pf file(s)" in row["detail"], row
    assert [s for s in audit if s.startswith("FAILED")] and not [
        s for s in audit if s.startswith("0 indexed")
    ], audit


def test_a_plaso_error_on_prefetch_fails(plaso):
    err = subprocess.CalledProcessError(1, ["log2timeline.py"])
    host, st, _ = plaso("prefetch", PF, err)
    (row,) = st["checklist"]
    assert row["status"] == "failed", row


def test_an_upper_case_pf_name_counts(plaso):
    host, st, _ = plaso("prefetch", {"Windows/Prefetch/CCC.EXE-0000CCCC.PF": "x"}, (0, 0))
    (row,) = st["checklist"]
    assert row["status"] == "failed" and "1 .pf file(s)" in row["detail"], row


def test_a_srum_database_that_gives_no_records_fails(plaso):
    host, st, _ = plaso("srum", {"Windows/System32/SRU/SRUDB.dat": "x" * 64}, (0, 0))
    (row,) = st["checklist"]
    assert row["status"] == "failed" and "SRUDB.dat" in row["detail"], row


def test_the_failure_survives_the_detection_phase_rewrite(plaso):
    from opensearch_mcp.ingest_cli import _rebuilt_status_host

    host, _, _ = plaso("prefetch", PF, (0, 0))
    (art,) = _rebuilt_status_host(host)["artifacts"]
    assert art["status"] == "failed" and "2 .pf file(s)" in art["error"], art


def test_a_prefetch_folder_with_no_pf_files_is_complete(plaso):
    files = {"Windows/Prefetch/Layout.ini": "x", "Windows/Prefetch/ReadyBoot/Trace1.fx": "x"}
    host, st, _ = plaso("prefetch", files, (0, 0))
    (row,) = st["checklist"]
    assert row["status"] == "done" and row["detail"].startswith("0 docs"), row


def test_prefetch_that_gives_records_is_complete(plaso):
    host, st, _ = plaso("prefetch", PF, (18, 0))
    (row,) = st["checklist"]
    assert row["status"] == "done" and row["detail"].startswith("18 docs"), row


def test_records_all_rejected_are_not_read_as_no_records(plaso):
    host, st, _ = plaso("prefetch", PF, (0, 5))
    (row,) = st["checklist"]
    # failed for the rejection, which names it; never "no records read"
    assert row["status"] == "failed" and "5 of 5 records rejected" in row["detail"], row
    assert "no records read" not in row["detail"]
