"""Every file an ingest parses is its own step, recorded before its records.

The step's entry names the file (its registered path and the registry's hash
when it is registered evidence, otherwise a fresh hash), where it was read
(realpath, st_dev, mount id) and the index, under an id no other entry has;
the file's records carry that id. What became of the file afterwards is an
entry of its own about the step. The audit writer is the real one, into the
case's audit folder; parsers and OpenSearch are fakes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sift_common.audit import AuditWriter

from opensearch_mcp import ingest
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost

UUID = "0123456789abcdef0123456789abcdef"
C12 = UUID[:12]


def _sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _entries(case: Path) -> list[dict]:
    out = []
    for f in sorted((case / "audit").glob("*.jsonl")):
        out += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    return out


def _steps(case: Path, tool: str) -> list[dict]:
    """The steps of `tool` that read a file (not the facts about them, nor an
    artifact's outcome)."""
    return [
        e for e in _entries(case) if e["tool"] == tool and "about" not in e and e.get("inputs")
    ]


def _summary(e: dict) -> str:
    s = e["result_summary"]
    return s["value"] if isinstance(s, dict) else s


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "acme"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(f"case_id: acme\ncase_uuid: {UUID}\n")
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return d


def _register(case: Path, path: Path) -> str:
    reg = json.loads((case / "evidence.json").read_text())
    digest = _sha(path)
    reg["files"].append({"path": str(path.resolve()), "sha256": digest})
    (case / "evidence.json").write_text(json.dumps(reg))
    return digest


def _place_ok(i: dict, path: Path) -> bool:
    real = os.path.realpath(path)
    return (
        i["path"] == str(path)
        and i["realpath"] == real
        and i["st_dev"] == os.stat(real).st_dev
        and isinstance(i["mnt_id"], int)
    )


def _evtx_host(root: Path, names=("Security.evtx", "System.evtx")) -> DiscoveredHost:
    host = DiscoveredHost(hostname="HOST1", volume_root=root, evtx_dir=root / "evtx")
    host.evtx_dir.mkdir(parents=True)
    for n, name in enumerate(names):
        (host.evtx_dir / name).write_bytes(bytes([n]) * 70000)
    return host


def _ingest_evtx(case: Path, host: DiscoveredHost, fail: str = "") -> list[tuple]:
    """ingest() over the host's evtx; each parse notes its id and the entries
    written by then."""
    seen = []

    def parse(evtx_path, **kw):
        seen.append((evtx_path.name, kw["ingest_audit_id"], len(_entries(case))))
        if evtx_path.name == fail:
            raise RuntimeError("parser crashed")
        return 3, 0, 0

    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.parse_and_index", side_effect=parse),
        patch("opensearch_mcp.ingest.evtx_truncation", return_value=[]),
        patch("opensearch_mcp.ingest._write_ingest_manifest"),
        patch("opensearch_mcp.ingest_status._STATUS_DIR", case / "status"),
    ):
        ingest.ingest(
            hosts=[host],
            client=client,
            audit=AuditWriter(mcp_name="opensearch-ingest-1"),
            case_id="acme",
            include={"evtx"},
            status_pid=os.getpid(),
            status_run_id="run-steps",
            case_dir=case,
        )
    return seen


def test_a_registered_evtx_s_step_names_it_by_the_registry_before_its_records(case):
    host = _evtx_host(case / "evidence" / "kape" / "HOST1")
    security = host.evtx_dir / "Security.evtx"
    digest = _register(case, security)
    seen = _ingest_evtx(case, host)
    steps = {Path(e["params"]["file"]).name: e for e in _steps(case, "ingest_evtx")}
    for name, aid, written_by_then in seen:  # the step was written before the parse
        step = steps[name]
        assert step["audit_id"] == aid
        assert step in _entries(case)[:written_by_then]
        assert step["params"]["index_name"] == f"case-{C12}-evtx-0"
    reg = steps["Security.evtx"]
    assert reg["input_registered"] == [{"path": str(security.resolve()), "sha256": digest}]
    assert "sha256" not in reg["inputs"][0]  # registered: never hashed again
    assert _place_ok(reg["inputs"][0], security)
    assert len({aid for _, aid, _ in seen}) == 2  # one step per file


def test_an_evtx_on_a_volume_outside_the_case_is_hashed_with_its_place(case, tmp_path):
    host = _evtx_host(tmp_path / "mnt" / "vol1")
    _ingest_evtx(case, host)
    assert len(_steps(case, "ingest_evtx")) == 2
    for step in _steps(case, "ingest_evtx"):
        path = Path(step["params"]["file"])
        (i,) = step["inputs"]
        assert i["sha256"] == _sha(path) and _place_ok(i, path)
        assert "input_registered" not in step


def test_what_became_of_each_file_is_its_own_entry_and_no_id_is_used_twice(case):
    host = _evtx_host(case / "evidence" / "kape" / "HOST1")
    _ingest_evtx(case, host, fail="System.evtx")
    entries = _entries(case)
    assert not [i for i, n in Counter(e["audit_id"] for e in entries).items() if n > 1]
    steps = {e["audit_id"]: Path(e["params"]["file"]).name for e in _steps(case, "ingest_evtx")}
    about = {steps[e["about"]]: _summary(e) for e in entries if "about" in e}
    assert about == {
        "Security.evtx": "3 indexed, 0 skipped",
        "System.evtx": "FAILED: parser crashed",
    }


def _bulk_into(sent: list):
    def bulk(client, actions, **kw):
        actions = list(actions)
        sent.extend(json.loads(json.dumps(a)) for a in actions)
        return len(actions), []

    return bulk


def test_records_of_several_files_in_one_batch_carry_each_file_s_own_step(case, monkeypatch):
    from opensearch_mcp import bulk
    from opensearch_mcp.ingest import _ingest_custom_artifact
    from opensearch_mcp.results import HostResult

    root = case / "evidence" / "HOST1"
    tasks = root / "Windows" / "System32" / "Tasks"
    tasks.mkdir(parents=True)
    xml = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<RegistrationInfo><Date>2023-01-17T10:48:01Z</Date></RegistrationInfo>"
        "<Actions><Exec><Command>{}</Command></Exec></Actions></Task>"
    )
    for name in ("Updater", "Backup"):
        (tasks / name).write_text(xml.format(name))
    sent: list = []
    monkeypatch.setattr(bulk.helpers, "bulk", _bulk_into(sent))
    monkeypatch.setattr(wc, "prepare_index", lambda client, index: None)
    monkeypatch.setattr(wc, "note_second_copy", lambda client, ctx, index: None)
    monkeypatch.setattr(wc, "_imported", {case})
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)
    monkeypatch.setattr(ingest, "_safe_count", lambda *a, **k: 0)
    monkeypatch.setattr(wc, "index_name", lambda t: f"case-{C12}-{t}-0")
    host = DiscoveredHost(hostname="HOST1", volume_root=root, system_timezone="UTC")
    ctx = wc.WriteContext(case_dir=case, c12=C12, unit="u-host1", unit_raw="HOST1")
    with wc.writing(ctx):
        _ingest_custom_artifact(
            "tasks", tasks, MagicMock(), AuditWriter(mcp_name="opensearch-ingest-1"), "acme",
            host, 0, HostResult(hostname="HOST1"), [], lambda *a, **k: None, lambda: None,
        )  # fmt: skip
    steps = {Path(e["params"]["file"]).name: e["audit_id"] for e in _steps(case, "ingest_tasks")}
    assert set(steps) == {"Updater", "Backup"} and len(set(steps.values())) == 2
    by_file = {Path(a["_source"]["vhir.source_file"]).name: a for a in sent}
    for name in ("Updater", "Backup"):
        assert by_file[name]["_source"]["vhir.ingest_audit_id"] == steps[name]
        assert wc.STEP_KEY not in by_file[name]  # the marker is never sent


def test_a_json_file_s_step_names_a_registered_file_by_the_registry(case, monkeypatch):
    from opensearch_mcp import ingest_cli

    folder = case / "evidence" / "json"
    folder.mkdir(parents=True)
    f = folder / "events.jsonl"
    f.write_text('{"a": 1}\n')
    digest = _register(case, f)
    seen = []

    def parse(path, *a, **kw):
        seen.append((kw["ingest_audit_id"], len(_entries(case))))
        return 1, 0, 0, False

    for name in ("_ensure_case_active", "_preflight_shard_capacity", "_write_bg_status"):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda c: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr(ingest_cli, "get_client", MagicMock())
    monkeypatch.setattr(ingest_cli, "_open_unit", MagicMock())
    monkeypatch.setattr("opensearch_mcp.parse_json.ingest_json", parse)
    monkeypatch.setattr("opensearch_mcp.write_context.index_name", lambda t: f"case-{C12}-{t}-0")
    args = argparse.Namespace(
        path=str(f), hostname="RD01", case=None, time_field=None, time_from=None,
        time_to=None, batch_size=1000, dry_run=False, index_suffix=None,
    )  # fmt: skip
    ingest_cli.cmd_ingest_json(args)
    (step,) = _steps(case, "ingest_json")
    ((aid, written),) = seen
    assert step["audit_id"] == aid and step in _entries(case)[:written]
    assert step["input_registered"] == [{"path": str(f.resolve()), "sha256": digest}]
    assert _place_ok(step["inputs"][0], f)


def _json_run(case, monkeypatch, f, dry_run=False):
    from opensearch_mcp import ingest_cli

    for name in ("_ensure_case_active", "_preflight_shard_capacity", "_write_bg_status"):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda c: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr(ingest_cli, "_case_dir_for", lambda c: case)
    monkeypatch.setattr(ingest_cli, "get_client", MagicMock())
    monkeypatch.setattr(ingest_cli, "_open_unit", MagicMock())
    monkeypatch.setattr("opensearch_mcp.parse_json.ingest_json", lambda *a, **k: (1, 0, 0, False))
    monkeypatch.setattr("opensearch_mcp.write_context.index_name", lambda t: f"case-{C12}-{t}-0")
    args = argparse.Namespace(
        path=str(f), hostname="RD01", case=None, time_field=None, time_from=None,
        time_to=None, batch_size=1000, dry_run=dry_run, index_suffix=None,
    )  # fmt: skip
    ingest_cli.cmd_ingest_json(args)


def test_the_run_is_one_entry_first_naming_its_registered_input_and_its_root(case, monkeypatch):
    f = case / "evidence" / "json" / "events.jsonl"
    f.parent.mkdir(parents=True)
    f.write_text('{"a": 1}\n')
    digest = _register(case, f)
    _json_run(case, monkeypatch, f)
    entries = _entries(case)
    runs = [e for e in entries if e["tool"] == "idx_ingest_json"]
    assert len(runs) == 1 and entries[0] == runs[0]
    (run,) = runs
    reg = {"path": str(f.resolve()), "sha256": digest}
    assert run["input_registered"] == [reg] and run["roots"] == [reg]
    assert _place_ok(run["inputs"][0], f) and run["params"]["input"] == str(f)
    assert len(entries) > 1  # its steps follow; none after them is the run's


def test_a_dry_run_writes_no_entry(case, monkeypatch):
    f = case / "events.jsonl"
    f.write_text('{"a": 1}\n')
    _json_run(case, monkeypatch, f, dry_run=True)
    assert _entries(case) == []


def test_srum_s_plaso_fallback_step_names_the_database_and_the_jsonl_it_wrote(case, monkeypatch):
    from opensearch_mcp import parse_plaso
    from opensearch_mcp.ingest import _ingest_plaso_artifact
    from opensearch_mcp.results import HostResult

    srum = case / "evidence" / "HOST1" / "SRUDB.dat"
    srum.parent.mkdir(parents=True)
    srum.write_bytes(b"esedb")
    written = {}

    def plaso(parser, source, tmpdir):
        out = Path(tmpdir) / "srum.jsonl"
        out.write_text('{"x": 1}\n')
        written["jsonl"] = (str(out), _sha(out))
        return out

    seen = []
    monkeypatch.setattr("opensearch_mcp.wintools.wintools_available", lambda: False)
    monkeypatch.setattr(parse_plaso, "_run_plaso", plaso)
    monkeypatch.setattr(
        parse_plaso, "_ingest_jsonl",
        lambda *a, **kw: seen.append((kw["ingest_audit_id"], len(_entries(case)))) or (4, 0),
    )  # fmt: skip
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)
    monkeypatch.setattr(ingest, "_safe_count", lambda *a, **k: 0)
    monkeypatch.setattr(wc, "index_name", lambda t: f"case-{C12}-{t}-0")
    monkeypatch.setattr(wc, "current", lambda: MagicMock(unit="u1"))
    host = DiscoveredHost(hostname="HOST1", volume_root=srum.parent)
    _ingest_plaso_artifact(
        "srum", srum, MagicMock(), AuditWriter(mcp_name="opensearch-ingest-1"), "acme", host, 0,
        HostResult(hostname="HOST1"), [], lambda *a, **k: None, lambda: None,
    )  # fmt: skip
    (step,) = [s for s in _steps(case, "ingest_srum") if s.get("inputs")]
    ((aid, written_by_then),) = seen
    assert step["audit_id"] == aid and step in _entries(case)[:written_by_then]
    assert step["inputs"][0]["sha256"] == _sha(srum) and _place_ok(step["inputs"][0], srum)
    path, digest = written["jsonl"]
    assert [(o["path"], o["sha256"]) for o in step["outputs"]] == [(path, digest)]


def _fake_wintools(case: Path, monkeypatch, csv_name: str = "SrumECmd_Output.csv"):
    """run_windows_command through the gateway: it writes the tool's CSV into
    the case's extractions and answers with its own audit id."""
    from opensearch_mcp import wintools

    def run(command, purpose, input_files=None, timeout=300):
        out = case / "extractions" / "wintools-out"
        out.mkdir(parents=True, exist_ok=True)
        (out / csv_name).write_text("a,b\n1,2\n")
        return {"success": True, "audit_id": "wintools-steve-20261009-007",
                "csv_output_dir": "extractions/wintools-out"}  # fmt: skip

    monkeypatch.setattr(wintools, "run_windows_tool", run)
    monkeypatch.setattr(wintools, "_to_unc_path", lambda rel: f"\\\\sift\\cases\\{rel}")
    return case / "extractions" / "wintools-out" / csv_name


def test_a_wintools_staging_copy_is_a_step_that_keeps_the_wintools_call_s_id(
    case, tmp_path, monkeypatch
):
    from opensearch_mcp import ops
    from opensearch_mcp.wintools import run_tool_and_get_csv

    prefetch = tmp_path / "mnt" / "vol1" / "Prefetch"  # outside the case: staged
    prefetch.mkdir(parents=True)
    (prefetch / "CMD.EXE-1.pf").write_bytes(b"pf1")
    _fake_wintools(case, monkeypatch, "PECmd_Output.csv")
    produced: list = []
    with ops.recording(AuditWriter(mcp_name="opensearch-ingest-1"), case, "ingest_prefetch", {}):
        run_tool_and_get_csv("PECmd.exe", "-d", str(prefetch), hostname="HOST1",
                             produced_by=produced)  # fmt: skip
    (step,) = [e for e in _entries(case) if e["tool"] == "stage_for_wintools"]
    original = prefetch / "CMD.EXE-1.pf"
    (i,) = step["inputs"]
    assert i["sha256"] == _sha(original) and _place_ok(i, original)
    (o,) = step["outputs"]
    copy = case / "extractions" / "Prefetch-HOST1" / "CMD.EXE-1.pf"
    assert (o["path"], o["sha256"]) == (str(copy), _sha(copy))
    assert step["wintools_audit_id"] == "wintools-steve-20261009-007"
    assert produced == [step["audit_id"], "wintools-steve-20261009-007"]


def test_srum_through_wintools_records_the_csv_its_records_come_from(case, monkeypatch):
    from opensearch_mcp import parse_csv
    from opensearch_mcp.ingest import _ingest_plaso_artifact
    from opensearch_mcp.results import HostResult

    srum = case / "evidence" / "HOST1" / "SRUDB.dat"
    srum.parent.mkdir(parents=True)
    srum.write_bytes(b"esedb")
    csv = _fake_wintools(case, monkeypatch)
    seen = []
    monkeypatch.setattr("opensearch_mcp.wintools.wintools_available", lambda: True)
    monkeypatch.setattr(
        parse_csv, "ingest_csv",
        lambda **kw: seen.append((kw["csv_path"], kw["ingest_audit_id"])) or (2, 0, 0),
    )  # fmt: skip
    monkeypatch.setattr(ingest, "_write_ingest_manifest", lambda *a, **k: None)
    monkeypatch.setattr(ingest, "_safe_count", lambda *a, **k: 0)
    monkeypatch.setattr(wc, "index_name", lambda t: f"case-{C12}-{t}-0")
    monkeypatch.setattr(wc, "current", lambda: MagicMock(unit="u1"))
    host = DiscoveredHost(hostname="HOST1", volume_root=srum.parent)
    _ingest_plaso_artifact(
        "srum", srum, MagicMock(), AuditWriter(mcp_name="opensearch-ingest-1"), "acme", host, 0,
        HostResult(hostname="HOST1"), [], lambda *a, **k: None, lambda: None,
    )  # fmt: skip
    ((read, aid),) = seen
    (step,) = [e for e in _entries(case) if e["audit_id"] == aid]
    (i,) = step["inputs"]
    assert (Path(i["path"]), i["sha256"]) == (csv, _sha(csv))  # the CSV, not SRUDB.dat
    (staged,) = [e for e in _entries(case) if e["tool"] == "stage_for_wintools"]
    assert i["produced_by"] == [staged["audit_id"], "wintools-steve-20261009-007"]
    assert staged["inputs"][0]["sha256"] == _sha(srum)
    assert [Path(o["path"]).name for o in staged["outputs"]] == ["SRUDB.dat"]


def _memory_run(
    case: Path, image: Path, monkeypatch, plugins="windows.pslist,windows.netscan", vol3=None
):
    """cmd_ingest_memory with vol3 a fake (each plugin gives one record naming
    the image it read); each flush notes its records' id and the entries
    written by then."""
    from opensearch_mcp import ingest_cli
    from opensearch_mcp import parse_memory as pm

    flushed, called = [], []

    def flush(client, actions):
        flushed.append((actions[0]["_source"]["vhir.ingest_audit_id"], len(_entries(case)),
                        [a["_source"]["Image"] for a in actions]))  # fmt: skip
        return len(actions), 0

    monkeypatch.setattr(pm, "_find_vol3", lambda: "vol")
    import subprocess
    import types

    # vol3's symbol check only; 7z and the rest keep the real subprocess
    monkeypatch.setattr(pm, "subprocess", types.SimpleNamespace(
        run=MagicMock(return_value=MagicMock(stderr="")),
        TimeoutExpired=subprocess.TimeoutExpired,
    ))  # fmt: skip
    monkeypatch.setattr(
        pm, "run_vol3_plugin",
        vol3 or (lambda image_path, plugin, timeout=0:
                 [{"PID": 4, "Plugin": plugin, "Image": image_path.name}]),
    )  # fmt: skip
    monkeypatch.setattr(pm, "flush_bulk", flush)
    monkeypatch.setattr(pm, "stored_counts", lambda *a, **k: {})
    monkeypatch.setattr("opensearch_mcp.gateway.call_tool", lambda n, a, **k: called.append(n))
    for name in ("_ensure_case_active", "_preflight_shard_capacity", "write_status", "_gate"):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda c: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr(ingest_cli, "_case_dir_for", lambda c: case)
    monkeypatch.setattr(ingest_cli, "get_client", MagicMock())
    args = argparse.Namespace(path=str(image), hostname="WKS1", case=None, tier=1,
                              plugins=plugins, yes=True, timeout=60)  # fmt: skip
    code = 0
    try:
        ingest_cli.cmd_ingest_memory(args)
    except SystemExit as e:
        code = e.code or 0
    return flushed, called, code


def test_each_vol3_plugin_is_its_own_step_naming_the_registered_image(case, monkeypatch):
    image = case / "evidence" / "wks1.raw"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"MEM" * 1000)
    digest = _register(case, image)
    flushed, _, code = _memory_run(case, image, monkeypatch)
    assert code == 0 and len(flushed) == 2
    ids = [aid for aid, _, _ in flushed]
    assert len(set(ids)) == 2  # one step per plugin
    for aid, written_by_then, _ in flushed:
        (step,) = [e for e in _entries(case)[:written_by_then] if e["audit_id"] == aid]
        assert step["tool"].startswith("ingest_vol3_")
        assert step["input_registered"] == [{"path": str(image.resolve()), "sha256": digest}]
        assert _place_ok(step["inputs"][0], image) and "sha256" not in step["inputs"][0]
    entries = _entries(case)
    assert not [a for a, n in Counter(e["audit_id"] for e in entries).items() if n > 1]
    assert [e for e in entries if e["tool"] == "idx_ingest_memory"] == [entries[0]]  # the run


def test_a_failed_plugin_is_its_one_entry(case, monkeypatch):
    image = case / "evidence" / "wks1.raw"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"MEM" * 1000)
    _register(case, image)

    def vol3(image_path, plugin, timeout=0):
        if plugin == "windows.netscan":
            raise RuntimeError("vol3 exited 1")
        return [{"PID": 4, "Plugin": plugin, "Image": image_path.name}]

    flushed, _, _ = _memory_run(case, image, monkeypatch, vol3=vol3)
    assert len(flushed) == 1
    netscan = [e for e in _entries(case) if e["params"].get("plugin") == "windows.netscan"]
    assert len(netscan) == 1 and _summary(netscan[0]) == "FAILED: vol3 exited 1"


def _stub_7z(tmp_path: Path, monkeypatch) -> None:
    """A stub on PATH, not 7z: it writes two samples into the -o folder."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    seven = bindir / "7z"
    seven.write_text(
        """#!/bin/sh
for a in "$@"; do case "$a" in -o*) d="${a#-o}";; esac; done
printf 'SAMPLE-ONE' > "$d/s1.raw"
printf 'SAMPLE-TWO' > "$d/s2.raw"
"""
    )
    seven.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")


def test_a_7z_s_extraction_is_a_step_and_each_sample_traces_to_it(case, tmp_path, monkeypatch):
    _stub_7z(tmp_path, monkeypatch)
    archive = case / "evidence" / "mem.7z"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"7z" + b"x" * 64)
    a_sha = _register(case, archive)
    monkeypatch.setenv("VHIR_ARCHIVE_PASSWORD", "hunter2")
    flushed, _, _ = _memory_run(case, archive, monkeypatch, plugins="windows.pslist")
    entries = _entries(case)
    (extraction,) = [e for e in entries if e["tool"] == "extract_archive"]
    assert extraction["input_registered"] == [{"path": str(archive.resolve()), "sha256": a_sha}]
    assert "hunter2" not in json.dumps(extraction)  # 7z reads it on stdin, never argv
    s2_sha = hashlib.sha256(b"SAMPLE-TWO").hexdigest()
    (s2,) = [o for o in extraction["outputs"] if o["path"].endswith("s2.raw")]
    assert s2["sha256"] == s2_sha and s2["size"] == 10
    ((aid, written_by_then, _),) = [f for f in flushed if f[2] == ["s2.raw"]]
    (step,) = [e for e in entries[:written_by_then] if e["audit_id"] == aid]
    (i,) = step["inputs"]
    assert (i["path"], i["sha256"]) == (s2["path"], s2_sha)  # the manifest's hash
    assert i["produced_by"] == extraction["audit_id"]
    assert entries.index(extraction) < entries.index(step)


def test_the_whole_7z_route_is_one_run_and_no_id_is_used_twice(case, tmp_path, monkeypatch):
    _stub_7z(tmp_path, monkeypatch)
    archive = case / "evidence" / "mem.7z"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"7z" + b"x" * 64)
    _register(case, archive)
    flushed, _, _ = _memory_run(case, archive, monkeypatch)  # 2 samples x 2 plugins
    entries = _entries(case)
    assert len(flushed) == 4 and len({aid for aid, _, _ in flushed}) == 4
    assert not [a for a, n in Counter(e["audit_id"] for e in entries).items() if n > 1]
    assert [e["tool"] for e in entries].count("idx_ingest_memory") == 1
    assert entries[0]["tool"] == "idx_ingest_memory"


def test_a_kape_zip_s_extraction_is_a_step_before_its_files_are_read(case, tmp_path, monkeypatch):
    import opensearch_mcp.containers as C
    from opensearch_mcp import ingest_cli as cli

    archive = case / "evidence" / "kape.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"PK\x03\x04" + b"z" * 32)
    digest = _register(case, archive)
    work = tmp_path / "work"
    work.mkdir()
    logs = "C/Windows/System32/winevt/Logs"

    def extract(path, dest, password=None):
        (dest / logs).mkdir(parents=True)
        (dest / logs / "Security.evtx").write_bytes(b"E" * 100)
        (dest / logs / "System.evtx").write_bytes(b"S" * 100)
        (dest / "C/Windows/System32/config").mkdir(parents=True)
        (dest / "C/Windows/System32/config/SYSTEM").write_bytes(b"R" * 10)

    class Stop(Exception):
        pass

    at_ingest = []

    def ingest(hosts=None, **kw):
        at_ingest.append(_entries(case))
        raise Stop

    for name, value in (
        ("detect_container", lambda p: "archive"),
        ("cleanup_orphaned_mounts", lambda: None),
        ("extract_container", extract),
        ("is_velociraptor_collection", lambda p: False),
        ("make_ingest_tmpdir", lambda case_id: work),
        ("cleanup_tmpdir", lambda *a, **k: None),
        ("check_sudo", lambda: None),
    ):
        monkeypatch.setattr(C, name, value)
    monkeypatch.setattr(cli, "ingest", ingest)
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "get_client", "_gate"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr(cli, "_case_dir_for", lambda c: case)
    args = argparse.Namespace(
        path=str(archive), case="acme", yes=True, hostname="HOST1", vss=False,
        all_logs=False, no_hayabusa=True, skip_triage=True,
    )  # fmt: skip
    with pytest.raises((Stop, SystemExit)):
        cli.cmd_scan(args)
    (extraction,) = [e for e in _entries(case) if e["tool"] == "extract_archive"]
    assert extraction["input_registered"] == [{"path": str(archive.resolve()), "sha256": digest}]
    made = {Path(o["path"]).name: o["sha256"] for o in extraction["outputs"]}
    assert made == {
        "Security.evtx": hashlib.sha256(b"E" * 100).hexdigest(),
        "System.evtx": hashlib.sha256(b"S" * 100).hexdigest(),
        "SYSTEM": hashlib.sha256(b"R" * 10).hexdigest(),
    }
    assert at_ingest and extraction in at_ingest[0]  # recorded before any file is read


def test_a_memory_ingest_registers_nothing(case, monkeypatch):
    image = case / "evidence" / "wks1.raw"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"MEM" * 1000)
    _register(case, image)
    before = (case / "evidence.json").read_text()
    _, called, code = _memory_run(case, image, monkeypatch, plugins="windows.pslist")
    assert code == 0 and "evidence_register" not in called
    assert (case / "evidence.json").read_text() == before


def test_a_mount_is_recorded_with_its_points_and_each_unmount_pairs_with_one(
    case, tmp_path, monkeypatch
):
    import subprocess as sp

    import opensearch_mcp.containers as C
    from opensearch_mcp import ops

    image = case / "evidence" / "disk.raw"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\0" * 512)
    digest = _register(case, image)
    dest = tmp_path / "mnt"

    def mount_raw(path, d, ctx):  # a stand-in: two volumes, as _mount_raw finds them
        vols = []
        for n, off in ((1, 1048576), (2, 105906176)):
            v = d / f"p{n}"
            v.mkdir(parents=True)
            ctx.add_mount(v)
            ctx.offsets[v] = off
            vols.append(v)
        return vols

    monkeypatch.setattr(C, "_mount_raw", mount_raw)
    monkeypatch.setattr(
        C.subprocess, "run", lambda cmd, **k: sp.CompletedProcess(cmd, 0, b"", b"")
    )
    ctx = C.MountContext()
    ops.set_run(AuditWriter(mcp_name="opensearch-ingest-1"), case)
    try:
        vols = C.mount_image(image, dest, ctx)
        (mount,) = [e for e in _entries(case) if "mount" in e]
        assert mount["mount"]["image"] == str(image.resolve())
        assert mount["input_registered"] == [{"path": str(image.resolve()), "sha256": digest}]
        points = mount["mount"]["points"]
        assert [(p["target"], p["offset"]) for p in points] == [
            (str(vols[0]), 1048576),
            (str(vols[1]), 105906176),
        ]
        for p in points:
            real = os.path.realpath(p["target"])
            assert p["realpath"] == real and p["st_dev"] == os.stat(real).st_dev
            assert p["mnt_id"] == ops.mnt_id(real) and isinstance(p["mnt_id"], int)
            assert "sha256" not in p  # a mount point is never hashed
        ctx.cleanup()
    finally:
        ops.set_run(None, None)
    unmounts = [e["umount"] for e in _entries(case) if "umount" in e]
    assert sorted((u["realpath"], u["mnt_id"]) for u in unmounts) == sorted(
        (p["realpath"], p["mnt_id"]) for p in points
    )
    assert not [e for e in _entries(case) if "umount" in e and "about" in e]  # paired by place


def test_each_shadow_copy_store_is_a_mount_point_with_its_store(case, tmp_path, monkeypatch):
    import opensearch_mcp.containers as C
    from opensearch_mcp import ops

    raw = tmp_path / "disk.raw"
    raw.write_bytes(b"\0" * 512)
    dest = tmp_path / "vss"

    def at(raw_path, d, ctx, offset, name):
        found = []
        for n in (1, 2):
            store = f"{name}-vss{n}" if name else f"vss{n}"  # as _mount_vss_at names them
            p = d / store
            p.mkdir(parents=True)
            found.append((store, p))
        return found, "", ""

    monkeypatch.setattr(C, "_is_ntfs", lambda path, off: True)
    monkeypatch.setattr(C, "_mount_vss_at", at)
    ctx = C.MountContext()
    ops.set_run(AuditWriter(mcp_name="opensearch-ingest-1"), case)
    try:
        C.mount_vss(raw, dest, ctx, offsets={"p2": 105906176})
    finally:
        ops.set_run(None, None)
    (mount,) = [e for e in _entries(case) if "mount" in e]
    points = mount["mount"]["points"]
    assert [(p["store"], p["offset"]) for p in points] == [
        ("vss1", 105906176),
        ("vss2", 105906176),
    ]
    for p in points:
        assert set(p) == {"target", "realpath", "st_dev", "mnt_id", "offset", "store"}


def _write_ctx(case, monkeypatch, sent):
    from opensearch_mcp import bulk

    monkeypatch.setattr(bulk.helpers, "bulk", _bulk_into(sent))
    monkeypatch.setattr(wc, "prepare_index", lambda client, index: None)
    monkeypatch.setattr(wc, "note_second_copy", lambda client, ctx, index: None)
    monkeypatch.setattr(wc, "_imported", {case})
    return wc.WriteContext(case_dir=case, c12=C12, unit="u-host1", unit_raw="HOST1")


def test_a_record_carries_the_step_open_when_it_is_written_whatever_its_parser_said(
    case, monkeypatch
):
    from opensearch_mcp.bulk import flush_bulk

    sent: list = []
    action = {"_index": f"case-{C12}-evtx-0", "_id": "r1",
              "_source": {"vhir.ingest_audit_id": "the-parser-s-own", "x": 1}}  # fmt: skip
    with wc.writing(_write_ctx(case, monkeypatch, sent)), wc.op("opensearch-ingest-1-001"):
        flush_bulk(MagicMock(), [action])
    assert sent[0]["_source"]["vhir.ingest_audit_id"] == "opensearch-ingest-1-001"


def test_a_case_record_with_no_step_open_is_refused_and_nothing_is_sent(case, monkeypatch):
    from opensearch_mcp.bulk import flush_bulk

    sent: list = []
    actions = [{"_index": f"case-{C12}-evtx-0", "_id": "r1", "_source": {"x": 1}}]
    with wc.writing(_write_ctx(case, monkeypatch, sent)):
        with pytest.raises(wc.NoWriteContext, match="no step is recorded"):
            flush_bulk(MagicMock(), actions)
    assert sent == []


def _json_stored(case, monkeypatch, f) -> list[dict]:
    """cmd_ingest_json over `f`, its unit and write context real, with a fake
    parser sending two records through the real flush_bulk; the records as
    stored."""
    from opensearch_mcp import ingest_cli
    from opensearch_mcp.bulk import flush_bulk

    sent: list = []
    _write_ctx(case, monkeypatch, sent)

    def parse(path, client, index_name, hostname, **kw):
        flush_bulk(client, [
            {"_index": index_name, "_id": f"{path.name}:{n}",
             "_source": {"row": n, "message": "café", "host.name": "RD01"}}
            for n in (1, 2)
        ])  # fmt: skip
        return 2, 0, 0, False

    for name in ("_ensure_case_active", "_preflight_shard_capacity", "_write_bg_status", "_gate"):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda c: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr(ingest_cli, "_case_dir_for", lambda c: case)
    monkeypatch.setattr(ingest_cli, "get_client", MagicMock())
    monkeypatch.setattr("opensearch_mcp.parse_json.ingest_json", parse)
    args = argparse.Namespace(
        path=str(f), hostname="RD01", case=None, time_field=None, time_from=None,
        time_to=None, batch_size=1000, dry_run=False, index_suffix=None,
    )  # fmt: skip
    ingest_cli.cmd_ingest_json(args)
    return [a["_source"] for a in sent]


def test_each_record_carries_the_registered_evidence_its_run_was_given(case, monkeypatch):
    f = case / "evidence" / "json" / "events.jsonl"
    f.parent.mkdir(parents=True)
    f.write_text('{"a": 1}\n')
    digest = _register(case, f)
    stored = _json_stored(case, monkeypatch, f)
    assert len(stored) == 2
    for src in stored:
        assert src["vhir.original.path"] == str(f.resolve())
        assert src["vhir.original.sha256"] == digest


def test_a_run_given_unregistered_evidence_stamps_no_original(case, monkeypatch):
    f = case / "loose.jsonl"
    f.write_text('{"a": 1}\n')
    stored = _json_stored(case, monkeypatch, f)
    assert len(stored) == 2
    assert not [k for src in stored for k in src if k.startswith("vhir.original")]


def _spec_hash(src: dict) -> str:
    """The content hash as defined, computed here independently: the dotted
    fields, sorted, compact, UTF-8, without the hash itself, host.id,
    vhir.prev_ids, triage.*, threat_intel.* and the evtx pipeline's fields."""

    def flat(d, prefix=""):
        out = {}
        for k, v in d.items():
            if isinstance(v, dict) and v:
                out.update(flat(v, f"{prefix}{k}."))
            else:
                out[f"{prefix}{k}"] = v
        return out

    keep = {
        k: v
        for k, v in flat(src).items()
        if k not in {"vhir.content_hash", "host.id", "vhir.prev_ids",
                     "winlog.event_data._pipeline_error"}
        and not k.startswith(("triage.", "threat_intel."))
    }  # fmt: skip
    text = json.dumps(keep, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_each_record_carries_its_content_hash_over_what_is_stored(case, monkeypatch):
    f = case / "evidence" / "json" / "events.jsonl"
    f.parent.mkdir(parents=True)
    f.write_text('{"a": 1}\n')
    _register(case, f)
    for src in _json_stored(case, monkeypatch, f):
        assert src["vhir.content_hash"] == _spec_hash(src)
        renamed = {**src, "host.id": "RD01 (renamed)", "triage.verdict": "SUSPICIOUS"}
        assert _spec_hash(renamed) == src["vhir.content_hash"]  # later changes don't count


def test_a_non_object_evtx_data_goes_to_data_raw_as_the_pipeline_writes_it():
    from opensearch_mcp.parse_evtx import _normalise_data

    for data, raw in (("text", "text"), (["a", 1, None, True], "[a, 1, null, true]")):
        doc = {"winlog.event_data": {"Data": data, "User": "bob"}}
        _normalise_data(doc)
        assert doc == {"winlog.event_data": {"Data_raw": raw, "User": "bob"}}
    obj = {"winlog.event_data": {"Data": {"Name": "a"}}}
    _normalise_data(obj)
    assert obj == {"winlog.event_data": {"Data": {"Name": "a"}}}  # an object stays


def test_every_template_maps_the_original_and_content_hash_as_keywords():
    from opensearch_mcp import mappings as m

    files = [m._EVTX_TEMPLATE_FILE] + [m._MAPPINGS_DIR / f for _, f in m._TEMPLATES_REGISTRY]
    assert len(files) == 16
    for path in files:
        props = m.with_host_key_fields(m._load_json(path))["template"]["mappings"]["properties"]
        for field in ("vhir.original.path", "vhir.original.sha256", "vhir.content_hash"):
            assert props[field] == {"type": "keyword"}, (path.name, field)


def test_what_evidence_says_for_the_stamped_fields_is_removed_and_replaced(case, monkeypatch):
    from opensearch_mcp.bulk import flush_bulk

    sent: list = []
    monkeypatch.setattr(wc, "REMOVED", {})  # this write's count only
    action = {"_index": f"case-{C12}-evtx-0", "_id": "r1", "_source": {
        "x": 1, "vhir.content_hash": "forged", "vhir.original.path": "/forged",
        "vhir": {"original": {"sha256": "forged"}},
    }}  # fmt: skip
    with wc.writing(_write_ctx(case, monkeypatch, sent)), wc.op("opensearch-ingest-1-001"):
        flush_bulk(MagicMock(), [action])
    src = sent[0]["_source"]
    assert "vhir" not in src and "vhir.original.path" not in src  # no run root: none stamped
    assert src["vhir.content_hash"] == _spec_hash(src) != "forged"
    assert wc.removed_note(c12=C12) == "3 reserved identity fields removed from evidence"


def test_each_existing_case_index_is_given_the_stamp_fields_as_one_step(case):
    from opensearch_mcp import mappings

    client = MagicMock()
    client.cat.indices.return_value = [
        {"index": f"case-{C12}-evtx-0"}, {"index": f"case-{C12}-json-x-0"},
    ]  # fmt: skip
    client.indices.put_mapping.side_effect = lambda index, body: (
        (_ for _ in ()).throw(RuntimeError("conflict")) if "json" in index else {}
    )
    result = mappings.put_stamp_fields(client, AuditWriter(mcp_name="opensearch-mcp"))
    keywords = {f: {"type": "keyword"} for f in mappings.STAMP_FIELDS}
    for call in client.indices.put_mapping.call_args_list:
        assert call.kwargs["body"] == {"properties": keywords}
    assert result["patched"] == [f"case-{C12}-evtx-0"]
    assert [f["index"] for f in result["failed"]] == [f"case-{C12}-json-x-0"]
    (step,) = [e for e in _entries(case) if e["tool"] == "put_stamp_fields"]
    assert step["params"]["indices"] == [f"case-{C12}-evtx-0"] and step["failed"]


def test_installing_the_templates_gives_existing_case_indices_the_stamp_fields():
    from opensearch_mcp import mappings

    client = MagicMock()
    client.cat.indices.return_value = [{"index": f"case-{C12}-evtx-0"}]
    result = mappings.install_all_templates(client)
    assert result["stamp_fields"]["patched"] == [f"case-{C12}-evtx-0"]
    bodies = [c.kwargs["body"] for c in client.indices.put_mapping.call_args_list]
    assert {"properties": {f: {"type": "keyword"} for f in mappings.STAMP_FIELDS}} in bodies
