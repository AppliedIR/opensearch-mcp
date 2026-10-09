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
