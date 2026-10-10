"""Ingest reads only what traces FULL to the case's registered evidence.

Before anything of an input is read, its trace is taken: a registered file or
folder, or a recorded output whose producing operation traces FULL (its hash
still pending on that operation's job while the file is the output recorded).
Anything else (a file nothing recorded, one made by a declared action, a
recorded output changed since) is refused: the worker exits nonzero, names
the file and the fix in a refusal entry, and nothing is parsed or sent. A run
records the roots its input traces to. Inside a registered folder only the
files its manifest lists are read. The audit writer and the resolver are the
real ones; parsers and OpenSearch are fakes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sift_common.audit import AuditWriter

from opensearch_mcp import ingest_cli, ops

pytestmark = pytest.mark.evidence_gate

UUID = "0123456789abcdef0123456789abcdef"
RUN = "the run, recorded before any of its steps"


def _sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _entries(case: Path) -> list[dict]:
    out = []
    for f in sorted((case / "audit").glob("*.jsonl")):
        out += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    return out


def _summary(e: dict) -> str:
    s = e.get("result_summary")
    return s.get("value", "") if isinstance(s, dict) else str(s or "")


def _runs(case: Path, tool: str) -> list[dict]:
    return [e for e in _entries(case) if e["tool"] == tool and _summary(e) == RUN]


def _refusals(case: Path) -> list[dict]:
    return [e for e in _entries(case) if _summary(e).startswith("REFUSED")]


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "acme"
    (d / "audit").mkdir(parents=True)
    (d / "evidence").mkdir()
    (d / "extractions").mkdir()
    (d / "CASE.yaml").write_text(f"case_id: acme\ncase_uuid: {UUID}\n")
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name in ("_ensure_case_active", "_preflight_shard_capacity", "_write_bg_status"):
        monkeypatch.setattr(ingest_cli, name, MagicMock())
    monkeypatch.setattr(ingest_cli, "_load_case_host_dict", lambda c: None)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "acme")
    monkeypatch.setattr(ingest_cli, "_case_dir_for", lambda c: d)
    monkeypatch.setattr(ingest_cli, "get_client", MagicMock())
    monkeypatch.setattr(ingest_cli, "_open_unit", MagicMock())
    monkeypatch.setattr("opensearch_mcp.write_context.index_name", lambda t: f"case-x-{t}-0")
    return d


def _register(case: Path, path: Path) -> dict:
    reg = json.loads((case / "evidence.json").read_text())
    row = {"path": str(path.resolve()), "sha256": _sha(path)}
    reg["files"].append(row)
    (case / "evidence.json").write_text(json.dumps(reg))
    return row


def _json(monkeypatch, f: Path) -> tuple[int, list[str]]:
    """cmd_ingest_json over `f`: (exit code, the files parsed)."""
    parsed: list[str] = []
    monkeypatch.setattr(
        "opensearch_mcp.parse_json.ingest_json",
        lambda path, *a, **k: parsed.append(Path(path).name) or (1, 0, 0, False),
    )
    args = argparse.Namespace(
        path=str(f), hostname="RD01", case=None, time_field=None, time_from=None,
        time_to=None, batch_size=1000, dry_run=False, index_suffix=None,
    )  # fmt: skip
    try:
        ingest_cli.cmd_ingest_json(args)
    except SystemExit as e:
        return int(e.code or 0), parsed
    return 0, parsed


def _delimited(monkeypatch, path: Path) -> tuple[int, list[str]]:
    """cmd_ingest_delimited over a file or folder: (exit code, the files parsed)."""
    parsed: list[str] = []
    monkeypatch.setattr(
        "opensearch_mcp.parse_delimited.ingest_delimited",
        lambda f, *a, **k: parsed.append(Path(f).name) or (1, 0, 0, False),
    )
    args = argparse.Namespace(
        path=str(path), hostname="RD01", recursive=False, auto_hosts="", case=None,
        time_field=None, delimiter=None, format=None, time_from=None, time_to=None,
        batch_size=1000, dry_run=False, index_suffix=None,
    )  # fmt: skip
    try:
        ingest_cli.cmd_ingest_delimited(args)
    except SystemExit as e:
        return int(e.code or 0), parsed
    return 0, parsed


def _output(path: Path, sha: str) -> dict:
    """An output record as file_place.output_records writes it."""
    st = path.stat()
    return {**ops.place(path), "sha256": sha, "size": st.st_size, "st_ino": st.st_ino,
            "mtime_ns": st.st_mtime_ns}  # fmt: skip


def _made(case: Path, tool: str, source: Path, made: Path, sha: str, **extra) -> None:
    """An operation that read the registered `source` and wrote `made`."""
    AuditWriter("sift-mcp", audit_dir=str(case / "audit")).log(
        tool=tool,
        params={"command": f"EvtxECmd -f {source} --csv {made.parent}"},
        result_summary={"exit_code": 0, "output_files": [str(made)]},
        extra={"inputs": [ops.place(source)],
               "input_registered": [{"path": str(source.resolve()), "sha256": _sha(source)}],
               "outputs": [_output(made, sha)], **extra},
    )  # fmt: skip


def test_a_file_nothing_registered_or_recorded_is_refused_before_it_is_read(
    case, monkeypatch, capsys
):
    f = case / "loose" / "events.jsonl"
    f.parent.mkdir()
    f.write_text('{"a": 1}\n')
    hashed: list = []
    monkeypatch.setattr(ops, "sha256_file", lambda p: hashed.append(p) or "0" * 64)
    code, parsed = _json(monkeypatch, f)
    assert code != 0 and parsed == [] and hashed == []  # refused unhashed
    assert _runs(case, "idx_ingest_json") == []  # no run: nothing of it was read
    (refusal,) = _refusals(case)
    assert refusal["refused"]["path"] == str(f.resolve()) and refusal["refused"]["fix"]
    assert "sha256" not in refusal["inputs"][0]
    err = capsys.readouterr().err
    assert "not ingested" in err and refusal["refused"]["fix"] in err


def test_a_registered_file_is_ingested_and_an_unrecorded_copy_beside_it_is_not(case, monkeypatch):
    f = case / "evidence" / "events.jsonl"
    f.write_text('{"a": 1}\n')
    reg = _register(case, f)
    copy = case / "evidence" / "events-copy.jsonl"
    copy.write_bytes(f.read_bytes())
    assert _json(monkeypatch, f) == (0, ["events.jsonl"])
    (run,) = _runs(case, "idx_ingest_json")
    assert run["roots"] == [reg]
    code, parsed = _json(monkeypatch, copy)
    assert code != 0 and parsed == []
    assert [r["refused"]["path"] for r in _refusals(case)] == [str(copy.resolve())]


def test_an_original_registered_where_it_lies_outside_the_case_is_ingested_in_place(
    case, tmp_path, monkeypatch
):
    srv = tmp_path / "srv" / "rd01"
    srv.mkdir(parents=True)
    original = srv / "events.jsonl"
    original.write_text('{"a": 1}\n')
    reg = _register(case, original)
    (srv / "notes.jsonl").write_text('{"b": 2}\n')  # beside it, never registered
    assert _json(monkeypatch, original) == (0, ["events.jsonl"])
    (run,) = _runs(case, "idx_ingest_json")
    assert run["roots"] == [reg] and run["inputs"][0]["realpath"] == str(original.resolve())
    assert not (case / "evidence" / "events.jsonl").exists()  # read where it lies
    code, parsed = _json(monkeypatch, srv / "notes.jsonl")
    assert code != 0 and parsed == []


def test_a_folder_of_files_nothing_recorded_is_refused_whole(case, monkeypatch):
    folder = case / "extractions" / "op-unknown"
    folder.mkdir()
    (folder / "a.csv").write_text("x,y\n1,2\n")
    (folder / "b.csv").write_text("x,y\n3,4\n")
    code, parsed = _delimited(monkeypatch, folder)
    assert code != 0 and parsed == []
    assert _runs(case, "idx_ingest_delimited") == []


def test_one_unrecorded_file_refuses_its_whole_folder(case, monkeypatch):
    """Partial should not be possible: a folder is read whole or not at all."""
    folder = case / "evidence" / "csvs"
    folder.mkdir()
    (folder / "a.csv").write_text("x,y\n1,2\n")
    _register(case, folder / "a.csv")
    (folder / "b.csv").write_text("x,y\n3,4\n")
    code, parsed = _delimited(monkeypatch, folder)
    assert code != 0 and parsed == []
    assert [r["refused"]["path"] for r in _refusals(case)] == [str((folder / "b.csv").resolve())]


def test_an_output_whose_hash_is_pending_is_ingested_by_its_producing_operation(
    case, tmp_path, monkeypatch
):
    image = tmp_path / "srv" / "host.E01"
    image.parent.mkdir()
    image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"q" * 64)
    reg = _register(case, image)
    csv = case / "extractions" / "rc-1" / "out.csv"
    csv.parent.mkdir()
    csv.write_text("x,y\n1,2\n")
    _made(case, "run_command", image, csv, "pending:hash-00000000000000c1")
    assert _delimited(monkeypatch, csv) == (0, ["out.csv"])
    (run,) = _runs(case, "idx_ingest_delimited")
    assert run["roots"] == [reg]


def test_a_recorded_output_changed_since_is_refused(case, tmp_path, monkeypatch):
    image = tmp_path / "srv" / "host.E01"
    image.parent.mkdir()
    image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"q" * 64)
    _register(case, image)
    csv = case / "extractions" / "rc-1" / "out.csv"
    csv.parent.mkdir()
    csv.write_text("x,y\n1,2\n")
    _made(case, "run_command", image, csv, "pending:hash-00000000000000c2")
    csv.write_text("x,y\n1,2\n9,9\n")  # rewritten after the operation recorded it
    code, parsed = _delimited(monkeypatch, csv)
    assert code != 0 and parsed == []
    (refusal,) = _refusals(case)
    assert refusal["refused"]["path"] == str(csv.resolve())


def test_a_file_a_declared_action_made_is_refused(case, tmp_path, monkeypatch):
    original = tmp_path / "srv" / "events.jsonl"
    original.parent.mkdir()
    original.write_text('{"a": 1}\n')
    _register(case, original)
    copy = case / "extractions" / "copied" / "events.jsonl"
    copy.parent.mkdir()
    copy.write_bytes(original.read_bytes())
    AuditWriter("case-mcp", audit_dir=str(case / "audit")).log(
        tool="log_external_action",
        params={"command": f"cp {original} {copy}"},
        result_summary={"status": "logged", "output_files": [str(copy)]},
        extra={"declared": True, "inputs": [ops.place(original)],
               "input_registered": [{"path": str(original.resolve()), "sha256": _sha(original)}],
               "outputs": [_output(copy, _sha(copy))]},
    )  # fmt: skip
    code, parsed = _json(monkeypatch, copy)
    assert code != 0 and parsed == []
    (refusal,) = _refusals(case)
    assert "declared" in refusal["refused"]["reason"]


def test_a_file_added_to_a_registered_folder_after_its_manifest_is_refused_and_named(
    case, monkeypatch
):
    folder = case / "evidence" / "kape"
    folder.mkdir()
    listed = folder / "part1.csv"
    listed.write_text("a,b\n1,2\n")
    (case / "evidence-manifests").mkdir()
    manifest = case / "evidence-manifests" / "1.json"
    manifest.write_text(
        json.dumps({"files": [{"path": "evidence/kape/part1.csv", "sha256": _sha(listed)}]})
    )
    reg = json.loads((case / "evidence.json").read_text())
    reg["files"].append({"kind": "folder", "path": str(folder.resolve()),
                         "manifest_path": "evidence-manifests/1.json",
                         "manifest_sha256": _sha(manifest), "file_count": 1})  # fmt: skip
    (case / "evidence.json").write_text(json.dumps(reg))
    (folder / "part2.csv").write_text("a,b\n3,4\n")
    code, parsed = _delimited(monkeypatch, folder)
    assert parsed == ["part1.csv"]
    (run,) = _runs(case, "idx_ingest_delimited")
    assert run["manifest_sha256"] == _sha(manifest)
    assert run["manifest_path"] == "evidence-manifests/1.json"
    assert run["roots"] == [{"path": str(folder.resolve()), "sha256": _sha(manifest)}]
    (refusal,) = _refusals(case)  # the added file, named, under the run
    assert os.path.basename(refusal["inputs"][0]["path"]) == "part2.csv"
    assert refusal["about"] == run["audit_id"]


def test_with_no_case_to_trace_it_in_nothing_is_read_and_the_fix_is_named(
    case, monkeypatch, capsys
):
    f = case / "evidence" / "events.jsonl"
    f.write_text('{"a": 1}\n')
    _register(case, f)
    monkeypatch.setattr(ingest_cli, "_case_dir_for", lambda c: None)
    monkeypatch.delenv("VHIR_CASE_DIR")
    code, parsed = _json(monkeypatch, f)
    assert code != 0 and parsed == []
    err = capsys.readouterr().err
    assert "not ingested: no case to trace it in" in err
    assert "activate the case it is registered in" in err


def test_a_refused_runs_status_is_failed_with_the_reason_and_the_fix(case, tmp_path, monkeypatch):
    from opensearch_mcp import ingest_status

    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-refused")
    f = case / "loose.jsonl"
    f.write_text('{"a": 1}\n')
    code, _ = _json(monkeypatch, f)
    (refusal,) = _refusals(case)
    (status,) = [json.loads(p.read_text()) for p in (tmp_path / "status").glob("*.json")]
    assert code != 0 and status["status"] == "failed" and status["pid"] == os.getpid()
    assert status["error"].startswith(f"not ingested: {refusal['refused']['reason']}")
    assert refusal["refused"]["fix"] in status["error"]
