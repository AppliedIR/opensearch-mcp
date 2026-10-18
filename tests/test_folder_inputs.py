"""A step that reads a folder of extracted files names each file as its input,
so a record from it traces to the registered evidence like a one-file step.
The real extraction step, the real steps and the real grader; Plaso and the
bulk write are stubbed. Values are synthetic."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from sift_common import provenance as pv
from sift_common.audit import AuditWriter

from opensearch_mcp import ingest, ops, parse_plaso
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.results import HostResult

UUID = "0123456789abcdef0123456789abcdef"
RECENT = "Users/u1/AppData/Roaming/Microsoft/Windows/Recent"
TREE = {
    "Windows/prefetch/A.EXE-11111111.pf": b"pf a",
    "Windows/prefetch/B.EXE-22222222.pf": b"pf b",
    "Windows/appcompat/Amcache.hve": b"regf",
    f"{RECENT}/AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms": b"jl a",
    f"{RECENT}/CustomDestinations/28c8b86deab549a1.customDestinations-ms": b"jl c",
    "$Recycle.Bin/S-1-5-21-1-1001/$IABC123.txt": b"$I",
    "$Recycle.Bin/S-1-5-21-1-1001/$RABC123.txt": b"$R",
    "Users/u1/AppData/Local/Google/Chrome/User Data/Default/History": b"SQLite format 3",
}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "acme"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(f"case_id: acme\ncase_uuid: {UUID}\n")
    archive = d / "evidence" / "triage.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK synthetic")
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (d / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(archive), "sha256": sha}]})
    )
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    x = d / "tmp" / "ingest-1" / "_x"
    c = x / "vol1" / "C"
    for rel, data in TREE.items():
        (c / rel).parent.mkdir(parents=True, exist_ok=True)
        (c / rel).write_bytes(data)
    audit = AuditWriter(mcp_name="opensearch-ingest-1")
    try:
        ops.extraction_step(audit, d, archive, x, ["7z", "x"])
        yield d, c, audit
    finally:
        ops.reset_extracted()


def _entries(d) -> list[dict]:
    lines = [
        ln for f in sorted((d / "audit").glob("*.jsonl")) for ln in f.read_text().splitlines()
    ]
    return [json.loads(ln) for ln in lines]


def _entry(d, sid) -> dict:
    return next(e for e in _entries(d) if e["audit_id"] == sid)


def _grade(d, sid):
    t = pv.trace_op(pv.load_case(d), sid)
    print("GRADE", t.grade, "| break", t.break_, "| inputs", len(_entry(d, sid).get("inputs", [])))
    return t


def _read_step(d, audit, folder) -> str:
    """The step ingest writes for an EZ tool that reads a folder (ingest.py's read_step call)."""
    sid, sha = ops.read_step(audit, "ingest_x", folder, case_dir=d, params={"tool": "x"})
    assert sha == ""  # a folder has no hash of its own: the ingest manifest keeps ""
    return sid


def _files(folder: Path) -> list[str]:
    return sorted(str(p) for p in folder.rglob("*") if p.is_file())


# defect rows: BROKEN "no recorded origin" before the fix


def test_plaso_prefetch_names_each_prefetch_file(case, monkeypatch):
    d, c, audit = case
    seen = {}

    def plaso(parser, source, tmpdir):
        out = Path(tmpdir) / "prefetch.jsonl"
        out.write_text('{"x": 1}\n')
        return out

    def index(*a, **kw):
        seen["sid"] = kw["ingest_audit_id"]
        return 1, 0

    monkeypatch.setattr(parse_plaso, "_run_plaso", plaso)
    monkeypatch.setattr(parse_plaso, "_ingest_jsonl", index)
    with ops.recording(audit, d, "ingest_prefetch", {}):
        parse_plaso.parse_prefetch(c / "Windows/prefetch", None, "case-acme-prefetch-0", "H1")
    t = _grade(d, seen["sid"])
    assert [i["path"] for i in _entry(d, seen["sid"])["inputs"]] == _files(c / "Windows/prefetch")
    assert t.grade == "FULL"


@pytest.mark.parametrize(
    "folder", [RECENT, "$Recycle.Bin"], ids=["jumplists: files only in subfolders",
                                             "recyclebin: no top-level file"]
)  # fmt: skip
def test_a_folder_step_names_every_file_under_it(case, folder):
    d, c, audit = case
    sid = _read_step(d, audit, c / folder)
    t = _grade(d, sid)
    inputs = _entry(d, sid)["inputs"]
    assert [i["path"] for i in inputs] == _files(c / folder)
    assert all(i["sha256"] and i["produced_by"] for i in inputs)
    assert t.grade == "FULL"


def test_plaso_over_users_names_each_file(case, monkeypatch):
    """The other write site: a Windows host's Plaso run over Users."""
    d, c, audit = case

    def run(parsers, source, workdir, read_as_root, zone):
        jsonl = workdir / "out.jsonl"
        jsonl.write_text("")
        return jsonl, {}

    monkeypatch.setattr(parse_plaso, "run_plaso_volume", run)
    monkeypatch.setattr(parse_plaso, "flush_bulk", lambda cl, a: (len(a), 0))
    monkeypatch.setattr(ingest, "_safe_count", lambda cl, i, unit="": 0)
    host = DiscoveredHost(hostname="h", volume_root=c)
    host.os = "windows"
    status = [{"hostname": "h", "artifacts": [{"name": "plaso", "status": "pending"}]}]
    ingest._ingest_plaso_volume(
        None, audit, "acme", host, 0, HostResult(hostname="h"), status,
        lambda *a, **k: None, lambda: None, case_dir=d,
    )  # fmt: skip
    (step,) = [e for e in _entries(d) if e["tool"] == "ingest_plaso" and "about" not in e]
    t = _grade(d, step["audit_id"])
    assert [i["path"] for i in step["inputs"]] == _files(c / "Users")
    assert t.grade == "FULL"


# twin row: a one-file step is unchanged


def test_a_one_file_step_is_unchanged(case):
    d, c, audit = case
    sid, sha = ops.read_step(audit, "ingest_amcache", c / "Windows/appcompat/Amcache.hve",
                             case_dir=d, params={})  # fmt: skip
    (inp,) = _entry(d, sid)["inputs"]
    assert inp["path"] == str(c / "Windows/appcompat/Amcache.hve") and sha == inp["sha256"]
    assert _grade(d, sid).grade == "FULL"


# guard rows: the step records the folder itself, as before


def _folder_entry(d, sid, folder):
    (inp,) = _entry(d, sid)["inputs"]
    assert inp["path"] == str(folder) and inp["sha256"] == ""


def test_a_file_outside_the_extraction_keeps_the_folder(case):
    d, c, audit = case
    (c / RECENT / "AutomaticDestinations" / "planted.automaticDestinations-ms").write_bytes(b"x")
    sid = _read_step(d, audit, c / RECENT)
    _folder_entry(d, sid, c / RECENT)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a folder whatever its mode")
def test_a_subfolder_the_walk_cannot_read_keeps_the_folder(case):
    """Its sibling's file would be named, so only the error keeps the folder."""
    d, c, audit = case
    sub = c / RECENT / "CustomDestinations"
    sub.chmod(0)
    try:
        sid = _read_step(d, audit, c / RECENT)
    finally:
        sub.chmod(0o755)
    _folder_entry(d, sid, c / RECENT)


def _extract_more(d, audit, folder, count):
    """``count`` more files, extracted (and recorded) into ``folder``."""
    for n in range(count):
        (folder / f"{n:05d}.lnk").write_bytes(b"L%d" % n)
    if count:
        ops.extraction_step(audit, d, d / "evidence" / "triage.zip", folder, ["7z", "x"])


@pytest.mark.parametrize("count", [0, 1101], ids=["no file", "over the bound"])
def test_a_folder_outside_the_bound_keeps_the_folder(case, count):
    d, c, audit = case
    big = c / "Users" / "u1" / "Desktop"
    big.mkdir(parents=True)
    _extract_more(d, audit, big, count)
    sid = _read_step(d, audit, big)
    _folder_entry(d, sid, big)


def test_the_bound_itself_is_named_file_by_file(case):
    d, c, audit = case
    big = c / "Users" / "u1" / "Desktop"
    big.mkdir(parents=True)
    _extract_more(d, audit, big, 1100)
    sid = _read_step(d, audit, big)
    t = _grade(d, sid)
    assert len(_entry(d, sid)["inputs"]) == 1100
    assert t.grade == "FULL"
