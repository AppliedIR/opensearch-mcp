"""The two Plaso routes into a folder step's input, through the real calls
(parse_prefetch and _ingest_plaso_volume to ops.step_inputs), and what a
registered folder in the case records when a member can't be read or the
folder path is a symlink. Plaso and the bulk write are stubbed; graded by
sift-common's grader. Values are synthetic."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from sift_common import file_identity as fi
from sift_common import provenance as pv
from sift_common.audit import AuditWriter

from opensearch_mcp import ingest, ops, parse_plaso
from opensearch_mcp.containers import make_ingest_tmpdir
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.results import HostResult

RECENT = "Users/u1/AppData/Roaming/Microsoft/Windows/Recent"
TREE = {
    "Windows/prefetch/A.EXE-11111111.pf": b"pf a",
    "Windows/prefetch/B.EXE-22222222.pf": b"pf b",
    "Windows/appcompat/Amcache.hve": b"regf",
    f"{RECENT}/AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms": b"jl a",
    f"{RECENT}/CustomDestinations/28c8b86deab549a1.customDestinations-ms": b"jl c",
    "Users/u1/AppData/Local/Google/Chrome/User Data/Default/History": b"SQLite format 3",
}
FOLDER = {  # a top-level file and two subfolders of one file each
    "x.lnk": b"lnk x",
    "AutomaticDestinations/a.automaticDestinations-ms": b"jl a",
    "CustomDestinations/c.customDestinations-ms": b"jl c",
}
P = {"hostname": "h", "index_name": "i", "run_id": "r"}


def _put(p, data: bytes) -> str:
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A case with a registered archive and the os writer."""
    tmp = tmp_path.resolve()
    d = tmp / "acme"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: acme\n")
    monkeypatch.setenv("HOME", str(tmp / "home"))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    archive = d / "evidence" / "triage.zip"
    files = [{"path": str(archive), "sha256": _put(archive, b"PK synthetic")}]
    (d / "evidence.json").write_text(json.dumps({"files": files}))
    try:
        yield d, AuditWriter("opensearch-ingest-1", audit_dir=str(d / "audit"))
    finally:
        ops.reset_extracted()
        ops.set_run(None, None)


def _entries(d) -> list[dict]:
    lines = [ln for f in sorted((d / "audit").glob("*.jsonl")) for ln in f.open()]
    return [json.loads(ln) for ln in lines]


def _entry(d, aid) -> dict:
    (e,) = [e for e in _entries(d) if e.get("audit_id") == aid]
    return e


def _digest(files: dict) -> dict:
    """The folder record a folder of ``files`` (relative path -> bytes) gets."""
    pairs = [(rel, hashlib.sha256(data).hexdigest()) for rel, data in files.items()]
    return {"files": len(files), "bytes": sum(map(len, files.values())),
            "sha256": fi.folder_digest(pairs)}  # fmt: skip


def _one_folder_input(d, aid, folder, files) -> dict:
    """The step's one input is ``folder`` with the digest of ``files``,
    graded FULL by its folder digest."""
    e = _entry(d, aid)
    (i,) = e["inputs"]
    assert i["path"] == str(folder) and i["sha256"] == "" and e["input_sha256s"] == [""]
    assert i["folder"] == _digest(files)
    t = pv.trace_op(pv.load_case(d), aid)
    assert t.grade == "FULL", t.reason
    assert "folder-digest" in {lk["method"] for lk in t.links}
    return i


def _volume(d, audit) -> Path:
    """Volume C, extracted (and recorded) by this run where make_ingest_tmpdir
    puts it, outside the case."""
    x = Path(make_ingest_tmpdir("acme"))
    c = x / "vol1" / "C"
    for rel, data in TREE.items():
        _put(c / rel, data)
    ops.extraction_step(audit, d, d / "evidence" / "triage.zip", x, ["7z", "x"])
    return c


def _under(prefix) -> dict:
    return {rel[len(prefix) + 1 :]: data for rel, data in TREE.items() if rel.startswith(prefix)}


def test_plaso_prefetch_records_the_folder_with_its_digest(case, monkeypatch):
    """parse_prefetch -> ops.step -> step_inputs over the Prefetch folder."""
    d, audit = case
    c = _volume(d, audit)
    seen = {}

    def plaso(parser, source, tmpdir):
        out = Path(tmpdir) / "prefetch.jsonl"
        out.write_text('{"x": 1}\n')
        return out

    def index(*a, **kw):
        seen["aid"] = kw["ingest_audit_id"]
        return 1, 0

    monkeypatch.setattr(parse_plaso, "_run_plaso", plaso)
    monkeypatch.setattr(parse_plaso, "_ingest_jsonl", index)
    with ops.recording(audit, d, "ingest_prefetch", {}):
        parse_plaso.parse_prefetch(c / "Windows/prefetch", None, "case-acme-prefetch-0", "H1")
    _one_folder_input(d, seen["aid"], c / "Windows/prefetch", _under("Windows/prefetch"))


def test_plaso_volume_records_the_folder_with_its_digest(case, monkeypatch):
    """_ingest_plaso_volume -> step_inputs (a Windows host's run over Users)."""
    d, audit = case
    c = _volume(d, audit)

    def run(parsers, source, workdir, read_as_root, zone, **kw):
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
    (step,) = [e for e in _entries(d) if e.get("tool") == "ingest_plaso" and "about" not in e]
    _one_folder_input(d, step["audit_id"], c / "Users", _under("Users"))


def _registered(d) -> Path:
    """FOLDER under a registered folder root in the case; returns the folder."""
    root = d / "evidence" / "kape"
    folder = root / "C" / RECENT
    rows = [{"path": os.path.relpath(folder / rel, d), "sha256": _put(folder / rel, data)}
            for rel, data in FOLDER.items()]  # fmt: skip
    man = json.dumps({"folder": str(root), "files": rows}).encode()
    _put(d / "evidence-manifests" / "1.json", man)
    reg = json.loads((d / "evidence.json").read_text())
    reg["files"].append({"kind": "folder", "path": str(root), "file_count": len(rows),
                         "manifest_path": "evidence-manifests/1.json",
                         "manifest_sha256": hashlib.sha256(man).hexdigest()})  # fmt: skip
    (d / "evidence.json").write_text(json.dumps(reg))
    return folder


def _read(d, audit, folder) -> str:
    aid, sha = ops.read_step(audit, "ingest_x", folder, case_dir=d, params=P)
    assert sha == ""
    return aid


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
@pytest.mark.parametrize(
    "locked", ["CustomDestinations/c.customDestinations-ms", "CustomDestinations"],
    ids=["member", "subfolder"],
)  # fmt: skip
def test_characterization_an_unreadable_member_leaves_no_digest(case, locked):
    """Characterization (the same before and after the one folder record): a
    registered folder in the case with a member file, or a subfolder, at mode
    000 records the folder with no digest, grades BROKEN, and raises nothing."""
    d, audit = case
    folder = _registered(d)
    (folder / locked).chmod(0)
    try:
        aid = _read(d, audit, folder)
    finally:
        (folder / locked).chmod(0o755)
    (i,) = _entry(d, aid)["inputs"]
    assert i["path"] == str(folder) and "folder" not in i
    assert pv.trace_op(pv.load_case(d), aid).grade == "BROKEN"


def test_a_symlinked_folder_path_gets_the_real_folders_digest(case):
    d, audit = case
    folder = _registered(d)
    link = d / "links" / "Recent"
    link.parent.mkdir()
    link.symlink_to(folder, target_is_directory=True)
    real = _one_folder_input(d, _read(d, audit, folder), folder, FOLDER)
    via = _one_folder_input(d, _read(d, audit, link), link, FOLDER)
    assert via["realpath"] == str(folder) and via["folder"] == real["folder"]
