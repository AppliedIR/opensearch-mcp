"""Contract rows C1-C7 of the one folder-input record: a folder step the real
os recorders write, graded by sift-common's grader. An extraction is where
make_ingest_tmpdir puts it, outside the case. Values are synthetic."""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from sift_common import file_place
from sift_common import provenance as pv
from sift_common.audit import AuditWriter

from opensearch_mcp import ops
from opensearch_mcp.containers import make_ingest_tmpdir

PF = "C/Windows/Prefetch"
P = {"hostname": "h", "index_name": "i", "run_id": "r"}


def _put(p, data: bytes) -> str:
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A case with a registered folder root (kape, 3 prefetch files), a
    registered archive and image, and the os writer."""
    tmp = tmp_path.resolve()
    d = tmp / "acme"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: acme\n")
    monkeypatch.setenv("HOME", str(tmp / "home"))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    kape = tmp / "kape"
    rows = [{"path": os.path.relpath(p, d), "sha256": _put(p, f"A {i}\n".encode())}
            for i in range(3) for p in [f"{kape}/{PF}/A{i}.pf"]]  # fmt: skip
    man = json.dumps({"folder": str(kape), "files": rows}).encode()
    _put(d / "evidence-manifests" / "1.json", man)
    files = [{"kind": "folder", "path": str(kape), "manifest_path": "evidence-manifests/1.json",
              "manifest_sha256": hashlib.sha256(man).hexdigest(), "file_count": 3}]  # fmt: skip
    for name in ("triage.zip", "disk.raw"):
        p = tmp / name
        files.append({"path": str(p), "sha256": _put(p, f"synthetic {name}\n".encode())})
    (d / "evidence.json").write_text(json.dumps({"files": files}))
    try:
        yield d, AuditWriter("opensearch-ingest-1", audit_dir=str(d / "audit"))
    finally:
        ops.reset_extracted()
        ops.set_run(None, None)


def _entry(d, aid) -> dict:
    lines = [ln for f in sorted((d / "audit").glob("*.jsonl")) for ln in f.open()]
    (e,) = [e for e in map(json.loads, lines) if e.get("audit_id") == aid]
    return e


def _read(d, audit, folder) -> str:
    """The step ingest writes for a tool that reads a folder (read_step)."""
    aid, sha = ops.read_step(audit, "ingest_x", folder, case_dir=d, params=P)
    assert sha == ""
    e = _entry(d, aid)
    assert len(e["inputs"]) == 1 and e["input_sha256s"] == [""]  # the folder, as sift lists it
    return aid


def _extraction(d, audit, n, *, forget=False, rename=False) -> str:
    """os over the Prefetch folder of this run's extraction of ``n`` files;
    ``forget``: with ``known`` empty; ``rename``: one file renamed after."""
    dest = make_ingest_tmpdir("acme")
    assert not str(dest).startswith(f"{d}{os.sep}")
    for i in range(n):
        _put(f"{dest}/{PF}/x{i:05}.pf", f"x {i}\n".encode())
    ops.extraction_step(audit, d, d.parent / "triage.zip", str(dest), ["7z", "x"])
    if forget:
        ops.reset_extracted()
    if rename:
        os.rename(f"{dest}/{PF}/x00000.pf", f"{dest}/{PF}/renamed.pf")
    return _read(d, audit, f"{dest}/{PF}")


def _changed(d, audit) -> str:
    _put(f"{d.parent}/kape/{PF}/A1.pf", b"changed after registration\n")
    return _read(d, audit, f"{d.parent}/kape/{PF}")


def _mounted(d, audit) -> str:
    point = d.parent / "mnt" / "nbd0p1"  # where the image's volume is mounted
    _put(point / "Windows/Prefetch/M0.pf", b"m0\n")
    ops.set_run(audit, d)
    assert ops.mount_step(d.parent / "disk.raw", [ops.mount_point(point)])
    return _read(d, audit, point / "Windows/Prefetch")


def _sift_in_case(d, audit) -> str:
    """sift run_command's entry over an in-case folder an earlier recorded
    step wrote, as run_command records it (input_record, listed)."""
    stage = d / "extractions" / "Prefetch-h"
    copied = []
    for i in range(3):
        src = d.parent / "kape" / PF / f"A{i}.pf"
        _put(stage / src.name, src.read_bytes())
        copied.append((src, stage / src.name))
    with ops.recording(audit, d, "ingest_prefetch", P):
        assert ops.staging_step(copied, "PECmd.exe")
    rec, reg = file_place.input_record(d, stage, "run_command", True)
    files, shas = file_place.listed([rec], [reg] if reg else [])
    sw = AuditWriter("sift-mcp", audit_dir=str(d / "audit"))
    aid = sw._next_audit_id()
    sw.log(tool="run_command", audit_id=aid, params={"command": ["PECmd.exe", "-d", str(stage)]},
           result_summary="t", input_files=files, input_sha256s=shas,
           extra={"inputs": [rec], **({"input_registered": [reg]} if reg else {})})  # fmt: skip
    return aid


ROWS = {
    "C1": (lambda d, a: _read(d, a, f"{d.parent}/kape/{PF}"), "FULL folder-digest"),
    "C2": (lambda d, a: _extraction(d, a, 1101), "FULL folder-digest"),
    "C2-control": (lambda d, a: _extraction(d, a, 1101, forget=True), "no recorded origin"),
    "C3": (lambda d, a: _extraction(d, a, 12000), "FULL folder-digest"),
    "C4": (lambda d, a: _extraction(d, a, 1100), "FULL folder-digest"),
    "C5": (_changed, "is a folder of 3 files"),
    "C6": (lambda d, a: _extraction(d, a, 1101, rename=True), "not FULL"),
    "C7-root": (lambda d, a: _read(d, a, f"{d.parent}/kape"), "FULL registered-path"),
    "C7-mount": (_mounted, "FULL recorded-mount"),
    "C7-sift": (_sift_in_case, "FULL folder-digest"),
}


@pytest.mark.parametrize("row", ROWS)
def test_folder_input_contract_row(case, row):
    d, audit = case
    make, want = ROWS[row]
    aid = make(d, audit)  # before the case is read
    t = pv.trace_op(pv.load_case(d), aid)
    methods = {lk["method"] for lk in t.links}
    if want.startswith("FULL"):
        assert t.grade == "FULL" and want.split()[1] in methods, (t.grade, t.reason, methods)
    else:
        assert t.grade != "FULL" and (want == "not FULL" or want in t.reason), t.reason
    if row == "C4":  # the chain a finding keeps stays small
        assert len(t.links) <= 6 and len(json.dumps(t.links, default=str)) <= 3000


@pytest.mark.parametrize("row", ["C1", "C2-control"])
def test_an_os_folder_input_is_sifts_record(case, row):
    """The folder step's input is the record sift's input_record writes for the
    folder, with the bare ``sha256: ""`` os write() lists."""
    d, audit = case
    aid = ROWS[row][0](d, audit)
    (i,) = _entry(d, aid)["inputs"]
    known = {real: made[0] for real, made in ops._extracted().items()}
    rec, _ = file_place.input_record(d, i["path"], folder=True, known=known)
    assert i == {**rec, "sha256": ""}
