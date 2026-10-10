"""An image copy an earlier operation made and recorded links to it: the mount
records the copy by the hash that operation's background job recorded, while
the copy is unchanged, so its chain runs through the operation to the
registered original. A declared copy (log_external_action) grades DECLARED.
The resolver and the audit writer are the real ones; nothing is mounted."""

from __future__ import annotations

import hashlib
import json
import time

import pytest
from sift_common import file_identity as fi
from sift_common import provenance as pv
from sift_common.audit import AuditWriter

from opensearch_mcp import ops


@pytest.fixture
def box(tmp_path):
    case, srv = tmp_path / "acme", tmp_path / "srv"
    (case / "audit").mkdir(parents=True)
    (case / "evidence" / "copies").mkdir(parents=True)
    srv.mkdir()
    (case / "CASE.yaml").write_text("case_id: acme\n")
    original, copy = srv / "rd01-triage.vhdx", case / "evidence" / "copies" / "rd01-triage.vhdx"
    original.write_bytes(b"VHDX image " * 4096)
    copy.write_bytes(original.read_bytes())
    sha = hashlib.sha256(original.read_bytes()).hexdigest()
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(original), "sha256": sha}]})
    )
    return case, original, copy, sha


def _declare_copy(case, original, copy, sha):
    """log_external_action as case-mcp writes it: the copy as its output, its
    hash pending on a background job, the registered original as its input."""
    job = fi.hash_for_call(copy, case_dir=case, requested_by="log_external_action",
                           inline_limit=0)  # fmt: skip
    assert isinstance(job, fi.Pending)
    AuditWriter("case-mcp", audit_dir=str(case / "audit")).log(
        tool="log_external_action",
        params={"command": f"cp {original} {copy}"},
        result_summary={"status": "logged", "output_files": [str(copy)]},
        extra={"declared": True, "inputs": [ops.place(original)],
               "input_registered": [{"path": str(original), "sha256": sha}],
               "outputs": [_output(copy, f"pending:{job.job_id}")]},
    )  # fmt: skip
    log = case / "audit" / "file-identity.jsonl"
    deadline = time.monotonic() + 30
    while not (log.exists() and job.job_id in log.read_text()):
        assert time.monotonic() < deadline, "the hash job never closed"
        time.sleep(0.05)


def _mount(case, image) -> pv.Trace:
    point = case.parent / "mnt" / "nbd0p1"  # where its volume would be mounted
    point.mkdir(parents=True, exist_ok=True)
    ops.set_run(AuditWriter("opensearch-ingest-1", audit_dir=str(case / "audit")), case)
    try:
        aid = ops.mount_step(image, [ops.mount_point(point)])
    finally:
        ops.set_run(None, None)
    assert aid
    return pv.trace_op(pv.load_case(case), aid)


def test_a_declared_image_copy_grades_declared_through_its_operation(box):
    case, original, copy, sha = box
    _declare_copy(case, original, copy, sha)
    t = _mount(case, copy)
    assert t.grade == "DECLARED", t.as_dict()
    assert t.root and t.root["path"] == str(original)
    assert any(link["method"] == "declared" for link in t.links)


def test_a_copy_changed_after_its_hash_stays_unlinked(box):
    case, original, copy, sha = box
    _declare_copy(case, original, copy, sha)
    with open(copy, "ab") as f:
        f.write(b"changed")
    t = _mount(case, copy)
    assert t.grade == "BROKEN" and t.break_["kind"] == "no-recorded-origin"


def test_a_registered_image_is_its_own_root(box):
    case, original, _, sha = box
    t = _mount(case, original)
    assert t.grade == "FULL" and t.root["sha256"] == sha


# -- an image an extraction wrote, read whole by a memory ingest


@pytest.fixture
def extracted(tmp_path):
    case, srv = tmp_path / "acme", tmp_path / "srv"
    (case / "audit").mkdir(parents=True)
    (case / "extractions" / "mem").mkdir(parents=True)
    srv.mkdir()
    (case / "CASE.yaml").write_text("case_id: acme\n")
    archive, image = srv / "memory.7z", case / "extractions" / "mem" / "wkstn05-memory.img"
    archive.write_bytes(b"7z archive " * 512)
    image.write_bytes(b"memory image " * 4096)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(archive), "sha256": sha}]})
    )
    return case, archive, image, sha


def _extract(case, archive, image, sha, job_id):
    """run_command's 7z extraction: the image an output whose hash is pending."""
    AuditWriter("sift-mcp", audit_dir=str(case / "audit")).log(
        tool="run_command",
        params={"command": f"7z x {archive}"},
        result_summary={"exit_code": 0},
        extra={"inputs": [ops.place(archive)],
               "input_registered": [{"path": str(archive), "sha256": sha}],
               "outputs": [_output(image, f"pending:{job_id}")]},
    )  # fmt: skip


def _output(path, sha):
    """An output record as file_place.output_records writes it."""
    st = path.stat()
    return {**ops.place(path), "sha256": sha, "size": st.st_size, "st_ino": st.st_ino,
            "mtime_ns": st.st_mtime_ns}  # fmt: skip


def _close(case, image, job_id):
    """file-identity closing the job, as its background thread does."""
    st = image.stat()
    row = {"path": str(image), "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
           "size": st.st_size, "st_dev": st.st_dev, "st_ino": st.st_ino,
           "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}  # fmt: skip
    AuditWriter("file-identity", audit_dir=str(case / "audit")).log(
        tool="hash_complete", params={"path": str(image)}, result_summary=row,
        extra={"job_id": job_id, "requested_by": "run_command", **row},
    )  # fmt: skip


def _memory_step(case, image) -> str:
    """A memory ingest's step reading the image whole (parse_memory's)."""
    image_in, image_reg = ops.image_input(case, image)
    audit = AuditWriter("opensearch-ingest-2", audit_dir=str(case / "audit"))
    return ops.write(audit, "vol_windows.pslist", params={}, summary="ran", inputs=[image_in],
                     input_registered=[image_reg] if image_reg else None)  # fmt: skip


def test_a_memory_image_an_extraction_wrote_is_full_to_the_registered_archive(extracted):
    case, archive, image, sha = extracted
    _extract(case, archive, image, sha, "hash-00000000000000a1")
    _close(case, image, "hash-00000000000000a1")
    aid = _memory_step(case, image)  # written before the case is read
    t = pv.trace_op(pv.load_case(case), aid)
    assert t.grade == "FULL", t.as_dict()
    assert t.root["path"] == str(archive)


def test_an_image_whose_hash_job_is_still_running_links_once_it_closes(extracted):
    case, archive, image, sha = extracted
    _extract(case, archive, image, sha, "hash-00000000000000b2")
    aid = _memory_step(case, image)  # the job hasn't closed: recorded pending
    (entry,) = [e for e, _ in pv.load_case(case).by_id[aid]]
    assert entry["inputs"][0]["sha256"] == "pending:hash-00000000000000b2"
    _close(case, image, "hash-00000000000000b2")
    t = pv.trace_op(pv.load_case(case), aid)
    assert t.grade == "FULL" and t.root["path"] == str(archive), t.as_dict()


def test_the_run_names_its_input_by_the_hash_the_extraction_recorded(extracted):
    case, archive, image, sha = extracted
    _extract(case, archive, image, sha, "hash-00000000000000c3")
    _close(case, image, "hash-00000000000000c3")
    assert ops.large_input(case, image)["sha256"] == hashlib.sha256(image.read_bytes()).hexdigest()
    assert "sha256" not in ops.large_input(case, archive)  # nothing recorded it


def test_a_file_replaced_while_its_job_runs_never_takes_the_pending_hash(extracted):
    """Another file put at the path before the job closes isn't the output
    recorded: no pending hash, so no link (never a wrong FULL)."""
    case, archive, image, sha = extracted
    _extract(case, archive, image, sha, "hash-00000000000000d4")
    replacement = image.with_name("other.img")
    replacement.write_bytes(b"another memory image " * 2048)
    replacement.replace(image)  # a new inode at the same path
    assert "sha256" not in ops.large_input(case, image)
    aid = _memory_step(case, image)
    _close(case, image, "hash-00000000000000d4")  # the job hashes what's there now
    t = pv.trace_op(pv.load_case(case), aid)
    assert t.grade != "FULL", t.as_dict()


def test_a_newer_pending_job_is_taken_over_an_older_closed_one(extracted):
    """An earlier extraction's job closed and the file was written again: the
    newer operation's pending job is the one taken."""
    case, archive, image, sha = extracted
    _extract(case, archive, image, sha, "hash-00000000000000e5")
    _close(case, image, "hash-00000000000000e5")
    image.write_bytes(b"memory image, extracted again " * 2048)
    _extract(case, archive, image, sha, "hash-00000000000000f6")
    assert ops.large_input(case, image)["sha256"] == "pending:hash-00000000000000f6"


def test_a_rewrite_with_its_mtime_set_back_never_takes_a_closed_job(extracted):
    """Jobs A and B both closed; the file is then rewritten in place, the
    same size, its mtime set back. Neither job is pending any more, and the
    completed hash refuses it on ctime: no hash, never FULL."""
    import os

    case, archive, image, sha = extracted
    _extract(case, archive, image, sha, "hash-00000000000000a7")
    _close(case, image, "hash-00000000000000a7")
    _extract(case, archive, image, sha, "hash-00000000000000b8")
    _close(case, image, "hash-00000000000000b8")
    st = image.stat()
    data = bytearray(image.read_bytes())
    data[0] ^= 0xFF  # other bytes, the same size
    with open(image, "r+b") as f:  # in place: the same inode
        f.write(data)
    os.utime(image, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert "sha256" not in ops.large_input(case, image)
    aid = _memory_step(case, image)
    t = pv.trace_op(pv.load_case(case), aid)
    assert t.grade != "FULL", t.as_dict()
