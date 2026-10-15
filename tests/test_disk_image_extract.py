"""A .vhdx that can't be mounted (no sudo, no free NBD device) is read anyway:
converted to a derived raw with qemu-img, then each partition's files written
out with tsk_recover in bwrap, and recorded as one extraction of the image.

The fixtures are real images, built without root: a 16 MiB NTFS partition at
sector 63 holding marker.txt ("hello"), with the boot sector's end marker
zeroed as some triage collections write it; and the same with one file's name
rewritten to ../../../ESCAPE. qemu-img, mmls, tsk_recover and bwrap run for
real. sudo never does: every sudo call is answered by a stand-in that fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sift_common.audit import AuditWriter

import opensearch_mcp.containers as C
import opensearch_mcp.hostname as hn
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ops

FIXTURES = Path(__file__).parent / "fixtures"
UUID = "0123456789abcdef0123456789abcdef"
REAL_RUN = subprocess.run


def _sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _entries(case: Path) -> list[dict]:
    out = []
    for f in sorted((case / "audit").glob("*.jsonl")):
        out += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    return out


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


def _image(fixture: str, where: Path) -> Path:
    where.parent.mkdir(parents=True, exist_ok=True)
    where.write_bytes(lzma.decompress((FIXTURES / fixture).read_bytes()))
    return where


@pytest.fixture
def no_sudo(monkeypatch):
    """Every sudo call fails without running; everything else runs. Returns
    the sudo calls made."""
    calls: list[list[str]] = []

    def run(cmd, *a, **kw):
        if str(cmd[0]) == "sudo":
            calls.append([str(c) for c in cmd])
            return subprocess.CompletedProcess(cmd, 1, b"", b"")
        return REAL_RUN(cmd, *a, **kw)

    monkeypatch.setattr(C.subprocess, "run", run)
    return calls


@pytest.fixture
def no_nbd(monkeypatch, no_sudo):
    def busy():
        raise RuntimeError("No available NBD devices (nbd0-nbd7 all in use)")

    monkeypatch.setattr(C, "check_sudo", lambda: None)
    monkeypatch.setattr(C, "_find_free_nbd", busy)
    return no_sudo


@pytest.fixture
def run_open(case):
    ops.set_run(AuditWriter(mcp_name="opensearch-ingest-1"), case)
    yield case
    ops.set_run(None, None)
    ops.reset_extracted()


def _dest(tmp_path: Path) -> Path:
    d = tmp_path / "ingest"
    d.mkdir()
    return d


def _extractions(case: Path) -> list[dict]:
    return [e for e in _entries(case) if e["tool"] == "extract_archive"]


def test_without_a_free_nbd_device_the_vhdx_s_files_are_extracted(run_open, no_nbd, tmp_path):
    image = _image("kape-like-tiny.vhdx.xz", run_open / "evidence" / "tiny.vhdx")
    ctx = C.MountContext()
    (vol,) = C.mount_image(image, _dest(tmp_path), ctx)
    assert (vol / "marker.txt").read_text() == "hello\n"
    assert ctx.extracted
    assert ctx.not_mounted == [f"tiny.vhdx: {C.NO_NBD_NOTE}"]
    assert ctx.offsets == {vol: 63 * 512}
    assert no_nbd == [["sudo", "modprobe", "nbd", "max_part=8"]]  # tried, never ran


def test_without_sudo_the_vhdx_s_files_are_extracted(run_open, no_sudo, tmp_path, monkeypatch):
    def refused():
        raise PermissionError(C.SUDO_REMEDY)

    monkeypatch.setattr(C, "check_sudo", refused)
    image = _image("kape-like-tiny.vhdx.xz", run_open / "evidence" / "tiny.vhdx")
    (vol,) = C.mount_image(image, _dest(tmp_path), C.MountContext())
    assert (vol / "marker.txt").read_text() == "hello\n"
    assert no_sudo == []


def test_the_extraction_is_one_entry_naming_the_registered_vhdx(run_open, no_nbd, tmp_path):
    image = _image("kape-like-tiny.vhdx.xz", run_open / "evidence" / "tiny.vhdx")
    digest = _register(run_open, image)
    dest = _dest(tmp_path)
    (vol,) = C.mount_image(image, dest, C.MountContext())
    (step,) = _extractions(run_open)
    assert [e["tool"] for e in _entries(run_open)] == ["extract_archive"]  # no mount entry
    assert step["input_registered"] == [{"path": str(image.resolve()), "sha256": digest}]
    assert "sha256" not in step["inputs"][0]  # registered: never hashed again
    (marker,) = [o for o in step["outputs"] if o["path"] == str(vol / "marker.txt")]
    assert marker["sha256"] == hashlib.sha256(b"hello\n").hexdigest()
    assert step["params"]["method"] == "qemu-img+tsk_recover"
    assert step["params"]["volumes"] == [{"offset": 32256, "end_marker_set": True}]
    assert step["params"]["dest"] == str(dest / "_x")
    assert any("bwrap" in c and "tsk_recover" in c for c in step["params"]["command"])
    assert _sha(image) == digest  # the image is only read
    assert not (dest / "_raw").exists()


def test_a_vhdx_an_earlier_extraction_wrote_is_named_by_its_manifest(
    run_open, no_nbd, tmp_path, monkeypatch
):
    """As a mount names it: by the manifest's hash and the step that wrote
    it, never hashed again."""
    archive = run_open / "evidence" / "triage.7z"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"7z")
    _register(run_open, archive)
    unpacked = tmp_path / "unpacked"
    image = _image("kape-like-tiny.vhdx.xz", unpacked / "tiny.vhdx")
    audit, _ = ops.current_run()
    first = ops.extraction_step(audit, run_open, archive, unpacked, ["7z", "x", str(archive)])
    hashed: list[Path] = []
    real_sha = ops.sha256_file
    monkeypatch.setattr(ops, "sha256_file", lambda p: hashed.append(Path(p)) or real_sha(p))
    C.mount_image(image, _dest(tmp_path), C.MountContext())
    (_, step) = _extractions(run_open)
    (i,) = step["inputs"]
    assert (i["sha256"], i["produced_by"]) == (_sha(image), first)
    assert "input_registered" not in step
    assert image not in hashed  # only the files extracted from it are hashed


def test_a_crafted_name_is_refused_and_written_nowhere(run_open, no_nbd, tmp_path):
    image = _image("crafted-name.vhdx.xz", run_open / "evidence" / "crafted.vhdx")
    dest = _dest(tmp_path)  # ../../../ESCAPE from dest/_x/vol1 is tmp_path/ESCAPE
    with pytest.raises(RuntimeError, match="refused") as refused:
        C.mount_image(image, dest, C.MountContext())
    assert "../../../ESCAPE" in str(refused.value)
    assert not (tmp_path / "ESCAPE").exists()
    assert _extractions(run_open) == []
    assert not (dest / "_raw").exists()


def test_with_no_run_open_nothing_is_extracted(case, no_nbd, tmp_path):
    image = _image("kape-like-tiny.vhdx.xz", case / "evidence" / "tiny.vhdx")
    dest = _dest(tmp_path)
    with pytest.raises(RuntimeError, match="no ingest run is open"):
        C.mount_image(image, dest, C.MountContext())
    assert list(dest.iterdir()) == []
    assert _entries(case) == []


def test_a_partition_tsk_can_t_read_is_a_failure_not_a_refusal(run_open, no_nbd, tmp_path):
    """No NTFS boot sector at all: nothing is written, the partition is
    reported as unreadable, as a partition that won't mount is."""
    image = _image("kape-like-tiny.vhdx.xz", run_open / "evidence" / "tiny.vhdx")
    raw = tmp_path / "blank.raw"
    REAL_RUN(["qemu-img", "convert", "-f", "vhdx", "-O", "raw", str(image), str(raw)], check=True)
    with open(raw, "r+b") as f:  # the boot sector and its backup gone
        f.seek(63 * 512)
        f.write(b"\0" * 512)
    blank = tmp_path / "evidence2" / "blank.vhdx"
    blank.parent.mkdir()
    REAL_RUN(["qemu-img", "convert", "-f", "raw", "-O", "vhdx", str(raw), str(blank)], check=True)
    ctx = C.MountContext()
    assert C.mount_image(blank, _dest(tmp_path), ctx) == []
    assert ctx.failures == [
        "partition at offset 32256 could not be read: Cannot determine file system type"
    ]
    (step,) = _extractions(run_open)
    assert step["params"]["volumes"] == [] and "outputs" not in step  # nothing written


def test_a_mounted_vhdx_never_takes_the_fallback(run_open, no_sudo, tmp_path, monkeypatch):
    image = _image("kape-like-tiny.vhdx.xz", run_open / "evidence" / "tiny.vhdx")
    mounted = tmp_path / "nbd0p1"
    mounted.mkdir()
    extracted: list = []
    monkeypatch.setattr(C, "_mount_nbd", lambda p, d, ctx: [mounted])
    monkeypatch.setattr(C, "_extract_disk_image", lambda *a: extracted.append(a) or [])
    ctx = C.MountContext()
    assert C.mount_image(image, _dest(tmp_path), ctx) == [mounted]
    assert extracted == [] and not ctx.extracted
    assert [e["tool"] for e in _entries(run_open)] == ["mount_image"]


@pytest.mark.parametrize("suffix", [".vmdk", ".vhd"])
def test_other_nbd_formats_keep_the_mount_only_route(no_nbd, tmp_path, suffix):
    image = tmp_path / f"disk{suffix}"
    image.write_bytes(b"")
    with pytest.raises(RuntimeError, match="No available NBD devices"):
        C.mount_image(image, _dest(tmp_path), C.MountContext())
    assert not (tmp_path / "ingest" / "_raw").exists()


class Stop(Exception):
    pass


@pytest.mark.parametrize("in_archive", [False, True])
def test_shadow_copies_are_not_read_from_extracted_folders(tmp_path, monkeypatch, in_archive):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    work = tmp_path / "work"
    work.mkdir()
    given = tmp_path / "evidence" / ("collection.zip" if in_archive else "disk.vhdx")
    given.parent.mkdir()
    given.write_bytes(b"\0")
    vss_reads: list = []

    def extract(path, dest, password=None):
        (dest / "disk.vhdx").write_bytes(b"\0")

    def mount(img, dest, ctx):  # as the fallback leaves it
        v = dest / "_x" / "vol1"
        (v / "Windows/System32/config").mkdir(parents=True)
        ctx.extracted = True
        ctx.not_mounted.append(f"{img.name}: {C.NO_NBD_NOTE}")
        return [v]

    def ingest(hosts=None, **kw):
        raise Stop

    for name, value in (
        ("detect_container", lambda p: "archive" if p.suffix == ".zip" else "nbd"),
        ("cleanup_orphaned_mounts", lambda: None),
        ("extract_container", extract),
        ("is_velociraptor_collection", lambda p: False),
        ("make_ingest_tmpdir", lambda case_id: work),
        ("mount_image", mount),
        ("mount_vss", lambda *a, **k: vss_reads.append(a) or []),
        ("cleanup_tmpdir", lambda *a, **k: None),
    ):
        monkeypatch.setattr(C, name, value)
    monkeypatch.setattr(cli, "ingest", ingest)
    monkeypatch.setattr(cli, "_image_hosts", lambda *a: ([], {}, []))
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(hn, "detect_hostname_from_volume", lambda v: None)
    args = argparse.Namespace(
        path=str(given), case="c1", yes=True, hostname=None, vss=True,
        all_logs=False, no_hayabusa=True, skip_triage=True,
    )  # fmt: skip
    with pytest.raises((Stop, SystemExit)):
        cli.cmd_scan(args)
    assert vss_reads == []
