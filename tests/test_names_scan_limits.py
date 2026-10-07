"""The names scan's limits, and the runs an archive's images make.

A file whose host columns can't be read is listed, not skipped; a mounted
volume is never walked whole; one volume is one unit in the dry run and the
ingest; and each image of an archive runs in its own folder with its own
status, under a status for the archive naming each image's outcome.
Values are synthetic.
"""

from __future__ import annotations

import argparse
import json
import os
import uuid

import pytest

from opensearch_mcp import containers, ingest_cli, ingest_status, names_scan
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost


def case():
    return wc.case_dir_for(f"lim-{uuid.uuid4().hex[:8]}")


# -- files whose host columns can't be read


def test_a_deeply_nested_json_file_is_listed_and_the_scan_goes_on(tmp_path):
    d = case()
    host = d / "evidence" / "WKS30"
    host.mkdir(parents=True)
    (host / "deep.json").write_text("[" * 100_000 + "]" * 100_000)
    (host / "rows.csv").write_text("Computer,x\nWKS30,1\n")
    unit = names_scan.host_folder_unit(DiscoveredHost(hostname="WKS30", volume_root=host), d)
    assert "WKS30" in {n.raw for n in unit.names}
    assert unit.attrs["names_not_sampled"] == [
        "evidence/WKS30/deep.json: nested too deeply to read"
    ]


def test_a_json_array_past_the_sample_is_noted(tmp_path, monkeypatch):
    monkeypatch.setattr(names_scan, "SAMPLE_BYTES", 64)
    f = tmp_path / "big.json"
    f.write_text(json.dumps([{"Computer": "WKS31", "pad": "x" * 200}]))
    try:
        names_scan.row_names(f)
    except names_scan.NotSampled as e:
        assert str(e) == "file too large"
    else:
        raise AssertionError("an array past the sample was skipped silently")


def test_a_host_whose_scan_fails_is_recorded_and_the_others_still_scan(monkeypatch):
    d = case()
    good = d / "evidence" / "WKS32"
    good.mkdir(parents=True)
    bad = DiscoveredHost(hostname="WKS33", volume_root=d / "evidence" / "WKS33")
    real = names_scan.host_folder_unit

    def scan(h, case_dir):
        if h is bad:
            raise RecursionError("maximum recursion depth exceeded")
        return real(h, case_dir)

    monkeypatch.setattr(names_scan, "host_folder_unit", scan)
    hosts = [bad, DiscoveredHost(hostname="WKS32", volume_root=good)]
    summary = ingest_cli._record_scan(d.name, good, hosts, [])
    notes = {u["locator"]: u.get("note", "") for u in summary}
    assert any("names couldn't be read: RecursionError" in n for n in notes.values())
    assert any(u["names"] == ["WKS32"] for u in summary)


def test_a_volume_is_sampled_shallowest_first_and_never_walked_whole(tmp_path, monkeypatch):
    monkeypatch.setattr(names_scan, "ROW_FILES", 5)
    for n in range(4):
        (tmp_path / f"top{n}.csv").write_text("x\n")
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    for n in range(10):
        (deep / f"deep{n}.csv").write_text("x\n")
    files, more = names_scan._row_files(tmp_path)
    assert more and len(files) == 5
    assert [f.name for f in files[:4]] == [f"top{n}.csv" for n in range(4)]


def test_a_folder_sampled_in_part_says_so():
    d = case()
    host = d / "evidence" / "WKS34"
    host.mkdir(parents=True)
    for n in range(3):
        (host / f"r{n}.csv").write_text("Computer,x\nWKS34,1\n")
    unit = names_scan.host_folder_unit(DiscoveredHost(hostname="WKS34", volume_root=host), d)
    assert "names_sampled" not in unit.attrs
    names_scan.ROW_FILES, keep = 2, names_scan.ROW_FILES
    try:
        unit = names_scan.host_folder_unit(DiscoveredHost(hostname="WKS34", volume_root=host), d)
    finally:
        names_scan.ROW_FILES = keep
    assert unit.attrs["names_sampled"] == "host columns read from the first 2 files only"


def test_a_link_out_of_the_volume_is_not_followed(tmp_path):
    vol = tmp_path / "vol"
    vol.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "rows.csv").write_text("Computer,x\nOTHER9,1\n")
    (vol / "out").symlink_to(elsewhere)
    (vol / "rows.csv").symlink_to(elsewhere / "rows.csv")
    assert names_scan._row_files(vol) == ([], False)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_file_that_cannot_be_opened_is_listed():
    d = case()
    host = d / "evidence" / "WKS35"
    host.mkdir(parents=True)
    locked = host / "locked.csv"
    locked.write_text("Computer,x\nWKS35,1\n")
    locked.chmod(0)
    try:
        unit = names_scan.host_folder_unit(DiscoveredHost(hostname="WKS35", volume_root=host), d)
    finally:
        locked.chmod(0o600)
    (note,) = unit.attrs["names_not_sampled"]
    assert note.startswith("evidence/WKS35/locked.csv: unreadable ([Errno 13] Permission denied")


# -- one volume, one unit


def test_a_volume_is_the_same_unit_in_the_dry_run_and_the_ingest(tmp_path):
    d = case()
    image = d / "evidence" / "disk.raw"
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"\0")
    leaf = {"selector": {"partitions": "p2"}, "offset": 22020096, "fs": "ntfs", "os": "windows"}
    (candidate,) = names_scan.image_candidates(image, [leaf], d)

    mounted = tmp_path / "run" / "vol1"
    mounted.mkdir(parents=True)
    via_mount = DiscoveredHost(hostname="WKS40", volume_root=mounted)
    via_plaso = DiscoveredHost(hostname="WKS40", volume_root=image)
    via_plaso.image_path, via_plaso.volume_label, via_plaso.volume_offset = image, "p2", 22020096
    ingest_cli._set_units(
        [via_mount], d.name, image, tmp_path / "run", None, "folder", {mounted: 22020096}
    )
    ingest_cli._set_units([via_plaso], d.name, image, None, None, "folder")
    assert via_mount.unit_locator == candidate.locator == via_plaso.unit_locator


def test_a_one_image_archives_volume_is_one_unit_mounted_or_read_off_the_image(tmp_path):
    d = case()
    archive = d / "evidence" / "one.zip"
    run = tmp_path / "ingest-x"  # the run's folder: the extracted image and its mounts
    image = run / "disk.raw"
    mounted = run / "p2"
    mounted.mkdir(parents=True)
    via_mount = DiscoveredHost(hostname="WKS41", volume_root=mounted)
    via_plaso = DiscoveredHost(hostname="WKS41", volume_root=image)
    via_plaso.image_path, via_plaso.volume_label, via_plaso.volume_offset = image, "p2", 22020096
    for host in (via_mount, via_plaso):
        ingest_cli._set_units(
            [host], d.name, archive, run, None, "folder", {mounted: 22020096},
            archive=(archive, "disk.raw"),
        )  # fmt: skip
    assert via_mount.unit_locator == "evidence/one.zip!disk.raw@22020096"
    assert via_plaso.unit_locator == via_mount.unit_locator


def test_a_volume_no_reader_covered_in_an_archives_image_is_named_by_the_archive(tmp_path):
    d = case()
    archive = d / "evidence" / "disks.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"\0")
    extracted = tmp_path / "ingest-x" / "disk2.raw"  # the run's temporary copy
    summary = ingest_cli._record_scan(
        d.name, extracted, [], [(1048576, "did not mount")], archive=(archive, "disk2.raw")
    )
    (unit,) = summary
    assert unit["locator"] == "evidence/disks.zip!disk2.raw@1048576"


# -- an archive's images: their own folders and statuses


def test_two_runs_in_one_second_get_their_own_folders(monkeypatch, tmp_path):
    monkeypatch.setattr("opensearch_mcp.paths.vhir_dir", lambda: tmp_path)
    parent = containers.make_ingest_tmpdir("c1")
    (parent / "disk2.raw").write_bytes(b"evidence")
    child = containers.make_ingest_tmpdir("c1")  # the same second, the same process
    assert child != parent
    containers.cleanup_tmpdir(child)  # the first image's run ends
    assert (parent / "disk2.raw").read_bytes() == b"evidence"  # the second is still there


def test_each_image_of_an_archive_has_its_own_status_and_the_archive_names_each(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-arc")
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "c1")
    pid = os.getpid()

    def command(sub, examiner=""):
        run = os.environ["VHIR_INGEST_RUN_ID"]
        status = "failed" if sub.archive_member == "b.raw" else "complete"
        ingest_status.write_status("c1", pid, run, status, [], {}, "t0")
        if status == "failed":
            raise SystemExit(1)

    args = argparse.Namespace(case="c1", path="x")
    images = [tmp_path / "a.raw", tmp_path / "b.raw"]
    try:
        ingest_cli._ingest_each_extracted(command, args, tmp_path / "disks.zip", images, "")
    except SystemExit:
        pass
    runs = {
        json.loads(f.read_text())["run_id"]: json.loads(f.read_text())
        for f in (tmp_path / "status").glob("*.json")
    }
    assert runs["run-arc-1"]["status"] == "complete" and runs["run-arc-2"]["status"] == "failed"
    archive = runs["run-arc"]
    assert archive["status"] == "failed"
    outcome = {h["hostname"]: h["artifacts"][0]["status"] for h in archive["hosts"]}
    assert outcome == {"a.raw": "complete", "b.raw": "failed"}


def test_an_images_run_is_not_taken_for_a_dead_worker(monkeypatch, tmp_path):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-img-7")  # set while the worker runs
    ingest_status.write_status("c1", os.getpid(), "run-img-7", "running", [], {}, "t0")
    ingest_status.read_active_ingests()  # the sweep, from any status poll
    (f,) = (tmp_path / "status").glob("*.json")
    assert json.loads(f.read_text())["status"] == "running"
