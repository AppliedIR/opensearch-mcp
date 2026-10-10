"""An E01's shadow copies trace to the E01, as its volumes do.

ewfmount exposes the E01 as a raw stream (`_ewf/ewf1`), and the shadow copies
are read from it; the shadow copy mount records the E01 as its input, so a
record found only in a shadow copy is FULL to the registered E01."""

from __future__ import annotations

import hashlib
import json
import subprocess as sp

import pytest
from sift_common import provenance as pv
from sift_common.audit import AuditWriter

import opensearch_mcp.containers as C
from opensearch_mcp import ops


@pytest.fixture
def box(tmp_path, monkeypatch):
    case = tmp_path / "acme"
    (case / "audit").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.yaml").write_text("case_id: acme\n")
    image = case / "evidence" / "rd01.E01"
    image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\0" * 4096)
    sha = hashlib.sha256(image.read_bytes()).hexdigest()
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(image), "sha256": sha}]})
    )

    def partitions(raw, dest, ctx):  # a stand-in: one NTFS volume, as _mount_raw finds it
        v = dest / "p2"
        v.mkdir()
        ctx.add_mount(v)
        ctx.offsets[v] = 105906176
        return [v]

    def stores(raw, dest, ctx, offset, name):  # two stores, as _mount_vss_at names them
        found = []
        for n in (1, 2):
            p = dest / f"vss{n}"
            p.mkdir()
            found.append((f"vss{n}", p))
        return found, "", ""

    monkeypatch.setattr(C, "check_sudo", lambda: None)
    monkeypatch.setattr(
        C.subprocess, "run", lambda cmd, **k: sp.CompletedProcess(cmd, 0, b"", b"")
    )
    monkeypatch.setattr(C, "_mount_raw_partitions", partitions)
    monkeypatch.setattr(C, "_is_ntfs", lambda path, off: True)
    monkeypatch.setattr(C, "_mount_vss_at", stores)
    return case, image, sha, tmp_path / "mnt"


def _mounts(case, image, dest, vss_raw=None):
    """mount_image, then mount_vss on the stream (or `vss_raw`), as an ingest
    of the image does: each mount's entry."""
    dest.mkdir()
    ctx = C.MountContext()
    ops.set_run(AuditWriter("opensearch-ingest-1", audit_dir=str(case / "audit")), case)
    try:
        C.mount_image(image, dest, ctx)
        C.mount_vss(vss_raw or dest / "_ewf" / "ewf1", dest, ctx, {"p2": 105906176})
    finally:
        ops.set_run(None, None)
    entries = [json.loads(x) for f in (case / "audit").glob("*.jsonl")
               for x in f.read_text().splitlines()]  # fmt: skip
    return {e["tool"]: e for e in entries if "mount" in e}


def test_an_e01s_shadow_copies_are_full_to_the_e01(box):
    case, image, sha, dest = box
    m = _mounts(case, image, dest)
    vss = m["mount_vss"]
    assert vss["mount"]["image"] == str(image.resolve())
    assert vss["input_registered"] == [{"path": str(image.resolve()), "sha256": sha}]
    assert [p["store"] for p in vss["mount"]["points"]] == ["vss1", "vss2"]
    for tool in ("mount_image", "mount_vss"):  # the volume and its shadow copies alike
        t = pv.trace_op(pv.load_case(case), m[tool]["audit_id"])
        assert t.grade == "FULL" and t.root["sha256"] == sha, (tool, t.as_dict())


def test_a_raw_images_shadow_copies_still_name_the_image(box):
    """No stream: the stores are read from the image itself, as before."""
    case, image, sha, dest = box
    raw = case / "evidence" / "rd01.raw"
    raw.write_bytes(image.read_bytes())
    m = _mounts(case, image, dest, vss_raw=raw)
    assert m["mount_vss"]["mount"]["image"] == str(raw.resolve())
