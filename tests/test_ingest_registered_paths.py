"""Evidence registered where it lies (a symlink in the case's evidence/ to an
original on read-only storage outside the usual mount points) can be ingested:
the ingest tools take a path whose real path is an original registered in the
active case. Home itself, and the hidden folders in it, stay refused first, so
registering a link never opens them; anything unregistered stays refused."""

from __future__ import annotations

import json
import os

import pytest

from opensearch_mcp import server


@pytest.fixture
def box(tmp_path, monkeypatch):
    home, case, srv = tmp_path / "home", tmp_path / "home" / "cases" / "INC-1", tmp_path / "srv"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: INC-1\n")
    (srv / "kape" / "C").mkdir(parents=True)
    (srv / "mem.raw").write_bytes(b"memory")
    (srv / "kape" / "C" / "Security.evtx").write_bytes(b"ElfFile")
    (srv / "other.raw").write_bytes(b"never registered")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("key")
    monkeypatch.setenv("HOME", str(home))
    # the test's folder may be under /tmp, itself allowed: the original lies elsewhere
    monkeypatch.setattr(server, "ALLOWED_ROOTS", ("/mnt", "/media"), raising=False)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    for name, target in (("mem.raw", srv / "mem.raw"), ("kape", srv / "kape"),
                         ("key", home / ".ssh" / "id_ed25519")):  # fmt: skip
        os.symlink(target, case / "evidence" / name)
    # as case-mcp records them: the link's real target
    (case / "evidence.json").write_text(json.dumps({"files": [
        {"path": str(srv / "mem.raw"), "sha256": "a" * 64},
        {"path": str(srv / "kape"), "kind": "folder", "manifest_sha256": "b" * 64},
        {"path": str(home / ".ssh" / "id_ed25519"), "sha256": "c" * 64}]}))  # fmt: skip
    return case, srv


def test_a_registered_original_where_it_lies_is_ingested(box):
    case, srv = box
    for p in (case / "evidence" / "mem.raw", srv / "mem.raw",  # the link, or its target
              case / "evidence" / "kape", srv / "kape" / "C" / "Security.evtx"):  # fmt: skip
        assert server._validate_path(str(p)) is None, p


def test_an_unregistered_path_outside_the_allowed_places_is_still_refused(box):
    _, srv = box
    assert "not in allowed locations" in server._validate_path(str(srv / "other.raw"))


def test_a_registered_link_into_home_s_hidden_folders_is_still_refused(box):
    case, _ = box
    err = server._validate_path(str(case / "evidence" / "key"))
    assert err and err.startswith("Refused:") and "hidden configuration area" in err


def test_with_no_active_case_nothing_counts_as_registered(box, monkeypatch):
    """Not even a registry in the working folder."""
    case, srv = box
    monkeypatch.delenv("VHIR_CASE_DIR")
    monkeypatch.chdir(case)  # its evidence.json lists the original
    assert "not in allowed locations" in server._validate_path(str(srv / "mem.raw"))
