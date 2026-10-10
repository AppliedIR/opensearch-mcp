"""Evidence registered where it lies (a symlink in the case's evidence/ to an
original on read-only storage outside the usual mount points) can be ingested:
the ingest tools take a path whose real path is an original registered in the
case they write to. Home itself, the hidden folders in it, and the system's
folders stay refused, so registering a link never opens them; anything
unregistered stays refused."""

from __future__ import annotations

import json
import os

import pytest

from opensearch_mcp import server

SYSTEM_FILE = "/etc/passwd"  # in a system folder, and on every box


def _case(cases, name, registered):
    case = cases / name
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\n")
    # as case-mcp records them: a link's real target
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(p), **extra} for p, extra in registered]})
    )
    return case


@pytest.fixture
def box(tmp_path, monkeypatch):
    home, srv = tmp_path / "home", tmp_path / "srv"
    cases = home / "cases"
    (srv / "kape" / "C").mkdir(parents=True)
    (srv / "mem.raw").write_bytes(b"memory")
    (srv / "kape" / "C" / "Security.evtx").write_bytes(b"ElfFile")
    (srv / "other.raw").write_bytes(b"never registered")
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("key")
    key = home / ".ssh" / "id_ed25519"
    case = _case(cases, "INC-1", [
        (srv / "mem.raw", {"sha256": "a" * 64}),
        (srv / "kape", {"kind": "folder", "manifest_sha256": "b" * 64}),
        (key, {"sha256": "c" * 64}),
        (SYSTEM_FILE, {"sha256": "d" * 64})])  # fmt: skip
    for name, target in (("mem.raw", srv / "mem.raw"), ("kape", srv / "kape"),
                         ("key", key), ("host-link", SYSTEM_FILE)):  # fmt: skip
        os.symlink(target, case / "evidence" / name)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    # the case the ingest writes to, as the tools read it
    (home / ".vhir").mkdir()
    (home / ".vhir" / "active_case").write_text(str(case))
    # the test's folder may be under /tmp, itself allowed: the original lies elsewhere
    monkeypatch.setattr(server, "ALLOWED_ROOTS", ("/mnt", "/media"), raising=False)
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


def test_a_registered_link_into_a_system_folder_is_still_refused(box):
    case, _ = box
    for p in (case / "evidence" / "host-link", SYSTEM_FILE):
        err = server._validate_path(str(p))
        assert err and f"(resolved target: {SYSTEM_FILE})" in err, p


def test_with_no_active_case_nothing_counts_as_registered(box, monkeypatch):
    """Not even a registry in the working folder."""
    case, srv = box
    (case.parent.parent / ".vhir" / "active_case").unlink()
    monkeypatch.chdir(case)  # its evidence.json lists the original
    assert "not in allowed locations" in server._validate_path(str(srv / "mem.raw"))


def test_the_registry_read_is_the_case_the_ingest_writes_to(box, monkeypatch):
    """VHIR_CASE_DIR naming another case changes nothing: the ingest writes to
    the active case, and only its registry counts."""
    case, srv = box
    other = _case(case.parent, "INC-2", [])
    monkeypatch.setenv("VHIR_CASE_DIR", str(other))
    assert server._validate_path(str(srv / "mem.raw")) is None  # the active case's
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case.parent.parent / ".vhir" / "active_case").write_text(str(other))
    assert "not in allowed locations" in server._validate_path(str(srv / "mem.raw"))
