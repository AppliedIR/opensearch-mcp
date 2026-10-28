"""What a query says when its entry isn't recorded, and where nothing goes.

A query takes its case as it starts: the response file and the entry go to
that case, and only while it is still one. Moved away before either is
written, nothing is recreated at its old path; the reply keeps the query's
result and says the case is gone. With no case, it says so under `audit`.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
from pathlib import Path

import pytest

from opensearch_mcp import ops
from opensearch_mcp import server as srv

NO_CASE = "not recorded: no case was active for this call"
RESULT = {"total": 3, "hits": [{"_id": "a"}], "shards": {"failed": 0}}
ENTRY = {"tool": "idx_search", "params": {"query": "x"}, "result_summary": {"total": 3}}


def _gone(path) -> str:
    return (
        f"not recorded: {path} is no longer a case (no CASE.yaml). "
        "The call itself ran; calling it again repeats it."
    )


@pytest.fixture
def pointer(monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    path = Path.home() / ".vhir" / "active_case"
    path.parent.mkdir(exist_ok=True)
    path.unlink(missing_ok=True)
    yield path
    path.unlink(missing_ok=True)


def _case(tmp_path, name="case-a"):
    case = tmp_path / "cases" / name
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\n")
    return case


def _query():
    return srv._logged_query(dict(RESULT), **ENTRY)


def _files(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.exists() else []


def test_a_query_with_no_case_says_so_and_warns_nothing(pointer):
    reply = _query()
    assert reply.get("audit") == NO_CASE and "warning" not in reply, reply
    assert {k: reply[k] for k in RESULT} == RESULT


def test_a_case_activated_during_a_query_keeps_the_no_case_note(pointer, tmp_path, monkeypatch):
    case = _case(tmp_path)

    def then_activate(real):
        def wrapped(*a, **k):
            got = real(*a, **k)
            pointer.write_text(str(case))
            return got

        return wrapped

    for name in ("resolve", "_get_audit_dir"):  # the query takes its case here
        real = getattr(srv.audit, name, None)
        if real is not None:
            monkeypatch.setattr(srv.audit, name, then_activate(real))
    reply = _query()
    assert reply.get("audit") == NO_CASE and "warning" not in reply, reply
    assert "audit_id" not in reply and _files(case / "audit") == []


@pytest.fixture
def move_at(monkeypatch):
    """Renames the case away at the first creation under it of the kind
    asked for: a folder (just after its CASE.yaml check) or the entry."""
    state: dict = {}
    real_mkdir, real_open = os.mkdir, os.open

    def move(path):
        case = state.get("case")
        if case and not state.get("moved") and str(path).startswith(str(case) + "/"):
            os.rename(case, str(case) + "-moved")
            state["moved"] = str(path)

    def mkdir(path, *a, **k):
        if state.get("at") == "folder":
            move(path)
        return real_mkdir(path, *a, **k)

    def open_(path, flags, *a, **k):
        if state.get("at") == "entry" and str(path).endswith(".jsonl"):
            move(path)
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "mkdir", mkdir)
    monkeypatch.setattr(os, "open", open_)
    accessor = getattr(pathlib, "_NormalAccessor", None)  # Python 3.10
    if accessor is not None:
        monkeypatch.setattr(accessor, "mkdir", staticmethod(mkdir), raising=False)
    return state


@pytest.mark.parametrize("at", ["folder", "entry"])
def test_a_case_moved_during_a_query_is_not_recreated(at, pointer, tmp_path, move_at):
    case = _case(tmp_path)
    pointer.write_text(str(case))
    move_at.update(case=case, at=at)
    reply = _query()
    assert move_at.get("moved"), "the case never moved"
    assert not case.exists(), _files(case)
    assert {k: reply[k] for k in RESULT} == RESULT
    assert reply.get("warning") == _gone(case) and "audit_id" not in reply, reply
    assert "audit" not in reply


def test_a_query_whose_case_stays_is_recorded(pointer, tmp_path, move_at):
    case = _case(tmp_path)
    pointer.write_text(str(case))
    reply = _query()
    assert "warning" not in reply and "audit" not in reply, reply
    (entry,) = [json.loads(x) for x in (case / "audit" / "opensearch-mcp.jsonl").read_text()
                .splitlines()]  # fmt: skip
    assert entry["audit_id"] == reply["audit_id"]
    assert (case / "extractions" / reply["audit_id"] / "response.json").is_file()


def test_a_case_writer_for_a_moved_case_creates_nothing(pointer, tmp_path):
    case = _case(tmp_path, "enriched")
    writer = ops.case_writer(srv.audit, case)
    os.rename(case, str(case) + "-moved")
    assert writer.log(**ENTRY) is None
    assert not case.exists()


# --- an audit folder from the environment is not a case ---------------------


def test_beside_an_audit_folder_with_no_parent_the_response_is_saved(
    pointer, tmp_path, monkeypatch
):
    folder = tmp_path / "not" / "yet" / "audit"
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(folder))
    reply = _query()
    assert "warning" not in reply and "audit" not in reply, reply
    saved = folder.parent / "extractions" / reply["audit_id"] / "response.json"
    assert json.loads(saved.read_text())["audit_id"] == reply["audit_id"]
    (entry,) = [json.loads(x) for x in (folder / "opensearch-mcp.jsonl").read_text()
                .splitlines()]  # fmt: skip
    assert entry["response"]["path"] == str(saved) and entry["case_id"] == "yet"


def test_beside_an_unwritable_audit_folder_the_query_says_so(pointer, tmp_path, monkeypatch):
    parent = tmp_path / "locked"
    parent.mkdir()
    parent.chmod(0o500)
    monkeypatch.setenv("VHIR_AUDIT_DIR", str(parent / "audit"))
    try:
        reply = _query()
    finally:
        parent.chmod(0o700)
    assert {k: reply[k] for k in RESULT} == RESULT and "audit_id" not in reply
    warning = reply.get("warning", "")
    assert warning.startswith("Audit write failed — not recorded: its response was not"
                              " saved ([Errno 13]"), reply  # fmt: skip
    assert _files(parent) == []


# --- the sift-common it needs ------------------------------------------------

# The first sift-common version carrying each name the source imports from it
FIRST = {
    "sift_common.SYSTEM_DIRS": "0.6.4",
    "sift_common.close_tool_arguments": "0.6.5.2",
    "sift_common.resolve_case_dir": "0.5.1",
    "sift_common.file_identity": "0.6.4",
    "sift_common.file_place": "0.6.4",
    "sift_common.host_gate": "0.6.4",
    "sift_common.host_identity": "0.6.4",
    "sift_common.host_proposal": "0.6.4",
    "sift_common.provenance": "0.6.4",
    "sift_common.audit.AuditWriter": "0.1.0",
    "sift_common.audit.AuditOutcome": "0.6.5.2",
    "sift_common.audit.is_case": "0.6.5.2",
    "sift_common.audit.mkdir_in_case": "0.6.5.2",
    "sift_common.content_hash.content_hash": "0.6.4",
    "sift_common.file_identity.NotRegularFile": "0.6.4",
    "sift_common.file_identity.hash_file": "0.6.4",
    "sift_common.host_gate.host_list_hint": "0.6.4",
    "sift_common.host_identity.spelling": "0.6.4",
    "sift_common.host_identity.unit_locator": "0.6.4",
}


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in text.split("."))


def test_the_sift_common_floor_carries_every_name_imported_from_it():
    imported = {
        f"{m[1]}.{name.split(' as ')[0].strip()}"
        for p in sorted((Path(__file__).parents[1] / "src").rglob("*.py"))
        for m in re.finditer(
            r"^\s*from (sift_common[\w.]*) import ([\w, ]+)$", p.read_text(encoding="utf-8"), re.M
        )
        for name in m[2].split(",")
    }
    assert imported - FIRST.keys() == set()
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    floor = re.search(r'"sift-common>=([\d.]+)"', pyproject)[1]
    assert _version(floor) >= max(_version(FIRST[n]) for n in imported)


# --- the census: no query site writes an audit text of its own -------------

SRC = Path(__file__).resolve().parents[1] / "src"
NEEDLES = ("not recorded", "_NOT_RECORDED", "Audit write failed",
           "is no longer a case (no CASE.yaml)")  # fmt: skip
# Lines that say "not recorded" of something other than a call's entry, and why
ALLOWED = {
    "opensearch_mcp/containers.py: raise RuntimeError("
    'f"{path.name}: its extraction was not recorded: {e}") from None': "an extraction's"
    " failure, raised to its caller",
    "opensearch_mcp/ingest_cli.py: except ops.NoEntry as e:"
    "  # unreadable (its failure recorded) or not recorded": "code comment, not reply text",
}


def test_no_site_writes_an_audit_outcome_text_of_its_own():
    hits = [
        f"{p.relative_to(SRC)}: {line.strip()}"
        for p in sorted(SRC.rglob("*.py"))
        for line in p.read_text(encoding="utf-8").splitlines()
        if any(t in line for t in NEEDLES)
    ]
    assert [h for h in hits if h not in ALLOWED] == []
