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


# --- the census: no query site writes an audit text of its own -------------

SRC = Path(__file__).resolve().parents[1] / "src"
TEXTS = ("action not recorded", "reasoning not recorded", "for shell evidence",
         "_NOT_RECORDED", "Audit write failed", "not recorded: no case",
         "is no longer a case (no CASE.yaml)")  # fmt: skip


def test_no_site_writes_an_audit_outcome_text_of_its_own():
    hits = [
        f"{p.relative_to(SRC)}:{n}: {line.strip()}"
        for p in sorted(SRC.rglob("*.py"))
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if any(t in line for t in TEXTS) and "logger." not in line
    ]
    assert hits == []
