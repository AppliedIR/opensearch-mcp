"""A relative evidence path stays in the active case, names something in it,
and one call reads the active case once.

- A path whose own `..` leaves the case folder is refused before anything is
  read or written. A dry run once previewed another case's file, and a memory
  dry run wrote a locator into this case's host observations.
- The join uses the folder the active-case pointer names, as case-mcp reads it,
  not VHIR_CASE_DIR, so both resolve the same case.
- `""` and `.` name the case folder itself and are refused, instead of the
  whole case being scanned or launched.
- A run that failed within the gate answer says so in its message and audit.
- The input's folder and the run's case come from one read of the pointer.

The server's tools run in-process with test_relative_evidence_path's fixture:
two cases, and a cwd holding decoys.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
from test_relative_evidence_path import env  # noqa: F401

from opensearch_mcp import ingest_status, paths
from opensearch_mcp import server as srv


def _files(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*") if p.is_file())


@pytest.mark.parametrize(
    "tool,path",
    [("idx_ingest_json", "../INC-RP2/evidence/sec.json"),
     ("idx_ingest_memory", "../INC-RP2/evidence/mem.raw"),
     ("idx_ingest_json", "evidence/../../INC-RP2/evidence/sec.json")],
)  # fmt: skip
def test_a_relative_path_that_leaves_the_case_is_refused_and_writes_nothing(env, tool, path):  # noqa: F811
    rp1 = env.cases["INC-RP1"]
    before = _files(rp1)
    for dry in (True, False):
        r = getattr(srv, tool)(path=path, hostname="h1", dry_run=dry)
        assert "leaves the case folder" in str(r.get("error")), r
    assert _files(rp1) == before and env.launched == []


def test_a_run_that_failed_at_once_says_so_in_its_message_and_audit(env, monkeypatch):  # noqa: F811
    audited = []
    monkeypatch.setattr(srv.audit, "log", lambda **kw: audited.append(kw) or "aid-1")

    def spawn(cmd, e, log, run_id):
        p = ingest_status._status_path_safe("INC-RP1", 4242, run_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"status": "failed", "error": "worker refused the input"}))
        return mock.MagicMock(pid=4242)

    monkeypatch.setattr(srv, "_spawn_ingest", spawn)
    r = srv.idx_ingest_json(path="evidence/sec.json", hostname="h1", dry_run=False)
    assert r["status"] == "failed" and "worker refused the input" in r["message"], r
    assert "started" not in r["message"].lower()
    summaries = [str(a.get("result_summary")) for a in audited]
    assert summaries and not any("started" in s for s in summaries), summaries
    assert any("failed" in s and "worker refused the input" in s for s in summaries), summaries


def test_the_join_uses_the_active_case_pointer_as_case_mcp_does(env, monkeypatch, tmp_path):  # noqa: F811
    alt = tmp_path / "alt" / "INC-RP1"
    (alt / "evidence").mkdir(parents=True)
    (alt / "CASE.yaml").write_text("case_id: INC-RP1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(alt))
    assert srv._case_path("evidence/x") == (str(env.cases["INC-RP1"] / "evidence/x"), None)


@pytest.mark.parametrize("path", ["", "."])
@pytest.mark.parametrize("tool", ["idx_ingest", "idx_ingest_json"])
def test_a_path_naming_the_case_folder_itself_is_refused(env, tool, path):  # noqa: F811
    for dry in (True, False):
        r = getattr(srv, tool)(path=path, hostname="h1", dry_run=dry)
        assert "the case folder itself" in str(r.get("error")), r
    assert env.launched == []


def test_the_input_and_the_case_come_from_one_read(env, monkeypatch):  # noqa: F811
    """The examiner switches cases while the call runs: the first look at the
    pointer folder sees INC-RP1, every later one INC-RP2."""
    vhir, looks = paths.vhir_dir(), []

    def vhir_dir():
        looks.append(1)
        if len(looks) == 2:
            env.activate("INC-RP2")
        return vhir

    monkeypatch.setattr(paths, "vhir_dir", vhir_dir)
    srv.idx_ingest_json(path="evidence/sec.json", hostname="h1", dry_run=False)
    argv = env.launched[-1]
    case = argv[argv.index("--case") + 1]
    inputs = [a for a in argv if a.endswith("sec.json")]
    assert inputs and all(a.startswith(str(env.cases[case])) for a in inputs), argv


# --- unchanged ------------------------------------------------------------------


def test_a_relative_path_inside_the_case_is_joined_as_given(env):  # noqa: F811
    rp1 = env.cases["INC-RP1"]
    for rel in ("evidence/sec.json", "evidence/../evidence/sec.json", "./evidence/sec.json"):
        assert srv._case_path(rel) == (str(rp1 / rel), None)
    r = srv.idx_ingest_json(path="evidence/sec.json", hostname="h1", dry_run=True)
    assert r == {"status": "preview", "file": "sec.json", "format": "jsonl"}, r


def test_an_absolute_path_is_returned_as_given(env):  # noqa: F811
    other = str(env.cases["INC-RP2"] / "evidence" / "sec.json")
    assert srv._case_path(other) == (other, None)
    assert srv._case_path("/") == ("/", None)


@pytest.mark.parametrize("pointer", ["INC-RP2", "x/INC-RP2"], ids=["bare id", "relative path"])
def test_a_relative_pointer_resolves_by_its_name_in_the_cases_folder(env, pointer):  # noqa: F811
    (paths.vhir_dir() / "active_case").write_text(pointer)
    assert srv._get_active_case() == "INC-RP2"
    assert srv._case_path("evidence/sec.json") == (
        str(env.cases["INC-RP2"] / "evidence/sec.json"),
        None,
    )
