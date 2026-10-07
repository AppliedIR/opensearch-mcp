"""idx_case_summary(case_id=X) flags X's failed ingests whichever case is active.

The ingest workers write their audit entries into the active case's audit dir,
labelled with the active case. The summary read only the active case's dir, so
a case that wasn't active showed no "may be incomplete" warning. It now also
reads the named case's own audit dir under the cases root. Synthetic entries.
"""

import json
from pathlib import Path

import pytest
from sift_common import host_identity

from opensearch_mcp import server
from opensearch_mcp import write_context as wc

DOCS = 1000


def _warning(cid):
    c12 = wc.case_identity(wc.case_dir_for(cid))[0]
    return (
        f"case-{c12}-registry-0 ({DOCS:,} docs from host1) may be incomplete: the most recent"
        " ingest of registry on host1 failed (FAILED: line contains NUL)"
    )


class _Cat:
    def indices(self, index, format="json", **kw):  # the case's case-<c12>-* scope
        return [{"index": index.removesuffix("*") + "registry-0", "docs.count": str(DOCS)}]


class _Client:
    cat = _Cat()

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            return {"aggregations": {"hosts": {"buckets": [{"key": "host1"}]}}}
        return {"aggregations": {"min_ts": {}, "max_ts": {}}}

    def count(self, index, body):  # a failed host's own documents, for its warning
        return {"count": DOCS if "host.name" in str(body) else 0}


def _entry(case_id, result, ts="2026-10-03T20:23:26+00:00", run="r1"):
    return {
        "ts": ts,
        "tool": "ingest_registry",
        "case_id": case_id,
        "params": {"hostname": "host1", "tool": "registry", "run_id": run},
        "result_summary": {"value": result},
    }


def _write(audit_dir: Path, *entries, name="opensearch-ingest-1.jsonl"):
    audit_dir.mkdir(parents=True, exist_ok=True)
    with open(audit_dir / name, "a") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


@pytest.fixture
def root(tmp_path, monkeypatch):
    """Cases a and b under the cases root, each with a failed registry ingest."""
    cases = tmp_path / "cases"
    for cid in ("a", "b"):
        (cases / cid).mkdir(parents=True)
        (cases / cid / "CASE.yaml").write_text(f"case_id: {cid}\n")
        host_identity.ensure_case_uuid(cases / cid, 2)
        _write(cases / cid / "audit", _entry(cid, "FAILED: line contains NUL"))
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    for var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(server, "_get_os", lambda: _Client())
    return cases


def activate(cases, cid):
    (Path.home() / ".vhir" / "active_case").write_text(str(cases / cid))


def incomplete(cid):
    resp = server.idx_case_summary(case_id=cid)
    return [w for w in resp.get("warnings", []) if "may be incomplete" in w]


def test_a_case_that_isnt_active_shows_its_flags(root):
    activate(root, "b")
    assert incomplete("a") == [_warning("a")]


def test_the_active_case_still_shows_its_own_flags(root):
    activate(root, "b")
    assert incomplete("b") == [_warning("b")]


def test_a_later_success_in_the_cases_own_log_clears_it(root):
    activate(root, "b")
    later = _entry("a", "1500 indexed", ts="2026-10-04T00:00:00+00:00", run="r2")
    _write(root / "a" / "audit", later)
    assert incomplete("a") == []


def test_another_cases_failures_arent_shown(root):
    activate(root, "b")
    (root / "c").mkdir()
    _write(root / "c" / "audit", _entry("c", "1500 indexed"))
    assert incomplete("c") == []


def test_a_pinned_case_dir_is_still_read(root, tmp_path, monkeypatch):
    # entries written under VHIR_CASE_DIR, labelled with the active case
    sink = tmp_path / "pinned"
    sink.mkdir()
    (sink / "CASE.yaml").write_text("case_id: pinned\n")
    _write(root / "a" / "audit", _entry("a", "1500 indexed", "2026-10-04T00:00:00+00:00", "r2"))
    failed = _entry("a", "FAILED: line contains NUL", "2026-10-05T00:00:00+00:00", "r3")
    _write(sink / "audit", failed)
    monkeypatch.setenv("VHIR_CASE_DIR", str(sink))
    activate(root, "a")
    assert incomplete("a") == [_warning("a")]


def test_entries_written_with_no_active_case_count_in_the_cases_own_log(root):
    log = root / "a" / "audit" / "opensearch-ingest-1.jsonl"
    log.write_text(log.read_text().replace('"case_id": "a"', '"case_id": ""'))
    activate(root, "b")
    assert incomplete("a") == [_warning("a")]


@pytest.mark.parametrize("cid", ["..", "../x"])
def test_an_id_with_path_components_reads_nothing_outside_the_root(root, cid, monkeypatch):
    outside = root / cid / "audit"  # the dir the id would name
    _write(outside, _entry(cid, "FAILED: outside the cases root"))
    _write(outside, _entry("", "FAILED: outside the cases root"))
    activate(root, "b")
    assert incomplete(cid) == []


def test_the_active_cases_log_is_read_once(root, monkeypatch):
    activate(root, "a")
    read = []
    real = Path.read_text

    def spy(self, *a, **kw):
        if self.name.startswith("opensearch-ingest-"):
            read.append(self.resolve())
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", spy)
    assert incomplete("a") == [_warning("a")]
    assert len(read) == len(set(read)) == 1
