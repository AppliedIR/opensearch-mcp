"""Shared fixtures for opensearch-mcp tests."""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from _helpers import make_windows_tree

# Tests run under a temporary HOME: some write ingest status and audit entries
# for real. Only the cluster settings below are reached through the real one.
# ingest_status._STATUS_DIR is read from HOME when the module is imported, so
# this runs when the root conftest is imported, before any test module.
_ORIGINAL_HOME = os.environ.get("HOME", "")
_TEST_HOME = tempfile.mkdtemp(prefix="opensearch-mcp-tests-home-")
atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)
os.environ["HOME"] = _TEST_HOME
# SUDO_USER too: under sudo, paths.vhir_home() takes that user's home, not HOME.
for _var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR", "SUDO_USER"):
    os.environ.pop(_var, None)
# The cluster's connection settings, linked rather than copied, so cluster tests
# still run.
_CLUSTER_CONFIG = Path(_ORIGINAL_HOME, ".vhir", "opensearch.yaml")
if _ORIGINAL_HOME and _CLUSTER_CONFIG.is_file():
    (Path(_TEST_HOME) / ".vhir").mkdir()
    (Path(_TEST_HOME) / ".vhir" / "opensearch.yaml").symlink_to(_CLUSTER_CONFIG)


@pytest.fixture(autouse=True)
def _reset_enrichment():
    """Reset server.py enrichment globals before each test."""
    from opensearch_mcp.server import reset_enrichment_state

    reset_enrichment_state()
    yield
    reset_enrichment_state()


@pytest.fixture(scope="session", autouse=True)
def _case_dirs(tmp_path_factory):
    """Every record is stored with its machine, which lives in the case's host
    logs, and every read is scoped by the case's CASE.yaml: give each case id
    a test names a case directory with a CASE.yaml (an existing one under
    VHIR_CASES_DIR or the active case is used as it is). Session-wide, so
    module fixtures that ingest before the first test get one too.
    `@pytest.mark.no_case_dirs` restores the real lookup for one test."""
    from opensearch_mcp import write_context as wc

    root = tmp_path_factory.mktemp("cases")
    real = wc.case_dir_for

    def case_dir_for(case_id):
        if not case_id or Path(case_id).name != case_id:
            return None
        d = real(case_id) or root / case_id
        d.mkdir(parents=True, exist_ok=True)
        if not (d / "CASE.yaml").exists():
            (d / "CASE.yaml").write_text(f"case_id: {case_id}\n")
        return d

    case_dir_for.real = real
    wc.case_dir_for = case_dir_for
    try:
        yield root
    finally:
        wc.case_dir_for = real


@pytest.fixture(autouse=True)
def _case_for_every_ingest(request, monkeypatch):
    """Open a unit, and a step, for writes made outside an ingest run (inner
    parsers called directly). `@pytest.mark.no_case_dirs` turns this and the case-directory
    hook off, for rows about a missing case or a write with no run open."""
    from opensearch_mcp import write_context as wc

    if request.node.get_closest_marker("no_case_dirs"):
        monkeypatch.setattr(wc, "case_dir_for", wc.case_dir_for.real)
        yield
        return
    default = wc.open_unit(
        wc.case_dir_for("test-case"), "evidence/test-host", "TEST-HOST", source="test"
    )
    # a case made here has nothing from before 0.6.4: its first write doesn't
    # ask the client (often a stand-in) for pre-0.6.4 indices
    wc._imported.add(default.case_dir)
    wc.set_current(default)
    try:
        with wc.op("opensearch-test-001"):  # and a step its records are written under
            yield
    finally:
        wc.set_current(None)


@pytest.fixture(autouse=True)
def _templates_installed(request, monkeypatch):
    """A process's first write installs the index templates once. Rows about
    something else (often with a stand-in client) start as if that install had
    succeeded; `@pytest.mark.template_install` runs the real one, from a new
    process's empty cache."""
    from opensearch_mcp import mappings

    if request.node.get_closest_marker("template_install"):
        monkeypatch.setattr(mappings, "_INSTALLED", None, raising=False)
        yield
        return
    names = [n for n, _ in mappings._TEMPLATES_REGISTRY]
    done = {"status": "ok", "other_templates": {"installed": names, "failed": []}}
    monkeypatch.setattr(mappings, "_INSTALLED", done, raising=False)
    yield


@pytest.fixture(autouse=True)
def _inputs_traced(request, monkeypatch):
    """Ingest refuses an input that doesn't trace FULL to registered evidence.
    Rows about something else run the real gate and, where it would refuse
    (an input they never registered), go on with no roots, as before the gate;
    `@pytest.mark.evidence_gate` keeps its refusals."""
    if request.node.get_closest_marker("evidence_gate"):
        yield
        return
    from opensearch_mcp import ops

    real = ops.gate

    def gate(case_dir, path):
        try:
            return real(case_dir, path)
        except ops.Refused:
            return [], {}

    monkeypatch.setattr(ops, "gate", gate)
    yield


@pytest.fixture(autouse=True)
def _hosts_confirmed(request, monkeypatch):
    """Ingest waits until the examiner confirms each unit's hosts. Rows about
    something else run as if every host were confirmed; `@pytest.mark.host_gate`
    keeps the real gate. Workers started as their own process keep it too."""
    if request.node.get_closest_marker("host_gate"):
        yield
        return
    from sift_common import host_gate

    from opensearch_mcp import server

    monkeypatch.setattr(host_gate, "unresolved", lambda state, units: [])
    monkeypatch.setattr(server, "_GATE_ANSWER_SECONDS", 0.0)
    yield


@pytest.fixture
def windows_tree(tmp_path):
    """Create a full Windows directory structure under tmp_path and return it."""
    make_windows_tree(tmp_path)
    return tmp_path


@pytest.fixture
def mock_evtx_record():
    """Factory for creating mock pyevtx-rs records."""

    def _make(
        event_id=4624,
        channel="Security",
        computer="TEST01",
        timestamp="2024-01-15T10:00:00Z",
        event_data=None,
        user_data=None,
        record_id=1,
    ):
        system = {
            "EventID": event_id,
            "Channel": channel,
            "Computer": computer,
            "TimeCreated": {"#attributes": {"SystemTime": timestamp}},
            "Provider": {"#attributes": {"Name": "TestProvider"}},
        }
        event = {"System": system}
        if event_data is not None:
            event["EventData"] = event_data
        else:
            event["EventData"] = {"TargetUserName": "testuser"}
        if user_data is not None:
            event["UserData"] = user_data

        return {
            "event_record_id": record_id,
            "data": json.dumps({"Event": event}),
        }

    return _make
