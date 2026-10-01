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

# Tests never use the real HOME: some write ingest status and audit entries
# for real. ingest_status._STATUS_DIR is read from HOME when the module is
# imported, so this runs when the root conftest is imported, before any test
# module.
_ORIGINAL_HOME = os.environ.get("HOME", "")
_TEST_HOME = tempfile.mkdtemp(prefix="opensearch-mcp-tests-home-")
atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)
os.environ["HOME"] = _TEST_HOME
for _var in ("VHIR_CASE_DIR", "VHIR_AUDIT_DIR"):
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
