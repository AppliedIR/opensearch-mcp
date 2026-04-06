"""Shared fixtures for opensearch-mcp tests."""

from __future__ import annotations

import json

import pytest
from _helpers import make_windows_tree


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
