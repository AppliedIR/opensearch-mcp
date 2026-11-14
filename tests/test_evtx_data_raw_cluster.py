"""Against a cluster, through the tree's evtx pipeline: a record with an object
`Data`, as the evtx parser sends it (its `Data_raw` already written), is
stored as sent. Values are synthetic."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest
from test_host_keys_cluster import client  # noqa: F401

from opensearch_mcp import mappings
from opensearch_mcp.parse_evtx import _normalise_data

pytestmark = pytest.mark.integration


def test_an_object_data_is_stored_as_sent(client):  # noqa: F811
    pipeline = json.loads(mappings._PIPELINE_FILE.read_text())
    sent = {"winlog.event_data": {"Data": {"#text": ["a", "b"]}, "User": "jdoe"}}
    _normalise_data(sent)
    body = {"pipeline": pipeline, "docs": [{"_source": deepcopy(sent)}]}
    stored = client.ingest.simulate(body=body)["docs"][0]["doc"]["_source"]
    assert stored == sent
