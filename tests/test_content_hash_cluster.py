"""Against a cluster, through the tree's evtx template and its pipeline: the
content hash stamped on a record as it is sent equals the hash of its stored
_source, whatever the pipeline added (`Data_raw` for an object `Data`), and
for a non-object `Data` the evtx parser moved to `Data_raw` itself.
Values are synthetic."""

from __future__ import annotations

import pytest
from sift_common.content_hash import content_hash
from test_host_keys_cluster import cases, client, write  # noqa: F401

from opensearch_mcp import write_context as wc
from opensearch_mcp.parse_evtx import _normalise_data

pytestmark = pytest.mark.integration


def test_a_stored_records_hash_is_the_one_stamped_when_it_was_sent(client, cases):  # noqa: F811
    case, c12 = cases("ch")
    plain = {"winlog.event_data": {"Data": "plain text", "User": "bob"}}
    _normalise_data(plain)  # as parse_evtx sends it
    docs = {
        "object": {"@timestamp": "2026-10-09T00:00:00Z", "event.code": "4624",
                   "winlog.event_data": {"Data": {"Name": "a", "#text": "b"}, "User": "bob"},
                   "message": "café"},
        "plain": {"@timestamp": "2026-10-09T00:00:01Z", "event.code": "4624", **plain},
        "nested": {"@timestamp": "2026-10-09T00:00:02Z", "event": {"code": "4625"},
                   "host": {"name": "WKS1"}},
    }  # fmt: skip
    with wc.op("opensearch-ingest-1-20261009-001"):
        write(client, case, "hosts/WKS1", "WKS1", docs)
    hits = client.search(index=f"case-{c12}-evtx-*", body={"size": 10})["hits"]["hits"]
    assert len(hits) == 3
    for h in hits:
        src = h["_source"]
        assert src["vhir.content_hash"] == content_hash(src), (h["_id"], src)
    by_rid = {h["_source"]["vhir.rid"]: h["_source"] for h in hits}
    assert "Data_raw" in by_rid["object"]["winlog.event_data"]  # the pipeline added it
    assert by_rid["plain"]["winlog.event_data"]["Data_raw"] == "plain text"
