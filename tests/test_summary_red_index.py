"""A red index doesn't cost the case summary its other indices.

`_cat/indices` gives a red index's `docs.count` as null (measured on
OpenSearch 3.5.0), and `int(None)` raised: one red index lost the summary of
every healthy one. Now an index whose count isn't a whole number isn't
counted (its documents are unknown, not zero): it is named in the summary's
partial warning, and the rest is computed as before.
"""

from __future__ import annotations

import pytest
import test_failed_artifact_warning as faw
from test_failed_artifact_warning import case  # noqa: F401 (a fixture)
from test_partial_shard_answers import (
    DELIM,
    EVTX,
    SHIM,
    WHOLE,
    Cluster,
    run,  # noqa: F401 (a fixture)
    summary,
)

COUNTS = (f"Document counts: partial; failing indices: {SHIM}; "
          "the counts are lower bounds")  # fmt: skip


def cluster(shim_count):
    c = Cluster(WHOLE, buckets=[("WKS1", 2)], indices=[EVTX, DELIM, SHIM])
    c.rows[2]["docs.count"] = shim_count
    c.rows[2]["health"] = "red"
    return c


@pytest.mark.parametrize(
    "count", [None, "", "n/a", "1.5"], ids=["null", "empty", "text", "fraction"]
)
def test_a_red_index_is_named_and_the_healthy_ones_are_counted(run, monkeypatch, count):  # noqa: F811
    reply = summary(run, monkeypatch, cluster(count))
    assert "error" not in reply
    assert reply["partial"] is True
    assert [w for w in reply["warnings"] if w.startswith("Document counts")] == [COUNTS]
    assert reply["total_docs"] == 2  # the two green indices, one document each
    assert {a: i["docs"] for a, i in reply["artifacts"].items()} == {"evtx": 1, "delim": 1}
    assert reply["hosts"] == ["WKS1"]  # the other parts still answer


def test_an_all_green_case_reads_as_before(run, monkeypatch):  # noqa: F811
    reply = summary(run, monkeypatch, cluster("1"))
    assert "partial" not in reply
    assert not [w for w in reply.get("warnings", []) if w.startswith("Document counts")]
    assert reply["total_docs"] == 3
    assert {a: i["docs"] for a, i in reply["artifacts"].items()} == {
        "evtx": 1, "delim": 1, "shimcache": 1
    }  # fmt: skip


def test_a_red_index_whose_last_ingest_failed_keeps_its_warning(case, monkeypatch):  # noqa: F811
    registry = f"case-{faw.CID}-registry-dev01"
    monkeypatch.setitem(faw.INDICES, registry, None)  # its row reads "docs.count": "None"
    resp = faw.server.idx_case_summary(case_id=faw.CID)
    assert faw.incomplete() == [
        f"{registry} (document count unknown) may be incomplete: the most recent"
        " ingest of registry on dev01 failed (FAILED: line contains NUL)"
    ]
    assert f"Document counts: partial; failing indices: {registry}; " in " ".join(resp["warnings"])
    assert resp["total_docs"] == 1694 + 252626
