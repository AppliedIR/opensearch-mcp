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


# --- a per-host count only some shards gave is unknown, not a count -------------

import test_summary_reads_the_cases_own_audit as own  # noqa: E402
from test_summary_reads_the_cases_own_audit import root  # noqa: E402, F401 (a fixture)

NONE_ANSWERED = {"total": 1, "successful": 0, "skipped": 0, "failed": 1}
ALL_ANSWERED = {"total": 1, "successful": 1, "skipped": 0, "failed": 0}


@pytest.mark.parametrize(
    "index_count,shards,count,shown",
    [
        (None, NONE_ANSWERED, 0, "document count unknown"),  # the red index codex measured
        ("1000", NONE_ANSWERED, 0, "document count unknown"),
        ("1000", {**ALL_ANSWERED, "total": 2, "failed": 1}, 400, "document count unknown"),
        (None, ALL_ANSWERED, 0, "0 docs from host1"),  # every shard answered: a real 0
        ("1000", ALL_ANSWERED, 1000, "1,000 docs from host1"),  # control
    ],
    ids=["red-none-answered", "green-none-answered", "half-answered", "whole-0", "whole"],
)
def test_a_per_host_count_some_shards_didnt_give_is_unknown(
    root,  # noqa: F811
    monkeypatch,
    index_count,
    shards,
    count,
    shown,
):
    class Client(own._Client):
        class cat:
            @staticmethod
            def indices(index, format="json", **kw):
                return [{"index": index.removesuffix("*") + "registry-0",
                         "docs.count": index_count}]  # fmt: skip

        def count(self, index, body):
            if "host.name" in str(body):
                return {"count": count, "_shards": dict(shards)}
            return {"count": 0}

    monkeypatch.setattr(faw.server, "_get_os", lambda: Client())
    own.activate(root, "a")
    (warning,) = own.incomplete("a")
    assert warning == own._warning("a").replace("1,000 docs from host1", shown)
