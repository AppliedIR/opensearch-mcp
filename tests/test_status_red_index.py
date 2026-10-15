"""idx_status and idx_shard_status keep answering on a red index.

`_cat/indices` gives a red index's `docs.count` as null (measured on
OpenSearch 3.5.0). idx_status raised on `int(None)`; idx_shard_status showed
the index as 0 documents (`or 0`) and raised on a count that isn't a number.
Now both show its count as unknown (None), never 0, keep every other index,
and name it in a partial warning.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from opensearch_mcp import server as srv

GREEN, RED = "case-acac00000001-evtx-0", "case-acac00000001-shimcache-0"


def warning(*names: str) -> str:
    return (f"Document counts: partial; failing indices: {', '.join(names)}; "
            "their counts are unknown")  # fmt: skip


class Cluster:
    """`_cat/indices` with GREEN at 1000 documents and RED at `red_count`."""

    def __init__(self, red_count):
        self.rows = [
            {"index": GREEN, "docs.count": "1000", "store.size": "5mb", "status": "open",
             "health": "green", "pri": "1", "rep": "0"},
            {"index": RED, "docs.count": red_count, "store.size": None, "status": "open",
             "health": "red", "pri": "1", "rep": "0"},
        ]  # fmt: skip
        self.cat = SimpleNamespace(indices=lambda **kw: [dict(r) for r in self.rows])
        self.cluster = SimpleNamespace(
            health=lambda **kw: {"status": "red", "number_of_nodes": 1},
            stats=lambda **kw: {"indices": {"shards": {"total": 2}},
                                "nodes": {"count": {"data": 1}}},
            get_settings=lambda **kw: {"persistent": {"cluster.max_shards_per_node": "1000"}},
        )  # fmt: skip


@pytest.fixture
def use(monkeypatch):
    monkeypatch.setattr(srv.audit, "log", lambda **kw: "aid-1")

    def go(cluster):
        monkeypatch.setattr(srv, "_get_os", lambda: cluster)

    return go


COUNTS = pytest.mark.parametrize(
    "count", [None, "", "n/a", "1.5"], ids=["null", "empty", "text", "fraction"]
)


@COUNTS
def test_idx_status_shows_a_red_index_as_unknown_and_names_it(use, count):
    use(Cluster(count))
    resp = srv.idx_status()
    assert {i["index"]: i["docs"] for i in resp["indices"]} == {GREEN: 1000, RED: None}
    assert resp["total_indices"] == 2
    assert resp["partial"] is True
    assert resp["warnings"] == [warning(RED)]


@COUNTS
def test_idx_shard_status_shows_a_red_index_as_unknown_not_0(use, count):
    use(Cluster(count))
    resp = srv.idx_shard_status()
    top = {i["index"]: i["doc_count"] for i in resp["top_indices_by_shard_count"]}
    assert top == {GREEN: 1000, RED: None}
    assert resp["partial"] is True
    assert resp["warnings"] == [warning(RED)]
    assert (resp["current_shards"], resp["status"]) == (2, "ok")


@pytest.mark.parametrize("tool", ["idx_status", "idx_shard_status"])
def test_an_all_green_cluster_reads_as_before(use, tool):
    use(Cluster("7"))
    resp = getattr(srv, tool)()
    rows = resp.get("indices") or resp["top_indices_by_shard_count"]
    assert sorted(r.get("docs", r.get("doc_count")) for r in rows) == [7, 1000]
    assert "partial" not in resp and "warnings" not in resp


def test_the_warning_names_five_indices_and_counts_the_rest(use):
    cluster = Cluster(None)
    reds = [f"case-acac00000001-r{i}-0" for i in "abcdef"]
    cluster.rows += [dict(cluster.rows[1], index=n) for n in reds]
    use(cluster)
    names = sorted([RED, *reds])
    assert srv.idx_status()["warnings"] == [
        f"Document counts: partial; failing indices: {', '.join(names[:5])} and 2 more; "
        "their counts are unknown"
    ]
