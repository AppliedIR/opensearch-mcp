"""A query answered by only some shards says so.

OpenSearch answers HTTP 200 when only some shards answer, with hits, totals
and buckets from those shards only. The five query tools and the case summary
read `_shards` and `timed_out`: a partial answer keeps every number and bucket
it has, is flagged `partial`, and names each failed index with its reason and
what repairs it; it never says "No results.". The investigation hints read
only this case.

The cluster is a stand-in that answers with the `_shards` shapes measured on
OpenSearch 3.5.0: a field expansion over too many fields failing 4 of 5
shards, an aggregation on a text field failing one index, a timeout, an
unavailable (red) index, and skipped shards.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from opensearch_mcp import server as srv

EVTX, SHIM, DELIM, CLI = (
    f"case-acac00000001-{t}-0" for t in ("evtx", "shimcache", "delim", "cli")
)
EXPANSION = ("failed to create query: field expansion for [*] matches too many fields, "
             "limit: 1024, got: 3346")  # fmt: skip
TEXT_AGG = ("Text fields are not optimised for operations that require per-document field "
            "data like aggregations and sorting, so these operations are disabled by default. "
            "Please use a keyword field instead. Alternatively, set fielddata=true on [{f}] in "
            "order to load field data by uninverting the inverted index. Note that this can "
            "however use significant memory.")  # fmt: skip


def failures(index, reason, kind="query_shard_exception"):
    """One grouped entry, as OpenSearch reports it: per index and reason."""
    return [{"shard": 0, "index": index, "node": "n1",
             "reason": {"type": kind, "reason": reason}}]  # fmt: skip


class Cluster:
    """Every search and count answers with `shards` (and `timed_out`), `total`
    hits and these `buckets`; `counts` maps a count query's field to its count."""

    def __init__(self, shards, total=0, buckets=(), timed_out=False, counts=None, indices=(),
                 count_shards=None):  # fmt: skip
        self.shards, self.total, self.buckets = shards, total, list(buckets)
        self.count_shards = count_shards or {}  # a count query's field -> its own _shards
        self.timed_out, self.counts = timed_out, counts or {}
        self.cat = SimpleNamespace(indices=self._cat)
        self.rows = [{"index": i, "docs.count": "1", "health": "green"} for i in indices]
        self.indices = SimpleNamespace(get_mapping=lambda **k: {})

    def _reply(self):
        return {"took": 1, "timed_out": self.timed_out, "_shards": copy.deepcopy(self.shards)}

    def _cat(self, index=None, **kw):
        return list(self.rows)

    def field_caps(self, **kw):
        return {"fields": {}}

    def search(self, index=None, body=None, **kw):
        aggs = {}
        for name, spec in ((body or {}).get("aggs") or {}).items():
            if name in ("min_ts", "max_ts"):
                aggs[name] = {"value_as_string": "2026-01-01T00:00:00.000Z"}
            elif "missing" in spec:
                aggs[name] = {"doc_count": 0}
            elif name in ("result_ingests", "by_index"):
                aggs[name] = {"buckets": []}
            else:
                aggs[name] = {"sum_other_doc_count": 0, "buckets": [
                    {"key": k, "key_as_string": k, "doc_count": n,
                     "names": {"buckets": [{"key": k, "doc_count": n}]}}
                    for k, n in self.buckets]}  # fmt: skip
        hits = {"total": {"value": self.total, "relation": "eq"}, "hits": []}
        return {**self._reply(), "hits": hits, "aggregations": aggs}

    def count(self, index=None, body=None, **kw):
        query = (body or {}).get("query") or {}
        field = (query.get("exists") or {}).get("field") or next(iter(query.get("term", {})), "")
        reply = {**self._reply(), "count": self.counts.get(field, 0)}
        if field in self.count_shards:
            reply["_shards"] = copy.deepcopy(self.count_shards[field])
        return reply


@pytest.fixture
def run(tmp_path, monkeypatch):
    """`run(cluster, tool, **kw)`: the tool's reply against `cluster`, with no
    case active unless `case` names one."""
    audited = []
    monkeypatch.setattr(srv.audit, "log", lambda **kw: audited.append(kw) or "aid-1")
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    (tmp_path / "cases" / "acme").mkdir(parents=True)
    (tmp_path / "cases" / "acme" / "CASE.yaml").write_text(
        "case_id: acme\ncase_uuid: acac0000-0001-4000-8000-000000000000\nnaming_version: 2\n"
    )

    def go(cluster, tool, case="", **kw):
        monkeypatch.setattr(srv, "_get_os", lambda: cluster)
        monkeypatch.setattr(srv, "_get_active_case", lambda: case or None)
        return getattr(srv, tool)(**kw)

    return go


def tools(query="*mimikatz*", index=f"{EVTX},{DELIM}", field="host.id"):
    """The five query tools over `index`."""
    return {
        "idx_search": {"query": query, "index": index},
        "idx_count": {"query": query, "index": index},
        "idx_aggregate": {"field": field, "query": query, "index": index},
        "idx_timeline": {"query": query, "index": index},
        "idx_field_values": {"field": field, "query": query, "index": index},
    }


LOW = "Totals, counts and buckets are a lower bound"
MOST_FAILED = {
    "total": 5,
    "successful": 1,
    "skipped": 0,
    "failed": 4,
    "failures": failures(EVTX, EXPANSION),
}


@pytest.mark.parametrize("tool", sorted(tools()))
def test_a_field_expansion_failing_most_shards_is_a_partial_answer(run, tool):
    reply = run(Cluster(MOST_FAILED), tool, **tools()[tool])
    assert reply["partial"] is True
    assert reply["shards"] == {"total": 5, "failed": 4}
    assert reply["failed_indices"] == [EVTX]
    warning = reply["partial_warning"]
    assert "4 of 5 shard(s) failed in" in warning and EVTX in warning
    assert "field expansion for [*] matches too many fields" in warning and LOW in warning
    assert "No results" not in str(reply)
    assert reply.get("total", reply.get("count", reply.get("total_docs", 0))) == 0


ONE_TEXT_INDEX = {"total": 4, "successful": 3, "skipped": 0, "failed": 1,
      "failures": failures(SHIM, TEXT_AGG.format(f="Path"),
                           "illegal_argument_exception")}  # fmt: skip


@pytest.mark.parametrize("tool", ["idx_aggregate", "idx_field_values"])
def test_an_aggregation_on_a_text_field_in_one_index_keeps_the_other_buckets(run, tool):
    buckets = [("d0", 1), ("d1", 1), ("d2", 1)]
    reply = run(Cluster(ONE_TEXT_INDEX, total=9, buckets=buckets), tool, field="Path",
                index=f"{SHIM},{DELIM}")  # fmt: skip
    assert (reply["partial"], reply["shards"], reply["failed_indices"]) == (
        True, {"total": 4, "failed": 1}, [SHIM])  # fmt: skip
    warning = reply["partial_warning"]
    assert "Text fields are not optimised" in warning and LOW in warning
    assert (
        "Path is text there: aggregate on a keyword form of Path if the index has one" in warning
    )
    assert "256" not in warning
    kept = reply.get("buckets") or reply.get("values")
    assert [(b.get("key", b.get("value")), b["count"]) for b in kept] == buckets
    if tool == "idx_aggregate":
        assert reply["total_docs"] == 9


CLI_TEXT = {"total": 2, "successful": 1, "skipped": 0, "failed": 1,
            "failures": failures(CLI, TEXT_AGG.format(f="vhir.ingest_audit_id"),
                                 "illegal_argument_exception")}  # fmt: skip


@pytest.mark.parametrize("tool", ["idx_count", "idx_aggregate"])
def test_an_index_made_without_its_template_names_its_repair(run, tool):
    reply = run(Cluster(CLI_TEXT, total=1, buckets=[("WKS1", 1)]), tool, case="acme",
                **{k: v for k, v in tools("*", f"{CLI},{DELIM}")[tool].items()})  # fmt: skip
    assert reply["failed_indices"] == [CLI]
    assert ("made without its template, repair it with opensearch-ingest repair-index "
            "--case acme") in reply["partial_warning"]  # fmt: skip
    if tool == "idx_count":
        assert reply["count"] == 1
    else:
        assert [(b["key"], b["count"]) for b in reply["buckets"]] == [("WKS1", 1)]


def test_a_search_that_timed_out_is_partial(run):
    shards = {"total": 3, "successful": 3, "skipped": 0, "failed": 0}
    reply = run(Cluster(shards, total=1, timed_out=True), "idx_count", query="*", index=DELIM)
    assert (reply["partial"], reply["timed_out"], reply["shards"], reply["count"]) == (
        True, True, {"total": 3, "failed": 0}, 1)  # fmt: skip
    assert "the search timed out" in reply["partial_warning"]


@pytest.mark.parametrize("tool", ["idx_count", "idx_aggregate"])
def test_an_unavailable_index_is_partial(run, tool):
    """A red index's shards are neither successful nor failed, with no
    failures entry."""
    shards = {"total": 2, "successful": 1, "skipped": 0, "failed": 0}
    reply = run(Cluster(shards, total=1, buckets=[("WKS1", 1)]), tool,
                **tools("*", f"{EVTX},{DELIM}")[tool])  # fmt: skip
    assert reply["shards"] == {"total": 2, "failed": 0, "unavailable": 1}
    assert "1 of 2 shard(s) unavailable" in reply["partial_warning"]
    assert reply.get("count", 1) == 1
    if tool == "idx_aggregate":
        assert [(b["key"], b["count"]) for b in reply["buckets"]] == [("WKS1", 1)]


def test_the_warning_names_at_most_five_indices(run):
    many = [{"shard": 0, "index": f"case-acac00000001-t{i}-0", "node": "n1",
             "reason": {"type": "x", "reason": f"bad {i}. More."}} for i in range(7)]  # fmt: skip
    shards = {"total": 8, "successful": 1, "skipped": 0, "failed": 7, "failures": many}
    reply = run(Cluster(shards), "idx_count", query="*", index=DELIM)
    assert len(reply["failed_indices"]) == 7
    assert "and 2 more indices" in reply["partial_warning"]
    assert "t5" not in reply["partial_warning"] and "bad 4" in reply["partial_warning"]


# --- the case summary ---------------------------------------------------------


def test_the_case_summary_says_which_parts_are_partial(run, monkeypatch):
    from opensearch_mcp import case_scope

    # its indices, as a case with an identity names them
    monkeypatch.setattr(case_scope, "case_read_scope", lambda *a, **k: "case-acac00000001-*")
    counts = {"triage.checked": 1, "triage.verdict": 1}
    cluster = Cluster(
        MOST_FAILED, buckets=[("WKS1", 3)], counts=counts, indices=[EVTX, DELIM, SHIM]
    )
    reply = run(cluster, "idx_case_summary", case="acme")
    assert reply["partial"] is True
    parts = sorted(w.split(":")[0] for w in reply["warnings"])
    assert parts == ["Host detection", "Intel stats", "Time range", "Triage stats"]
    # the intel part's four counts fail alike: said once
    assert all(w.count(EVTX) == 1 for w in reply["warnings"])
    (time_range,) = [w for w in reply["warnings"] if w.startswith("Time range")]
    assert "may be narrower" in time_range and "lower bound" not in time_range
    assert sorted(reply["hosts"]) == ["WKS1"] and reply["total_docs"] == 3
    assert reply["enrichment"]["triage"]["checked"] == 1
    assert reply["enrichment"]["triage"]["suspicious"] == 1


# --- controls: a complete answer is as it was ---------------------------------

WHOLE = {"total": 2, "successful": 2, "skipped": 0, "failed": 0}


@pytest.mark.parametrize("tool", sorted(tools()))
def test_an_answer_every_shard_gave_is_not_flagged(run, tool):
    reply = run(Cluster(WHOLE, total=2, buckets=[("WKS1", 2)]), tool,
                **tools("event.code:4624")[tool])  # fmt: skip
    assert not {"partial", "shards", "failed_indices", "partial_warning"} & set(reply)


def test_skipped_shards_answered(run):
    """A shard the cluster skipped (it can't match) counts as successful."""
    shards = {"total": 3, "successful": 3, "skipped": 2, "failed": 0}
    reply = run(Cluster(shards, total=2), "idx_count", query="*", index=DELIM)
    assert {k: v for k, v in reply.items() if k != "audit_id"} == {"count": 2}


def test_a_complete_search_with_no_match_still_says_no_results(run):
    reply = run(Cluster(WHOLE), "idx_search", query="nothing", index=DELIM)
    assert reply["hint"].startswith("No results.") and "partial" not in reply


# --- the hints read only this case --------------------------------------------

USN = ("Cross-host: idx_aggregate(field='host.id', query='(Name:<file>) AND "
       "_exists_:UpdateReasons'); omit index, and pass case_id unless this case is "
       "active")  # fmt: skip
EVTXECMD = ("Prefer native evtx when available — proper ECS fields. For native evtx records "
            "only, query (<your query>) AND _exists_:winlog.channel; omit index, and pass "
            "case_id unless this case is active.")  # fmt: skip
POINTER = ("Mixed evtx/EvtxECmd indices — query (<your query>) AND _exists_:winlog.channel for "
           "ECS fields, or (<your query>) AND _exists_:EventId for CSV fields; omit index, and "
           "pass case_id unless this case is active.")  # fmt: skip


def test_the_hints_name_no_index_pattern(monkeypatch):
    resp: dict = {}
    srv._add_investigation_hints(resp, {"usn": {}}, "acme")
    usn = [h for h in resp.get("investigation_hints", []) if "Cross-host" in h]
    assert len(usn) == 1 and usn[0].endswith(USN)
    names = {"case-acac00000001-evtx-0", "case-acac00000001-delim-evtxecmd_x-0"}
    monkeypatch.setattr(srv, "_get_case_indices", lambda pattern, client: names)
    monkeypatch.setattr(srv, "_field_hint_delivered", False)
    first, again = {}, {}
    srv._add_field_hint(first, "case-acac00000001-*", None)
    srv._add_field_hint(again, "case-acac00000001-*", None)
    assert first["field_hint"].endswith(EVTXECMD) and again["field_hint"] == POINTER
    assert "case-*" not in str([usn, first, again])


def test_a_text_field_with_no_keyword_form_gets_the_neutral_repair(run):
    """The evtx template maps ScriptBlockText as text with no .keyword."""
    field = "winlog.event_data.ScriptBlockText"
    shards = {"total": 2, "successful": 1, "skipped": 0, "failed": 1,
              "failures": failures(EVTX, TEXT_AGG.format(f=field),
                                   "illegal_argument_exception")}  # fmt: skip
    reply = run(Cluster(shards, total=1, buckets=[("x", 1)]), "idx_aggregate", field=field,
                index=f"{EVTX},{DELIM}")  # fmt: skip
    warning = reply["partial_warning"]
    assert (
        f"{field} is text there: aggregate on a keyword form of {field} if the index has one"
        in warning
    )
    assert f"{field}.keyword" not in warning and "256" not in warning


def test_two_failing_indices_in_one_summary_part_are_both_named(run, monkeypatch):
    from opensearch_mcp import case_scope

    monkeypatch.setattr(case_scope, "case_read_scope", lambda *a, **k: "case-acac00000001-*")
    one = {"total": 3, "successful": 2, "skipped": 0, "failed": 1,
           "failures": failures(EVTX, "first failure")}  # fmt: skip
    other = {"total": 3, "successful": 2, "skipped": 0, "failed": 1,
             "failures": failures(SHIM, "second failure")}  # fmt: skip
    cluster = Cluster(WHOLE, buckets=[("WKS1", 3)], indices=[EVTX, DELIM, SHIM],
                      counts={"triage.checked": 1, "triage.verdict": 1},
                      count_shards={"triage.checked": one, "triage.verdict": other})  # fmt: skip
    reply = run(cluster, "idx_case_summary", case="acme")
    (triage,) = [w for w in reply["warnings"] if w.startswith("Triage stats")]
    assert EVTX in triage and SHIM in triage
    assert "first failure" in triage and "second failure" in triage


def test_each_reply_of_a_summary_part_keeps_its_own_numbers(run, monkeypatch):
    """No arithmetic across replies: (3 shards, 1 failed, 2 unavailable) and
    (3 shards, 1 failed) are each said with their own numbers."""
    from opensearch_mcp import case_scope

    monkeypatch.setattr(case_scope, "case_read_scope", lambda *a, **k: "case-acac00000001-*")
    first = {"total": 3, "successful": 0, "skipped": 0, "failed": 1,
             "failures": failures(EVTX, "first failure")}  # fmt: skip
    second = {"total": 3, "successful": 2, "skipped": 0, "failed": 1,
              "failures": failures(SHIM, "second failure")}  # fmt: skip
    cluster = Cluster(WHOLE, buckets=[("WKS1", 3)], indices=[EVTX, DELIM, SHIM],
                      counts={"triage.checked": 1, "triage.verdict": 1},
                      count_shards={"triage.checked": first,
                                    "triage.verdict": second})  # fmt: skip
    reply = run(cluster, "idx_case_summary", case="acme")
    (triage,) = [w for w in reply["warnings"] if w.startswith("Triage stats")]
    assert f"1 of 3 shard(s) failed in {EVTX}: first failure" in triage
    assert "2 of 3 shard(s) unavailable" in triage
    assert f"1 of 3 shard(s) failed in {SHIM}: second failure" in triage
