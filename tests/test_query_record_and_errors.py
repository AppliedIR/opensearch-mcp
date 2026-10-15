"""What a query records, and what its errors say.

- A query that names another case (`case_id`) is recorded in the case its
  entry is written to, with `params.queried_case`; one naming the case it is
  recorded in carries none. With no case active nothing is recorded, and the
  reply says so.
- A page past the last result isn't told its query found nothing.
- A shard failure with no index (a node's) is never named "None".
- A query whose every shard failed names the cause and the index.

The audit writer is real; OpenSearch is query-shards' stand-in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from opensearchpy.exceptions import RequestError
from test_partial_shard_answers import Cluster, tools

from opensearch_mcp import server as srv

UUID = {"alpha": "a1a10000-0001-4000-8000-000000000000",
        "bravo": "b2b20000-0002-4000-8000-000000000000"}  # fmt: skip
BRAVO = "case-b2b200000002-evtx-0"
OK = {"total": 2, "successful": 2, "skipped": 0, "failed": 0}
NOT_RECORDED = "not recorded: no active case, or the audit write failed"
TOOLS = {t: {k: v for k, v in kw.items() if k != "index"} for t, kw in tools().items()}


@pytest.fixture
def cases(tmp_path, monkeypatch):
    """Cases alpha and bravo; `activate(name)` makes one active ("" for none)."""
    root = tmp_path / "cases"
    for name, u in UUID.items():
        (root / name / "audit").mkdir(parents=True)
        (root / name / "CASE.yaml").write_text(
            f"case_id: {name}\ncase_uuid: {u}\nnaming_version: 2\n"
        )
    monkeypatch.setenv("VHIR_CASES_DIR", str(root))
    pointer = Path.home() / ".vhir" / "active_case"
    pointer.parent.mkdir(exist_ok=True)

    def activate(name):
        if name:
            pointer.write_text(str(root / name))
        else:
            pointer.unlink(missing_ok=True)

    yield root, activate
    pointer.unlink(missing_ok=True)


def entries(case: Path) -> list[dict]:
    return [json.loads(line) for f in sorted((case / "audit").glob("*.jsonl"))
            for line in f.read_text().splitlines()]  # fmt: skip


def ask(monkeypatch, tool, cluster=None, **kw):
    monkeypatch.setattr(srv, "_get_os", lambda: cluster or Cluster(OK, total=1, indices=[BRAVO]))
    return getattr(srv, tool)(**{**TOOLS[tool], **kw})


@pytest.mark.parametrize("tool", list(TOOLS))
def test_a_query_of_another_case_says_which_case_it_read(cases, monkeypatch, tool):
    root, activate = cases
    activate("alpha")
    reply = ask(monkeypatch, tool, case_id="bravo")
    (entry,) = [e for e in entries(root / "alpha") if e["audit_id"] == reply["audit_id"]]
    assert entry["case_id"] == "alpha" and entry["params"]["queried_case"] == "bravo"
    assert entries(root / "bravo") == []


@pytest.mark.parametrize("named", ["alpha", ""], ids=["named", "default"])
@pytest.mark.parametrize("tool", list(TOOLS))
def test_a_query_of_the_case_it_is_recorded_in_carries_no_queried_case(
    cases, monkeypatch, tool, named
):
    root, activate = cases
    activate("alpha")
    alpha = Cluster(OK, total=1, indices=["case-a1a100000001-evtx-0"])
    reply = ask(monkeypatch, tool, cluster=alpha, case_id=named)
    (entry,) = [e for e in entries(root / "alpha") if e["audit_id"] == reply["audit_id"]]
    assert "queried_case" not in entry["params"]


@pytest.mark.parametrize("tool", list(TOOLS))
def test_with_no_case_active_the_reply_says_the_query_wasnt_recorded(cases, monkeypatch, tool):
    root, activate = cases
    activate("")
    reply = ask(monkeypatch, tool, case_id="bravo")
    assert reply.get("audit") == NOT_RECORDED and not reply.get("audit_id")
    assert entries(root / "alpha") == entries(root / "bravo") == []  # none written anywhere


@pytest.mark.parametrize("offset", [5, 10])
def test_a_page_past_the_last_result_isnt_told_it_found_nothing(monkeypatch, offset):
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster(OK, total=5))
    reply = srv.idx_search(query="*", index=BRAVO, limit=2, offset=offset)
    assert (reply["total"], reply["returned"]) == (5, 0)
    assert "No results" not in str(reply)


def test_a_query_that_found_nothing_still_gets_the_hint(monkeypatch):
    monkeypatch.setattr(srv, "_get_os", lambda: Cluster(OK, total=0))
    reply = srv.idx_search(query="svchost", index=BRAVO)
    assert reply["hint"].startswith("No results.")


NODE_FAILURE = {"total": 2, "successful": 1, "skipped": 0, "failed": 1,
                "failures": [{"shard": -1, "index": None, "node": "n1",
                              "reason": {"type": "node_disconnected_exception",
                                         "reason": "node left"}}]}  # fmt: skip


@pytest.mark.parametrize("tool", list(TOOLS))
def test_a_failure_with_no_index_isnt_named_none(monkeypatch, tool):
    cluster = Cluster(NODE_FAILURE, total=1, buckets=[("x", 1)])
    reply = ask(monkeypatch, tool, cluster=cluster, index=BRAVO)
    assert reply["partial"] is True and "node left" in reply["partial_warning"]
    assert "None" not in reply["failed_indices"] and "None" not in reply["partial_warning"]


def test_a_red_index_beside_a_good_one_is_still_said_as_before(monkeypatch):
    red = {"total": 2, "successful": 1, "skipped": 0, "failed": 0}
    reply = ask(monkeypatch, "idx_search", cluster=Cluster(red, total=5), index=BRAVO)
    assert reply["partial_warning"] == (
        "Incomplete answer: 1 of 2 shard(s) unavailable. Totals, counts and buckets are a lower "
        "bound: they cover only the shards that answered, and 0 is not 'no match'."
    )


CAUSE = (
    "failed to create query: field expansion for [*] matches too many fields, "
    "limit: 1024, got: 2200"
)
ALL_FAILED = {  # OpenSearch 3.5.0's 400, measured on an index over 1,024 fields
    "error": {
        "root_cause": [{"type": "query_shard_exception", "reason": CAUSE, "index": BRAVO,
                        "index_uuid": "j32MkARiSgaT-n3Jtjngbg"}],
        "type": "search_phase_execution_exception", "reason": "all shards failed",
        "phase": "query", "grouped": True,
        "failed_shards": [{"shard": 0, "index": BRAVO, "node": "n1", "reason": {
            "type": "query_shard_exception", "reason": CAUSE, "index": BRAVO}}],
    },
    "status": 400,
}  # fmt: skip


class AllShardsFailed(Cluster):
    def search(self, index=None, body=None, **kw):
        raise RequestError(400, "search_phase_execution_exception", ALL_FAILED)

    count = search


@pytest.mark.parametrize("tool", ["idx_search", "idx_count"])
def test_all_shards_failed_names_the_cause_and_the_index(monkeypatch, tool):
    with pytest.raises(ValueError) as e:
        ask(monkeypatch, tool, cluster=AllShardsFailed(OK), index=BRAVO)
    assert str(e.value) == f"Query error: all shards failed: {CAUSE} ({BRAVO})"


# --- every shard failed on a field that is text: the failed index and its repair ---

OLD = "case-5804970a586d-json-events-0"  # an index made before its template (0.6.4)
TEXT_REASON = (
    "Text fields are not optimised for operations that require per-document field data "
    "like aggregations and sorting, so these operations are disabled by default. Please "
    "use a keyword field instead. Alternatively, set fielddata=true on [{f}] in order to "
    "load field data by uninverting the inverted index. Note that this can use "
    "significant memory."
)


def text_failed(*entries):
    """OpenSearch 3.5.0's 400 when every shard fails on a text field, measured on
    a 0.6.4 index (idx_count's ingest aggregation): root_cause names no index;
    each failed_shards entry has its index and its own reason. `entries`:
    (index, field) pairs, or raw failed_shards entries."""
    shards = [e if not isinstance(e, tuple) else {
        "shard": 0, "index": e[0], "node": "ukUDTAaDTPqq2rlmO-Wb1g",
        "reason": {"type": "illegal_argument_exception", "reason": TEXT_REASON.format(f=e[1])},
    } for e in entries]  # fmt: skip
    first = TEXT_REASON.format(f=entries[0][1] if isinstance(entries[0], tuple) else "x")
    cause = {"type": "illegal_argument_exception", "reason": first}
    return {"error": {"root_cause": [cause], "type": "search_phase_execution_exception",
                      "reason": "all shards failed", "phase": "query", "grouped": True,
                      "failed_shards": shards, "caused_by": {**cause, "caused_by": cause}},
            "status": 400}  # fmt: skip


class Refused(Cluster):
    def __init__(self, info):
        super().__init__(OK)
        self.info = info

    def search(self, index=None, body=None, **kw):
        raise RequestError(400, "search_phase_execution_exception", self.info)

    count = search


def refused(monkeypatch, tool, info):
    with pytest.raises(ValueError) as e:
        ask(monkeypatch, tool, cluster=Refused(info), index=OLD)
    return str(e.value)


AS_BEFORE = f"Query error: all shards failed: {TEXT_REASON.format(f='vhir.ingest_audit_id')}"


@pytest.mark.parametrize("tool", sorted(TOOLS))
def test_every_shard_failing_on_a_vhir_field_names_the_index_and_its_repair(monkeypatch, tool):
    got = refused(monkeypatch, tool, text_failed((OLD, "vhir.ingest_audit_id")))
    assert got == (
        f"{AS_BEFORE} ({OLD}; vhir.ingest_audit_id is text there: the index was made "
        "without its template, delete the index and re-ingest it)"
    )


def test_every_shard_failing_on_another_field_names_its_keyword_hint(monkeypatch):
    got = refused(monkeypatch, "idx_aggregate", text_failed((OLD, "Path")))
    assert got.endswith(
        f" ({OLD}; Path is text there: aggregate on a keyword form of Path "
        f"with index={OLD}, if that index has one)"
    )


def test_each_failed_index_is_named_with_its_own_repair_once(monkeypatch):
    other = "case-5804970a586d-delim-events-0"
    entries = [(OLD, "vhir.ingest_audit_id"), (other, "Path"), (OLD, "vhir.ingest_audit_id")]
    got = refused(monkeypatch, "idx_count", text_failed(*entries))
    assert got.endswith(
        f" ({OLD}; vhir.ingest_audit_id is text there: the index was made without its "
        f"template, delete the index and re-ingest it; {other}; Path is text there: "
        f"aggregate on a keyword form of Path with index={other}, if that index has one)"
    )


def test_more_than_five_failed_indices_are_counted_past_the_fifth(monkeypatch):
    names = [f"case-5804970a586d-json-{n}-0" for n in range(7)]
    got = refused(monkeypatch, "idx_count",
                  text_failed(*[(n, "vhir.ingest_audit_id") for n in names]))  # fmt: skip
    assert all(n in got for n in names[:5]) and names[5] not in got
    assert got.endswith("re-ingest it; and 2 more indices)")


@pytest.mark.parametrize("bad", [
    "not a list", ["not an entry"], [{"index": 7, "reason": {"reason": "fielddata=true on [x]"}}],
    [{"index": OLD, "reason": "fielddata=true on [x]"}], [{"index": OLD}], [{"reason": {}}],
])  # fmt: skip
def test_a_malformed_failed_shards_entry_leaves_the_error_as_it_was(monkeypatch, bad):
    info = text_failed((OLD, "vhir.ingest_audit_id"))
    info["error"]["failed_shards"] = bad
    assert refused(monkeypatch, "idx_count", info) == AS_BEFORE


def test_a_failure_with_no_repair_leaves_the_error_as_it_was(monkeypatch):
    """Every shard failed, for a reason no field repair answers."""
    got = refused(monkeypatch, "idx_count", ALL_FAILED)
    assert got == f"Query error: all shards failed: {CAUSE} ({BRAVO})"
