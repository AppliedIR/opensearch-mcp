"""Each investigation hint is shown once per case, when its artifact appears.

The hints were gated by one process-wide flag, so after the first
idx_case_summary every call, in any case, got only the pointer: a type indexed
after the first summary, or a second case, never got its hint. Rows run through
idx_case_summary with a fake client and assert opening words or exact lists;
the pointer itself names MFT and evtx, so a substring would match it.
"""

import pytest

from opensearch_mcp import server

POINTER = ["MFT/USN/evtx indexed — call suggest_tools for investigation patterns"]
INDICES: dict[str, list[tuple[str, int]]] = {}  # case -> [(index, docs)]


class _Cat:
    def indices(self, index, format="json", **kw):
        case = index.removeprefix("case-").removesuffix("-*")
        return [{"index": n, "docs.count": str(d)} for n, d in INDICES.get(case, [])]


class _Client:
    cat = _Cat()

    def search(self, index, body):
        if "hosts" in body.get("aggs", {}):
            return {"aggregations": {"hosts": {"buckets": [{"key": "host1"}]}}}
        return {"aggregations": {"min_ts": {}, "max_ts": {}}}

    def count(self, index, body):
        return {"count": 0}


@pytest.fixture(autouse=True)
def fake_os(monkeypatch):
    INDICES.clear()
    monkeypatch.setattr(server, "_get_os", lambda: _Client())


def hints(case):
    return server.idx_case_summary(case_id=case).get("investigation_hints")


def heads(case):
    return [h.split(".")[0] for h in hints(case)]


def test_a_type_indexed_after_the_first_summary_gets_its_hint():
    INDICES["a"] = [("case-a-evtx-host1", 5000)]
    assert heads("a") == ["EVTX indexed"]
    INDICES["a"].append(("case-a-mft-host1", 90000))
    assert heads("a") == ["MFT indexed"]


def test_a_second_case_in_the_same_process_gets_its_hints():
    INDICES["a"] = [("case-a-evtx-host1", 5000)]
    INDICES["b"] = [("case-b-evtx-host1", 300)]
    assert heads("a") == ["EVTX indexed"]
    assert heads("b") == ["EVTX indexed"]


def test_anchor_nothing_new_gets_the_pointer_only():
    INDICES["a"] = [("case-a-evtx-host1", 5000)]
    assert heads("a") == ["EVTX indexed"]
    assert hints("a") == POINTER


def test_anchor_after_a_reset_hints_come_as_on_a_first_call():
    INDICES["a"] = [("case-a-evtx-host1", 5000)]
    INDICES["c"] = [("case-c-json-host1", 10)]
    assert heads("a") == ["EVTX indexed"]
    server.reset_enrichment_state()  # stands in for a new process
    assert hints("c") is None  # no hint artifact: no key, as today
    assert heads("a") == ["EVTX indexed"]


def test_a_hint_the_budget_dropped_comes_on_the_next_summary():
    INDICES["a"] = [
        ("case-a-mft-host1", 300000),
        ("case-a-usn-host1", 900000),
        ("case-a-evtx-host1", 50000),
    ]
    assert heads("a") == ["USN Journal indexed"]  # the 500-character cap drops two
    assert heads("a") == ["MFT indexed", "EVTX indexed"]
    assert hints("a") == POINTER
