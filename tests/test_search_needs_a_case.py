"""The search tools search one case, never every case by default.

With no index, no case_id and no active case, idx_search, idx_count,
idx_aggregate, idx_timeline and idx_field_values used to fall back to `case-*`
and answer from every case on the cluster. They now refuse, as the case
summary and enrichment already did. An explicit index (even `case-*`) is
searched as given; a case_id names its indices from its case folder, and is
refused, saying why, when this box has no folder for it. The Hayabusa alerts
are an implicit fallback, so there are none to name with no case. The client
is a mock that records what was asked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import opensearch_mcp.server as srv

REFUSAL = {"error": "No active case. Run 'vhir case activate' first, or pass case_id or index."}

CALLS = {
    "idx_search": lambda: srv.idx_search(query="*"),
    "idx_count": lambda: srv.idx_count(),
    "idx_aggregate": lambda: srv.idx_aggregate(field="host.name"),
    "idx_timeline": lambda: srv.idx_timeline(),
    "idx_field_values": lambda: srv.idx_field_values(field="host.name"),
}


@pytest.fixture
def client(monkeypatch):
    c = MagicMock()
    c.count.return_value = {"count": 6}
    c.cat.indices.return_value = [{"index": "case-other-delim-netstat-h1", "status": "open"}]
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    monkeypatch.setattr(srv.audit, "log", lambda **kw: "aid-1")
    return c


@pytest.fixture
def no_case(monkeypatch):
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)


@pytest.mark.parametrize("tool", sorted(CALLS))
def test_with_no_case_each_search_tool_refuses_without_asking_the_cluster(client, no_case, tool):
    assert CALLS[tool]() == REFUSAL
    for method in (client.search, client.count, client.field_caps, client.cat.indices):
        method.assert_not_called()


@pytest.mark.parametrize("pointer", ["", "\n", "/"], ids=["empty", "a newline", "a bare slash"])
def test_a_pointer_that_names_no_case_counts_as_no_case(client, tmp_path, monkeypatch, pointer):
    import opensearch_mcp.paths as paths

    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "active_case").write_text(pointer)
    monkeypatch.setattr(paths, "vhir_home", lambda: tmp_path)
    assert srv.idx_count() == REFUSAL
    client.count.assert_not_called()


@pytest.mark.parametrize(
    "index", ["case-other-*", "case-*"], ids=["an index pattern", "every case, asked for"]
)
def test_with_no_case_an_explicit_index_is_searched_as_given(client, no_case, index):
    assert srv.idx_count(index=index)["count"] == 6
    assert client.count.call_args.kwargs["index"] == index


def test_with_no_case_a_case_id_names_its_indices_from_its_folder(client, no_case):
    from opensearch_mcp.case_scope import case_read_scope

    assert srv.idx_count(case_id="other")["count"] == 6
    assert client.count.call_args.kwargs["index"] == case_read_scope("other", client)


@pytest.mark.no_case_dirs
def test_a_case_id_with_no_folder_here_is_refused_saying_why(client, no_case):
    assert srv.idx_count(case_id="elsewhere") == {
        "error": "Case 'elsewhere' has no folder on this box, so its indices can't be "
        "resolved; pass index= or activate it."
    }
    client.count.assert_not_called()


def test_with_no_case_there_are_no_hayabusa_alerts_to_name(no_case):
    assert srv._hayabusa_index() == ""


def test_the_active_case_is_the_default(client, monkeypatch):
    monkeypatch.setattr(srv, "_get_active_case", lambda: "mix")
    assert srv.idx_count()["count"] == 6
    assert client.count.call_args.kwargs["index"] == "case-mix-*"


def test_with_no_case_the_summary_refuses(client, no_case):
    assert srv.idx_case_summary() == {
        "error": "No active case: activate a case (vhir case activate) or pass case_id."
    }


def test_the_active_case_is_read_once(client, monkeypatch):
    """The check and the pattern use one read: a pointer changed between
    two reads could pass the check and then search another case."""
    reads = iter(["mix", None])
    monkeypatch.setattr(srv, "_get_active_case", lambda: next(reads))
    assert srv.idx_count()["count"] == 6
    assert client.count.call_args.kwargs["index"] == "case-mix-*"
