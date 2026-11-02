"""idx_search's sort is honoured or refused: checked through
_field_holders, refused before any search, and a field only some indices
hold sorts with a note naming the indices whose documents come after."""

from __future__ import annotations

import inspect
import re
from unittest.mock import MagicMock, patch

import pytest
from _mapping_shapes import serve
from opensearchpy.exceptions import ConnectionTimeout

import opensearch_mcp.server as srv

C = "case-0123456789ab"
MFT, EVTX, DELIM, LNK = (f"{C}-{t}-0" for t in ("mft", "evtx", "delim", "lnk"))
CASE = {
    MFT: {"Created0x10": "date", "FileName": "text", "FileName.keyword": "keyword"},
    EVTX: {
        "@timestamp": "date",
        "event.code": "integer",
        "winlog.channel": "keyword",
        "script_block_text": "text",
    },
    DELIM: {"@timestamp": "date", "query": "keyword"},
}
HITS = {"hits": {"total": {"value": 1}, "hits": [{"_index": EVTX, "_id": "1", "_source": {}}]}}
NO_INDEX = {"_shards": {"total": 0}, "hits": {"total": {"value": 0}, "hits": []}}
ONE_FIELD = "sort takes one field:order (e.g. Created0x10:asc)"
SEE = "find a sortable field with idx_case_summary(include_fields=true)"
AFTER = "if any match, come after the sorted ones, in no order"


@pytest.fixture
def client(monkeypatch):
    c = MagicMock()
    c.cluster.health.return_value = {"status": "green"}
    c.search.return_value = HITS
    serve(c, CASE)
    monkeypatch.setattr(srv, "_client", None)
    monkeypatch.setattr(srv, "_client_verified", False)
    monkeypatch.setattr(srv, "_resolve_index", lambda index, *a, **k: (index or f"{C}-*", ""))
    with (patch("opensearch_mcp.server.get_client", return_value=c),
          patch("opensearch_mcp.server._get_active_case", return_value="test-case")):  # fmt: skip
        yield c


def _sort(c) -> list:
    return c.search.call_args.kwargs["body"]["sort"]


def _refused(c, r) -> str:
    """The refusal, made before any search request."""
    c.search.assert_not_called()
    assert set(r) == {"error"}
    return r["error"]


def _holder_reads(c) -> list:
    """The field-holder reads (not the client's first-use template check)."""
    reads = [k.kwargs.get("filter_path", "") for k in c.indices.get_mapping.call_args_list]
    return [r for r in reads if ".mappings.properties." in r]


def _mapped(c, extra: dict) -> None:
    serve(c, {**CASE, **extra})


# --- One reader ----------------------------------------------------


def test_the_sort_is_checked_through_field_holders_only():
    src = inspect.getsource(srv._sort_check)
    assert "_field_holders" in src
    for other in ("get_mapping", "field_caps", "get_field_mapping", "_mapping_of", ".search("):
        assert other not in src
    assert "_sort_check(" in inspect.getsource(srv.idx_search)


# --- Rule 1, the order word ------------------------------------------


@pytest.mark.parametrize("word", ["ascending", "up"])
def test_a_bad_order_word_is_refused(client, word):
    r = srv.idx_search(query="*", index=MFT, sort=f"Created0x10:{word}")
    assert _refused(client, r) == (
        f"sort order must be asc or desc (got '{word}'): e.g. Created0x10:asc"
    )
    assert _holder_reads(client) == []


@pytest.mark.parametrize("word, sent", [("ASC", "asc"), ("Asc", "asc"), ("DESC", "desc")])
def test_the_order_word_is_matched_in_any_case_and_sent_lowercase(client, word, sent):
    srv.idx_search(query="*", index=MFT, sort=f"Created0x10:{word}")
    assert _sort(client) == [{"Created0x10": {"order": sent, "unmapped_type": "date"}}]


def test_no_order_word_is_desc(client):
    srv.idx_search(query="*", index=MFT, sort="Created0x10")
    assert _sort(client) == [{"Created0x10": {"order": "desc", "unmapped_type": "date"}}]


# --- Rule 2, one field -----------------------------------------------


@pytest.mark.parametrize("sort", ["a,b:asc", "*:asc", "Created*:asc", "File Name:asc", ":asc", ""])
def test_not_one_field_is_refused(client, sort):
    assert _refused(client, srv.idx_search(query="*", index=MFT, sort=sort)) == ONE_FIELD
    assert _holder_reads(client) == []


def test_a_second_sort_after_the_order_is_refused(client):
    """Split at the last ':', the field is 'Created0x10:asc,EntryNumber':
    rule 2 refuses it, with no search and no read."""
    r = srv.idx_search(query="*", index=MFT, sort="Created0x10:asc,EntryNumber:desc")
    assert _refused(client, r) == ONE_FIELD
    assert _holder_reads(client) == []


def test_a_field_name_with_a_colon_is_split_at_the_last_one(client):
    r = srv.idx_search(query="*", index=MFT, sort="a:b:asc")
    assert _refused(client, r) == f"a:b is in no searched index's mapping ({MFT}): {SEE}"


# --- Rule 4, held by no searched index -----------------------------------


def test_a_keyword_form_no_index_holds_names_its_parent(client):
    r = srv.idx_search(query="*", index=MFT, sort="Created0x10.keyword:asc")
    assert _refused(client, r) == (
        f"Created0x10.keyword is in no searched index's mapping ({MFT}); Created0x10 "
        "is (date) there: sort by Created0x10:asc"
    )


@pytest.mark.parametrize("sort", ["Created0x10.keyword:asc", "FileName:asc"])
def test_a_field_and_its_parent_or_keyword_are_one_read(client, sort):
    """The parent hint and the .keyword hint reuse the field's
    own reads: one field-mapping read, one index list."""
    _refused(client, srv.idx_search(query="*", index=MFT, sort=sort))
    assert _holder_reads(client) == [f"*.mappings.properties.{sort.split('.')[0].split(':')[0]}"]
    assert [k.kwargs["index"] for k in client.cat.indices.call_args_list].count(MFT) == 1


def test_a_field_no_index_holds_is_refused(client):
    r = srv.idx_search(query="*", index=MFT, sort="NoSuchField:asc")
    assert _refused(client, r) == f"NoSuchField is in no searched index's mapping ({MFT}): {SEE}"


# --- Rule 4's exception, no @timestamp ----------------------------------


@pytest.mark.parametrize("index, use", [
    (MFT, "the index's own date field, e.g. Created0x10:asc"),
    (LNK, "the index's own date field, e.g. TargetModified:asc"),
    (f"{MFT},{LNK}", "the index's own date field, e.g. Created0x10:asc, TargetModified:asc"),
    (f"{C}-prefetch-0", "its own date field (see idx_case_summary(include_fields=true))"),
])  # fmt: skip
def test_the_default_sort_with_no_timestamp_searches_with_a_note(client, index, use):
    _mapped(client, {LNK: {"TargetModified": "date"}, f"{C}-prefetch-0": {"RunCount": "long"}})
    r = srv.idx_search(query="*", index=index)
    assert r["sort_note"] == (
        f"No searched index has @timestamp, so results are in no order. Sort by {use}."
    )
    assert _sort(client) == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    assert r["total"] == 1


# --- Rule 5, text ---------------------------------------------------------


@pytest.mark.parametrize("index", [MFT, None])
def test_a_text_field_is_refused_naming_its_keyword(client, index):
    r = srv.idx_search(query="*", index=index or "", sort="FileName:asc")
    assert _refused(client, r) == (
        f"FileName is text in {MFT}: text fields can't sort; sort by FileName.keyword:asc"
    )


@pytest.mark.parametrize("index", [EVTX, None])
def test_a_text_field_with_no_keyword_is_refused(client, index):
    r = srv.idx_search(query="*", index=index or "", sort="script_block_text:asc")
    assert _refused(client, r) == f"script_block_text is text in {EVTX}: text fields can't sort"


def test_text_in_one_index_and_keyword_in_another_is_refused(client):
    """Today OpenSearch sorts the keyword index and fails the text one."""
    _mapped(client, {f"{C}-delim-1": {"FileName": "keyword"}})
    r = srv.idx_search(query="*", sort="FileName:asc")
    assert _refused(client, r) == (
        f"FileName is text in {MFT}: text fields can't sort; sort by FileName.keyword:asc"
    )


@pytest.mark.parametrize("order", ["asc", "desc"])
def test_the_keyword_hint_fed_back_sorts_in_the_asked_order(client, order):
    """The hint keeps the order the call asked for, as rule 4's does."""
    err = _refused(client, srv.idx_search(query="*", index=MFT, sort=f"FileName:{order}"))
    r = srv.idx_search(query="*", index=MFT, sort=re.search(r"sort by (\S+)$", err)[1])
    assert "error" not in r and r["total"] == 1
    assert _sort(client) == [{"FileName.keyword": {"order": order, "unmapped_type": "keyword"}}]


# --- The sort Args text -----------------------------------------------------


@pytest.mark.parametrize("sentence", [
    "sort: Sort field:order, order asc or desc (default @timestamp:desc).",
    "One field.",
    "A text field sorts only by its .keyword sub-field.",
    "EZ-tool CSV indices have no @timestamp: sort them by their own date field "
    "(e.g. Created0x10:asc).",
])  # fmt: skip
def test_the_sort_args_text(sentence):
    assert sentence in " ".join(srv.idx_search.__doc__.split())


# --- Rule 8, some indices hold it ---------------------------------


def test_a_field_some_indices_hold_sorts_with_a_note(client):
    r = srv.idx_search(query="*", sort="Created0x10:asc")
    assert _sort(client) == [{"Created0x10": {"order": "asc", "unmapped_type": "date"}}]
    assert r["sort_note"] == (
        f"Created0x10 is in 1 of the 3 searched indices; documents from {DELIM}, {EVTX}, {AFTER}"
    )


def test_the_default_sort_over_some_untimed_indices_has_no_note(client):
    r = srv.idx_search(query="*")
    assert "sort_note" not in r
    assert _sort(client) == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]


def test_a_keyword_some_indices_hold_is_sent_as_keyword(client):
    """An unmapped_type of date on a keyword sort crashes the search (500,
    class_cast_exception); the holders' type doesn't."""
    r = srv.idx_search(query="*", sort="winlog.channel:asc")
    assert _sort(client) == [{"winlog.channel": {"order": "asc", "unmapped_type": "keyword"}}]
    assert r["sort_note"] == (
        f"winlog.channel is in 1 of the 3 searched indices; documents from {DELIM}, {MFT}, {AFTER}"
    )


def test_the_note_names_five_and_counts_the_rest(client):
    _mapped(client, {f"{C}-delim-{i}": {"@timestamp": "date"} for i in range(1, 7)})
    note = srv.idx_search(query="*", sort="winlog.channel:asc")["sort_note"]
    assert note.startswith("winlog.channel is in 1 of the 9 searched indices; documents from ")
    assert note.endswith(f"{C}-delim-4, and 3 more, {AFTER}")


# --- Rules 6 and 7, measured ---------------------------------------------------


@pytest.mark.parametrize("other", ["keyword", "long"])
def test_holders_of_more_than_one_type_are_refused(client, other):
    """Date in one index and keyword in another is a 500 for the whole
    search; integer and long are refused too."""
    _mapped(client, {f"{C}-delim-1": {"event.code": other}})
    r = srv.idx_search(query="*", sort="event.code:asc")
    assert _refused(client, r) == (
        f"event.code is mapped as integer in {EVTX} and as {other} in {C}-delim-1: one sort "
        "can't combine them. Sort each set with index=<those names>, or narrow the pattern."
    )


@pytest.mark.parametrize("field", ["_id", "_index", "_score", "_doc"])
def test_these_metadata_fields_sort_unchecked(client, field):
    srv.idx_search(query="*", sort=f"{field}:asc")
    spec = {"order": "asc"}
    if field in ("_id", "_index"):  # fields: unmapped_type as before
        spec["unmapped_type"] = "date"
    assert _sort(client) == [{field: spec}]
    assert _holder_reads(client) == []


@pytest.mark.parametrize("field", ["_source", "_seq_no", "_routing", "_version"])
def test_other_metadata_fields_are_refused(client, field):
    r = srv.idx_search(query="*", sort=f"{field}:asc")
    assert _refused(client, r) == (
        f"{field} is a metadata field; idx_search sorts by _score, _doc, _id, _index or a "
        "mapped field"
    )


# --- Accepted sorts send the same body as before -------------------------------


@pytest.mark.parametrize("index, sort, spec", [
    (MFT, "Created0x10:asc", {"Created0x10": {"order": "asc", "unmapped_type": "date"}}),
    (EVTX, "event.code:desc", {"event.code": {"order": "desc", "unmapped_type": "date"}}),
    (EVTX, "_score:desc", {"_score": {"order": "desc"}}),
    (EVTX, "_doc:asc", {"_doc": {"order": "asc"}}),
    (EVTX, "@timestamp:desc", {"@timestamp": {"order": "desc", "unmapped_type": "date"}}),
])  # fmt: skip
def test_an_accepted_sort_sends_the_same_body(client, index, sort, spec):
    """Byte-equal to the body before sorts were checked, except the unmapped_type value."""
    srv.idx_search(query="*", index=index, sort=sort)
    body = client.search.call_args.kwargs["body"]
    for got in [*body["sort"][0].values(), *spec.values()]:
        if "unmapped_type" in got:
            got["unmapped_type"] = "<value>"
    assert body == {"query": {"query_string": {"query": "*"}}, "sort": [spec], "size": 50}


def test_a_numeric_field_is_sent_as_its_type(client):
    srv.idx_search(query="*", index=EVTX, sort="event.code:desc")
    assert _sort(client) == [{"event.code": {"order": "desc", "unmapped_type": "integer"}}]


# --- No index, the default sort, a time range, hints and closed indices -------------


@pytest.mark.parametrize("sort", ["Created0x10:asc", "@timestamp:desc"])
def test_no_index_matched_gives_the_no_index_error(client, sort):
    """No check; the search runs and says no open index matched."""
    serve(client, {})
    client.search.return_value = NO_INDEX
    r = srv.idx_search(query="*", sort=sort)
    assert r["error"].startswith(f"No open index matches '{C}-*': nothing was searched.")
    assert "sort_note" not in r


def test_an_empty_index_list_makes_no_timestamp_claim(client):
    """The reads found no index, yet the search answers (an index made since):
    no note that no searched index has @timestamp."""
    serve(client, {})
    r = srv.idx_search(query="*")
    assert r["total"] == 1 and "sort_note" not in r


def test_the_no_timestamp_note_names_three_own_date_fields(client):
    names = [f"{C}-{t}-0" for t in ("amcache", "lnk", "mft", "usn")]
    _mapped(client, {n: {"Path": "keyword"} for n in names})
    r = srv.idx_search(query="*", index=",".join(names))
    assert r["sort_note"].endswith(
        "e.g. Created0x10:asc, FileKeyLastWriteTimestamp:asc, TargetModified:asc."
    )


def test_a_failed_read_of_timestamp_searches_with_a_note(client):
    """The default sort is never refused; it searches as today."""
    client.indices.get_mapping.side_effect = ConnectionTimeout("TIMEOUT", "read timed out", None)
    r = srv.idx_search(query="*")
    assert r["total"] == 1 and r["sort_note"] == (
        "couldn't check which indices lack an event time (ConnectionTimeout); EZ-tool CSV "
        "indices sort after the others, in no order"
    )


def test_a_failed_read_with_a_window_notes_it_once(client):
    client.indices.get_mapping.side_effect = ConnectionTimeout("TIMEOUT", "read timed out", None)
    r = srv.idx_search(query="*", time_from="2024-01-01T00:00:00Z")
    assert r["time_note"].startswith(
        "couldn't check which indices lack an event time (ConnectionTimeout)"  # its own class
    )
    assert "sort_note" not in r and r["total"] == 1


def test_a_failed_read_of_a_named_field_is_an_error(client):
    client.indices.get_mapping.side_effect = ConnectionTimeout("TIMEOUT", "read timed out", None)
    with pytest.raises(RuntimeError, match="OpenSearch connection temporarily lost"):
        srv.idx_search(query="*", sort="Created0x10:asc")
    client.search.assert_not_called()


@pytest.mark.parametrize("sort", ["@timestamp:desc", "Created0x10:asc"])
def test_a_window_reads_the_timestamp_holders_once(client, sort):
    srv.idx_search(query="*", sort=sort, time_from="2024-01-01T00:00:00Z")
    assert _holder_reads(client).count("*.mappings.properties.@timestamp") == 1


@pytest.mark.parametrize("other", ["text", "keyword"])
def test_timestamp_of_another_type_is_never_refused(client, other):
    """The shard that can't sort fails as today, and partial_warning names it."""
    _mapped(client, {f"{C}-delim-1": {"@timestamp": other}})
    r = srv.idx_search(query="*")
    assert r["total"] == 1 and "sort_note" not in r
    assert _sort(client) == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]


def test_a_window_leaves_the_untimed_indices_out_of_the_note(client):
    """The range leaves out the indices with no @timestamp."""
    _mapped(client, {LNK: {"TargetModified": "date"}})
    r = srv.idx_search(query="*", sort="winlog.channel:asc", time_from="2024-01-01T00:00:00Z")
    assert r["sort_note"] == (
        f"winlog.channel is in 1 of the 4 searched indices; documents from {DELIM}, {AFTER}"
    )
    r = srv.idx_search(query="*", sort="winlog.channel:asc")
    assert f"documents from {DELIM}, {LNK}, {MFT}, {AFTER}" in r["sort_note"]


def test_no_note_when_the_window_leaves_out_every_index_lacking_it(client):
    _mapped(client, {LNK: {"TargetModified": "date"}})
    r = srv.idx_search(query="*", index=f"{EVTX},{LNK}", sort="winlog.channel:asc", time_to="2025")
    assert "sort_note" not in r
    assert _sort(client) == [{"winlog.channel": {"order": "asc", "unmapped_type": "keyword"}}]


@pytest.mark.parametrize("more", [0, 6])
def test_a_window_that_leaves_out_every_holder_says_so(client, more):
    """Created0x10 is only in untimed mft indices, which the range leaves out;
    the names take rule 8's form."""
    extra = {f"{C}-mft-{i}": {"Created0x10": "date"} for i in range(1, more + 1)}
    _mapped(client, extra)
    r = srv.idx_search(query="*", sort="Created0x10:asc", time_from="2024-01-01T00:00:00Z")
    names = f"{MFT}, " + ", ".join(sorted(extra)[:4]) + ", and 2 more" if more else MFT
    assert r["total"] == 1 and r["sort_note"] == (
        f"Created0x10 is only in {names}, which the time range leaves out (they have no "
        "@timestamp): results are in no order. Search those indices without time_from/time_to "
        "to sort by Created0x10."
    )


def test_a_window_that_leaves_out_every_keyword_holder_sends_keyword(client):
    _mapped(client, {LNK: {"TargetPath": "keyword"}})
    r = srv.idx_search(query="*", sort="TargetPath:asc", time_from="2024-01-01T00:00:00Z")
    assert r["sort_note"].startswith(f"TargetPath is only in {LNK}, which the time range ")
    assert _sort(client) == [{"TargetPath": {"order": "asc", "unmapped_type": "keyword"}}]


@pytest.mark.parametrize("sort, index, extra, hint", [
    ("Created0x10.keyword:asc", MFT, {}, "Created0x10:asc"),
    ("Created0x10.keyword", MFT, {}, "Created0x10:desc"),  # no order word: the default
    ("Created0x10.keyword:ASC", MFT, {}, "Created0x10:asc"),  # as it is sent
    ("FileName:asc", MFT, {}, "FileName.keyword:asc"),
    ("FileName", MFT, {}, "FileName.keyword:desc"),  # no order word: the default
    ("FileName:ASC", MFT, {}, "FileName.keyword:asc"),
    ("FileName:asc", "", {f"{C}-delim-1": {"FileName": "keyword"}}, "FileName.keyword:asc"),
    ("_id.keyword:asc", "", {}, "_id:asc"),
    ("F:asc", "", {f"{C}-delim-1": {"F": "text", "F.keyword": "text"}}, None),  # rule 5
    ("_source.keyword:asc", "", {}, None),  # rule 7
    ("_routing.keyword:asc", "", {}, None),
])  # fmt: skip
def test_a_hint_names_a_sort_that_is_accepted(client, sort, index, extra, hint):
    """A refusal's hint, fed back to idx_search, is accepted; a form the
    rules refuse is never named."""
    _mapped(client, extra)
    got = re.search(
        r"sort by (\S+)$", _refused(client, srv.idx_search(query="*", index=index, sort=sort))
    )
    if got:
        r = srv.idx_search(query="*", index=index, sort=got[1])
        assert "error" not in r and [*_sort(client)[0]] == [got[1].split(":")[0]]
    assert (got and got[1]) == hint


def test_a_text_only_parent_is_not_named(client):
    """Ftxt:asc would be refused too, so Ftxt.keyword gets the generic text."""
    _mapped(client, {f"{C}-delim-1": {"Ftxt": "text"}})
    r = srv.idx_search(query="*", sort="Ftxt.keyword:asc")
    assert _refused(client, r) == f"Ftxt.keyword is in no searched index's mapping ({C}-*): {SEE}"


def test_a_parent_of_two_types_is_not_named(client):
    _mapped(client, {f"{C}-delim-1": {"T": "date"}, f"{C}-delim-2": {"T": "long"}})
    r = srv.idx_search(query="*", sort="T.keyword:asc")
    assert _refused(client, r) == f"T.keyword is in no searched index's mapping ({C}-*): {SEE}"


def test_a_keyword_of_two_types_is_not_named(client):
    _mapped(client, {
        f"{C}-delim-1": {"N": "text", "N.keyword": "keyword"},
        f"{C}-delim-2": {"N": "text", "N.keyword": "wildcard"},
    })  # fmt: skip
    r = srv.idx_search(query="*", sort="N:asc")
    assert _refused(client, r) == f"N is text in {C}-delim-1, {C}-delim-2: text fields can't sort"


def test_a_closed_index_named_explicitly_is_not_said_to_lack_it(client):
    """The cat API lists an explicitly named closed index; _mapping leaves it out."""
    closed = f"{C}-mft-9"
    client.cat.indices = MagicMock(return_value=[{"index": closed}])
    r = srv.idx_search(query="*", index=closed, sort="Created0x10:asc")
    want = f"Created0x10 is in no searched index's mapping ({closed}): {SEE}"
    assert _refused(client, r) == want
