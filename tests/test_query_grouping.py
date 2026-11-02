"""A query OpenSearch read with some clauses optional says so in `query_note`.

query_string gives AND no precedence over OR: beside AND (or +), a clause
joined only by OR is optional. After a tool's search succeeds it asks
`_validate/query?explain=true` how the query was read, and reads that answer
alone, never the query string. When an index wasn't read, the note says the
grouping wasn't checked; the result itself never changes.

The explanations replayed here were captured from OpenSearch 3.5.0 on real
evtx and delimited indices (fixtures/query_grouping_explanations.json.xz):
each row's label is what the query means (T: a clause is optional beside a
required one), and its count is the hits it found.
"""

from __future__ import annotations

import json
import lzma
import time
from pathlib import Path

import pytest
from opensearchpy.exceptions import ConnectionError, ConnectionTimeout
from test_partial_shard_answers import DELIM, EVTX, WHOLE, Cluster, failures, run, tools  # noqa: F401  (run is a fixture)

from opensearch_mcp import server as srv

NOT_CHECKED = "The query's AND/OR grouping wasn't checked ("
CLEAN = "+ConstantScore(winlog.channel:Security) +ConstantScore(event.code:4624)"
TRAP = "+ConstantScore(winlog.channel:Security) +ConstantScore(event.code:4624) event.code:4672"
FIXTURE = Path(__file__).parent / "fixtures" / "query_grouping_explanations.json.xz"
SETS = json.loads(lzma.decompress(FIXTURE.read_bytes()))["sets"]
# Keyword terms are rendered unescaped, so a paren inside one moves a level:
# measured, accepted, and asserted as measured.
RESIDUAL = {("real0", 14): "FN", ("real0", 16): "FN", ("real0", 17): "FP", ("real0", 29): "FP"}


class Validating(Cluster):
    """A cluster whose `_validate/query` answers `validate()`, or raises it;
    each search's and validate's index and body are kept in `calls`."""

    def __init__(self, validate, shards=WHOLE, **kw):
        super().__init__(shards, total=2, buckets=[("WKS1", 2)], counts={"": 2}, **kw)
        self.calls = []

        def asked(**k):
            self.calls.append(("validate", k.get("index"), k.get("body"), k))
            return validate(**k)

        self.indices.validate_query = asked

    def search(self, index=None, body=None, **kw):
        self.calls.append(("search", index, json.dumps(body, sort_keys=False), kw))
        return super().search(index=index, body=body, **kw)


def answer(explanations, valid=True):
    def validate(**kw):
        return {"valid": valid, "explanations": explanations}

    return validate


def read(*texts, index=DELIM):
    """Explanations OpenSearch read, one per text."""
    return [{"index": index, "valid": True, "explanation": t} for t in texts]


def unread(error):
    return {"index": EVTX, "valid": False, "error": error}


def raising(exc):
    def validate(**kw):
        raise exc

    return validate


EXPANSION = ("[case-acac00000001-evtx-0/x] QueryShardException[failed to create query: field "
             "expansion for [*] matches too many fields, limit: 1024, got: 1347];; java.lang."
             "IllegalArgumentException: field expansion for [*] matches too many fields, limit: "
             "1024, got: 1347")  # fmt: skip
FAILED_CHECKS = {
    "raises": (
        raising(ConnectionError("N/A", "refused", None)),
        "no index checked: ConnectionError",
    ),
    "times out": (raising(ConnectionTimeout("TIMEOUT", "timed out", None)), "timed out after 5 s"),
    "valid false": (answer(read(CLEAN), valid=False), "OpenSearch called the query invalid"),
    "an index unread": (
        answer([unread(EXPANSION)], valid=False),
        "1 of 1 indices: field expansion for [*] matches too many fields",
    ),
    "no explanations": (answer([]), "no index checked: OpenSearch gave no reading"),
    "top valid, one index unread": (answer([*read(CLEAN), unread(EXPANSION)]), "1 of 2 indices: "),
}


def without_note(reply):
    return {k: v for k, v in reply.items() if k not in ("query_note", "audit_id")}


def note_of(*texts, valid=True):
    return srv._grouping_note({"valid": valid, "explanations": read(*texts)})


@pytest.mark.parametrize("tool", sorted(tools()))
@pytest.mark.parametrize("check", sorted(FAILED_CHECKS))
def test_a_check_that_cannot_run_says_so_and_changes_nothing_else(run, tool, check):  # noqa: F811
    validate, why = FAILED_CHECKS[check]
    kw = tools("winlog.channel:Security AND event.code:4624", DELIM)[tool]
    reply = run(Validating(validate), tool, **kw)
    assert reply["query_note"].startswith(NOT_CHECKED)
    assert why in reply["query_note"]
    assert reply["query_note"].endswith(").")
    assert without_note(reply) == without_note(run(Validating(answer(read(CLEAN))), tool, **kw))


@pytest.mark.parametrize("tool", sorted(tools()))
def test_an_optional_clause_gives_the_note_with_opensearchs_reading_and_the_same_result(run, tool):  # noqa: F811
    kw = tools("winlog.channel:Security AND event.code:4624 OR event.code:4672", DELIM)[tool]
    reply = run(Validating(answer(read(TRAP))), tool, **kw)
    assert reply["query_note"] == srv._OPTIONAL + TRAP
    assert "A AND B OR C AND D requires all four" in reply["query_note"]
    assert without_note(reply) == without_note(run(Validating(answer(read(CLEAN))), tool, **kw))
    assert "query_note" not in run(Validating(answer(read(CLEAN))), tool, **kw)


@pytest.mark.parametrize("tool", sorted(tools()))
def test_the_check_reads_opensearchs_answer_never_the_query_string(run, tool):  # noqa: F811
    """A control's string with a trap's reading fires; a trap's string with a
    control's reading doesn't."""
    control = tools("winlog.channel:Security AND event.code:(4624 OR 4672)", DELIM)[tool]
    trap = tools("winlog.channel:Security AND event.code:4624 OR event.code:4672", DELIM)[tool]
    assert run(Validating(answer(read(TRAP))), tool, **control)["query_note"].startswith(
        srv._OPTIONAL
    )
    assert "query_note" not in run(Validating(answer(read(CLEAN))), tool, **trap)


def test_a_trap_in_a_later_explanation_fires():
    assert note_of(CLEAN, CLEAN, TRAP) == srv._OPTIONAL + TRAP


def test_the_reading_quoted_is_the_trapped_one_with_the_fewest_unmapped_fields():
    """A delimited index sorts before the evtx ones and maps no event.code: its
    reading isn't quoted over one that has the field. A tie goes to the first.
    Other unmatched leaves (a date field that can't parse the term) don't count."""
    unmapped = ' MatchNoDocsQuery("unmapped fields [event.code]")'
    assert note_of(TRAP + unmapped, TRAP) == srv._OPTIONAL + TRAP
    other = TRAP.replace("4672", "4673")
    assert note_of(TRAP + unmapped, other + unmapped) == srv._OPTIONAL + TRAP + unmapped
    unparsed = ' MatchNoDocsQuery("failed [@timestamp] query, caused by parse_exception")' * 2
    assert note_of(other + unmapped, TRAP + unparsed) == srv._OPTIONAL + TRAP + unparsed


def test_a_trap_in_any_read_index_fires_whatever_the_others_and_the_top_level_say():
    many = {r["row"]: r for r in SETS["many"]["rows"]}
    assert not many[23]["valid"] and sum(not e["valid"] for e in many[23]["explanations"]) == 2
    note = srv._grouping_note({"valid": False, "explanations": many[23]["explanations"]})
    assert note.startswith(srv._OPTIONAL)
    assert srv._grouping_note({"valid": False, "explanations": [unread(EXPANSION), *read(TRAP)]})\
        .startswith(srv._OPTIONAL)  # fmt: skip
    assert srv._grouping_note({"valid": False, "explanations": many[22]["explanations"]}) == (
        f"{NOT_CHECKED}2 of 6 indices: field expansion for [*] matches too many fields, "
        "limit: 1024, got: 1347)."
    )


def test_an_unread_index_is_never_read_for_a_trap():
    trap_unread = {"index": EVTX, "valid": False, "explanation": TRAP, "error": "x"}
    assert srv._grouping_note({"valid": True, "explanations": [trap_unread]}).startswith(
        NOT_CHECKED
    )
    not_true = {"index": EVTX, "valid": "true", "explanation": TRAP}
    assert srv._grouping_note({"valid": True, "explanations": [not_true]}).startswith(NOT_CHECKED)


def test_an_unread_index_s_reason_is_cut_at_150_characters():
    note = srv._grouping_note({"valid": False, "explanations": [unread("x" * 200)]})
    assert note == f"{NOT_CHECKED}1 of 1 indices: {'x' * 150})."


@pytest.mark.parametrize("tool", sorted(tools()))
def test_a_partial_search_with_a_failed_check_says_both(run, tool):  # noqa: F811
    shards = {"total": 2, "successful": 1, "skipped": 0, "failed": 1,
              "failures": failures(EVTX, "timed out")}  # fmt: skip
    kw = tools("winlog.channel:Security AND event.code:4624", DELIM)[tool]
    reply = run(Validating(raising(ConnectionTimeout("TIMEOUT", "t", None)), shards), tool, **kw)
    assert reply["partial"] and reply["partial_warning"]
    assert reply["query_note"].startswith(NOT_CHECKED)


@pytest.mark.parametrize(
    ("reading", "fires"),
    [
        ("+a +b c", True),  # + beside unmarked
        ("#a b", True),  # # beside unmarked
        ("+a +b", False),  # nothing unmarked
        ("a b -c", False),  # - doesn't count
        ("-a #*:*", False),
        ("+a (b c)", True),  # the group is unmarked beside +a
        ("+a +(b c)", False),
        ("+a +(+b c)", True),  # a level inside
        ("ConstantScore(x +y) z", False),  # a ( after a letter is a term's
        ("+field:a\\ +b +c", False),  # an escaped space belongs to the term
        ("+field:a\\ b +c", False),
        ("field:\\(a +b +c d", True),  # an escaped paren too
        ('MatchNoDocsQuery("x) +y z") c', False),  # a failure reason is one clause
        ('+MatchNoDocsQuery("(a") +b c', True),
        ("+(f1:a | f2:a) +b", False),  # a field expansion is no optional clause
        ("+(f1:a | f2:a) +b c", True),
        ('+a +f:"x y"', False),  # a phrase belongs to its term
        ('+a +f:"x y"~2', False),
        ('+a +f:"x y" c', True),
        ("+a +ConstantScore(f:x y)", False),  # a keyword phrase renders unquoted
        ("+a +x_(+b c)", False),  # a ( after _ is a term's too
        ("+f:/x | y/ +g", False),  # a regex belongs to its term
        ("+f:/x | y/ +g c", True),
        ("+f:/a\\/b c/ +g", False),  # to its first unescaped /
        ("+f:/x (a b/ +g", True),  # unsure: a ( may open a group
        ("+ConstantScore(f:/c x) +g d", True),  # a keyword value starting with /
        ("+ConstantScore(f:/c x) +g:/p q/", False),  # ends at a / before a space, ) or the end
        ("+ConstantScore(f:/c x) d +g:/p/", True),
        ("+ConstantScore(f:/etc) ConstantScore(other:foo) +ConstantScore(g:/)", True),
        ("+ConstantScore(g:/) ConstantScore(other:foo) +ConstantScore(f:/etc)", True),
        ("+ConstantScore(a:/tmp) ConstantScore(o:x) +ConstantScore(b:/) +e:1", True),
        ("+ConstantScore(a:/x) ConstantScore(b:y/) +c:1", True),  # no clause starts in a regex
        ("+e:1 +(+c:d +f:/a b/)", False),  # a regex can end at its group's )
        ("+f:a/b c +g:d/", True),  # only a / after a colon opens one
        ("+f:a/b c/ +g", True),
        ("+f:/a d +g:b/c", True),
        ("+f:/a d +g:b/", True),
        ("+f:/a d -g:b/ +h", True),
        ("+f:/a d #g:b/", True),
        ("+winlog.event_data.Payload:/etc* ConstantScore(o:foo) +ConstantScore(g:/)", True),
        ("+f:/tmp* ConstantScore(g:x/) +h:1", True),  # a prefix renders as f:/etc*
        ("+f:/etc* o:x/ +h:1", True),
        ("+f:/etc* a.b@c*d-e:x/ +h:1", True),  # a field name can hold most characters
        ("+f:/etc* (o:x/) +h:1", True),
        ("+(+a:1 +ConstantScore(P:/etc)) (c:d e:f)", True),
        ("+P:/.*(Set|Get) x.*/ +IndexOrDocValuesQuery(q)", False),  # a regex's own parens
        ("+f:/[)] a/ +g", False),
        ('+f:/"a)b" c/ +g:y', False),
        ("+f:/etc* (+o:x/ +h:1)", True),  # a nested group renders as (+, (# or (-
        ("+ConstantScore(f:/etc) (+o:*x/ +h:1)", True),
        ("+f:/etc* (#o:x/ #h:1)", True),
        ("+f:/etc* ((#o:x/ #h:1)) +k:1", True),
        ("+f:/etc* (-o:x/ +h:1)", True),
        ("+f:/etc* (-*x/ +h:1)", True),
        ("+f:/etc* $x:y/ +h:1", True),
        ("+f:/etc* a%b:x/ +h:1", True),
        ("+f:/etc* a[0]:x/ +h:1", True),
        ("+f:/etc* a]b:x/ +h:1", True),
        ("+f:/etc* «a»:x/ +h:1", True),
        ("+f:/etc* x +*y/ +h:1", True),  # a mark starts a clause
        ("+f:/etc* x -*y/ +h:1", True),
        ("+f:/etc* x #*y/ +h:1", True),
        ("+f:/etc* x\no:y/ +h:1", True),  # a value can hold a line break
        ("+f:/etc* x/y +h:1", True),  # a / inside a later term closes nothing
        ("+f:/etc* x", True),  # no closing /
        ("+f:/etc* g:/ +h:1", True),  # a : just before the closing /
        ("+f:/a b-c/ +g:1", False),  # a mark inside a word starts nothing
        ("+f:/.*[(]/ +g:1", False),  # with no space, a ( stays in the regex
        ("+f:/a +b c/ +g:1", True),  # a mark right after the first space
    ],
)
def test_the_level_rule(reading, fires):
    assert note_of(reading).startswith(srv._OPTIONAL) is fires


def test_the_reading_quoted_is_the_level_that_fired_with_field_expansions_collapsed():
    assert note_of("+a +(+b c)") == srv._OPTIONAL + "+b c"
    assert note_of("+(f1:a | f2:a | f3:a) +b c") == srv._OPTIONAL + "+(3 fields: f1:a) +b c"
    long = "+" + " ".join(f"+f{i}:x" for i in range(100)) + " c"
    assert note_of(long) == srv._OPTIONAL + long[:300] + "…"


def test_an_unfielded_query_quotes_its_trap_from_the_tail_of_a_long_reading():
    """An unfielded term expands to every default field, so the reading is
    about 29 KB and the clauses that make the trap come last."""
    row = {r["row"]: r for r in SETS["real0"]["rows"]}[23]
    assert row["query"] == "mimikatz AND event.code:4624 OR event.code:4672"
    text = row["explanations"][0]["explanation"]
    required = "+IndexOrDocValuesQuery(indexQuery=event.code:[4624 TO 4624]"
    optional = " IndexOrDocValuesQuery(indexQuery=event.code:[4672 TO 4672]"
    assert len(text.encode()) >= 20000 and text.index(required) > 20000
    note = srv._grouping_note({"valid": True, "explanations": row["explanations"]})
    reading = note.removeprefix(srv._OPTIONAL)
    assert reading.startswith("+(451 fields: ConstantScore(winlog.event_data.NewProcessName:")
    assert required in reading and optional in reading and len(reading) <= 300
    clean = {r["query"]: r for r in SETS["real0"]["rows"]}
    assert "mimikatz OR event.code:4624" not in clean  # the guard is a bed row


def test_a_regex_with_a_space_beside_required_clauses_gives_no_note():
    """Captured escapes row 8, then the same reading without its OR clause."""
    row = {r["row"]: r for r in SETS["escapes"]["rows"]}[8]
    assert row["query"] == (
        "winlog.event_data.Payload:/x | y/ AND event.code:4103 OR event.code:4104"
    )
    text = row["explanations"][0]["explanation"]
    optional = (
        " IndexOrDocValuesQuery(indexQuery=event.code:[4104 TO 4104],"
        " dvQuery=event.code:[4104 TO 4104])"
    )
    assert text.startswith("+winlog.event_data.Payload:/x | y/ +") and text.endswith(optional)
    assert note_of(text).startswith(srv._OPTIONAL + "+winlog.event_data.Payload:/x | y/ +")
    assert note_of(text.removesuffix(optional)) == ""


@pytest.mark.parametrize(
    "text",
    [
        "+f:/" + "a " * 50000 + "x/ +g:1",  # one keyword value near the term cap and over
        "+(" + " | ".join(["f:/" + "a " * 4000 + "x/"] * 30) + ") +g:1",  # a field expansion
    ],
    ids=["one-term", "expansion"],
)
def test_a_long_value_with_many_spaces_is_read_in_one_pass(text):
    t0 = time.perf_counter()
    note = note_of(text)
    took = time.perf_counter() - t0
    assert note == ""  # every clause is required
    assert took < 1, took  # a loose ceiling for slow runners: about 0.05 s here


ROWS = [(name, r) for name in ("real0", "escapes", "phrases") for r in SETS[name]["rows"]]


@pytest.mark.parametrize(("name", "row"), ROWS, ids=[f"{n}-{r['row']}" for n, r in ROWS])
def test_captured_readings(name, row):
    fires = srv._grouping_note({"valid": row["valid"], "explanations": row["explanations"]})
    fires = fires.startswith(srv._OPTIONAL)
    residual = RESIDUAL.get((name, row["row"]))
    assert fires is ((row["label"] == "T") != bool(residual)), (residual, row["query"])


def test_the_query_clause_is_built_once_and_the_search_body_is_unchanged(run):  # noqa: F811
    q = "winlog.channel:Security AND event.code:4624 OR event.code:4672"
    clause = {"query_string": {"query": q}}
    for tool, kw in tools(q, DELIM).items():
        cluster = Validating(answer(read(TRAP)))
        run(cluster, tool, **kw)
        (search,) = [c for c in cluster.calls if c[0] == "search"]
        (validate,) = [c for c in cluster.calls if c[0] == "validate"]
        assert json.loads(search[2])["query"] == clause
        assert validate[1] == search[1] == DELIM
        assert validate[2] == {"query": clause}
        assert validate[3]["explain"] is True and validate[3]["request_timeout"] == 5


@pytest.mark.parametrize("tool", ["idx_search", "idx_timeline"])
def test_a_time_window_keeps_its_wrapper_and_the_check_asks_about_the_index_searched(run, tool):  # noqa: F811
    q = "winlog.channel:Security AND event.code:4624 OR event.code:4672"
    cluster = Validating(answer(read(TRAP)))
    run(cluster, tool, query=q, index=f"{EVTX},{DELIM}", time_from="2024-01-01T00:00:00Z")
    (search,) = [c for c in cluster.calls if c[0] == "search"]
    (validate,) = [c for c in cluster.calls if c[0] == "validate"]
    must = json.loads(search[2])["query"]["bool"]["must"]
    assert must == [{"query_string": {"query": q}},
                    {"range": {"@timestamp": {"gte": "2024-01-01T00:00:00Z"}}}]  # fmt: skip
    assert validate[1] == search[1] == f"{EVTX},{DELIM}"
    assert validate[2] == {"query": {"query_string": {"query": q}}}


@pytest.mark.parametrize("tool", ["idx_count", "idx_aggregate", "idx_timeline"])
def test_the_unconfirmed_hosts_count_searches_the_same_clause(run, tool, monkeypatch):  # noqa: F811
    q = "winlog.channel:Security AND event.code:4624"
    monkeypatch.setattr(srv, "_host_review", lambda case_id="": ({"k1"}, ""))
    cluster = Validating(answer(read(CLEAN)))
    run(cluster, tool, **tools(q, DELIM)[tool])
    searches = [json.loads(c[2]) for c in cluster.calls if c[0] == "search"]
    assert len(searches) == 2 and len([c for c in cluster.calls if c[0] == "validate"]) == 1
    assert searches[1]["query"]["bool"]["must"] == [searches[0]["query"]]
    assert searches[1]["query"]["bool"]["filter"] == [{"terms": {"vhir.host_key": ["k1"]}}]
