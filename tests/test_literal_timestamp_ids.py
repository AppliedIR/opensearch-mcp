# ruff: noqa: F811 - `cluster`, `cases` and `new_process` are the fixtures imported below
"""A source's own @timestamp keeps json and delimited rows apart.

`@timestamp` is volatile in the json and delimited ids, so a parser-derived
time stays out of them; but a literal source `@timestamp` was dropped too, and
ECS-shaped rows that differ only in time became one record. A non-empty literal
`@timestamp` is now hashed (its source value, read before a time field can
overwrite it). Such a record carries the id 0.6.4 gave it, so the stamp marks
it `vhir.id_scheme: 2` (evidence can't carry the marker in) and a re-ingest of
evidence stored before 0.6.5 keeps the stored record instead of adding a
second copy.

The parsers and the write stamp are real; the cluster is record_ids_cluster.
Ids are pinned for a fixed case identity and the commands' own index names.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_record_ids import (  # noqa: F401
    FILL_STATE,
    cases,
    cluster,
    kept,
    new_process,
    new_run,
    step,
)

from opensearch_mcp import bulk
from opensearch_mcp import write_context as wc
from opensearch_mcp.parse_delimited import ingest_delimited
from opensearch_mcp.parse_json import ingest_json
from opensearch_mcp.paths import stem_type

CASE_UUID = "6a2f00c0-ffee-4b1d-9e0d-1c2b3a4f5e6d"
MACHINE = "0123456789abcdef"
ECS = [
    {"@timestamp": "2026-10-01T00:00:00Z", "event.action": "logon-failed", "user": "bob",
     "source_ip": "203.0.113.5"},
    {"@timestamp": "2026-10-01T00:01:00Z", "event.action": "logon-failed", "user": "bob",
     "source_ip": "203.0.113.5"},
]  # fmt: skip


def jl(rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


FILES = {  # rows that differ only in a literal @timestamp
    "a-json": ("ecs.jsonl", jl(ECS), None),
    "b-csv": ("export.csv", "@timestamp,event.action,user,source_ip\n"
              "2026-10-01T00:00:00Z,logon-failed,bob,203.0.113.5\n"
              "2026-10-01T00:01:00Z,logon-failed,bob,203.0.113.5\n", None),
    "c-source": ("wrapped.jsonl", jl([{"_source": r} for r in ECS]), None),
    "d-json-timefield": ("ecs_when.jsonl", jl([dict(r, when="2026-10-01T05:00:00Z") for r in ECS]),
                         "when"),
    "d-csv-timefield": ("ecs_when.csv", "@timestamp,when,event.action,user\n"
                        "2026-10-01T00:00:00Z,2026-10-01T05:00:00Z,logon-failed,bob\n"
                        "2026-10-01T00:01:00Z,2026-10-01T05:00:00Z,logon-failed,bob\n", "when"),
}  # fmt: skip
# each case's two parser ids (measured on the design's sketch, the same inputs)
RIDS = {
    "a-json": ["ae836763e1330f775d0d", "d695545e59349e9c8f1c"],
    "b-csv": ["b6caae7be842c941e79a", "c9b9a6a05585d81b01ee"],
    "c-source": ["c44bd4845bbd90303fa7", "febe47e03aa07500d38f"],
    "d-json-timefield": ["069a9de92a5f19db83d1", "4afd82c5ee0d52c348b1"],
    "d-csv-timefield": ["2c310286b9adf77ab5d5", "a2a32359d4e947ff6c66"],
}


def ingest(cluster, cases, monkeypatch, name, text, time_field=None) -> str:
    """One run of one file, as the json or delimited command makes it: the
    case's identity fixed, the file's own index. Its index."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    case = cases / "g2"
    case.mkdir(exist_ok=True)
    (case / "CASE.yaml").write_text(f"case_id: g2\ncase_uuid: {CASE_UUID}\nnaming_version: 2\n")
    wc.set_current(wc.open_unit(case, "evidence/srv1", "srv1", source="evidence folder"))
    f = case / name
    f.write_text(text)
    bulk.reset_circuit_breaker()
    s = step()
    with wc.op(s):
        if f.suffix == ".csv":
            index = wc.index_name(stem_type("delim", f.stem))
            ingest_delimited(f, cluster.client(), index, "srv1", time_field=time_field,
                             source_file=f"evidence/{name}", ingest_audit_id=s)  # fmt: skip
        else:
            index = wc.index_name(stem_type("json", f.stem))
            ingest_json(f, cluster.client(), index, "srv1", time_field=time_field,
                        source_file=f"evidence/{name}", ingest_audit_id=s)  # fmt: skip
    wc.set_current(None)
    return index


def rids(cluster, index):
    return sorted(s["vhir.rid"] for _, s in cluster.docs(index))


@pytest.mark.parametrize("case", list(FILES))
def test_rows_that_differ_only_in_their_own_time_are_two_records(
    cluster, cases, monkeypatch, case
):
    name, text, time_field = FILES[case]
    index = ingest(cluster, cases, monkeypatch, name, text, time_field)
    held = [s for _, s in cluster.docs(index)]
    assert len(held) == 2 and all(s.get("vhir.id_scheme") == 2 for s in held)
    assert rids(cluster, index) == RIDS[case]


def test_the_same_file_again_adds_nothing(cluster, cases, monkeypatch):
    index = ingest(cluster, cases, monkeypatch, "ecs.jsonl", jl(ECS))
    first = sorted(cluster.store)
    ingest(cluster, cases, monkeypatch, "ecs.jsonl", jl(ECS))
    assert sorted(cluster.store) == first and rids(cluster, index) == RIDS["a-json"]


def test_true_duplicates_are_still_one_record(cluster, cases, monkeypatch):
    index = ingest(cluster, cases, monkeypatch, "dup.jsonl", jl([ECS[0], ECS[0]]))
    assert len(cluster.docs(index)) == 1


# ids measured at e0adcc0 for these inputs, unmarked: no literal @timestamp
NO_LITERAL = {
    ("plain.jsonl", None): (jl([
        {"timestamp": "2026-10-01T00:00:00Z", "event.action": "a", "user": "bob"},
        {"timestamp": "2026-10-01T00:01:00Z", "event.action": "a", "user": "bob"}]),
        ["86576d67379b530d7b03", "95e4dd5c9a100d6507d4"]),
    ("velo.jsonl", None): (jl([{"Timestamp": 1759276800, "Name": "x"},
                               {"Timestamp": 1759276860, "Name": "x"}]),
                           ["5069fb5142f86450e5ba", "7c0d362d632692633912"]),
    ("events.csv", "when"): ("when,what\n2026-01-01T00:00:00Z,a\n2026-01-01T00:00:01Z,b\n",
                             ["4674bf3e41035d6424d2", "e8bfc11be90ba54f8b1e"]),
    ("nulls.jsonl", None): (jl([
        {"@timestamp": None, "event.action": "x", "user": "bob"},
        {"@timestamp": None, "event.action": "x", "user": "eve"},
        {"@timestamp": "", "event.action": "y", "user": "bob"},
        {"@timestamp": "", "event.action": "y", "user": "eve"}]),
        ["269ce4d258f03595d44b", "2a9acb278eb026148da3", "c09030ff3a65bde6d732",
         "c6a126b1729e77a8c323"]),
    ("nulls.csv", None): ("@timestamp,event.action,user\n,z,bob\n,z,eve\n",
                          ["dc606809307f08d4a890", "efa288b133579706b200"]),
}  # fmt: skip


@pytest.mark.parametrize("name,time_field", list(NO_LITERAL), ids=[n for n, _ in NO_LITERAL])
def test_no_literal_timestamp_keeps_its_0_6_4_id(cluster, cases, monkeypatch, name, time_field):
    """No literal, or a null or empty one: e0adcc0's ids, unmarked."""
    text, expected = NO_LITERAL[(name, time_field)]
    index = ingest(cluster, cases, monkeypatch, name, text, time_field)
    assert rids(cluster, index) == expected
    assert not any("vhir.id_scheme" in s for _, s in cluster.docs(index))


def test_evidence_cannot_carry_the_marker(cluster, cases, monkeypatch):
    """vhir.id_scheme is the stamp's: a row that brings its own is stored
    without it, unless its id changed (then the stamp's own 2)."""
    rows = [
        {"event.action": "a", "vhir.id_scheme": 2},
        {"@timestamp": "2026-10-01T00:00:00Z", "event.action": "b", "vhir.id_scheme": 7},
    ]
    index = ingest(cluster, cases, monkeypatch, "carried.jsonl", jl(rows))
    marks = sorted((s["event.action"], s.get("vhir.id_scheme")) for _, s in cluster.docs(index))
    assert marks == [("a", None), ("b", 2)]


# --- a re-ingest of json and delimited evidence stored before 0.6.5 ---------

FIXTURES = Path(__file__).parent / "fixtures" / "record_ids_064"


def step_064(cluster, cases, monkeypatch, reverse=False) -> dict:
    """Step 1, as every version runs it (run under e0adcc0 to make the
    fixture): the json and csv twins, the rows differing only in time.
    `reverse`: the same rows in the other order."""
    out = {}
    for name, text, _ in (FILES["a-json"], FILES["b-csv"]):
        if reverse:  # a csv keeps its header first
            lines = text.splitlines(keepends=True)
            head = [] if name.endswith(".jsonl") else lines[:1]
            text = "".join(head + lines[len(head) :][::-1])
        out[name] = ingest(cluster, cases, monkeypatch, name, text)
    return out


@pytest.mark.parametrize("reverse", [False, True], ids=["same-order", "other-order"])
def test_a_re_ingest_of_json_and_csv_stored_by_0_6_4_keeps_each_record(
    cluster, cases, monkeypatch, reverse
):
    """0.6.4 kept the first of the two rows (one id); the re-ingest keeps
    that stored record and adds the other, so each row is stored once."""
    for index, _id, version, src in json.loads((FIXTURES / "literal.json").read_text()):
        cluster.store[(index, _id)] = src
        cluster.versions[(index, _id)] = version
        cluster.created.add(index)
    stored = set(cluster.store)
    new_run(*FILL_STATE)
    out = step_064(cluster, cases, monkeypatch, reverse)
    assert stored <= set(cluster.store)
    for index in out.values():
        times = sorted(s["@timestamp"] for _, s in cluster.docs(index))
        assert times == ["2026-10-01T00:00:00Z", "2026-10-01T00:01:00Z"]
    note = {
        t: wc.fill_note(artifact_type=t) for t in (wc.artifact_type_of(i) for i in out.values())
    }
    assert note == {t: f"{t}: {kept(1)}" for t in note}


def test_a_batch_sent_again_keeps_its_mark(cluster, cases, monkeypatch):
    """The carrier is gone after the first send; the stamp keeps its own mark."""
    from sift_common import host_identity

    monkeypatch.setattr(host_identity, "new_machine_key", lambda: MACHINE)
    case = cases / "g2"
    case.mkdir(exist_ok=True)
    (case / "CASE.yaml").write_text(f"case_id: g2\ncase_uuid: {CASE_UUID}\nnaming_version: 2\n")
    wc.set_current(wc.open_unit(case, "evidence/srv1", "srv1", source="evidence folder"))
    index = wc.index_name("json-ecs")
    action = {"_index": index, "_id": "rid-1", "_source": dict(ECS[0]), "_vhir_old_rid": "old-1"}
    with wc.op(step()):
        bulk.flush_bulk(cluster.client(), [action])
        cluster.store.clear()
        bulk.flush_bulk(cluster.client(), [action])  # the same batch, sent again
    ((_, src),) = cluster.docs(index)
    assert src["vhir.id_scheme"] == 2 and "_vhir_old_rid" not in action
