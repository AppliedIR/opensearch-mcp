"""Security 4688 and 4799 records name who acted in user.*, from one table.

normalize_event mapped user.name from TargetUserName and user.effective.name
from SubjectUserName for every event. In a 4688 record TargetUserName is the
new process's account (often "-") and SubjectUserName the creator; in a 4799
record TargetUserName is the group. A table (mappings/evtx_fields.tsv) now
names, per channel, provider and event id, which payload field fills which
ECS field. For a key with rows, every field the table names anywhere comes
only from the table; a key without rows keeps the generic lines, and
winlog.event_data is kept as it was. Old indices are given the new fields'
mapping by the install's patch.

The records are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import mappings, normalize
from opensearch_mcp.normalize import normalize_event

SRC = Path(normalize.__file__).resolve().parent
TSV = SRC / "mappings" / "evtx_fields.tsv"
TEMPLATE = SRC / "mappings" / "evtx_ecs_template.json"
HEADER = ["channel", "provider", "event_id", "target", "sources", "skip", "transform", "cite"]
SEC, AUDITING = "Security", "Microsoft-Windows-Security-Auditing"
# every field the table names, in the order it first names them
TARGETS = [
    "user.name", "user.domain", "user.id",
    "user.effective.name", "user.effective.domain", "user.effective.id",
    "group.name", "group.domain", "group.id",
]  # fmt: skip
SID = "winlog.user.identifier"
DOM = "S-1-5-21-1111111111-2222222222-3333333333"
ABSENT = object()


def _nested(fields):
    """put_mapping properties mapping each dotted field `keyword`."""
    out: dict = {}
    for f in fields:
        node = out
        *parents, leaf = f.split(".")
        for p in parents:
            node = node.setdefault(p, {"properties": {}})["properties"]
        node[leaf] = {"type": "keyword"}
    return out


USER_PUT = {"properties": _nested(TARGETS)}


def _record(eid, data, channel=SEC, provider=AUDITING):
    system = {
        "EventID": eid,
        "Channel": channel,
        "Computer": "WS01",
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:30:00Z"}},
        "Provider": {"#attributes": {"Name": provider}},
    }
    return {"Event": {"System": system, "EventData": data}}


_688 = {"SubjectLogonId": "0x3e7", "NewProcessId": "0x1a2c", "TokenElevationType": "%%1936",
        "ProcessId": "0x4f0", "CommandLine": "cmd.exe /c whoami", "TargetLogonId": "0x0",
        "ParentProcessName": "C:\\Windows\\explorer.exe",
        "MandatoryLabel": "S-1-16-12288"}  # fmt: skip
_799 = {"SubjectLogonId": "0x5c1d2", "CallerProcessId": "0x1b40",
        "CallerProcessName": "C:\\Windows\\System32\\net1.exe"}  # fmt: skip
ALICE = {"SubjectUserSid": f"{DOM}-1001", "SubjectUserName": "alice", "SubjectDomainName": "WS01"}
GROUP = {"TargetUserName": "Administrators", "TargetDomainName": "Builtin",
         "TargetSid": "S-1-5-32-544"}  # fmt: skip

PAYLOADS = {
    # a process created under the creator's own token: no target account
    "R688D": {**_688, **ALICE, "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
              "TargetUserSid": "S-1-0-0", "TargetUserName": "-", "TargetDomainName": "-"},
    # a process created by the computer account for another account
    "R688T": {**_688, "SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS01$",
              "SubjectDomainName": "WORKGROUP", "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
              "TargetUserSid": f"{DOM}-1002", "TargetUserName": "bob", "TargetDomainName": "WS01"},
    "R799": {**_799, **ALICE, **GROUP},
    "R799S": {**_799, **GROUP, "SubjectUserSid": "-", "SubjectUserName": "-",
              "SubjectDomainName": ""},
    "RG24": {"TargetUserName": "jsmith", "SubjectUserName": "SYSTEM",
             "SubjectDomainName": "NT AUTHORITY", "LogonType": "3"},
    "RGFW": {**_799, **ALICE, **GROUP},
}  # fmt: skip
RECORDS = {
    "R688D": _record(4688, PAYLOADS["R688D"]),
    "R688T": _record(4688, PAYLOADS["R688T"]),
    "R799": _record(4799, PAYLOADS["R799"]),
    "R799S": _record(4799, PAYLOADS["R799S"]),
    "RG24": _record(4624, PAYLOADS["RG24"]),
    "RGFW": _record(4799, PAYLOADS["RGFW"], channel="ForwardedEvents"),
}

ROWS = [
    ("d-name", "R688D", "user.name", "alice"),
    ("d-domain", "R688D", "user.domain", "WS01"),
    ("d-id", "R688D", "user.id", f"{DOM}-1001"),
    ("d-eff-absent", "R688D", ("user.effective.name",), ABSENT),
    ("d-effdom-absent", "R688D", ("user.effective.domain",), ABSENT),
    ("d-effid-absent", "R688D", ("user.effective.id",), ABSENT),
    ("d-proc", "R688D", "process.name", "C:\\Windows\\System32\\cmd.exe"),
    ("t-name", "R688T", "user.name", "WS01$"),
    ("t-eff", "R688T", "user.effective.name", "bob"),
    ("t-effdom", "R688T", "user.effective.domain", "WS01"),
    ("t-effid", "R688T", "user.effective.id", f"{DOM}-1002"),
    ("g-name", "R799", "user.name", "alice"),
    ("g-domain", "R799", "user.domain", "WS01"),
    ("g-id", "R799", "user.id", f"{DOM}-1001"),
    ("g-group", "R799", "group.name", "Administrators"),
    ("g-groupdom", "R799", "group.domain", "Builtin"),
    ("g-groupid", "R799", "group.id", "S-1-5-32-544"),
    ("g-eff-absent", "R799", ("user.effective.name",), ABSENT),
    ("s-name-absent", "R799S", ("user.name",), ABSENT),
    ("s-domain-absent", "R799S", ("user.domain",), ABSENT),
    ("s-group", "R799S", "group.name", "Administrators"),
    ("u-name", "RG24", "user.name", "jsmith"),
    ("u-eff", "RG24", "user.effective.name", "SYSTEM"),
    ("u-no-new", "RG24", ("user.domain", "user.id", "group.name", "group.domain", "group.id"),
     ABSENT),
    ("k-exact", "RGFW", ("group.name", "user.domain"), ABSENT),
]  # fmt: skip


@pytest.mark.parametrize("rec, field, want", [r[1:] for r in ROWS], ids=[r[0] for r in ROWS])
def test_each_record_names_who_acted(rec, field, want):
    doc = normalize_event(RECORDS[rec])
    if want is ABSENT:
        assert {f: doc[f] for f in field if f in doc} == {}
    else:
        assert doc.get(field) == want


@pytest.mark.parametrize("rec", list(RECORDS), ids=[f"raw-{r}" for r in RECORDS])
def test_the_event_data_is_kept_as_it_was(rec):
    assert normalize_event(RECORDS[rec])["winlog.event_data"] == PAYLOADS[rec]


def _table_rows():
    """The shipped table's rows as lists of cells, or None when it is missing."""
    if not TSV.is_file():
        return None
    return [line.split("\t") for line in TSV.read_text().splitlines() if line]


def test_table_covered():
    """Every (key, target) the table maps has a row above that expects a value."""
    rows = _table_rows()
    systems = {r: RECORDS[r]["Event"]["System"] for r in RECORDS}
    expected = {
        (systems[r]["EventID"], f)
        for _, r, f, w in ROWS
        if w is not ABSENT and systems[r]["Channel"] == SEC
    }
    pairs = None if rows is None else {(int(c[2]), c[3]) for c in rows[1:] if len(c) > 3}
    assert pairs is not None and pairs - expected == set()


def test_table_valid():
    rows = _table_rows()
    problems = ["no table"] if rows is None else []
    if rows is not None:
        if rows[0] != HEADER:
            problems.append(f"header {rows[0]}")
        for n, cells in enumerate(rows[1:], 2):
            if len(cells) != 8:
                problems.append(f"line {n}: {len(cells)} cells")
            elif cells[6] != "none" or not cells[7].strip() or not cells[2].isdigit():
                problems.append(f"line {n}: {cells}")
        problems += [] if len(rows) > 1 else ["no rows"]
    assert problems == []


@pytest.mark.parametrize("target", TARGETS)
def test_template_keyword(target):
    t = json.loads(TEMPLATE.read_text())
    assert t["template"]["mappings"]["properties"].get(target, {}).get("type") == "keyword"


# --- the loader refuses a bad table rather than run without one ---------------

GOOD = (
    "\t".join(HEADER)
    + "\n"
    + "\t".join([SEC, AUDITING, "4688", "user.name", "SubjectUserName", "-", "none", "MSL4688"])
    + "\n"
)
BAD = {
    "bad-header": GOOD.replace("\ttarget\t", "\ttargets\t", 1),
    "short-row": GOOD.replace("\tnone\tMSL4688", "\tnone"),
    "transform": GOOD.replace("\tnone\t", "\tlower\t"),
    "no-cite": GOOD.replace("MSL4688", ""),
    "eid-not-int": GOOD.replace("\t4688\t", "\t46x8\t"),
    "repeated-target": GOOD + GOOD.split("\n", 1)[1],
    "no-rows": GOOD.split("\n", 1)[0] + "\n",
}  # fmt: skip


def _outcome(path):
    loader = getattr(normalize, "load_fields_table", None)
    try:
        loader(path)
    except ValueError:
        return "ValueError"
    except Exception as e:  # noqa: BLE001 - the row names what else happened
        return type(e).__name__
    return "loaded"


@pytest.mark.parametrize("text", list(BAD.values()), ids=list(BAD))
def test_the_loader_refuses_a_bad_table(text, tmp_path):
    path = tmp_path / "evtx_fields.tsv"
    path.write_text(text)
    assert _outcome(path) == "ValueError"


def test_the_loader_reads_a_good_table(tmp_path):
    path = tmp_path / "evtx_fields.tsv"
    path.write_text(GOOD)
    assert _outcome(path) == "loaded"


# --- the install's patch maps the table's fields on an old index --------------

LIMIT = "illegal_argument_exception: Limit of total fields [61] exceeded"


def _index(*fields, sid=True):
    props = {"event": {"properties": {"code": {"type": "integer"}}}}
    for f in fields:
        node = props
        *parents, leaf = f.split(".")
        for p in parents:
            node = node.setdefault(p, {"properties": {}})["properties"]
        node[leaf] = {"type": "text", "fields": {"keyword": {"type": "keyword"}}} if (
            f == "group.name") else {"type": "keyword"}  # fmt: skip
    if sid:
        winlog = props.setdefault("winlog", {"properties": {}})["properties"]
        winlog["user"] = {"properties": {"identifier": {"type": "keyword"}}}
    return {"mappings": {"properties": props}}


def _patch(indices, refuse=False):
    """patch_evtx_indices over `indices`; with `refuse`, a put of the table's
    fields is refused at the field limit."""
    sent = []

    def put(index, body):
        sent.append((index, body))
        if refuse and "winlog" not in body.get("properties", {}):
            raise RuntimeError(LIMIT)

    c = MagicMock()
    c.indices.get_mapping.return_value = indices
    c.indices.put_mapping.side_effect = put
    with patch.object(mappings, "_low_event_data", return_value=({}, {})):
        return mappings.patch_evtx_indices(c), sent


IDX = "case-a-evtx-0"
PARTIAL = ["user.domain", "user.id", "user.effective.domain", "user.effective.id",
           "group.domain", "group.id"]  # fmt: skip


def test_patch_old_index_is_given_every_table_field():
    result, sent = _patch({IDX: _index()})
    assert (sent, result["patched"]) == ([(IDX, USER_PUT)], {IDX: TARGETS})


def test_patch_sends_only_the_fields_not_mapped_yet():
    """user.name and user.effective.name keyword as the template maps them,
    group.name as a dynamic text field: none of the three is sent again."""
    result, sent = _patch({IDX: _index("user.name", "user.effective.name", "group.name")})
    want = [(IDX, {"properties": _nested(PARTIAL)})]
    assert (sent, result["patched"]) == (want, {IDX: PARTIAL})


def test_patch_an_index_with_every_field_is_sent_nothing():
    result, sent = _patch({IDX: _index(*TARGETS)})
    assert (sent, result["unchanged"]) == ([], [IDX])


def test_patch_a_refused_put_is_named_with_its_fields():
    result, _ = _patch({IDX: _index()}, refuse=True)
    assert (result["patched"], result["failed"]) == (
        {}, [{"index": IDX, "error": LIMIT, "fields": TARGETS}])  # fmt: skip


def test_patch_a_refused_put_never_costs_the_header_sid():
    result, sent = _patch({IDX: _index(sid=False)}, refuse=True)
    assert (result["patched"], [b for _, b in sent][-1]) == ({IDX: [SID]}, USER_PUT)
