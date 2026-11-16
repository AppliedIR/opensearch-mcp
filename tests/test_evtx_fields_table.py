"""Security records name who acted, on what, from where, from one table.

normalize_event mapped user.name from TargetUserName and user.effective.name
from SubjectUserName for every event. In a 4688 record TargetUserName is the
new process's account (often "-") and SubjectUserName the creator; in a 4799
record TargetUserName is the group. A table (mappings/evtx_fields.tsv) now
names, per channel, provider and event id (or a list of ids), which payload
field fills which ECS field, through which transform, or a constant. For a
key with rows, every field the table names anywhere comes only from the
table; a key without rows keeps the generic lines, and winlog.event_data is
kept as it was. Old indices are given the template's fields by the install's
patch.

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
TMAP = json.loads(TEMPLATE.read_text())["template"]["mappings"]
TPROPS = TMAP["properties"]
HEADER = ["channel", "provider", "event_id", "target", "sources", "skip", "transform", "cite"]
SEC, AUDITING, EVENTLOG = (
    "Security",
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-Eventlog",
)
TARGETS = [
    "user.name", "user.domain", "user.id",
    "user.effective.name", "user.effective.domain", "user.effective.id",
    "group.name", "group.domain", "group.id",
]  # fmt: skip
# the fields derived after the table (normalize._derive): never a row's target
DERIVED = {"process.name", "process.parent.name", "dll.name", "file.name", "file.directory",
           "file.extension", "registry.hive", "registry.key", "registry.value",
           "related.user", "related.ip", "related.hash"}  # fmt: skip
SID = "winlog.user.identifier"
DOM = "S-1-5-21-1111111111-2222222222-3333333333"
ABSENT = object()


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
# every source field the shipped rows name, once
FULL = {"SubjectUserSid": f"{DOM}-1001", "SubjectUserName": "jdoe", "SubjectDomainName": "EXAMPLE",
        "TargetUserSid": f"{DOM}-1002", "TargetSid": f"{DOM}-1003", "TargetUserName": "asmith",
        "TargetDomainName": "EXAMPLE2", "ProcessId": "0x1111",
        "ProcessName": "C:\\Users\\jdoe\\Desktop\\sample.exe", "IpAddress": "::ffff:192.0.2.10",
        "IpPort": "49152", "WorkstationName": "WKS-EXAMPLE02", "TargetServerName": "SRV-EXAMPLE03",
        "CallerProcessId": "0x2222", "CallerProcessName": "C:\\Users\\jdoe\\Desktop\\caller.exe",
        "ClientProcessId": "4660", "MemberSid": f"{DOM}-1004"}  # fmt: skip
_IDS = (4611, 4616, 4624, 4625, 4634, 4647, 4648, 4672, 4697, 4719, 4720, 4722, 4724, 4725,
        4726, 4728, 4732, 4738, 4756, 4768, 4769, 4798, 4907, 5140, 5379)  # fmt: skip

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
    # a 4799 record without SubjectUserSid: the field it fills is absent
    "R799N": {**_799, **GROUP, "SubjectUserName": "alice", "SubjectDomainName": "WS01"},
    "RG24": {"TargetUserName": "jsmith", "SubjectUserName": "SYSTEM",
             "SubjectDomainName": "NT AUTHORITY", "LogonType": "3"},
    "RGFW": {**_799, **ALICE, **GROUP},
    # a session reconnect: the client's own address and name
    "C4778": {"AccountName": "jdoe", "AccountDomain": "EXAMPLE", "ClientName": "WKS-EXAMPLE04",
              "ClientAddress": "198.51.100.20"},
    "K4771": {"TargetUserName": "asmith", "TargetSid": f"{DOM}-1003", "IpAddress": "-",
              "IpPort": "0"},
    "N4776": {"TargetUserName": "asmith", "Workstation": "WKS-EXAMPLE05"},
    **{f"F{eid}": FULL for eid in _IDS},
}  # fmt: skip
RECORDS = {
    "R688D": _record(4688, PAYLOADS["R688D"]),
    "R688T": _record(4688, PAYLOADS["R688T"]),
    "R799": _record(4799, PAYLOADS["R799"]),
    "R799S": _record(4799, PAYLOADS["R799S"]),
    "R799N": _record(4799, PAYLOADS["R799N"]),
    "RG24": _record(4740, PAYLOADS["RG24"]),  # an id without rows
    "RGFW": _record(4799, PAYLOADS["RGFW"], channel="ForwardedEvents"),
    "C4778": _record(4778, PAYLOADS["C4778"]),
    "C4779": _record(4779, PAYLOADS["C4778"]),
    "K4771": _record(4771, PAYLOADS["K4771"]),
    "N4776": _record(4776, PAYLOADS["N4776"]),
    **{f"F{eid}": _record(eid, FULL) for eid in _IDS},
}
# a log cleared: its fields are in UserData
U1102 = _record(1102, None, provider=EVENTLOG)
U1102["Event"]["UserData"] = {
    "LogFileCleared": {
        "#attributes": {"xmlns": "http://example.test/ns"},
        "SubjectUserSid": f"{DOM}-1001",
        "SubjectUserName": "jdoe",
        "SubjectDomainName": "EXAMPLE",
        "SubjectLogonId": "0x1111111",
    }
}
ALL = {**RECORDS, "U1102": U1102}  # fmt: skip

ROWS = [
    ("d-name", "R688D", "user.name", "alice"),
    ("d-domain", "R688D", "user.domain", "WS01"),
    ("d-id", "R688D", "user.id", f"{DOM}-1001"),
    ("d-eff-absent", "R688D", ("user.effective.name",), ABSENT),
    ("d-effdom-absent", "R688D", ("user.effective.domain",), ABSENT),
    ("d-effid-absent", "R688D", ("user.effective.id",), ABSENT),
    ("d-proc", "R688D", "process.name", "cmd.exe"),
    ("d-exe", "R688D", "process.executable", "C:\\Windows\\System32\\cmd.exe"),
    ("d-pid", "R688D", "process.pid", 0x1A2C),
    ("d-cmd", "R688D", "process.command_line", "cmd.exe /c whoami"),
    ("d-ppid", "R688D", "process.parent.pid", 0x4F0),
    ("d-pexe", "R688D", "process.parent.executable", "C:\\Windows\\explorer.exe"),
    ("d-pname", "R688D", "process.parent.name", "explorer.exe"),
    ("d-cat", "R688D", "event.category", "process"),
    ("d-type", "R688D", "event.type", "start"),
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
    ("g-pid", "R799", "process.pid", 0x1B40),
    ("g-type", "R799", "event.type", ["group", "info"]),
    ("s-name-absent", "R799S", ("user.name",), ABSENT),
    ("s-domain-absent", "R799S", ("user.domain",), ABSENT),
    ("s-group", "R799S", "group.name", "Administrators"),
    ("n-id-absent", "R799N", ("user.id",), ABSENT),
    ("n-name", "R799N", "user.name", "alice"),
    ("u-name", "RG24", "user.name", "jsmith"),
    ("u-eff", "RG24", "user.effective.name", "SYSTEM"),
    ("u-no-new", "RG24", ("user.domain", "user.id", "group.name", "group.domain", "group.id",
                          "event.category", "event.type"), ABSENT),
    ("k-exact", "RGFW", ("group.name", "user.domain"), ABSENT),
    # the subject families
    ("s-actor", "F4720", "user.name", "jdoe"),
    ("s-actordom", "F4732", "user.domain", "EXAMPLE"),
    ("s-actorid", "F5140", "user.id", f"{DOM}-1001"),
    ("l-actor", "F4624", "user.name", "asmith"),
    ("l-actordom", "F4769", "user.domain", "EXAMPLE2"),
    ("l-actorid", "F4634", "user.id", f"{DOM}-1002"),
    ("l-actorsid", "K4771", "user.id", f"{DOM}-1003"),  # the second source
    ("l-no-subject", "F4624", ("user.effective.name",), ABSENT),
    ("r-actor", "C4778", "user.name", "jdoe"),
    ("r-actordom", "C4779", "user.domain", "EXAMPLE"),
    ("e-actor", "U1102", "user.name", "jdoe"),
    ("e-actordom", "U1102", "user.domain", "EXAMPLE"),
    ("e-actorid", "U1102", "user.id", f"{DOM}-1001"),
    # process, network and run-as
    ("p-pid", "F4624", "process.pid", 0x1111),
    ("p-exe", "F4907", "process.executable", "C:\\Users\\jdoe\\Desktop\\sample.exe"),
    ("p-name", "F4907", "process.name", "sample.exe"),
    ("p-caller", "F4798", "process.executable", "C:\\Users\\jdoe\\Desktop\\caller.exe"),
    ("p-client", "F5379", "process.pid", 4660),
    ("n-ip", "F4648", "source.ip", "192.0.2.10"),  # the IPv4-mapped form
    ("n-client-ip", "C4778", "source.ip", "198.51.100.20"),
    ("n-port", "F4625", "source.port", 49152),
    ("n-skipped", "K4771", ("source.ip", "source.port"), ABSENT),
    ("n-wks", "F4624", "source.domain", "WKS-EXAMPLE02"),
    ("n-ntlm-wks", "N4776", "source.domain", "WKS-EXAMPLE05"),
    ("n-client", "C4779", "source.domain", "WKS-EXAMPLE04"),
    ("n-dest", "F4648", "destination.domain", "SRV-EXAMPLE03"),
    ("x-eff", "F4648", "user.effective.name", "asmith"),
    ("x-effdom", "F4648", "user.effective.domain", "EXAMPLE2"),
    # accounts and groups changed
    ("a-target", "F4726", "user.target.name", "asmith"),
    ("a-targetdom", "F4738", "user.target.domain", "EXAMPLE2"),
    ("a-targetid", "F4720", "user.target.id", f"{DOM}-1003"),
    ("m-group", "F4728", "group.name", "asmith"),
    ("m-groupdom", "F4756", "group.domain", "EXAMPLE2"),
    ("m-groupid", "F4732", "group.id", f"{DOM}-1003"),
    ("m-member", "F4732", "user.target.id", f"{DOM}-1004"),
    # the constants
    ("c-auth", "F4624", "event.category", "authentication"),
    ("c-iam", "F4672", "event.category", "iam"),
    ("c-config", "F4697", "event.category", "configuration"),
    ("c-share", "F5140", "event.category", ["network", "file"]),
    ("c-cleared", "U1102", "event.category", "configuration"),
    ("c-start", "F4768", "event.type", "start"),
    ("c-end", "F4647", "event.type", "end"),
    ("c-admin", "F4672", "event.type", "admin"),
    ("c-change", "F4719", "event.type", "change"),
    ("c-install", "F4697", "event.type", "installation"),
    ("c-create", "F4720", "event.type", ["user", "creation"]),
    ("c-uchange", "F4725", "event.type", ["user", "change"]),
    ("c-delete", "F4726", "event.type", ["user", "deletion"]),
    ("c-gchange", "F4756", "event.type", ["group", "change"]),
    ("c-uinfo", "F4798", "event.type", ["user", "info"]),
    ("c-access", "F5379", "event.type", "access"),
    ("c-deletion", "U1102", "event.type", "deletion"),
]  # fmt: skip


@pytest.mark.parametrize("rec, field, want", [r[1:] for r in ROWS], ids=[r[0] for r in ROWS])
def test_each_record_names_who_acted(rec, field, want):
    doc = normalize_event(ALL[rec])
    if want is ABSENT:
        assert {f: doc[f] for f in field if f in doc} == {}
    else:
        assert doc.get(field) == want


@pytest.mark.parametrize("rec", list(RECORDS), ids=[f"raw-{r}" for r in RECORDS])
def test_the_event_data_is_kept_as_it_was(rec):
    sent = RECORDS[rec]["Event"]["EventData"]
    assert normalize_event(RECORDS[rec])["winlog.event_data"] == sent


def test_an_empty_command_line_is_absent_where_a_row_writes_it():
    doc = normalize_event(_record(4688, {**PAYLOADS["R688D"], "CommandLine": ""}))
    assert "process.command_line" not in doc


def test_a_source_its_transform_makes_nothing_of_gives_way_to_the_next():
    """IpAddress "::" is not a skip value, but no address: source.ip is the
    row's next source, ClientAddress."""
    doc = normalize_event(_record(4778, {**PAYLOADS["C4778"], "IpAddress": "::"}))
    assert doc["source.ip"] == "198.51.100.20"


@pytest.mark.parametrize("rec", list(ALL))
def test_every_field_written_is_in_the_template(rec):
    doc = normalize_event(ALL[rec])
    objects = ("winlog.event_data", "winlog.user_data")  # their fields: the template's rules
    assert [f for f in doc if f not in TPROPS and f not in objects] == []


def _table_rows():
    """The shipped table's rows as lists of cells, or None when it is missing."""
    if not TSV.is_file():
        return None
    return [line.split("\t") for line in TSV.read_text().splitlines() if line]


def test_table_covered():
    """Every row of the table has a row above that expects a value from it."""
    rows = _table_rows()
    expected = set()
    for _, rec, field, want in ROWS:
        system = ALL[rec]["Event"]["System"]
        if want is not ABSENT:
            provider = system["Provider"]["#attributes"]["Name"]
            expected.add((system["Channel"], provider, system["EventID"], field))
    assert rows is not None
    uncovered = [
        c for c in rows[1:]
        if len(c) > 3 and not any((c[0], c[1], int(i), c[3]) in expected for i in c[2].split(","))
    ]  # fmt: skip
    assert uncovered == []


def test_table_valid():
    rows = _table_rows()
    problems = ["no table"] if rows is None else []
    if rows is not None:
        if rows[0] != HEADER:
            problems.append(f"header {rows[0]}")
        for n, cells in enumerate(rows[1:], 2):
            if len(cells) != 8:
                problems.append(f"line {n}: {len(cells)} cells")
            elif (
                cells[6] not in normalize._TRANSFORMS
                or not cells[7].strip()
                or not all(i.isdigit() for i in cells[2].split(","))
            ):
                problems.append(f"line {n}: {cells}")
        problems += [] if len(rows) > 1 else ["no rows"]
    assert problems == []


def test_every_target_is_in_the_template_and_none_is_derived():
    targets = {c[3] for c in _table_rows()[1:]}
    assert (sorted(targets - set(TPROPS)), sorted(targets & DERIVED)) == ([], [])


@pytest.mark.parametrize("target", TARGETS)
def test_template_keyword(target):
    assert TPROPS.get(target, {}).get("type") == "keyword"


# --- what each transform makes of a value -----------------------------------

TRANSFORMS = [
    ("none", "-x-", "-x-"), ("hex", "0x1a2c", 0x1A2C), ("hex", "1A2C", 0x1A2C),
    ("hex", "zz", None), ("int", "4660", 4660), ("int", "0x10", 16),
    ("int", {"#text": "5"}, 5), ("int", "x", None), ("bool", "true", True),
    ("bool", "FALSE", False), ("bool", "1", None), ("lower", "ExAmple", "example"),
    ("ip", "::ffff:192.0.2.10", "192.0.2.10"), ("ip", "2001:db8::10", "2001:db8::10"),
    ("ip", " 192.0.2.10 ", "192.0.2.10"), ("ip", "-", None), ("ip", "LOCAL", None),
    ("ip", "not-an-ip", "not-an-ip"), ("name", "EXAMPLE\\jdoe", "jdoe"),
    ("name", "jdoe", "jdoe"), ("name", "EXAMPLE\\", None),
    ("domain", "EXAMPLE\\jdoe", "EXAMPLE"), ("domain", "jdoe", None),
]  # fmt: skip


@pytest.mark.parametrize("name, value, want", TRANSFORMS)
def test_each_transform(name, value, want):
    assert normalize._TRANSFORMS[name](value) == want


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
    "transform": GOOD.replace("\tnone\t", "\tupper\t"),
    "no-cite": GOOD.replace("MSL4688", ""),
    "eid-not-int": GOOD.replace("\t4688\t", "\t46x8\t"),
    "eid-list-not-int": GOOD.replace("\t4688\t", "\t4688,x\t"),
    "repeated-target": GOOD + GOOD.split("\n", 1)[1],
    # a list naming an id that has its own row for the same target
    "list-repeats-single": GOOD + GOOD.split("\n", 1)[1].replace("\t4688\t", "\t4689,4688\t"),
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


def test_the_loader_gives_each_listed_id_the_row(tmp_path):
    path = tmp_path / "evtx_fields.tsv"
    path.write_text(GOOD.replace("\t4688\t", "\t4688,4689\t"))
    table = normalize.load_fields_table(path)
    assert sorted(table) == [(SEC, AUDITING, 4688), (SEC, AUDITING, 4689)]


# --- the install's patch maps the template's fields on an old index ------------

LIMIT = "illegal_argument_exception: Limit of total fields [61] exceeded"
UD_RULE, EVTX_RULE = "winlog_user_data_strings", "winlog_event_data_strings"
UD = next(e for e in TMAP["dynamic_templates"] if UD_RULE in e)
FIELDS = [f for f in TPROPS if f != SID]
NEW = [f for f in FIELDS if f != "event.code"]  # what an index mapping only event.code lacks


def _own(limit):
    """An index's own event-data rule, from before the rule copied its values."""
    mapping = {"type": "keyword", "ignore_above": limit}
    return {EVTX_RULE: {"path_match": "winlog.event_data.*", "match_mapping_type": "string",
                        "mapping": mapping}}  # fmt: skip


def _nested(fields):
    """put_mapping properties mapping each dotted field as the template does."""
    out: dict = {}
    for f in fields:
        node = out
        *parents, leaf = f.split(".")
        for p in parents:
            node = node.setdefault(p, {}).setdefault("properties", {})
        node.setdefault(leaf, {}).update(TPROPS[f])
    return out


def _index(*fields, sid=True, rules=()):
    props = _nested(["event.code", *fields, *([SID] if sid else [])])
    if "group.name" in fields:  # mapped by dynamic mapping, not as the template does
        props["group"]["properties"]["name"] = {
            "type": "text",
            "fields": {"keyword": {"type": "keyword"}},
        }
    rules = {"dynamic_templates": list(rules)} if rules else {}
    return {"mappings": {"properties": props, **rules}}


def _paths(props, prefix=""):
    """{dotted path: its mapping} for every node `props` maps."""
    out = {}
    for name, m in props.items():
        out[prefix + name] = m
        if isinstance(m.get("properties"), dict):
            out.update(_paths(m["properties"], f"{prefix}{name}."))
    return out


def fields_put(index):
    """The template's fields (all but the header SID) an index's mapping lacks,
    and the put mapping them: a field counts as mapped when its path is, or a
    parent is mapped as a leaf."""
    have = _paths(index["mappings"].get("properties", {}))

    def mapped(f):
        parts = f.split(".")
        parents = [".".join(parts[:n]) for n in range(1, len(parts))]
        leaf = [
            p for p in parents if have.get(p, {}).get("type") not in (None, "object", "nested")
        ]
        return f in have or bool(leaf)

    missing = [f for f in FIELDS if not mapped(f)]
    return missing, {"properties": _nested(missing)}


# the template's fields added with the table's ECS fields
ECS_NEW = [
    "event.provider", "winlog.provider_guid", "winlog.record_id", "winlog.computer_name",
    "winlog.version", "winlog.task", "event.action", "winlog.opcode", "winlog.keywords",
    "event.outcome", "log.level", "event.kind", "winlog.activity_id",
    "winlog.related_activity_id", "winlog.process.pid", "winlog.process.thread.id",
    "winlog.user_data.xml_name", "user.target.name", "user.target.domain", "user.target.id",
    "process.pid", "process.executable", "process.parent.pid", "process.parent.executable",
    "source.port", "source.domain", "destination.domain", "event.category", "event.type",
    "related.user", "related.ip", "related.hash", "file.name", "file.directory",
    "file.extension",
]  # fmt: skip


def _patch(indices, refuse=False):
    """patch_evtx_indices over `indices`; with `refuse`, a put of the template's
    fields is refused at the field limit."""
    sent = []

    def put(index, body):
        sent.append((index, body))
        if refuse and "event" in body.get("properties", {}):
            raise RuntimeError(LIMIT)

    c = MagicMock()
    c.indices.get_mapping.return_value = indices
    c.indices.put_mapping.side_effect = put
    with patch.object(mappings, "_low_event_data", return_value=({}, {})):
        return mappings.patch_evtx_indices(c), sent


IDX = "case-a-evtx-0"


def test_patch_old_index_is_given_every_template_field():
    result, sent = _patch({IDX: _index()})
    want = [(IDX, {"dynamic_templates": [UD]}), (IDX, {"properties": _nested(NEW)})]
    assert (sent, result["patched"]) == (want, {IDX: [UD_RULE, *NEW]})


def test_patch_sends_only_the_fields_not_mapped_yet():
    """user.name and user.effective.name keyword as the template maps them,
    group.name as a dynamic text field: none of the three is sent again."""
    mapped = ["user.name", "user.effective.name", "group.name"]
    result, sent = _patch({IDX: _index(*mapped, rules=[UD])})
    rest = [f for f in NEW if f not in mapped]
    assert (sent, result["patched"]) == ([(IDX, {"properties": _nested(rest)})], {IDX: rest})


def test_patch_a_parent_mapped_as_a_leaf_is_given_no_sub_field():
    index = _index(rules=[UD])
    index["mappings"]["properties"]["user"] = {"properties": {"target": {"type": "keyword"}}}
    result, _ = _patch({IDX: index})
    assert [f for f in result["patched"][IDX] if f.startswith("user.target.")] == []


def test_a_field_under_a_parent_mapped_as_a_leaf_counts_as_mapped():
    leaf = {"properties": {"user": {"properties": {"target": {"type": "keyword"}}}}}
    assert mappings._mapped(leaf, "user.target.name")
    assert not mappings._mapped({"properties": {"user": {"properties": {}}}}, "user.target.name")


def test_patch_an_index_with_every_field_and_rule_is_sent_nothing():
    result, sent = _patch({IDX: _index(*NEW, rules=[_own(8191), UD])})
    assert (sent, result["unchanged"]) == ([], [IDX])


@pytest.mark.parametrize("limit, raised", [(8191, []), (1024, [EVTX_RULE])], ids=["at", "below"])
def test_patch_the_user_data_rule_reaches_an_old_index(limit, raised):
    """At the limits (no put without the rule) and below them (the raise and
    the rule in one put), the index's own rule kept, the template's appended."""
    result, sent = _patch({IDX: _index(*NEW, rules=[_own(limit)])})
    want = [(IDX, {"dynamic_templates": [_own(8191), UD]})]
    assert (sent, result["patched"]) == (want, {IDX: [*raised, UD_RULE]})


def test_patch_a_refused_put_is_named_with_its_fields():
    result, _ = _patch({IDX: _index()}, refuse=True)
    assert (result["patched"], result["failed"]) == (
        {IDX: [UD_RULE]}, [{"index": IDX, "error": LIMIT, "fields": NEW}])  # fmt: skip


def test_patch_a_refused_put_never_costs_the_header_sid():
    result, sent = _patch({IDX: _index(sid=False)}, refuse=True)
    want = {"properties": _nested(NEW)}
    assert (result["patched"], [b for _, b in sent][-1]) == ({IDX: [UD_RULE, SID]}, want)
