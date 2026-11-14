"""The record header's ECS fields, the paramN values, the user data and the
fields derived from others, as OSS Winlogbeat writes them.

The records are synthetic, in the shapes pyevtx-rs gives.
"""

from __future__ import annotations

import pytest

from opensearch_mcp import normalize
from opensearch_mcp.normalize import normalize_event
from opensearch_mcp.parse_evtx import _normalise_data

AUDITING = "Microsoft-Windows-Security-Auditing"
GUID = "{00000000-0000-0000-0000-000000000001}"
ACTIVITY = "{11111111-1111-1111-1111-111111111111}"


def _record(eid=4740, data=None, provider=AUDITING, channel="Security", **system):
    head = {
        "EventID": eid,
        "Channel": channel,
        "Computer": "WS01.example.test",
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:30:00Z"}},
        "Provider": {"#attributes": {"Name": provider}},
        **system,
    }
    return {"Event": {"System": head, "EventData": data}}


FULL = _record(
    4624,
    {"TargetUserName": "jdoe"},
    Provider={"#attributes": {"Name": AUDITING, "Guid": GUID}},
    Version=2, Level=0, Task=12544, Opcode=0, Keywords="0x80a0000000000000",
    EventRecordID=12345, Correlation={"#attributes": {"ActivityID": ACTIVITY}},
    Execution={"#attributes": {"ProcessID": 676, "ThreadID": 1234}},
)  # fmt: skip
HEADER = {
    "event.provider": AUDITING,
    "event.kind": "event",
    "event.outcome": "success",
    "event.action": "Logon",
    "winlog.task": "Logon",
    "winlog.provider_guid": GUID,
    "winlog.record_id": "12345",
    "winlog.computer_name": "WS01.example.test",
    "winlog.version": 2,
    "winlog.opcode": "Info",
    "winlog.keywords": ["Audit Success", "Classic"],
    "log.level": "information",
    "winlog.activity_id": ACTIVITY,
    "winlog.process.pid": 676,
    "winlog.process.thread.id": 1234,
}


def test_the_header_fields():
    doc = normalize_event(FULL)
    assert {k: doc.get(k) for k in HEADER} == HEADER


def test_a_failure_keyword_is_a_failure_outcome():
    doc = normalize_event(_record(Keywords="0x8090000000000000"))
    assert (doc["event.outcome"], doc["winlog.keywords"]) == (
        "failure",
        ["Audit Failure", "Classic"],
    )


def test_a_minimal_header_leaves_out_what_it_lacks():
    doc = normalize_event(_record())
    absent = ["event.outcome", "winlog.opcode", "winlog.keywords", "winlog.version",
              "winlog.task", "event.action", "winlog.provider_guid", "winlog.record_id",
              "winlog.activity_id", "winlog.process.pid"]  # fmt: skip
    present = (doc["log.level"], doc["event.kind"], doc["event.provider"])
    assert ([k for k in absent if k in doc], present) == ([], ("information", "event", AUDITING))


@pytest.mark.parametrize(
    "system, field",
    [({"Task": 12544}, "winlog.task"), ({"Opcode": 99}, "winlog.opcode"),
     ({"Version": 0}, "winlog.version"), ({"Level": 9}, "log.level")],
    ids=["task-other-provider", "opcode-unknown", "version-zero", "level-unknown"],
)  # fmt: skip
def test_a_code_without_a_name_is_left_out(system, field):
    provider = "Microsoft-Windows-Example" if "Task" in system else AUDITING
    assert field not in normalize_event(_record(provider=provider, **system))


@pytest.mark.parametrize("level, want", [(1, "critical"), (2, "error"), (3, "warning"),
                                         (4, "information"), (5, "verbose")])  # fmt: skip
def test_each_level(level, want):
    assert normalize_event(_record(Level=level))["log.level"] == want


# --- the unnamed <Data> values ---------------------------------------------------


def _event_data(data):
    return normalize_event(_record(data=data))["winlog.event_data"]


def test_unnamed_values_are_params_by_position():
    data = {"Data": {"#text": ["a", "", "c\r\nd"]}}
    assert _event_data(data) == {**data, "param1": "a", "param3": "c\nd"}


def test_a_named_param_keeps_its_value():
    assert _event_data({"Data": {"#text": ["a", "b"]}, "param1": "x"})["param1"] == "x"


def test_a_single_value_is_param1():
    assert _event_data({"Data": "only"})["param1"] == "only"


# --- the user data ---------------------------------------------------------------


def test_user_data_keeps_its_strings_and_its_element_name():
    rec = _record(1102, provider="Microsoft-Windows-Eventlog")
    rec["Event"]["UserData"] = {"LogFileCleared": {
        "#attributes": {"xmlns": "http://example.test/ns"}, "SubjectUserName": "jdoe",
        "SubjectDomainName": "EXAMPLE", "SubjectLogonId": "0x1111111", "Empty": "",
        "Nested": {"a": "b"}}}  # fmt: skip
    want = {"SubjectUserName": "jdoe", "SubjectDomainName": "EXAMPLE",
            "SubjectLogonId": "0x1111111", "xml_name": "LogFileCleared"}  # fmt: skip
    assert normalize_event(rec)["winlog.user_data"] == want


def test_event_data_gives_no_user_data():
    assert "winlog.user_data" not in normalize_event(_record(data={"A": "b"}))


# --- the fields derived from others ------------------------------------------------


def test_a_file_path_gives_its_name_directory_and_extension():
    doc = {"file.path": "C:\\Users\\jdoe\\Desktop\\sample.exe"}
    normalize._derive(doc)
    assert doc == {**doc, "file.name": "sample.exe", "file.directory": "C:\\Users\\jdoe\\Desktop",
                   "file.extension": "exe"}  # fmt: skip


def test_a_file_without_an_extension_has_none():
    doc = {"file.path": "C:\\Windows\\hosts"}
    normalize._derive(doc)
    assert ("file.extension" in doc, doc["file.name"]) == (False, "hosts")


def test_related_values_are_each_named_once():
    doc = {
        "user.name": "jdoe",
        "user.target.name": "jdoe",
        "user.effective.name": "-",
        "source.ip": "192.0.2.10",
        "process.hash.sha256": "ab" * 32,
        "pe.imphash": "cd" * 16,
    }
    normalize._derive(doc)
    assert (doc["related.user"], doc["related.ip"], doc["related.hash"]) == (
        ["jdoe"], ["192.0.2.10"], ["ab" * 32, "cd" * 16])  # fmt: skip


def test_no_related_values_no_related_fields():
    doc = {"user.name": "-"}
    normalize._derive(doc)
    assert [k for k in doc if k.startswith("related.")] == []


# --- which fields own a value: the table's key, the generic lines, the image -------

_CMD = "C:\\Windows\\System32\\cmd.exe"


def test_an_empty_command_line_stays_on_an_id_without_rows():
    assert normalize_event(_record(data={"CommandLine": ""}))["process.command_line"] == ""


@pytest.mark.parametrize("image, exe", [("Image", "process"), ("ParentImage", "process.parent")])
def test_a_present_empty_image_is_kept_and_names_no_process(image, exe):
    data = {image: "", "NewProcessName": _CMD, "ParentProcessName": _CMD}
    doc = normalize_event(_record(data=data))
    assert (doc[f"{exe}.executable"], f"{exe}.name" in doc) == ("", False)


def test_an_absent_image_falls_back_to_the_new_process_name():
    data = {"NewProcessName": _CMD, "ParentProcessName": "C:\\Windows\\explorer.exe"}
    doc = normalize_event(_record(data=data))
    assert (doc["process.name"], doc["process.parent.name"]) == ("cmd.exe", "explorer.exe")


def test_a_keyed_id_takes_the_table_fields_only_from_its_rows():
    """4672 names the account in Subject*: TargetUserName never reaches user.name."""
    data = {"SubjectUserName": "jdoe", "TargetUserName": "asmith", "Image": _CMD}
    doc = normalize_event(_record(4672, data=data))
    popped = [k for k in ("user.effective.name", "process.executable", "process.name") if k in doc]
    assert (doc["user.name"], popped) == ("jdoe", [])


def test_an_object_data_is_kept_and_mirrored_as_text():
    doc = {"winlog.event_data": {"Data": {"#text": ["a", "b"]}, "User": "jdoe"}}
    _normalise_data(doc)
    assert doc["winlog.event_data"] == {"Data": {"#text": ["a", "b"]}, "User": "jdoe",
                                        "Data_raw": "{#text=[a, b]}"}  # fmt: skip
