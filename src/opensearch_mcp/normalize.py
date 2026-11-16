"""Normalize pyevtx-rs JSON output to ECS fields for OpenSearch indexing."""

from __future__ import annotations

import ipaddress
import ntpath
from pathlib import Path

_INVALID_IPS = {"", "-", "LOCAL", "::"}
_AUDITING = "Microsoft-Windows-Security-Auditing"
_AUDIT_FAILURE, _AUDIT_SUCCESS = 0x10000000000000, 0x20000000000000
# The standard keyword bits, levels and opcodes every provider shares: OSS
# Winlogbeat's defaultWinMeta (sys/winevent/winmeta.go, Apache-2.0), from the
# Windows SDK's winmeta.xml.
_KEYWORDS = {
    0x1000000000000: "Response Time",
    0x4000000000000: "WDI Diag",
    0x8000000000000: "SQM",
    _AUDIT_FAILURE: "Audit Failure",
    _AUDIT_SUCCESS: "Audit Success",
    0x40000000000000: "Correlation Hint",
    0x80000000000000: "Classic",
}
_LEVELS = {
    0: "information",
    1: "critical",
    2: "error",
    3: "warning",
    4: "information",
    5: "verbose",
}
_OPCODES = {
    0: "Info",
    1: "Start",
    2: "Stop",
    3: "DCStart",
    4: "DCStop",
    5: "Extension",
    6: "Reply",
    7: "Resume",
    8: "Suspend",
    9: "Send",
}
# Security-Auditing task numbers: the audit subcategory each Microsoft event
# page names, without its leading "Audit "
_TASKS = {
    12288: "Security State Change",
    12289: "Security System Extension",
    12544: "Logon",
    12545: "Logoff",
    12548: "Special Logon",
    12551: "Other Logon/Logoff Events",
    12801: "Registry",
    12804: "Other Object Access Events",
    12808: "File Share",
    12811: "Detailed File Share",
    13312: "Process Creation",
    13313: "Process Termination",
    13568: "Policy Change",
    13570: "Authorization Policy Change",
    13824: "User Account Management",
    13826: "Security Group Management",
    14336: "Credential Validation",
    14337: "Kerberos Service Ticket Operations",
    14339: "Kerberos Authentication Service",
}
_FIELDS_HEADER = [
    "channel",
    "provider",
    "event_id",
    "target",
    "sources",
    "skip",
    "transform",
    "cite",
]


def _num(value) -> int | None:
    """An integer written in decimal or as 0x hex, else None."""
    text = str(value.get("#text") if isinstance(value, dict) else value).strip()
    try:
        return int(text, 16) if text[:2].lower() == "0x" else int(text)
    except ValueError:
        return None


def _long(value) -> int | None:
    """_num's integer when a long field holds it, else None: the field is left
    unwritten and the raw value stays in the event data (a larger number would
    cost its record at the long field, or every later record at serialisation)."""
    number = _num(value)
    return number if number is not None and -(2**63) <= number < 2**63 else None


def _split(value) -> tuple[str, str]:
    """DOMAIN\\name as (domain, name); a value without a backslash is a name."""
    domain, sep, name = str(value).partition("\\")
    return (domain, name) if sep else ("", domain)


# What a row's transform makes of a source value; None means no value
_TRANSFORMS = {
    "none": lambda v: v,
    "hex": lambda v: _long(v if str(v).lower().startswith("0x") else f"0x{v}"),
    "int": _long,
    "bool": lambda v: {"true": True, "false": False}.get(str(v).strip().lower()),
    "lower": lambda v: str(v).lower(),
    "ip": lambda v: _clean_ip(str(v)),
    "name": lambda v: _split(v)[1] or None,
    "domain": lambda v: _split(v)[0] or None,
    "const": None,  # the row's sources are the value
}


def load_fields_table(path) -> dict[tuple, list[tuple]]:
    """The evtx fields table: for each (channel, provider, event id), its rows
    (target, sources, values to skip, transform) in file order. A row's event
    id may be a comma list, one row for each id; a const row's sources are its
    value, an array when there are several. Raises ValueError on a table it
    can't trust, never returning an empty one: an empty table would silently
    give every event the generic fields again."""
    lines = [line for line in Path(path).read_text(encoding="utf-8").splitlines() if line]
    if not lines or lines[0].split("\t") != _FIELDS_HEADER:
        raise ValueError(f"{path}: the header isn't {_FIELDS_HEADER}")
    table: dict[tuple, list[tuple]] = {}
    for n, line in enumerate(lines[1:], 2):
        cells = line.split("\t")
        if len(cells) != len(_FIELDS_HEADER):
            raise ValueError(f"{path}:{n}: {len(cells)} cells, not {len(_FIELDS_HEADER)}")
        channel, provider, eids, target, sources, skip, transform, cite = cells
        ids = eids.split(",")
        if transform not in _TRANSFORMS or not cite.strip() or not all(i.isdigit() for i in ids):
            raise ValueError(f"{path}:{n}: transform, cite or event id not valid: {cells}")
        for eid in ids:
            rows = table.setdefault((channel, provider, int(eid)), [])
            if any(row[0] == target for row in rows):
                raise ValueError(f"{path}:{n}: {target} repeated for its key")
            rows.append((target, sources.split(","), set(skip.split(",")) | {""}, transform))
    if not table:
        raise ValueError(f"{path}: no rows")
    return table


_FIELDS = load_fields_table(Path(__file__).resolve().parent / "mappings" / "evtx_fields.tsv")
# every field the table names, in the order it first names them
FIELDS_TARGETS = list(dict.fromkeys(row[0] for rows in _FIELDS.values() for row in rows))


def _coerce_list_item(item):
    """Coerce a list element: recurse dicts, stringify scalars."""
    if isinstance(item, dict):
        return _coerce_scalars(item)
    if isinstance(item, list):
        return [_coerce_list_item(i) for i in item]
    if item is not None:
        return str(item)
    return item


def _coerce_scalars(d: dict) -> dict:
    """Coerce scalar values to strings, recurse into nested dicts."""
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _coerce_scalars(v)
        elif isinstance(v, list):
            result[k] = [_coerce_list_item(i) for i in v]
        elif v is not None:
            result[k] = str(v)
        else:
            result[k] = v
    return result


def _clean_ip(value: str | None) -> str | None:
    """Return IP string or None if invalid/placeholder.

    EventData IpAddress can contain "-", "", "LOCAL", or "::".
    The index template maps source.ip as type ip — non-IP strings
    cause indexing errors. An IPv4-mapped IPv6 address (::ffff:a.b.c.d)
    is written as its IPv4 address.
    """
    if not value or str(value).strip() in _INVALID_IPS:
        return None
    value = str(value).strip()
    try:
        mapped = getattr(ipaddress.ip_address(value), "ipv4_mapped", None)
    except ValueError:
        return value
    return str(mapped) if mapped else value


def _header_sid(system: dict) -> str | None:
    """System/Security@UserID: the SID in the record header, often the
    account the provider ran as. None when absent or empty, whatever shape
    `Security` has (null on most Security records)."""
    sec = system.get("Security")
    attrs = sec.get("#attributes") if isinstance(sec, dict) else None
    uid = attrs.get("UserID") if isinstance(attrs, dict) else None
    return uid if isinstance(uid, str) and uid else None


def _attrs(node) -> dict:
    attrs = node.get("#attributes") if isinstance(node, dict) else None
    return attrs if isinstance(attrs, dict) else {}


def _header(system: dict, provider_name: str) -> dict:
    """The record-header fields OSS Winlogbeat keeps (sys/winevent/event.go):
    an absent or zero number is left out, and so is a code with no name."""
    keywords = _num(system.get("Keywords")) or 0
    opcode = system.get("Opcode")
    task = _TASKS.get(_num(system.get("Task"))) if provider_name == _AUDITING else None
    correlation, execution = _attrs(system.get("Correlation")), _attrs(system.get("Execution"))
    if keywords & _AUDIT_FAILURE:
        outcome = "failure"
    else:
        outcome = "success" if keywords & _AUDIT_SUCCESS else None
    record_id = system.get("EventRecordID")
    return {
        "event.provider": provider_name or None,
        "event.kind": "event",
        "event.outcome": outcome,
        "event.action": task,
        "winlog.task": task,
        "winlog.provider_guid": _attrs(system.get("Provider")).get("Guid") or None,
        "winlog.record_id": str(record_id) if record_id else None,
        "winlog.computer_name": system.get("Computer"),
        "winlog.version": _long(system.get("Version")) or None,
        "winlog.opcode": None if opcode is None else _OPCODES.get(_num(opcode)),
        "winlog.keywords": [name for bit, name in _KEYWORDS.items() if keywords & bit] or None,
        "log.level": _LEVELS.get(_num(system.get("Level")) or 0),
        "winlog.activity_id": correlation.get("ActivityID") or None,
        "winlog.related_activity_id": correlation.get("RelatedActivityID") or None,
        "winlog.process.pid": _long(execution.get("ProcessID")) or None,
        "winlog.process.thread.id": _long(execution.get("ThreadID")) or None,
    }


def _params(data) -> dict:
    """Unnamed <Data> values as param1..N by their 1-based position, empty
    ones skipped (OSS Winlogbeat sys/winevent/maputil.go)."""
    if isinstance(data, dict):
        data = data.get("#text")
    values = [data] if isinstance(data, str) else data if isinstance(data, list) else []
    return {
        f"param{n}": str(v).replace("\r\n", "\n")
        for n, v in enumerate(values, 1)
        if v not in (None, "") and not isinstance(v, (dict, list))
    }


def _derive(doc: dict) -> None:
    """The fields ECS derives from others: a process's file name, a file's
    name, directory and extension, and the related.* sets."""
    for exe, name in (
        ("process.executable", "process.name"),
        ("process.parent.executable", "process.parent.name"),
    ):
        if doc.get(exe):
            doc[name] = ntpath.basename(str(doc[exe]))
    if doc.get("file.path"):
        directory, name = ntpath.split(str(doc["file.path"]))
        parts = {"file.name": name, "file.directory": directory}
        parts["file.extension"] = ntpath.splitext(name)[1][1:]
        doc.update({k: v for k, v in parts.items() if v})
    hashes = [
        v for k, v in doc.items() if k.split(".")[-2:-1] == ["hash"] or k.endswith(".imphash")
    ]
    related = {
        "related.user": [
            doc.get(k) for k in ("user.name", "user.target.name", "user.effective.name")
        ],
        "related.ip": [doc.get("source.ip"), doc.get("destination.ip")],
        "related.hash": hashes,
    }
    for field, values in related.items():
        values = list(
            dict.fromkeys(v for v in values if isinstance(v, str) and v not in ("", "-"))
        )
        if values:
            doc[field] = values


def normalize_event(data: dict) -> dict:
    """Flatten pyevtx-rs quirks before indexing.

    Handles:
    - EventID as int, string, or dict with #text
    - Timestamps nested in #attributes
    - EventData null (returns None, not {})
    - Provider always a dict with #attributes
    """
    system = data.get("Event", {}).get("System", {})

    # Normalize EventID — can be int, string, or dict with #text
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text", eid)
    try:
        eid = int(eid)
    except (TypeError, ValueError):
        eid = None

    # Extract timestamp
    tc = system.get("TimeCreated", {})
    if isinstance(tc, dict):
        tc = tc.get("#attributes", {}).get("SystemTime") or None
    else:
        tc = str(tc) if tc else None

    # Extract provider name (always a dict from pyevtx-rs)
    provider = system.get("Provider", {})
    provider_name = ""
    if isinstance(provider, dict):
        provider_name = provider.get("#attributes", {}).get("Name", "")

    # EventData can be null — use `or {}` to safely handle None.
    # Some events use UserData instead of EventData (WMI, TerminalServices,
    # Application-Experience, etc). Fall back to UserData if EventData is absent.
    event = data.get("Event", {})
    event_data = event.get("EventData") or {}
    user_data = event.get("UserData") or {}

    # Flatten UserData: it wraps content in a provider-specific key
    # e.g. {"Operation_ClientFailure": {"#attributes": {...}, "User": "...", ...}}
    # Extract the inner dict, stripping the wrapper key and xmlns attributes.
    flat_user_data = {}
    ud_name = None
    if user_data and not event_data:
        if isinstance(user_data, dict):
            key, val = next(iter(user_data.items()))  # truthy, so it has a first item
        else:
            key, val = None, user_data
        if isinstance(val, dict):
            flat_user_data = {k: v for k, v in val.items() if k != "#attributes"}
            ud_name = key
        else:  # If it's not a dict, store as-is
            flat_user_data = user_data

    # Use EventData if available, otherwise flattened UserData
    payload = event_data if event_data else flat_user_data
    if not isinstance(payload, dict):  # a value of another type has no named fields
        payload = {}
    # Store both for searchability
    stored_data = event_data if event_data else (flat_user_data if flat_user_data else {})

    # Extract top-level ECS fields from ORIGINAL uncoerced payload first
    doc = {
        "event.code": eid,
        "winlog.event_id": eid,
        "winlog.channel": system.get("Channel"),
        "host.name": system.get("Computer"),
        "@timestamp": tc,
        "winlog.provider_name": provider_name,
        "winlog.user.identifier": _header_sid(system),
        "user.name": payload.get("TargetUserName") or payload.get("User"),
        "user.effective.name": payload.get("SubjectUserName"),
        "source.ip": _clean_ip(payload.get("IpAddress") or payload.get("Address")),
        "winlog.logon.type": payload.get("LogonType"),
        "process.executable": payload.get("Image", payload.get("NewProcessName")),
        "process.command_line": payload.get("CommandLine"),
        "process.parent.executable": payload.get("ParentImage", payload.get("ParentProcessName")),
        "file.path": payload.get("TargetFilename"),
        "script_block_text": payload.get("ScriptBlockText"),
        **_header(system, provider_name),
    }
    if ud_name:
        pairs = {
            k: str(v).replace("\r\n", "\n")
            for k, v in flat_user_data.items()
            if v not in (None, "") and not isinstance(v, (dict, list))
        }
        if pairs:
            doc["winlog.user_data"] = {**pairs, "xml_name": ud_name}

    # A key the table has rows for takes every field the table names only from
    # its rows: the first source present, not None, not a value to skip and
    # that its transform makes a value of. A const row's sources are its value.
    rows = _FIELDS.get((system.get("Channel"), provider_name, eid))
    if rows:
        for target in FIELDS_TARGETS:
            doc.pop(target, None)
        for target, sources, skip, transform in rows:
            if transform == "const":
                doc[target] = sources[0] if len(sources) == 1 else sources
                continue
            for source in sources:
                value = payload.get(source)
                if value is None or str(value) in skip:
                    continue
                value = _TRANSFORMS[transform](value)
                if value is not None:
                    doc[target] = value
                    break
    _derive(doc)

    # Unnamed <Data> values join the stored event data as paramN; a named
    # field of the same name keeps its value.
    if isinstance(event_data, dict) and event_data.get("Data") is not None:
        params = _params(event_data["Data"]).items()
        stored_data = {**stored_data, **{k: v for k, v in params if k not in stored_data}}

    # Coerce EventData/UserData scalar values to strings for consistent dynamic
    # mapping. Prevents type conflicts across Event IDs (e.g., LogonType: "3" vs 3).
    # Top-level ECS fields above keep their proper types (int, ip, keyword).
    # Nested dicts/lists are left as-is (UserData wrappers, Data elements).
    if isinstance(stored_data, dict) and stored_data:
        doc["winlog.event_data"] = _coerce_scalars(stored_data)
    else:
        doc["winlog.event_data"] = stored_data

    # Strip None values — most events only populate 5-6 of the ~15 mapped fields.
    # Saves ~60% of field storage at scale. Keeps empty dict {} and empty string "".
    return {k: v for k, v in doc.items() if v is not None}
