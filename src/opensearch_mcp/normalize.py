"""Normalize pyevtx-rs JSON output to ECS fields for OpenSearch indexing."""

from __future__ import annotations

_INVALID_IPS = {"", "-", "LOCAL", "::"}


def _clean_ip(value: str | None) -> str | None:
    """Return IP string or None if invalid/placeholder.

    EventData IpAddress can contain "-", "", "LOCAL", or "::".
    The index template maps source.ip as type ip — non-IP strings
    cause indexing errors.
    """
    if not value or value.strip() in _INVALID_IPS:
        return None
    return value.strip()


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
        tc = tc.get("#attributes", {}).get("SystemTime", "")
    else:
        tc = str(tc) if tc else ""

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
    if user_data and not event_data:
        for _key, val in user_data.items():
            if isinstance(val, dict):
                flat_user_data = {k: v for k, v in val.items() if k != "#attributes"}
                break
            # If it's not a dict, store as-is
            flat_user_data = user_data
            break

    # Use EventData if available, otherwise flattened UserData
    payload = event_data if event_data else flat_user_data
    # Store both for searchability
    stored_data = event_data if event_data else user_data

    doc = {
        "event.code": eid,
        "winlog.event_id": eid,
        "winlog.channel": system.get("Channel"),
        "host.name": system.get("Computer"),
        "@timestamp": tc,
        "winlog.provider_name": provider_name,
        "winlog.event_data": stored_data,
        "user.name": payload.get("TargetUserName") or payload.get("User"),
        "user.effective.name": payload.get("SubjectUserName"),
        "source.ip": _clean_ip(payload.get("IpAddress") or payload.get("Address")),
        "winlog.logon.type": payload.get("LogonType"),
        "process.name": payload.get("Image", payload.get("NewProcessName")),
        "process.command_line": payload.get("CommandLine"),
        "process.parent.name": payload.get("ParentImage", payload.get("ParentProcessName")),
        "file.path": payload.get("TargetFilename"),
        # Long text fields promoted to top-level with text type.
        # Can't be under winlog.event_data (flat_object can't have typed sub-fields).
        "script_block_text": payload.get("ScriptBlockText"),
    }

    # Strip None values — most events only populate 5-6 of the ~15 mapped fields.
    # Saves ~60% of field storage at scale. Keeps empty dict {} and empty string "".
    return {k: v for k, v in doc.items() if v is not None}
