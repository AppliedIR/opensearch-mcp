"""Path resolution helpers — handles sudo and case-insensitive lookups."""

from __future__ import annotations

import os
from pathlib import Path


def vhir_home() -> Path:
    """Get the real user's home directory, even under sudo.

    When running as root via sudo, Path.home() returns /root/.
    The actual user's home is resolved via SUDO_USER.
    """
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                import pwd

                return Path(pwd.getpwnam(sudo_user).pw_dir)
            except KeyError:
                pass
    return Path.home()


def vhir_dir() -> Path:
    """Return ~/.vhir/ for the real user."""
    return vhir_home() / ".vhir"


def members(folder) -> tuple[list[Path], list[Path]]:
    """(kept, skipped links): a folder's entries a folder ingest reads, never
    a link (the gate's walk skips links), and the links, to be named. Every
    walk lists every folder at every level through this, so host detection,
    previews and the worker see the same files and skip the same links."""
    kept: list[Path] = []
    links: list[Path] = []
    for p in Path(folder).iterdir():
        (links if p.is_symlink() else kept).append(p)
    return kept, links


def resolve_case_insensitive(base: Path, rel_path: str) -> Path | None:
    """Resolve a relative path case-insensitively under base.

    Windows paths have inconsistent case in triage images (KAPE, Velociraptor).
    Linux is case-sensitive. This walks each path component and matches
    case-insensitively.

    Returns the resolved Path if found, None if any component is missing.
    """
    current = base
    for part in Path(rel_path).parts:
        # Try exact match first (fast path)
        candidate = current / part
        try:
            exists = candidate.exists()
        except OSError:  # a folder we can't search (e.g. lost+found) can't hold it
            return None
        if exists:
            current = candidate
            continue
        # Case-insensitive scan
        lower = part.lower()
        found = False
        try:
            for child in current.iterdir():
                if child.name.lower() == lower:
                    current = child
                    found = True
                    break
        except OSError:
            return None
        if not found:
            return None
    return current


# Windows timezone names → IANA (from Unicode CLDR windowsZones.xml)
_WIN_TZ_MAP = {
    "AUS Central Standard Time": "Australia/Darwin",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "Afghanistan Standard Time": "Asia/Kabul",
    "Alaskan Standard Time": "America/Anchorage",
    "Arab Standard Time": "Asia/Riyadh",
    "Arabian Standard Time": "Asia/Dubai",
    "Arabic Standard Time": "Asia/Baghdad",
    "Atlantic Standard Time": "America/Halifax",
    "Canada Central Standard Time": "America/Regina",
    "Central America Standard Time": "America/Guatemala",
    "Central Asia Standard Time": "Asia/Almaty",
    "Central Europe Standard Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Warsaw",
    "Central Pacific Standard Time": "Pacific/Guadalcanal",
    "Central Standard Time": "America/Chicago",
    "Central Standard Time (Mexico)": "America/Mexico_City",
    "China Standard Time": "Asia/Shanghai",
    "E. Africa Standard Time": "Africa/Nairobi",
    "E. Australia Standard Time": "Australia/Brisbane",
    "E. Europe Standard Time": "Europe/Chisinau",
    "E. South America Standard Time": "America/Sao_Paulo",
    "Eastern Standard Time": "America/New_York",
    "Egypt Standard Time": "Africa/Cairo",
    "FLE Standard Time": "Europe/Kiev",
    "GMT Standard Time": "Europe/London",
    "GTB Standard Time": "Europe/Bucharest",
    "Georgian Standard Time": "Asia/Tbilisi",
    "Greenwich Standard Time": "Atlantic/Reykjavik",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "India Standard Time": "Asia/Kolkata",
    "Iran Standard Time": "Asia/Tehran",
    "Israel Standard Time": "Asia/Jerusalem",
    "Japan Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "Mountain Standard Time": "America/Denver",
    "Mountain Standard Time (Mexico)": "America/Chihuahua",
    "Myanmar Standard Time": "Asia/Rangoon",
    "N. Central Asia Standard Time": "Asia/Novosibirsk",
    "Nepal Standard Time": "Asia/Kathmandu",
    "New Zealand Standard Time": "Pacific/Auckland",
    "Newfoundland Standard Time": "America/St_Johns",
    "North Asia East Standard Time": "Asia/Irkutsk",
    "North Asia Standard Time": "Asia/Krasnoyarsk",
    "Pacific SA Standard Time": "America/Santiago",
    "Pacific Standard Time": "America/Los_Angeles",
    "Pacific Standard Time (Mexico)": "America/Tijuana",
    "Romance Standard Time": "Europe/Paris",
    "Russian Standard Time": "Europe/Moscow",
    "SA Eastern Standard Time": "America/Cayenne",
    "SA Pacific Standard Time": "America/Bogota",
    "SA Western Standard Time": "America/La_Paz",
    "SE Asia Standard Time": "Asia/Bangkok",
    "Singapore Standard Time": "Asia/Singapore",
    "South Africa Standard Time": "Africa/Johannesburg",
    "Sri Lanka Standard Time": "Asia/Colombo",
    "Taipei Standard Time": "Asia/Taipei",
    "Tasmania Standard Time": "Australia/Hobart",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Turkey Standard Time": "Europe/Istanbul",
    "US Eastern Standard Time": "America/Indianapolis",
    "US Mountain Standard Time": "America/Phoenix",
    "UTC": "UTC",
    "UTC+12": "Pacific/Fiji",
    "UTC-02": "America/Noronha",
    "UTC-11": "Pacific/Pago_Pago",
    "W. Australia Standard Time": "Australia/Perth",
    "W. Central Africa Standard Time": "Africa/Lagos",
    "W. Europe Standard Time": "Europe/Berlin",
    "West Asia Standard Time": "Asia/Tashkent",
    "West Pacific Standard Time": "Pacific/Port_Moresby",
    "Yakutsk Standard Time": "Asia/Yakutsk",
}


def resolve_timezone(tz_name: str | None) -> str | None:
    """Resolve a timezone name to IANA format.

    Handles:
    - Windows names from registry ("Eastern Standard Time" → "America/New_York")
    - IANA names passed through ("America/New_York" → "America/New_York")
    - None → None
    """
    if not tz_name:
        return None

    from dateutil.tz import gettz

    # Try direct resolution first (works for IANA names on all platforms,
    # and Windows names on Windows)
    if gettz(tz_name) is not None:
        return tz_name

    # Map Windows name to IANA
    iana = _WIN_TZ_MAP.get(tz_name)
    if iana and gettz(iana) is not None:
        return iana

    # Case-insensitive fallback
    lower = tz_name.lower()
    for win_name, iana_name in _WIN_TZ_MAP.items():
        if win_name.lower() == lower:
            if gettz(iana_name) is not None:
                return iana_name

    return None


_TIMESTAMP_CANDIDATES = [
    "@timestamp",
    "timestamp",
    "ts",
    "datetime",
    "event_time",
    "time",
    "CreatedTime",
    "EventTime",
    "date",
]

# Files whose records had no time field in this ingest run (reset per run;
# each file once, by full path: every host's procs.csv is its own file);
# reported on the console and in the ingest status.
NO_TIME_FIELD: list[str] = []


def auto_detect_time_field(sample: dict, extra: tuple[str, ...] = ()) -> str | None:
    """Find the timestamp field from a sample record; `extra` are candidates
    one parser alone may use."""
    for candidate in (*_TIMESTAMP_CANDIDATES, *extra):
        if candidate in sample:
            return candidate
    return None


# (file, time field, count) of this run's time values that are digits of a
# width no epoch has (20230129, 202301292357): not used as @timestamp, which
# OpenSearch would read as epoch milliseconds (1970, 1976)
TIME_NOT_UNDERSTOOD: list[tuple[str, str, int]] = []


def no_time_field_note() -> str:
    """What to tell the examiner about NO_TIME_FIELD and TIME_NOT_UNDERSTOOD, or ""."""
    notes = []
    if NO_TIME_FIELD:
        first = Path(NO_TIME_FIELD[0])
        notes.append(
            f"No time field detected in {len(NO_TIME_FIELD)} file(s), "
            f"e.g. {first.parent.name}/{first.name}: "
            "no @timestamp, so idx_timeline won't show them. Re-ingest with time_field=<column>."
        )
    by_field: dict[str, int] = {}
    for _, field, n in TIME_NOT_UNDERSTOOD:
        by_field[field] = by_field.get(field, 0) + n
    for field, n in by_field.items():
        notes.append(f"{n} values in {field} not understood; not used as the timestamp")
    return "; ".join(notes)


def sanitize_index_component(value: str) -> str:
    """Sanitize a hostname or case_id for use in OpenSearch index names."""
    import re

    return re.sub(r"[^a-z0-9._-]", "-", value.lower())


def legacy_index_name(case_id: str, artifact_type: str, hostname: str) -> str:
    """A pre-0.6.4 index name, case-{case}-{type}-{host}: for reading old data only."""
    return (
        f"case-{sanitize_index_component(case_id)}"
        f"-{sanitize_index_component(artifact_type)}"
        f"-{sanitize_index_component(hostname)}"
    )


def build_index_name(c12: str, artifact_type: str) -> str:
    """The index every write of `artifact_type` in a case goes to:
    case-{c12}-{type}-0. No host appears in it."""
    return f"case-{c12}-{sanitize_index_component(artifact_type)}-0"


_STEM_MAX = 100


def stem_type(prefix: str, stem: str) -> str:
    """The artifact type for a per-file index (`json-`, `delim-`, `zeek-`,
    `bodyfile-`): `<prefix>-<stem>`, where the stem has `_` for `-` (so no
    other template's `case-*-<type>-*` pattern can match), is cut to 92
    bytes plus `_<hash>` past 100, and gets a trailing `_` when it equals a
    template's type."""
    import hashlib

    from opensearch_mcp.mappings import template_type_tokens

    s = sanitize_index_component(stem).replace("-", "_")
    if s.startswith(prefix + "_"):
        s = s[len(prefix) + 1 :]
    if len(s.encode()) > _STEM_MAX:
        s = s[:92] + "_" + hashlib.sha256(stem.encode()).hexdigest()[:7]
    if s in template_type_tokens():
        s += "_"
    return f"{prefix}-{s}"


def validate_index_name(index_name: str) -> str | None:
    """Return error message if index name is invalid, None if OK."""
    if index_name != index_name.lower():
        return (
            f"Index name '{index_name}' contains uppercase characters. "
            "OpenSearch requires lowercase index names. "
            "This is likely a filename with mixed case in the path."
        )
    if any(c in index_name for c in ' ,"*\\<|>?/'):
        return f"Index name '{index_name}' contains invalid characters."
    return None


def relative_evidence_path(file_path: Path, volume_root: Path) -> str:
    """Compute a volume-root-relative path for dedup IDs.

    Normalizes absolute mount paths so the same evidence file produces
    the same relative path regardless of where the volume is mounted.
    Falls back to the filename if the file isn't under volume_root.
    """
    try:
        return str(file_path.relative_to(volume_root))
    except ValueError:
        return file_path.name
