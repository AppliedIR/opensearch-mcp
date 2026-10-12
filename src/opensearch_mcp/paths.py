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


# Windows time zone ids → IANA: Unicode CLDR windowsZones, territory "001" for
# every id (CLDR 48, as ICU compiles it in Ubuntu tzdata 2026c's
# /usr/share/zoneinfo-icu/44/le/windowsZones.res). Kept: Asia/Kolkata,
# Asia/Kathmandu and UTC (CLDR spells them Asia/Calcutta, Asia/Katmandu and
# Etc/UTC; the same offsets), and "Japan Standard Time" (not in CLDR).
_WIN_TZ_MAP = {
    "AUS Central Standard Time": "Australia/Darwin",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "Afghanistan Standard Time": "Asia/Kabul",
    "Alaskan Standard Time": "America/Anchorage",
    "Aleutian Standard Time": "America/Adak",
    "Altai Standard Time": "Asia/Barnaul",
    "Arab Standard Time": "Asia/Riyadh",
    "Arabian Standard Time": "Asia/Dubai",
    "Arabic Standard Time": "Asia/Baghdad",
    "Argentina Standard Time": "America/Buenos_Aires",
    "Astrakhan Standard Time": "Europe/Astrakhan",
    "Atlantic Standard Time": "America/Halifax",
    "Aus Central W. Standard Time": "Australia/Eucla",
    "Azerbaijan Standard Time": "Asia/Baku",
    "Azores Standard Time": "Atlantic/Azores",
    "Bahia Standard Time": "America/Bahia",
    "Bangladesh Standard Time": "Asia/Dhaka",
    "Belarus Standard Time": "Europe/Minsk",
    "Bougainville Standard Time": "Pacific/Bougainville",
    "Canada Central Standard Time": "America/Regina",
    "Cape Verde Standard Time": "Atlantic/Cape_Verde",
    "Caucasus Standard Time": "Asia/Yerevan",
    "Cen. Australia Standard Time": "Australia/Adelaide",
    "Central America Standard Time": "America/Guatemala",
    "Central Asia Standard Time": "Asia/Bishkek",
    "Central Brazilian Standard Time": "America/Cuiaba",
    "Central Europe Standard Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Warsaw",
    "Central Pacific Standard Time": "Pacific/Guadalcanal",
    "Central Standard Time": "America/Chicago",
    "Central Standard Time (Mexico)": "America/Mexico_City",
    "Chatham Islands Standard Time": "Pacific/Chatham",
    "China Standard Time": "Asia/Shanghai",
    "Cuba Standard Time": "America/Havana",
    "Dateline Standard Time": "Etc/GMT+12",
    "E. Africa Standard Time": "Africa/Nairobi",
    "E. Australia Standard Time": "Australia/Brisbane",
    "E. Europe Standard Time": "Europe/Chisinau",
    "E. South America Standard Time": "America/Sao_Paulo",
    "Easter Island Standard Time": "Pacific/Easter",
    "Eastern Standard Time": "America/New_York",
    "Eastern Standard Time (Mexico)": "America/Cancun",
    "Egypt Standard Time": "Africa/Cairo",
    "Ekaterinburg Standard Time": "Asia/Yekaterinburg",
    "FLE Standard Time": "Europe/Kiev",
    "Fiji Standard Time": "Pacific/Fiji",
    "GMT Standard Time": "Europe/London",
    "GTB Standard Time": "Europe/Bucharest",
    "Georgian Standard Time": "Asia/Tbilisi",
    "Greenland Standard Time": "America/Godthab",
    "Greenwich Standard Time": "Atlantic/Reykjavik",
    "Haiti Standard Time": "America/Port-au-Prince",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "India Standard Time": "Asia/Kolkata",
    "Iran Standard Time": "Asia/Tehran",
    "Israel Standard Time": "Asia/Jerusalem",
    "Japan Standard Time": "Asia/Tokyo",
    "Jordan Standard Time": "Asia/Amman",
    "Kaliningrad Standard Time": "Europe/Kaliningrad",
    "Korea Standard Time": "Asia/Seoul",
    "Libya Standard Time": "Africa/Tripoli",
    "Line Islands Standard Time": "Pacific/Kiritimati",
    "Lord Howe Standard Time": "Australia/Lord_Howe",
    "Magadan Standard Time": "Asia/Magadan",
    "Magallanes Standard Time": "America/Punta_Arenas",
    "Marquesas Standard Time": "Pacific/Marquesas",
    "Mauritius Standard Time": "Indian/Mauritius",
    "Middle East Standard Time": "Asia/Beirut",
    "Montevideo Standard Time": "America/Montevideo",
    "Morocco Standard Time": "Africa/Casablanca",
    "Mountain Standard Time": "America/Denver",
    "Mountain Standard Time (Mexico)": "America/Mazatlan",
    "Myanmar Standard Time": "Asia/Rangoon",
    "N. Central Asia Standard Time": "Asia/Novosibirsk",
    "Namibia Standard Time": "Africa/Windhoek",
    "Nepal Standard Time": "Asia/Kathmandu",
    "New Zealand Standard Time": "Pacific/Auckland",
    "Newfoundland Standard Time": "America/St_Johns",
    "Norfolk Standard Time": "Pacific/Norfolk",
    "North Asia East Standard Time": "Asia/Irkutsk",
    "North Asia Standard Time": "Asia/Krasnoyarsk",
    "North Korea Standard Time": "Asia/Pyongyang",
    "Omsk Standard Time": "Asia/Omsk",
    "Pacific SA Standard Time": "America/Santiago",
    "Pacific Standard Time": "America/Los_Angeles",
    "Pacific Standard Time (Mexico)": "America/Tijuana",
    "Pakistan Standard Time": "Asia/Karachi",
    "Paraguay Standard Time": "America/Asuncion",
    "Qyzylorda Standard Time": "Asia/Qyzylorda",
    "Romance Standard Time": "Europe/Paris",
    "Russia Time Zone 10": "Asia/Srednekolymsk",
    "Russia Time Zone 11": "Asia/Kamchatka",
    "Russia Time Zone 3": "Europe/Samara",
    "Russian Standard Time": "Europe/Moscow",
    "SA Eastern Standard Time": "America/Cayenne",
    "SA Pacific Standard Time": "America/Bogota",
    "SA Western Standard Time": "America/La_Paz",
    "SE Asia Standard Time": "Asia/Bangkok",
    "Saint Pierre Standard Time": "America/Miquelon",
    "Sakhalin Standard Time": "Asia/Sakhalin",
    "Samoa Standard Time": "Pacific/Apia",
    "Sao Tome Standard Time": "Africa/Sao_Tome",
    "Saratov Standard Time": "Europe/Saratov",
    "Singapore Standard Time": "Asia/Singapore",
    "South Africa Standard Time": "Africa/Johannesburg",
    "South Sudan Standard Time": "Africa/Juba",
    "Sri Lanka Standard Time": "Asia/Colombo",
    "Sudan Standard Time": "Africa/Khartoum",
    "Syria Standard Time": "Asia/Damascus",
    "Taipei Standard Time": "Asia/Taipei",
    "Tasmania Standard Time": "Australia/Hobart",
    "Tocantins Standard Time": "America/Araguaina",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Tomsk Standard Time": "Asia/Tomsk",
    "Tonga Standard Time": "Pacific/Tongatapu",
    "Transbaikal Standard Time": "Asia/Chita",
    "Turkey Standard Time": "Europe/Istanbul",
    "Turks And Caicos Standard Time": "America/Grand_Turk",
    "US Eastern Standard Time": "America/Indianapolis",
    "US Mountain Standard Time": "America/Phoenix",
    "UTC": "UTC",
    "UTC+12": "Etc/GMT-12",
    "UTC+13": "Etc/GMT-13",
    "UTC-02": "Etc/GMT+2",
    "UTC-08": "Etc/GMT+8",
    "UTC-09": "Etc/GMT+9",
    "UTC-11": "Etc/GMT+11",
    "Ulaanbaatar Standard Time": "Asia/Ulaanbaatar",
    "Venezuela Standard Time": "America/Caracas",
    "Vladivostok Standard Time": "Asia/Vladivostok",
    "Volgograd Standard Time": "Europe/Volgograd",
    "W. Australia Standard Time": "Australia/Perth",
    "W. Central Africa Standard Time": "Africa/Lagos",
    "W. Europe Standard Time": "Europe/Berlin",
    "W. Mongolia Standard Time": "Asia/Hovd",
    "West Asia Standard Time": "Asia/Tashkent",
    "West Bank Standard Time": "Asia/Hebron",
    "West Pacific Standard Time": "Pacific/Port_Moresby",
    "Yakutsk Standard Time": "Asia/Yakutsk",
    "Yukon Standard Time": "America/Whitehorse",
}
_WIN_TZ_LOWER = {k.lower(): v for k, v in _WIN_TZ_MAP.items()}


def resolve_timezone(tz_name: str | None) -> str | None:
    """Resolve a timezone name to IANA format.

    Handles:
    - Windows names from registry ("Eastern Standard Time" → "America/New_York"),
      in any case, with a NUL tail or outer spaces cut
    - IANA names passed through ("America/New_York" → "America/New_York")
    - None, or a name with a space that isn't a Windows id → None
    """
    if not tz_name:
        return None

    from dateutil.tz import gettz

    # A registry value can carry a NUL tail and stray spaces
    name = tz_name.split("\x00", 1)[0].strip()

    # The map first: dateutil reads a Windows id such as "Russia Time Zone 3"
    # as a POSIX string, at the wrong offset
    iana = _WIN_TZ_LOWER.get(name.lower())
    if iana is not None:
        return iana if gettz(iana) is not None else None

    # No IANA or POSIX name has whitespace: an unknown Windows-style name stays unknown
    if name and not any(c.isspace() for c in name) and gettz(name) is not None:
        return name

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
