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
        if candidate.exists():
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


def sanitize_index_component(value: str) -> str:
    """Sanitize a hostname or case_id for use in OpenSearch index names."""
    import re

    return re.sub(r"[^a-z0-9._-]", "-", value.lower())


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
