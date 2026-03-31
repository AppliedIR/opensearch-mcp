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
