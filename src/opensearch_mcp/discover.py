"""Discover Windows artifacts and host directories in triage packages."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Artifact paths relative to the volume root (directory containing Windows/)
ARTIFACT_PATHS: dict[str, str] = {
    "amcache": "Windows/appcompat/Programs/Amcache.hve",
    "shimcache": "Windows/System32/config/SYSTEM",
    "registry_system": "Windows/System32/config/SYSTEM",
    "registry_software": "Windows/System32/config/SOFTWARE",
    "registry_sam": "Windows/System32/config/SAM",
    "registry_security": "Windows/System32/config/SECURITY",
    "mft": "$MFT",
    "usn": "$Extend/$J",
    "recyclebin": "$Recycle.Bin",
}

# Per-user artifact paths relative to a user profile directory (Users/*/)
USER_ARTIFACTS: dict[str, str | list[str]] = {
    "shellbags": "",  # SBECmd takes the profile dir itself
    "jumplists": "AppData/Roaming/Microsoft/Windows/Recent",
    "lnk": ["AppData/Roaming/Microsoft/Windows/Recent", "Desktop"],
    "timeline": "AppData/Local/ConnectedDevicesPlatform",
}

# The sentinel path used to detect a Windows volume root
_WINDOWS_SENTINEL = "Windows/System32/config"


@dataclass
class DiscoveredHost:
    """A host discovered in a triage package."""

    hostname: str
    volume_root: Path  # directory containing the Windows/ tree
    artifacts: list[tuple[str, Path]] = field(default_factory=list)
    evtx_dir: Path | None = None
    user_profiles: list[Path] = field(default_factory=list)


def find_volume_root(host_dir: Path) -> Path | None:
    """Find the volume root within a host directory.

    Scans for Windows/System32/config/ at any depth to handle:
    - host/Windows/... (flat)
    - host/C/Windows/... (KAPE with drive letter)
    - host/C%3A/Windows/... (Velociraptor URL-encoded)
    """
    # Direct check: host_dir itself is the volume root
    if (host_dir / _WINDOWS_SENTINEL).is_dir():
        return host_dir

    # One level deep: drive-letter dirs like C/, C%3A/, D/
    for child in host_dir.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        # Only check short names (drive letters: C, D, C%3A, etc.)
        if len(child.name) > 4:
            continue
        if (child / _WINDOWS_SENTINEL).is_dir():
            return child

    return None


def discover_artifacts(host: DiscoveredHost) -> None:
    """Populate a DiscoveredHost with found artifacts."""
    vr = host.volume_root

    # System artifacts
    for artifact_name, rel_path in ARTIFACT_PATHS.items():
        full_path = vr / rel_path
        if artifact_name == "recyclebin":
            if full_path.is_dir():
                host.artifacts.append((artifact_name, full_path))
        elif full_path.is_file():
            host.artifacts.append((artifact_name, full_path))

    # Event logs directory
    evtx_dir = vr / "Windows/System32/winevt/Logs"
    if evtx_dir.is_dir():
        evtx_count = sum(1 for f in evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
        if evtx_count > 0:
            host.evtx_dir = evtx_dir

    # User profiles
    users_dir = vr / "Users"
    if users_dir.is_dir():
        for profile in sorted(users_dir.iterdir()):
            if profile.is_dir() and profile.name not in (
                "Public",
                "Default",
                "Default User",
                "All Users",
            ):
                host.user_profiles.append(profile)

                # Per-user artifacts
                for artifact_name, rel_paths in USER_ARTIFACTS.items():
                    if isinstance(rel_paths, list):
                        for rp in rel_paths:
                            full = profile / rp
                            if full.is_dir():
                                host.artifacts.append((artifact_name, full))
                    elif rel_paths == "":
                        # SBECmd takes the profile directory itself
                        host.artifacts.append((artifact_name, profile))
                    else:
                        full = profile / rel_paths
                        if full.is_dir() or full.is_file():
                            host.artifacts.append((artifact_name, full))


def scan_triage_directory(root: Path) -> list[DiscoveredHost]:
    """Scan a triage directory for host subdirectories with Windows artifacts.

    Returns a list of DiscoveredHost, one per detected host. If root itself
    is a volume root (no host subdirs), returns a single host with hostname
    derived from root.name.
    """
    hosts: list[DiscoveredHost] = []

    # Check if root itself is a volume root (single-host flat dir)
    vr = find_volume_root(root)
    if vr is not None:
        host = DiscoveredHost(hostname=root.name, volume_root=vr)
        discover_artifacts(host)
        if host.artifacts or host.evtx_dir:
            hosts.append(host)
        return hosts

    # Scan subdirectories as host directories
    for subdir in sorted(root.iterdir()):
        if not subdir.is_dir():
            continue
        if subdir.name.startswith("."):
            continue

        vr = find_volume_root(subdir)
        if vr is None:
            continue

        host = DiscoveredHost(hostname=subdir.name, volume_root=vr)
        discover_artifacts(host)
        if host.artifacts or host.evtx_dir:
            hosts.append(host)

    return hosts
