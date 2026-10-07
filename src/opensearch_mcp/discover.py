"""Discover hosts (Windows, Linux, macOS) and their artifacts in triage packages."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from opensearch_mcp.paths import resolve_case_insensitive

# Artifact paths relative to the volume root (directory containing Windows/)
# Components are case-insensitive — resolved via resolve_case_insensitive()
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
    "prefetch": "Windows/Prefetch",
    "srum": "Windows/System32/SRU/SRUDB.dat",
}

# Per-user artifact paths relative to a user profile directory (Users/*/)
USER_ARTIFACTS: dict[str, str | list[str]] = {
    "shellbags": "",  # SBECmd takes the profile dir itself
    "jumplists": "AppData/Roaming/Microsoft/Windows/Recent",
    "lnk": ["AppData/Roaming/Microsoft/Windows/Recent", "Desktop"],
    "timeline": "AppData/Local/ConnectedDevicesPlatform",
}

# timezone_source when the examiner's --source-timezone set the zone: it wins
# for every host, a volume Plaso reads off an image included
EXAMINER_ZONE = "examiner override"

# Where Plaso's narrow Windows set looks, relative to the volume root
PLASO_WINDOWS_DIRS = ("Users", "Windows/inf")

# A profile's own registry hives, each parsed by RECmd on its own
USER_HIVES = ("NTUSER.DAT", "AppData/Local/Microsoft/Windows/UsrClass.dat")

# The sentinel path used to detect a Windows volume root
_WINDOWS_SENTINEL = "Windows/System32/config"

# macOS is checked before Linux: its etc links to private/etc, so it has etc/passwd.
_MACOS_SENTINEL = "System/Library/CoreServices/SystemVersion.plist"
_LINUX_RELEASE_FILES = (
    "etc/os-release",
    "usr/lib/os-release",
    "etc/lsb-release",
    "etc/debian_version",
    "etc/redhat-release",
    "etc/alpine-release",
    "etc/SuSE-release",
)


def os_of_root(path: Path) -> str | None:
    """The OS whose root `path` is: windows, macos, linux, or None."""
    if resolve_case_insensitive(path, _WINDOWS_SENTINEL) is not None:
        return "windows"
    if resolve_case_insensitive(path, _MACOS_SENTINEL) is not None:
        return "macos"
    if resolve_case_insensitive(path, "etc/passwd") is not None and any(
        resolve_case_insensitive(path, f) is not None for f in _LINUX_RELEASE_FILES
    ):
        return "linux"
    return None


def _contained(root: Path, rel: str) -> Path | None:
    """root/rel when it resolves inside root (a link out of the volume, such
    as an absolute one, would read the analysis host's file), else None."""
    try:
        real_root = root.resolve()
        real = (root / rel).resolve()
    except (OSError, RuntimeError):
        return None
    return real if real.is_relative_to(real_root) else None


def _valid_zone(name: str | None) -> str | None:
    """name when Plaso can use it (it looks zones up in pytz), else None."""
    try:
        import pytz

        return name if name and pytz.timezone(name) else None
    except Exception:
        return None


def unix_timezone(root: Path) -> tuple[str | None, str]:
    """A Linux or macOS volume's own zone and the file it came from, read as
    Plaso reads it: the etc/localtime link's target after zoneinfo/, else
    etc/timezone. (None, "") when neither names a zone Plaso can use."""
    etc = _contained(root, "etc")
    if etc is not None:
        try:
            target = os.readlink(etc / "localtime")
        except OSError:
            target = ""
        if "zoneinfo/" in target:
            zone = _valid_zone(target.partition("zoneinfo/")[2])
            return (zone, "etc/localtime") if zone else (None, "")
    tz_file = _contained(root, "etc/timezone")
    try:
        lines = tz_file.read_text(errors="replace").split() if tz_file else []
    except OSError:
        lines = []
    zone = _valid_zone(lines[0]) if lines else None
    return (zone, "etc/timezone") if zone else (None, "")


@dataclass
class DiscoveredHost:
    """A host discovered in a triage package."""

    hostname: str
    volume_root: Path  # directory containing the Windows/ tree
    artifacts: list[tuple[str, Path]] = field(default_factory=list)
    evtx_dir: Path | None = None
    user_profiles: list[Path] = field(default_factory=list)
    vss_id: str = ""  # "live", "vss1", "vss2", etc. Empty = non-VSS
    system_timezone: str | None = None  # IANA zone: the SYSTEM hive, or the volume's etc
    timezone_source: str = ""  # where system_timezone came from
    from_image: bool = False  # found on a mounted disk-image volume, not a folder
    image_path: Path | None = None  # set for a volume Plaso reads straight off the image
    image_args: list[str] = field(default_factory=list)  # its --partitions/--volumes
    volume_label: str = ""  # its partition or volume, stamped as vhir.volume
    zone_note: str = ""  # the zone as Plaso finds it on the image
    os: str = "windows"  # windows | linux | macos
    # The evidence source the records come from (a folder, an image path and
    # volume). Empty: the volume root. A shadow copy shares its volume's, so
    # its records replace the volume's own copies.
    unit_locator: str = ""
    # Where `hostname` came from: the folder name, an argument, or evidence.
    name_origin: str = "folder"


def find_volume_root(host_dir: Path) -> Path | None:
    """Find the volume root within a host directory.

    Uses case-insensitive path resolution to handle NTFS case variations
    in KAPE, Velociraptor, and other triage tools.
    """
    # Direct check: host_dir itself is the volume root
    if os_of_root(host_dir) is not None:
        return host_dir

    # One level deep: drive-letter dirs like C/, C%3A/, D/
    try:
        for child in host_dir.iterdir():
            if not child.is_dir() or child.name.startswith("."):
                continue
            if len(child.name) > 4:
                continue
            if os_of_root(child) is not None:
                return child
    except OSError:
        pass

    return None


def discover_artifacts(host: DiscoveredHost) -> None:
    """Populate a DiscoveredHost with found artifacts.

    All path lookups are case-insensitive to handle NTFS case variations
    on Linux mounts.
    """
    vr = host.volume_root

    # System artifacts
    for artifact_name, rel_path in ARTIFACT_PATHS.items():
        full_path = resolve_case_insensitive(vr, rel_path)
        if full_path is None:
            continue
        if artifact_name in ("recyclebin", "prefetch"):
            if full_path.is_dir():
                host.artifacts.append((artifact_name, full_path))
        elif full_path.is_file():
            host.artifacts.append((artifact_name, full_path))

    # Event logs directory
    evtx_dir = resolve_case_insensitive(vr, "Windows/System32/winevt/Logs")
    if evtx_dir is not None and evtx_dir.is_dir():
        evtx_count = sum(1 for f in evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
        if evtx_count > 0:
            host.evtx_dir = evtx_dir

    # User profiles
    users_dir = resolve_case_insensitive(vr, "Users")
    if users_dir is not None and users_dir.is_dir():
        skip_names = {"public", "default", "default user", "all users"}
        for profile in sorted(users_dir.iterdir()):
            if profile.is_dir() and profile.name.lower() not in skip_names:
                host.user_profiles.append(profile)
                for rel in USER_HIVES:
                    hive = resolve_case_insensitive(profile, rel)
                    if hive is not None and hive.is_file():
                        host.artifacts.append(("registry_user", hive))

                # Per-user artifacts
                for artifact_name, rel_paths in USER_ARTIFACTS.items():
                    if isinstance(rel_paths, list):
                        for rp in rel_paths:
                            full = resolve_case_insensitive(profile, rp)
                            if full is not None and full.is_dir():
                                host.artifacts.append((artifact_name, full))
                    elif rel_paths == "":
                        host.artifacts.append((artifact_name, profile))
                    else:
                        full = resolve_case_insensitive(profile, rel_paths)
                        if full is not None and (full.is_dir() or full.is_file()):
                            host.artifacts.append((artifact_name, full))

    # Plaso's narrow Windows set (browser history, WebCache, SetupAPI) over
    # Users and Windows/inf
    if any(resolve_case_insensitive(vr, d) is not None for d in PLASO_WINDOWS_DIRS):
        host.artifacts.append(("plaso", vr))

    # PowerShell transcripts — read GP config from registry, then discover files
    try:
        from opensearch_mcp.parse_transcripts import (
            _read_transcript_config,
            discover_transcripts,
        )

        gp_dir, tz = _read_transcript_config(vr)
        from opensearch_mcp.paths import resolve_timezone

        host.system_timezone = resolve_timezone(tz)
        host.timezone_source = "registry" if host.system_timezone else ""
        transcript_files = discover_transcripts(vr, gp_transcript_dir=gp_dir)
        if transcript_files:
            # Store volume_root as the artifact path (prefetch pattern) —
            # parser discovers files internally via discover_transcripts()
            host.artifacts.append(("transcripts", vr))
    except ImportError:
        pass  # regipy not installed — skip transcripts

    # Defender MPLog
    mplog_dir = resolve_case_insensitive(vr, "ProgramData/Microsoft/Windows Defender/Support")
    if mplog_dir and mplog_dir.is_dir():
        mplogs = [f for f in mplog_dir.iterdir() if f.name.lower().startswith("mplog")]
        if mplogs:
            host.artifacts.append(("defender", mplog_dir))

    # IIS logs (only if inetpub exists — server hosts)
    iis_dir = resolve_case_insensitive(vr, "inetpub/logs/LogFiles")
    if iis_dir and iis_dir.is_dir():
        host.artifacts.append(("iis", iis_dir))

    # HTTPERR
    httperr_dir = resolve_case_insensitive(vr, "Windows/System32/LogFiles/HTTPERR")
    if httperr_dir and httperr_dir.is_dir():
        host.artifacts.append(("httperr", httperr_dir))

    # Scheduled Tasks XML
    tasks_dir = resolve_case_insensitive(vr, "Windows/System32/Tasks")
    if tasks_dir and tasks_dir.is_dir():
        host.artifacts.append(("tasks", tasks_dir))

    # WER reports — check ALL locations
    for wer_path in [
        "ProgramData/Microsoft/Windows/WER/ReportArchive",
        "ProgramData/Microsoft/Windows/WER/ReportQueue",
    ]:
        wer_dir = resolve_case_insensitive(vr, wer_path)
        if wer_dir and wer_dir.is_dir():
            host.artifacts.append(("wer", wer_dir))
    for profile in host.user_profiles:
        user_wer = resolve_case_insensitive(profile, "AppData/Local/Microsoft/Windows/WER")
        if user_wer and user_wer.is_dir():
            host.artifacts.append(("wer", user_wer))

    # Firewall log
    fw_log = resolve_case_insensitive(vr, "Windows/System32/LogFiles/Firewall/pfirewall.log")
    if fw_log and fw_log.is_file():
        host.artifacts.append(("firewall", fw_log))

    # OpenSSH text logs
    for ssh_path in ["ProgramData/ssh/logs", "Windows/System32/OpenSSH/logs"]:
        ssh_dir = resolve_case_insensitive(vr, ssh_path)
        if ssh_dir and ssh_dir.is_dir():
            host.artifacts.append(("ssh", ssh_dir))


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
        host = make_host(root.name, vr)
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

        host = make_host(subdir.name, vr)
        if host.artifacts or host.evtx_dir:
            hosts.append(host)

    return hosts


def make_host(hostname: str, volume_root: Path) -> DiscoveredHost:
    """The host at a volume root, with its artifacts. A Linux or macOS root is
    one Plaso artifact over the whole volume, with the volume's own zone."""
    host = DiscoveredHost(hostname=hostname, volume_root=volume_root)
    host.os = os_of_root(volume_root) or "windows"
    if host.os == "windows":
        discover_artifacts(host)
    else:
        host.artifacts.append(("plaso", volume_root))
        host.system_timezone, host.timezone_source = unix_timezone(volume_root)
    return host
