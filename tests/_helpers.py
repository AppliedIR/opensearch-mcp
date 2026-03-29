"""Shared test helpers (importable, unlike conftest.py)."""

from __future__ import annotations

from pathlib import Path


def make_windows_tree(
    root: Path,
    *,
    users: list[str] | None = None,
    mft: bool = False,
    recycle_bin: bool = False,
    usn: bool = False,
    timeline: bool = False,
) -> None:
    """Create a realistic Windows directory structure.

    Args:
        root: volume root
        users: user profile names to create (default: ["admin"])
        mft: create $MFT at volume root
        recycle_bin: create $Recycle.Bin directory
        usn: create $Extend/$J
        timeline: create ActivitiesCache.db per user
    """
    if users is None:
        users = ["admin"]

    # System32/config hives
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY"):
        (config / hive).touch()

    # Amcache
    amcache = root / "Windows" / "appcompat" / "Programs"
    amcache.mkdir(parents=True)
    (amcache / "Amcache.hve").touch()

    # Event logs
    evtx_dir = root / "Windows" / "System32" / "winevt" / "Logs"
    evtx_dir.mkdir(parents=True)
    (evtx_dir / "Security.evtx").touch()
    (evtx_dir / "System.evtx").touch()

    # MFT
    if mft:
        (root / "$MFT").touch()

    # Recycle Bin
    if recycle_bin:
        (root / "$Recycle.Bin").mkdir(exist_ok=True)

    # USN Journal
    if usn:
        extend = root / "$Extend"
        extend.mkdir(exist_ok=True)
        (extend / "$J").touch()

    # User profiles
    for uname in users:
        profile = root / "Users" / uname
        profile.mkdir(parents=True, exist_ok=True)

        # Recent items (for jumplists + lnk)
        recent = profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
        recent.mkdir(parents=True)

        # Desktop (for lnk)
        (profile / "Desktop").mkdir(exist_ok=True)

        # Timeline
        if timeline:
            cdp = profile / "AppData" / "Local" / "ConnectedDevicesPlatform"
            cdp.mkdir(parents=True)

    # Skipped profiles
    for skip in ("Public", "Default", "All Users"):
        (root / "Users" / skip).mkdir(parents=True, exist_ok=True)
