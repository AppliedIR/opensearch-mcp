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
    prefetch: bool = False,
    srum: bool = False,
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
            cdp = profile / "AppData" / "Local" / "ConnectedDevicesPlatform" / f"L.{uname}"
            cdp.mkdir(parents=True)
            (cdp / "ActivitiesCache.db").write_bytes(b"SQLite format 3\x00")

    # Prefetch
    if prefetch:
        pf_dir = root / "Windows" / "Prefetch"
        pf_dir.mkdir(parents=True, exist_ok=True)
        (pf_dir / "CMD.EXE-89305D47.pf").touch()

    # SRUM
    if srum:
        sru_dir = root / "Windows" / "System32" / "SRU"
        sru_dir.mkdir(parents=True, exist_ok=True)
        (sru_dir / "SRUDB.dat").touch()

    # Skipped profiles
    for skip in ("Public", "Default", "All Users"):
        (root / "Users" / skip).mkdir(parents=True, exist_ok=True)


def confirm_unit(case_dir, path, *names) -> str:
    """Confirm, as the examiner would in the Hosts tab, the names a run of
    `path` gives (through the product's decision API), so a worker started as
    its own process goes through the host gate. Returns the machine key."""
    from sift_common import host_identity as hi

    unit = hi.unit_key(hi.unit_locator(path, case_dir))
    hi.ensure_host_files(case_dir)
    hi.append_observations(case_dir, [{"kind": "unit", "unit": unit, "locator":
                                        hi.unit_locator(path, case_dir)}])  # fmt: skip
    key = hi.new_machine_key()
    hi.append_decision(case_dir, {"action": "confirm", "examiner": "test", "args": {
        "machines": [{"key": key, "canonical": names[0],
                      "pairs": [[unit, n] for n in names]}]}},
        hi.load(case_dir).obs_offset)  # fmt: skip
    return key
