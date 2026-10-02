"""Volatility 3 plugin tiers for a memory ingest.

Kept free of other imports: the vhir command line registers its subcommands
on every run, and reads the tiers from here.
"""

# Plugin tiers — ordered within each tier for dependency resolution
TIER_1 = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netstat",
    "windows.svcscan",
    "windows.modules",
    "windows.registry.hivelist",
]

TIER_2 = TIER_1 + [
    "windows.netscan",
    "windows.dlllist",
    "windows.envars",
    "windows.getsids",
    "windows.psscan",
    "windows.ldrmodules",
    "windows.callbacks",
    "windows.ssdt",
    "windows.registry.userassist",
]

TIER_3 = TIER_2 + [
    "windows.handles",
    "windows.filescan",
    "windows.malfind",
    "windows.shimcachemem",
    "windows.driverscan",
    "windows.mutantscan",
    "timeliner",
]
# UAT 2026-04-23 BUG 4: removed from TIER_3:
# - windows.registry.hashdump — not in Vol3 2.26.2's argparse choice
#   list (errors with "invalid choice PLUGIN" on every invocation).
#   Credentials evidence is better surfaced via disk-side SAM/SECURITY
#   hives (already ingested as the "registry" artifact) + live-collected
#   creds from Kansa/Velociraptor.
# - windows.vadinfo — compute-heavy (>60s on 5GB memory images, times
#   out) and its forensic value overlaps malfind + dlllist + ldrmodules
#   + handles that are already in the tier. Operators can run it on-
#   demand via `vol -f <img> windows.vadinfo --pid <pid>`.

# The tiers a memory ingest accepts: the tool, the CLI and the worker read this.
TIERS = {1: TIER_1, 2: TIER_2, 3: TIER_3}
