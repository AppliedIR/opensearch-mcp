"""Hostname detection for idx_ingest auto-hostname priority chain.

See `specs/host-identity-normalization-2026-04-24.md` Rev 5 — Fix C. The
ingest-time priority order:

  1. `hostname=` param (operator override)                    [caller]
  2. Mounted volume registry → ComputerName + Domain          [this file]
  3. Evidence-internal field-priority (first doc's hostname)  [this file]
  4. Fail loud — `hostname_unmapped` response + proposal      [caller]

Archive basename is NEVER used as host.name — that fallback is removed in
this same commit (ingest_cli.py line 398 pre-fix).

IMPLEMENTATION CONTRACT (regipy leading-backslash):
  `regipy.RegistryHive.get_key()` requires a leading `\\` on the path.
  Without it the call silently raises RegistryKeyNotFoundException.
  This was the root cause of BUG 1 in the parse_defender 3-bug chain
  and cost a full session to rediscover. See
  `parse_transcripts._read_transcript_config` (commit 93cdd27) for the
  established precedent — same ControlSet001/002 fallback, same
  graceful-None error posture.
"""

from __future__ import annotations

import logging
from pathlib import Path

from opensearch_mcp.paths import resolve_case_insensitive

logger = logging.getLogger(__name__)


# Shared per-row/per-doc hostname source fields for parse_csv + parse_json.
# First non-empty hit wins; extends by new conventions without touching
# parser logic. Velociraptor / Kansa / ad-hoc JSON all pass through this.
_HOST_FIELD_PRIORITY: tuple[str, ...] = (
    "Host",  # Kansa convention
    "ComputerName",  # Windows-native artifacts
    "Computer",  # EventData.Computer flattened into JSON
    "Hostname",  # Velociraptor default
    "ClientInfo.Hostname",  # Velociraptor nested (dotted)
    "host.name",  # pre-stamped by upstream, preserved verbatim
)


def _dotted_get(doc: dict, dotted: str) -> object | None:
    """Traverse `doc` by dotted key path. Returns None on any gap."""
    cur: object = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def extract_host_from_record(doc: dict) -> str | None:
    """Walk `_HOST_FIELD_PRIORITY` on a parsed CSV row / JSON doc.

    First non-empty string hit wins. Returns the raw value unchanged —
    normalization is HostDictionary's job. None if no priority field
    resolves.
    """
    for field in _HOST_FIELD_PRIORITY:
        val = _dotted_get(doc, field) if "." in field else doc.get(field)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def detect_hostname_from_volume(volume_root: Path) -> str | None:
    """Read ComputerName + Domain from mounted volume's SYSTEM hive.

    Returns raw FQDN (case-preserved from registry) or None.

    Contract:
      - Leading backslash on every `get_key` call (regipy requirement).
      - ControlSet001 primary, ControlSet002 fallback when 001 absent.
      - Graceful None on any regipy exception — never raise out.
      - Joins name+domain as "<Name>.<Domain>" if both present; returns
        bare name if domain absent.

    See module docstring and `parse_transcripts._read_transcript_config`
    (93cdd27) for the established precedent.
    """
    system = resolve_case_insensitive(volume_root, "Windows/System32/config/SYSTEM")
    if not system:
        return None

    try:
        from regipy.registry import RegistryHive
    except ImportError:
        logger.warning("regipy not available; skipping registry hostname detect")
        return None

    try:
        reg = RegistryHive(str(system))
    except Exception as e:
        logger.warning("could not open SYSTEM hive at %s: %s", system, e)
        return None

    computer_name: str | None = None
    domain: str | None = None

    for cs in ("ControlSet001", "ControlSet002"):
        # ComputerName\ActiveComputerName is what Windows uses; fall back to
        # ComputerName\ComputerName when the Active variant is absent.
        for sub in ("ActiveComputerName", "ComputerName"):
            try:
                key = reg.get_key(f"\\{cs}\\Control\\ComputerName\\{sub}")
                for val in key.iter_values():
                    if val.name == "ComputerName" and val.value:
                        computer_name = str(val.value).strip()
                        break
                if computer_name:
                    break
            except Exception as e:
                logger.debug("no %s\\Control\\ComputerName\\%s: %s", cs, sub, e)
                continue
        if computer_name:
            # Domain lookup in the same ControlSet
            try:
                key = reg.get_key(f"\\{cs}\\Services\\Tcpip\\Parameters")
                for val in key.iter_values():
                    if val.name == "Domain" and val.value:
                        domain = str(val.value).strip()
                        break
            except Exception as e:
                logger.debug("no %s Tcpip Parameters Domain: %s", cs, e)
            break

    if not computer_name:
        return None
    if domain:
        return f"{computer_name}.{domain}"
    return computer_name


def classify_host(
    raw: str | None,
    host_dict,
) -> tuple[str, str | None, str | None, float]:
    """Classify a raw hostname against the dictionary.

    Returns (status, raw, proposed_canonical, confidence):
      - "mapped"                  : raw resolves directly → canonical is set
      - "unmapped-with-proposal"  : resolve misses but propose_canonical
                                    returns a suggestion at ≥0.85
      - "unmapped-no-proposal"    : miss and no close match
      - "empty"                   : raw was empty/None (caller decides)
    """
    from opensearch_mcp.host_dictionary import propose_canonical

    if not raw or not raw.strip():
        return "empty", raw, None, 0.0
    canonical = host_dict.resolve(raw) if host_dict else None
    if canonical is not None:
        return "mapped", raw, canonical, 1.0
    if not host_dict:
        return "unmapped-no-proposal", raw, None, 0.0
    suggestion, conf = propose_canonical(raw, host_dict)
    if suggestion is not None:
        return "unmapped-with-proposal", raw, suggestion, conf
    return "unmapped-no-proposal", raw, None, 0.0


def write_host_unmapped_yaml(
    case_dir: Path,
    entries: list[dict],
) -> Path:
    """Write `<case-dir>/host-unmapped.yaml` with entries + actionable cmds.

    Each entry dict should carry at least:
        raw, first_seen, sources, proposed_canonical, confidence
    """
    import yaml

    path = case_dir / "host-unmapped.yaml"
    payload = {
        "note": (
            "Ingest blocked — resolve each entry below by running the "
            "suggested command. Re-run idx_ingest after all are resolved; "
            "this file will be renamed to host-unmapped.yaml.resolved.<ts>."
        ),
        "entries": entries,
    }
    path.write_text(
        yaml.safe_dump(payload, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return path


def archive_resolved_unmapped_yaml(case_dir: Path) -> Path | None:
    """Rename host-unmapped.yaml to host-unmapped.yaml.resolved.<ISO8601>.

    Returns the new path, or None if no file to rename. Called after a
    successful re-run where every previously-unmapped entry now resolves.
    """
    from datetime import datetime, timezone

    src = case_dir / "host-unmapped.yaml"
    if not src.exists():
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = case_dir / f"host-unmapped.yaml.resolved.{ts}"
    src.rename(dest)
    return dest
