"""Hostname extraction primitives consumed by the v1 host-identity preflight.

See `specs/host-identity-2026-05-11.md` v1. The discovery orchestrator
(`host_discovery.discover_hosts`) calls these primitives once per
ingest to populate the case host-dictionary with auto-applied
decisions. Parsers then resolve `host.id` from that dictionary at
parse time.

Exports:
  - `_HOST_FIELD_PRIORITY` — first-hit-wins field list for CSV/JSON.
  - `extract_host_from_record` — walk the priority list on one record.
  - `detect_hostname_from_volume` — read ComputerName+Domain from a
    mounted volume's SYSTEM hive.
  - `peek_hostname_from_evidence` — first parseable CSV/JSON file in
    the evidence root; extract the hostname from its first record.
  - `classify_host` — `(status, raw, proposed, confidence)` against a
    dictionary; used by both `host_discovery._classify` and downstream
    consumers.

Archive basename is NEVER used as host.name. The shipped Rev 8
fail-loud surface (`write_host_unmapped_yaml`,
`archive_resolved_unmapped_yaml`, `_classify_or_fail` in
ingest_cli.py) is removed in v1; the always-proceed preflight in
`ingest_cli._preflight_host_discovery` replaces it.

IMPLEMENTATION CONTRACT (regipy leading-backslash):
  `regipy.RegistryHive.get_key()` requires a leading `\\` on the path.
  Without it the call silently raises RegistryKeyNotFoundException.
  See `parse_transcripts._read_transcript_config` (commit 93cdd27) for
  the established precedent — same ControlSet001/002 fallback, same
  graceful-None error posture.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from opensearch_mcp.paths import resolve_case_insensitive

if TYPE_CHECKING:
    from opensearch_mcp.host_dictionary import HostDictionary

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
    host_dict: HostDictionary | None,
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


def peek_hostname_from_evidence(scan_root: Path) -> str | None:
    """Walk `scan_root` for the first parseable CSV/JSONL/JSON file and
    extract a hostname from its first record via `_HOST_FIELD_PRIORITY`.

    Rev 1.5 Commit B fallback affordance — when registry detect fails,
    gives cmd_scan's classify step a real hostname (from evidence
    content) instead of directory-scan junk like `_mnt_1`. So when
    host-unmapped.yaml lands, the operator sees a meaningful raw name
    (e.g. `admin01.shieldbase.com` from evtx Computer field) that they
    can propose a canonical for.

    Returns None when:
      - scan_root has no CSV/JSONL/JSON files (bare VHDX mount with
        no pre-extracted artifacts)
      - all candidate files fail to parse / have no priority-list field
      - any filesystem error (scan_root missing, permission denied)

    Skips `.index` sidecars (Velociraptor binary offsets) and respects
    the extension allowlist used by idx_ingest_json.

    Does NOT parse evtx — that requires pyevtx-rs spinning up a parser
    per file; cost isn't worth it for a fallback affordance. Most
    triage packages carry CSVs (Kansa, EZ-tool output) or JSON
    (Velociraptor) alongside any evtx.
    """
    if not scan_root or not scan_root.exists():
        return None

    import csv
    import json as _json

    allowed_suffixes = {".csv", ".tsv", ".json", ".jsonl", ".ndjson"}
    try:
        candidates = sorted(
            f
            for f in scan_root.rglob("*")
            if f.is_file()
            and f.suffix.lower() in allowed_suffixes
            and not f.name.endswith(".index")
        )
    except OSError:
        return None

    for path in candidates[:50]:  # cap walk cost — early hits are typical
        try:
            if path.suffix.lower() in (".json", ".jsonl", ".ndjson"):
                with open(path, encoding="utf-8", errors="replace") as f:
                    head = f.readline().strip()
                    if not head:
                        continue
                    # jsonl first; array fallback; pretty single-object
                    # not covered here (first-line `{` would parse OK via
                    # a fuller read, but for a fallback-affordance peek
                    # the jsonl / array shapes cover the interesting
                    # cases)
                    if head.startswith("["):
                        rest = head + f.read()
                        try:
                            arr = _json.loads(rest)
                        except _json.JSONDecodeError:
                            continue
                        if not arr:
                            continue
                        record = arr[0]
                    else:
                        try:
                            record = _json.loads(head)
                        except _json.JSONDecodeError:
                            continue
                if not isinstance(record, dict):
                    continue
                hn = extract_host_from_record(record)
                if hn:
                    return hn
            else:  # .csv / .tsv
                delim = "\t" if path.suffix.lower() == ".tsv" else ","
                with open(path, encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f, delimiter=delim)
                    row = next(reader, None)
                if row is None:
                    continue
                hn = extract_host_from_record(dict(row))
                if hn:
                    return hn
        except (OSError, UnicodeError, csv.Error):
            # csv.Error catches Python 3.10's "line contains NUL"; later
            # Pythons may not raise but the input is still adversarial
            # and the discover gate drops it downstream regardless.
            continue
    return None
