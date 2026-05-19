"""Host discovery orchestrator — consolidates every hostname detection
source into one pass before any parser runs.

See `specs/host-identity-2026-05-11.md` v1.

Flow:
  1. discover_hosts(evidence_root, case_dict) walks the evidence and
     extracts raw hostname values from every available source.
  2. For each unique raw value, classifies against the dict:
       - mapped:                 dict already resolves it (no-op)
       - propose_with_match:     propose_canonical returned ≥0.85 match
       - propose_no_match:       no close match — raw becomes own canonical
  3. _preflight_host_discovery (caller) applies decisions:
       - confidence=1.00 exact-strip → add_alias(raw, proposed)
       - propose with confidence <1.00 → add_alias (best guess)
       - no match → add_canonical(raw)
       Then saves the dict atomically. Parsers see a complete dict.

Sources:
  1. Operator override (`hostname=` param) — caller-supplied, not by us.
  2. Registry detect via detect_hostname_from_volume (when VHDX mounted).
  3. Velociraptor client_idx/hostname/ (when datastore present).
  4. Path pattern via --hostname-from-path (when supplied).
  5. Content peek via peek_hostname_from_evidence (first CSV/JSON record).
  6. EVTX Computer-field sampling — one .evtx per host subdir, first 100
     records (implicit aggregate cap: hosts × 100).

discover_hosts() returns data only — no dict mutation, no I/O side
effects. Caller decides what to do with the report.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from opensearch_mcp.host_dictionary import HostDictionary, propose_canonical
from opensearch_mcp.hostname import (
    detect_hostname_from_volume,
    peek_hostname_from_evidence,
)

logger = logging.getLogger(__name__)

# Per-evtx sampling cap. Some forwarder/multi-host evtx files carry
# events from many hosts; we sample multiple .evtx files per subdir
# (Security/System/ForwardedEvents) and bound per-file by record count
# and per-subdir by an aggregate cap.
_EVTX_SAMPLE_RECORDS_PER_FILE = 100
_EVTX_SAMPLE_FILES_PER_SUBDIR = 5
_EVTX_SAMPLE_AGGREGATE_PER_SUBDIR = 1000


def _is_safe_raw_hostname(raw: str) -> bool:
    """Best-effort pre-filter for discovery-sourced raws.

    Authoritative input gating lives at the dict primitives
    (`host_dictionary._validate_hostname_for_storage`). This function
    mirrors that contract for the discovery path so adversarial raws
    from evidence get dropped early (with a log line) rather than
    crashing `add_alias`/`add_canonical` later.

    Allowed: non-empty string, no NULL byte, no ASCII control char
    below 0x20 except tab. Lucene metacharacters and Unicode are
    accepted — they pass safely through the term-DSL filter at query
    time.
    """
    if not isinstance(raw, str) or not raw:
        return False
    if "\x00" in raw:
        return False
    for ch in raw:
        if ord(ch) < 0x20 and ch != "\t":
            return False
    return True


@dataclass
class HostEntry:
    """One unique raw hostname with the sources that observed it."""

    raw: str
    sources: list[dict] = field(default_factory=list)
    # Set by classify(): "mapped" | "propose_with_match" | "propose_no_match"
    status: str = ""
    # Set by classify() when status != "mapped": proposed canonical (or
    # raw itself when no close match).
    proposed_canonical: str | None = None
    confidence: float = 0.0

    def add_source(self, method: str, evidence: str) -> None:
        """Append (method, evidence) — dedup on identical pairs.

        Closes WSL2 Test D2: harvesters can hit the same evidence
        multiple times (e.g., registry walk visits both parent and
        subdir of the same mount root). Without dedup, sources[] would
        list the same pair repeatedly.
        """
        for s in self.sources:
            if s.get("method") == method and s.get("evidence") == evidence:
                return
        self.sources.append({"method": method, "evidence": evidence})


@dataclass
class DiscoveryReport:
    """Result of discover_hosts."""

    entries: list[HostEntry] = field(default_factory=list)

    def by_raw(self) -> dict[str, HostEntry]:
        return {e.raw: e for e in self.entries}

    def unmapped_entries(self) -> list[HostEntry]:
        return [e for e in self.entries if e.status != "mapped"]


def discover_hosts(
    evidence_root: Path,
    case_dict: HostDictionary,
    *,
    hostname_from_path_re: re.Pattern | None = None,
) -> DiscoveryReport:
    """Walk evidence_root, harvest raw hostnames from every source.

    Returns a DiscoveryReport. Pure: no dict writes, no filesystem
    writes other than reads of evidence.

    Performance:
      - peek_hostname_from_evidence caps walk at 50 files
      - evtx sampling: one .evtx per host subdir, ≤100 records each
      - Velociraptor walk caps at client_idx/hostname/ directory only
    """
    report = DiscoveryReport()
    raws: dict[str, HostEntry] = {}  # normalized raw → entry

    if not evidence_root or not evidence_root.exists():
        return report

    # Source 2: registry detect on every mounted volume root we can find.
    # In the cmd_scan flow the caller mounts before calling discover_hosts;
    # we walk for SYSTEM hives under the evidence root as a backstop.
    _harvest_registry(evidence_root, raws)

    # Source 3: Velociraptor client_idx/hostname/ if present.
    _harvest_velociraptor_client_idx(evidence_root, raws)

    # Source 4: path-pattern extraction.
    if hostname_from_path_re is not None:
        _harvest_path_pattern(evidence_root, hostname_from_path_re, raws)

    # Source 5: content peek (first parseable CSV/JSON record).
    peeked = peek_hostname_from_evidence(evidence_root)
    if peeked:
        entry = raws.setdefault(peeked, HostEntry(raw=peeked))
        entry.add_source("csv_peek", str(evidence_root))

    # Source 6: EVTX Computer-field sampling (one .evtx per host subdir,
    # first _EVTX_SAMPLE_RECORDS each).
    _harvest_evtx_sample(evidence_root, raws)

    # Adversarial-input gate. Strip any raw with NULL byte or ASCII
    # control char before classification — these survive yaml.safe_dump
    # as escape-encoded strings (PyYAML doesn't raise) and would
    # contaminate the dict on disk.
    rejected = [raw for raw in raws if not _is_safe_raw_hostname(raw)]
    for raw in rejected:
        logger.warning("rejecting adversarial raw hostname %r from discovery", raw)
        del raws[raw]

    # Classify each raw against the existing dictionary.
    for entry in raws.values():
        _classify(entry, case_dict)

    report.entries = list(raws.values())
    return report


def _classify(entry: HostEntry, case_dict: HostDictionary) -> None:
    """Set entry.status, entry.proposed_canonical, entry.confidence."""
    canonical = case_dict.resolve(entry.raw)
    if canonical is not None:
        entry.status = "mapped"
        entry.proposed_canonical = canonical
        entry.confidence = 1.0
        return
    proposed, confidence = propose_canonical(entry.raw, case_dict)
    if proposed is not None:
        entry.status = "propose_with_match"
        entry.proposed_canonical = proposed
        entry.confidence = confidence
    else:
        entry.status = "propose_no_match"
        entry.proposed_canonical = entry.raw  # auto_new_canonical default
        entry.confidence = 0.0


def _harvest_registry(evidence_root: Path, raws: dict[str, HostEntry]) -> None:
    """Walk for SYSTEM hives under evidence_root, extract host.name.

    Looks for Windows/System32/config/SYSTEM at any depth (case-
    insensitive via resolve_case_insensitive in detect_hostname_from_volume).
    detect_hostname_from_volume takes a volume_root; we feed it candidate
    roots (depth-bounded search).
    """
    try:
        # Look for SYSTEM hives up to 5 levels deep — covers
        # tmpdir/<mount>/Windows/... and tmpdir/<host>/<mount>/...
        candidates = []
        for depth_root in [evidence_root] + [p for p in evidence_root.iterdir() if p.is_dir()]:
            if (depth_root / "Windows" / "System32" / "config" / "SYSTEM").exists() or any(
                depth_root.rglob("SYSTEM")
            ):
                candidates.append(depth_root)
        for vol in candidates[:10]:  # bound to first 10 plausible roots
            try:
                hn = detect_hostname_from_volume(vol)
            except (OSError, Exception) as e:
                logger.debug("registry detect on %s failed: %s", vol, e)
                continue
            if hn:
                entry = raws.setdefault(hn, HostEntry(raw=hn))
                entry.add_source("registry", str(vol))
    except OSError as e:
        logger.debug("registry walk failed under %s: %s", evidence_root, e)


def _harvest_velociraptor_client_idx(
    evidence_root: Path,
    raws: dict[str, HostEntry],
) -> None:
    """Read Velociraptor client_idx/hostname/ JSON files when present.

    Each JSON file maps a client GUID to a hostname. Both values become
    aliases of the eventual canonical (operator typically aliases the
    GUID to the hostname via case_host_fix later).
    """
    candidates = list(evidence_root.rglob("client_idx/hostname/*"))
    for path in candidates[:200]:  # cap to bound runaway datastores
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("client_idx %s parse failed: %s", path, e)
            continue
        if not isinstance(data, dict):
            continue
        guid = data.get("client_id") or path.name
        hn = data.get("os_info", {}).get("hostname") or data.get("hostname")
        if guid:
            entry = raws.setdefault(str(guid), HostEntry(raw=str(guid)))
            entry.add_source("velociraptor_client_idx", str(path))
        if hn:
            entry = raws.setdefault(str(hn), HostEntry(raw=str(hn)))
            entry.add_source("velociraptor_client_idx", str(path))


def _harvest_path_pattern(
    evidence_root: Path,
    pattern: re.Pattern,
    raws: dict[str, HostEntry],
) -> None:
    """Apply --hostname-from-path regex to every file under evidence_root.

    Capture group 1 is the raw hostname. L2: os.walk with followlinks=
    False so symlink loops in evidence trees don't hang discovery.
    """
    import os as _os

    try:
        for dirpath, _dirnames, filenames in _os.walk(evidence_root, followlinks=False):
            for fname in filenames:
                path = Path(dirpath) / fname
                m = pattern.search(str(path))
                if not m or not m.groups():
                    continue
                raw = m.group(1)
                if not raw:
                    continue
                entry = raws.setdefault(raw, HostEntry(raw=raw))
                entry.add_source("from_path", str(path))
    except OSError as e:
        logger.debug("path-pattern walk failed under %s: %s", evidence_root, e)


def _harvest_evtx_sample(evidence_root: Path, raws: dict[str, HostEntry]) -> None:
    """Sample EVTX Computer fields per host subdir.

    Sampling shape (closes WSL2 Test B3 — preflight missed origin hosts
    on forwarder/multi-evtx setups):
      - For each immediate subdirectory of evidence_root, prefer the
        forwarder-relevant evtx files (ForwardedEvents, Security,
        System, Application) over arbitrary order.
      - Sample up to _EVTX_SAMPLE_FILES_PER_SUBDIR files per subdir.
      - Sample up to _EVTX_SAMPLE_RECORDS_PER_FILE records per file.
      - Stop the subdir's sampling once _EVTX_SAMPLE_AGGREGATE_PER_SUBDIR
        records have been read across all files.

    Best-effort: if pyevtx-rs is unavailable or a file fails to parse,
    the source contributes nothing — discovery doesn't fail.
    """
    try:
        from evtx import PyEvtxParser
    except ImportError:
        logger.debug("pyevtx-rs not available; skipping evtx sampling")
        return

    # File-name priority — forwarder + auth-relevant first; multi-host
    # values are most likely to surface in these. Anything else is
    # sampled too but only up to the per-subdir budget.
    _PRIORITY_PREFIXES = (
        "forwardedevents",
        "security",
        "system",
        "application",
    )

    subdirs = [d for d in evidence_root.iterdir() if d.is_dir()] if evidence_root.is_dir() else []
    if not subdirs:
        subdirs = [evidence_root]

    for subdir in subdirs:
        evtx_files = list(subdir.rglob("*.evtx"))
        if not evtx_files:
            continue

        # Sort: priority-prefix files first (alphabetical within tier),
        # everything else after (alphabetical).
        def _priority(p: Path) -> tuple[int, str]:
            name = p.name.lower()
            for idx, prefix in enumerate(_PRIORITY_PREFIXES):
                if name.startswith(prefix):
                    return (idx, name)
            return (len(_PRIORITY_PREFIXES), name)

        evtx_files.sort(key=_priority)

        subdir_records_total = 0
        for evtx in evtx_files[:_EVTX_SAMPLE_FILES_PER_SUBDIR]:
            if subdir_records_total >= _EVTX_SAMPLE_AGGREGATE_PER_SUBDIR:
                break
            try:
                parser = PyEvtxParser(str(evtx))
                file_count = 0
                for record in parser.records_json():
                    if file_count >= _EVTX_SAMPLE_RECORDS_PER_FILE:
                        break
                    if subdir_records_total >= _EVTX_SAMPLE_AGGREGATE_PER_SUBDIR:
                        break
                    file_count += 1
                    subdir_records_total += 1
                    try:
                        data = json.loads(record["data"])
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue
                    ev = data.get("Event") or {}
                    system = ev.get("System") or {}
                    computer = system.get("Computer")
                    if computer:
                        entry = raws.setdefault(str(computer), HostEntry(raw=str(computer)))
                        entry.add_source("evtx_sample", str(evtx))
            except Exception as e:
                logger.debug("evtx sample on %s failed: %s", evtx, e)
                continue
