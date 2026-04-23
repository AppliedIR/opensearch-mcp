"""Parse Windows Defender MPLog + MPDetection files.

UAT 2026-04-24 (3-bug chain): MPLog/MPDetection are UTF-16LE on disk
(per Defender's native encoding on Windows), the parser used to glob
only `MPLog-*.log` so the MPDetection behavioral channel was invisible,
and the `_DETECTION_PATTERN` regex targeted a legacy `DETECTION_ADD ...
Name:<x>#` format that current Defender versions don't emit. All three
defects had to be fixed together — any one alone still yielded 0 docs.
See `parse-defender-3bug-chain-2026-04-24.md` for the full analysis.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

_TS_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(.+)")

# New-format DETECTION (Defender current — behavioral/signature both).
# Matches: "DETECTION Behavior:Win32/CobaltStrike.E!sms behavior:process:..."
# `\b` word boundary prevents mid-word matches on tokens like
# "PREDETECTION". Named groups power the indexed-doc field map.
_DETECTION_PATTERN = re.compile(
    r"\bDETECTION\s+(?P<category>[A-Za-z]+):"
    r"(?P<platform>[^/\s]+)/"
    r"(?P<name>[^\s!]+)"
    r"(?:!(?P<variant>\w+))?"
    r"(?:\s+(?P<context>.+))?"
)

# Legacy-format DETECTION (older Defender builds). Retained as a
# fallback when `_DETECTION_PATTERN` doesn't match — zero loss of
# coverage for corpora we haven't surveyed yet. Matches the pre-UAT
# shape `DETECTION_ADD ... Name:<threat>#`.
_LEGACY_DETECTION_PATTERN = re.compile(
    r"DETECTION[_\s]*(ADD|CLEAN|DELETE).*?Name[:\s]*(.+?)(?:#|$)"
)

_EXCLUSION_ADD = re.compile(r"(?:Adding|Added)\s+exclusion[:\s]*(.+)", re.IGNORECASE)
_EXCLUSION_DEL = re.compile(r"(?:Removing|Removed)\s+exclusion[:\s]*(.+)", re.IGNORECASE)
_THREAT_PATTERN = re.compile(r"ThreatType[:\s]*(.+?)(?:#|\s|$)")
_FILE_PATTERN = re.compile(r"(?:file|path)[:\s]*(.+?)(?:#|\s*$)", re.IGNORECASE)

# Context sub-parse patterns for the DETECTION tail. Each shape maps a
# leading keyword to ECS-style field(s) on the indexed doc. Unmatched
# context stays in `defender.detection_context` raw.
_CTX_BEHAVIOR_PROCESS = re.compile(
    r"behavior:process:\s*(?P<path>.+?)(?:,\s*pid:(?P<pid>\d+))?$", re.IGNORECASE
)
_CTX_FILE = re.compile(r"file:\s*(?P<path>.+?)$", re.IGNORECASE)
_CTX_REGKEY = re.compile(r"regkey:\s*(?P<path>.+?)$", re.IGNORECASE)
_CTX_TASKSCHEDULER = re.compile(r"taskscheduler:\s*(?P<path>.+?)$", re.IGNORECASE)


def _sniff_encoding(path: Path) -> str:
    """Return the codec name to open `path` with, sniffed from the BOM.

    MPLog/MPDetection are UTF-16LE on Windows. Using `"utf-16-le"`
    decodes the bytes but leaves the BOM as `\\ufeff` in the decoded
    text, which breaks downstream `^`-anchored regex on line 1. The
    bare `"utf-16"` codec auto-detects LE/BE from the BOM AND consumes
    it — which is what we want. Collapsing both UTF-16 variants to
    `"utf-16"` is correct and simpler than paper-over handling of the
    residual `\\ufeff` in every consumer.
    """
    with open(path, "rb") as fb:
        head = fb.read(4)
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def _parse_detection_context(context: str, doc: dict) -> None:
    """Best-effort sub-parse of DETECTION context tail into ECS-ish fields.

    Matches the 4 shapes observed on the SRL corpus:
      behavior:process:<path>[, pid:<n>]  → process.executable, process.pid
      file:<path>                         → file.path
      regkey:<path>                       → registry.key
      taskscheduler:<path>                → defender.task_name

    Unmatched shapes stay in `doc["defender.detection_context"]` raw
    (set by caller) — safe floor for any shape not in this catalog.
    """
    if not context:
        return
    context = context.strip()

    m = _CTX_BEHAVIOR_PROCESS.match(context)
    if m:
        doc["process.executable"] = m.group("path").strip().rstrip(",")
        if m.group("pid"):
            try:
                doc["process.pid"] = int(m.group("pid"))
            except ValueError:
                pass  # malformed pid — leave unset vs. index non-int
        return

    m = _CTX_FILE.match(context)
    if m:
        doc["file.path"] = m.group("path").strip()
        return

    m = _CTX_REGKEY.match(context)
    if m:
        doc["registry.key"] = m.group("path").strip()
        return

    m = _CTX_TASKSCHEDULER.match(context)
    if m:
        doc["defender.task_name"] = m.group("path").strip()
        return
    # No match — raw context remains on the doc per caller.


def parse_mplog(
    mplog_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    system_timezone: str | None = None,
    volume_root: Path | None = None,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Parse all MPLog files in directory. Returns (indexed, skipped, bulk_failed)."""
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    from dateutil.tz import gettz, tzutc

    from opensearch_mcp.paths import relative_evidence_path

    tz_info = gettz(system_timezone) if system_timezone else None

    # Glob both MPLog-*.log (telemetry + exclusions) and MPDetection-*.log
    # (behavioral detections). Alphabetical sort places MPDetection first
    # lexically; order doesn't matter functionally — timestamps drive
    # indexing and doc IDs are content-hashed. MPDeviceControl-*.log is
    # explicitly out of scope (removable-media schema unsurveyed).
    mp_files = sorted(
        list(mplog_dir.glob("MPLog-*.log")) + list(mplog_dir.glob("MPDetection-*.log"))
    )
    for log_file in mp_files:
        rel_file = relative_evidence_path(log_file, volume_root) if volume_root else str(log_file)
        current_ts = None

        # Sniff BOM to pick codec. MPLog/MPDetection are UTF-16LE on
        # disk; prior `utf-8-sig` decoded to NUL-interleaved garbage and
        # silently skipped every line. Must use bare `utf-16` (not
        # `utf-16-le`) so the BOM is consumed — suffixed codec leaves
        # `\ufeff` in the text and breaks `^` anchors on line 1.
        enc = _sniff_encoding(log_file)
        with open(log_file, encoding=enc, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                doc: dict = {"host.name": hostname}

                ts_match = _TS_PATTERN.match(line)
                if ts_match:
                    current_ts = ts_match.group(1)
                    line_body = ts_match.group(2)
                else:
                    line_body = line

                if current_ts:
                    # Convert non-UTC timestamps to UTC
                    if current_ts.endswith("Z"):
                        doc["@timestamp"] = current_ts
                    elif tz_info:
                        try:
                            naive = datetime.fromisoformat(current_ts)
                            aware = naive.replace(tzinfo=tz_info)
                            utc_ts = aware.astimezone(tzutc()).isoformat().replace("+00:00", "Z")
                            doc["@timestamp"] = utc_ts
                            current_ts = utc_ts  # use converted for filtering
                        except ValueError:
                            doc["@timestamp"] = current_ts
                    else:
                        # No timezone, no Z — skip this line (unreliable timestamp)
                        skipped += 1
                        continue

                # Time range filter
                if current_ts and (time_from or time_to):
                    try:
                        ts = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
                        if time_from and ts < time_from:
                            skipped += 1
                            continue
                        if time_to and ts > time_to:
                            skipped += 1
                            continue
                    except ValueError:
                        pass

                # Classify line. Try the new (current Defender) DETECTION
                # shape first, then the legacy DETECTION_ADD/CLEAN/DELETE
                # shape as a fallback. Exclusions are a third independent
                # classification shared by both formats.
                det = _DETECTION_PATTERN.search(line_body)
                legacy_det = None if det else _LEGACY_DETECTION_PATTERN.search(line_body)
                excl_add = None if (det or legacy_det) else _EXCLUSION_ADD.search(line_body)
                excl_del = (
                    None if (det or legacy_det or excl_add) else _EXCLUSION_DEL.search(line_body)
                )

                if det:
                    doc["defender.event_type"] = "detection"
                    doc["defender.detection_category"] = det.group("category")
                    doc["defender.platform"] = det.group("platform")
                    doc["defender.threat_name"] = det.group("name")
                    if det.group("variant"):
                        doc["defender.variant"] = det.group("variant")
                    context = det.group("context")
                    if context:
                        # Raw tail first so operators always see what we
                        # saw, even if the sub-parse couldn't classify it.
                        doc["defender.detection_context"] = context.strip()
                        _parse_detection_context(context, doc)
                elif legacy_det:
                    # Backward-compat: older Defender builds emit
                    # "DETECTION_ADD ... Name:<threat>#". Preserve the
                    # pre-UAT field shape so operators re-ingesting
                    # legacy corpora still see detection_add / _clean /
                    # _delete as before.
                    doc["defender.event_type"] = f"detection_{legacy_det.group(1).lower()}"
                    doc["defender.threat_name"] = legacy_det.group(2).strip()
                    threat = _THREAT_PATTERN.search(line_body)
                    if threat:
                        doc["defender.threat_type"] = threat.group(1).strip()
                    fpath = _FILE_PATTERN.search(line_body)
                    if fpath:
                        doc["file.path"] = fpath.group(1).strip()
                elif excl_add:
                    doc["defender.event_type"] = "exclusion_added"
                    doc["defender.exclusion_path"] = excl_add.group(1).strip()
                elif excl_del:
                    doc["defender.event_type"] = "exclusion_removed"
                    doc["defender.exclusion_path"] = excl_del.group(1).strip()
                else:
                    skipped += 1
                    continue  # skip noise — only index forensic events

                doc["defender.raw_line"] = line_body
                from opensearch_mcp.paths import relative_evidence_path

                doc["vhir.source_file"] = (
                    relative_evidence_path(log_file, volume_root) if volume_root else str(log_file)
                )
                if ingest_audit_id:
                    doc["vhir.ingest_audit_id"] = ingest_audit_id
                if pipeline_version:
                    doc["pipeline_version"] = pipeline_version
                doc["vhir.parse_method"] = "defender-mplog"
                if vss_id:
                    doc["vhir.vss_id"] = vss_id

                line_hash = hashlib.md5(line_body.encode()).hexdigest()
                id_input = f"{index_name}:{rel_file}:{current_ts or ''}:{line_hash}"
                doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
                actions.append({"_index": index_name, "_id": doc_hash, "_source": doc})

                if len(actions) >= 1000:
                    flushed, failed = flush_bulk(client, actions)
                    count += flushed
                    bulk_failed += failed
                    actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, skipped, bulk_failed
