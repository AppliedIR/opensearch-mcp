"""PowerShell transcript parser — discover, parse, and index transcript files."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path, PureWindowsPath

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk
from opensearch_mcp.parse_csv import _doc_id
from opensearch_mcp.paths import resolve_case_insensitive


def _read_transcript_config(volume_root: Path) -> tuple[str | None, str | None]:
    """Read PS transcript GP config + system timezone from registry hives.

    Returns (gp_transcript_dir, windows_timezone_name).
    """
    transcript_dir = None
    timezone = None

    software = resolve_case_insensitive(volume_root, "Windows/System32/config/SOFTWARE")
    if software:
        try:
            from regipy.registry import RegistryHive

            reg = RegistryHive(str(software))
            key = reg.get_key("Policies\\Microsoft\\Windows\\PowerShell\\Transcription")
            for val in key.iter_values():
                if val.name == "OutputDirectory" and val.value:
                    transcript_dir = val.value
        except Exception:
            pass

    system = resolve_case_insensitive(volume_root, "Windows/System32/config/SYSTEM")
    if system:
        try:
            from regipy.registry import RegistryHive

            reg = RegistryHive(str(system))
            for cs in ["ControlSet001", "ControlSet002"]:
                try:
                    key = reg.get_key(f"{cs}\\Control\\TimeZoneInformation")
                    for val in key.iter_values():
                        if val.name == "TimeZoneKeyName" and val.value:
                            timezone = val.value
                            break
                    if timezone:
                        break
                except Exception:
                    continue
        except Exception:
            pass

    return transcript_dir, timezone


def discover_transcripts(volume_root: Path, gp_transcript_dir: str | None = None) -> list[Path]:
    """Find all PowerShell transcript files."""
    files: list[Path] = []

    # User profiles (default location)
    users_dir = resolve_case_insensitive(volume_root, "Users")
    if users_dir and users_dir.is_dir():
        files.extend(users_dir.rglob("PowerShell_transcript.*.txt"))

    # GP-configured directory
    if gp_transcript_dir:
        parts = PureWindowsPath(gp_transcript_dir).parts[1:]
        if parts:
            rel = str(Path(*parts))
            gp_dir = resolve_case_insensitive(volume_root, rel)
            if gp_dir and gp_dir.is_dir():
                files.extend(gp_dir.rglob("PowerShell_transcript.*.txt"))

    # Common non-default locations
    for extra in ["ProgramData/Transcripts", "Program Files/Amazon"]:
        d = resolve_case_insensitive(volume_root, extra)
        if d and d.is_dir():
            files.extend(d.rglob("PowerShell_transcript.*.txt"))

    return sorted(set(files))


def _parse_transcript_time(time_str: str, system_tz_name: str | None) -> str:
    """Parse transcript timestamp to UTC ISO 8601.

    Handles both PS 5.x (yyyyMMddHHmmss, local time) and PS 7.x (ISO 8601 with offset).
    Uses dateutil.tz.gettz() which handles Windows timezone names natively.
    """
    time_str = time_str.strip()

    # Try ISO 8601 first (PS 7.x — includes timezone offset)
    try:
        from datetime import timezone as _tz

        return (
            datetime.fromisoformat(time_str).astimezone(_tz.utc).isoformat().replace("+00:00", "Z")
        )
    except ValueError:
        pass

    # Fall back to PS 5.x format (yyyyMMddHHmmss, local time)
    try:
        naive = datetime.strptime(time_str, "%Y%m%d%H%M%S")
        if system_tz_name:
            from dateutil.tz import gettz, tzutc

            tz = gettz(system_tz_name)
            if tz:
                aware = naive.replace(tzinfo=tz)
                return aware.astimezone(tzutc()).isoformat().replace("+00:00", "Z")
        # Timezone unknown — cannot produce reliable UTC timestamp
        return None
    except Exception:
        return None


def _detect_session_type(host_app: str) -> str:
    """Detect PS session type from Host Application header."""
    lower = host_app.lower()
    if "wsmprovhost" in lower or "serverremotehost" in lower:
        return "remoting"
    if "-encodedcommand" in lower:
        return "encoded"
    if "-noninteractive" in lower:
        return "noninteractive"
    if "powershell" in lower:
        return "interactive"
    return "other"


def parse_transcript(file_path: Path, system_timezone: str | None = None) -> dict:
    """Parse a single PowerShell transcript file into a document."""
    text = file_path.read_text(errors="replace")
    lines = text.splitlines()

    doc: dict = {}
    commands: list[str] = []
    current_command: list[str] = []
    in_command = False

    for line in lines:
        if line.startswith("Start time: "):
            doc["@timestamp"] = _parse_transcript_time(line[12:], system_timezone)
        elif line.startswith("End time: "):
            doc["transcript.end_time"] = _parse_transcript_time(line[10:], system_timezone)
        elif line.startswith("Username: "):
            full = line[10:].strip()
            if "\\" in full:
                doc["user.domain"], doc["user.name"] = full.split("\\", 1)
            else:
                doc["user.name"] = full
        elif line.startswith("RunAs User: "):
            doc["user.runas"] = line[12:].strip()
        elif line.startswith("Machine: "):
            parts = line[9:].strip()
            if " (" in parts:
                machine, os_ver = parts.split(" (", 1)
                doc["transcript.machine"] = machine
                doc["host.os.version"] = os_ver.rstrip(")")
            else:
                doc["transcript.machine"] = parts
        elif line.startswith("Host Application: "):
            app = line[18:].strip()
            app_parts = app.split(None, 1)
            # rsplit handles Windows backslash paths on Linux (Path().name doesn't)
            exe = app_parts[0] if app_parts else app
            doc["process.name"] = exe.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if len(app_parts) > 1:
                doc["process.args"] = app_parts[1]
            doc["transcript.session_type"] = _detect_session_type(app)
        elif line.startswith("Process ID: "):
            try:
                doc["process.pid"] = int(line[12:].strip())
            except ValueError:
                pass
        elif line.startswith("PSVersion: "):
            doc["transcript.ps_version"] = line[11:].strip()
        elif line.startswith("PS>") or line.startswith(">> "):
            if current_command:
                commands.append("\n".join(current_command))
            prefix_len = 3
            current_command = [line[prefix_len:]]
            in_command = True
        elif line.startswith("****") and in_command:
            if current_command:
                commands.append("\n".join(current_command))
                current_command = []
            in_command = False
        elif in_command:
            current_command.append(line)

    if current_command:
        commands.append("\n".join(current_command))

    doc["transcript.commands"] = commands
    doc["transcript.command_count"] = len(commands)
    doc["transcript.full_text"] = text

    # Duration
    if "@timestamp" in doc and "transcript.end_time" in doc:
        try:
            start = datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(doc["transcript.end_time"].replace("Z", "+00:00"))
            doc["transcript.duration_seconds"] = int((end - start).total_seconds())
        except Exception:
            pass

    return doc


def ingest_transcripts(
    transcript_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    volume_root: Path | None = None,
    system_timezone: str | None = None,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int]:
    """Discover and ingest transcript files from a directory.

    Returns (count_indexed, count_bulk_failed).
    """
    # Discover files in this directory tree
    files = discover_transcripts(transcript_dir)
    if not files:
        return 0, 0

    count = 0
    bulk_failed = 0
    actions: list[dict] = []

    for f in files:
        doc = parse_transcript(f, system_timezone=system_timezone)
        # Skip documents with unreliable timestamps — wrong data is not evidence
        if doc.get("@timestamp") is None:
            import sys

            print(
                f"  transcripts: skipped {f.name} — timezone unknown, timestamps unreliable",
                file=sys.stderr,
            )
            continue
        doc["host.name"] = hostname
        doc["vhir.source_file"] = str(f)
        if ingest_audit_id:
            doc["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            doc["pipeline_version"] = pipeline_version
        if vss_id:
            doc["vhir.vss_id"] = vss_id
        doc["vhir.parse_method"] = "transcript-parser"

        from opensearch_mcp.paths import relative_evidence_path

        rel = relative_evidence_path(f, volume_root) if volume_root else str(f)
        _id = _doc_id(index_name, {"source_file": rel})
        actions.append({"_index": index_name, "_id": _id, "_source": doc})

        if len(actions) >= 100:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, bulk_failed
