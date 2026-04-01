"""Parse Windows Scheduled Task XML definitions."""

from __future__ import annotations

import hashlib
from pathlib import Path

import defusedxml.ElementTree as ET
from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

_SYSTEM_PREFIXES = {"Microsoft", "MicrosoftEdge", "GoogleUpdate", "Adobe", "OneDrive", "CCleaner"}


def parse_task_xml(file_path: Path) -> dict | None:
    """Parse a single scheduled task XML file. Returns doc or None on failure."""
    try:
        tree = ET.parse(str(file_path))
        root = tree.getroot()
    except ET.ParseError:
        return None

    doc: dict = {}

    reg = root.find(".//t:RegistrationInfo", NS)
    if reg is not None:
        date_el = reg.find("t:Date", NS)
        if date_el is not None and date_el.text:
            doc["@timestamp"] = date_el.text
        author_el = reg.find("t:Author", NS)
        if author_el is not None and author_el.text:
            doc["task.author"] = author_el.text
        desc_el = reg.find("t:Description", NS)
        if desc_el is not None and desc_el.text:
            doc["task.description"] = desc_el.text

    exec_el = root.find(".//t:Actions/t:Exec", NS)
    if exec_el is not None:
        cmd = exec_el.find("t:Command", NS)
        if cmd is not None and cmd.text:
            doc["task.command"] = cmd.text
        args = exec_el.find("t:Arguments", NS)
        if args is not None and args.text:
            doc["task.arguments"] = args.text

    triggers = root.find(".//t:Triggers", NS)
    if triggers is not None:
        trigger_types = []
        for child in triggers:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            trigger_types.append(tag)
        doc["task.trigger_types"] = trigger_types

    principal = root.find(".//t:Principals/t:Principal", NS)
    if principal is not None:
        uid = principal.find("t:UserId", NS)
        if uid is not None and uid.text:
            doc["task.user_id"] = uid.text
        run_level = principal.find("t:RunLevel", NS)
        if run_level is not None and run_level.text:
            doc["task.run_level"] = run_level.text

    settings = root.find(".//t:Settings", NS)
    if settings is not None:
        enabled = settings.find("t:Enabled", NS)
        if enabled is not None and enabled.text:
            doc["task.enabled"] = enabled.text.lower() == "true"

    doc["task.name"] = file_path.name

    parts = file_path.parts
    task_idx = next((i for i, p in enumerate(parts) if p.lower() == "tasks"), -1)
    if task_idx >= 0 and task_idx + 1 < len(parts):
        first_subdir = parts[task_idx + 1]
        doc["task.is_system"] = first_subdir in _SYSTEM_PREFIXES
    else:
        doc["task.is_system"] = False

    doc["task.xml"] = ET.tostring(root, encoding="unicode")

    return doc


def parse_tasks_dir(
    tasks_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    system_timezone: str | None = None,
    volume_root: Path | None = None,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
) -> tuple[int, int, int]:
    """Parse all task XML files in the directory tree.

    Task timestamps are local system time. Converts to UTC using
    system_timezone. Skips if timezone is unknown.
    """
    from dateutil.tz import gettz, tzutc

    tz_info = gettz(system_timezone) if system_timezone else None
    count = 0
    skipped = 0
    bulk_failed = 0
    actions: list[dict] = []

    for task_file in sorted(tasks_dir.rglob("*")):
        if not task_file.is_file():
            continue
        if task_file.suffix.lower() not in ("", ".xml"):
            continue
        doc = parse_task_xml(task_file)
        if doc is None:
            skipped += 1
            continue

        # Convert local timestamp to UTC
        if "@timestamp" in doc:
            ts_str = doc["@timestamp"]
            if ts_str and not ts_str.endswith("Z") and "+" not in ts_str:
                if tz_info:
                    try:
                        from datetime import datetime

                        naive = datetime.fromisoformat(ts_str)
                        aware = naive.replace(tzinfo=tz_info)
                        doc["@timestamp"] = (
                            aware.astimezone(tzutc()).isoformat().replace("+00:00", "Z")
                        )
                    except ValueError:
                        del doc["@timestamp"]
                else:
                    # Timezone unknown — remove unreliable timestamp
                    del doc["@timestamp"]

        doc["host.name"] = hostname
        doc["vhir.source_file"] = str(task_file)
        if ingest_audit_id:
            doc["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            doc["pipeline_version"] = pipeline_version
        doc["vhir.parse_method"] = "task-xml"
        if vss_id:
            doc["vhir.vss_id"] = vss_id

        from opensearch_mcp.paths import relative_evidence_path

        rel = relative_evidence_path(task_file, volume_root) if volume_root else str(task_file)
        id_input = f"{index_name}:{rel}"
        doc_hash = hashlib.sha256(id_input.encode()).hexdigest()[:20]
        actions.append({"_index": index_name, "_id": doc_hash, "_source": doc})

        if len(actions) >= 100:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, skipped, bulk_failed
