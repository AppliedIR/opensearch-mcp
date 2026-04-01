"""Windows triage DB enrichment for ingest-time baseline checks.

Two modes:
- Local: SQLite databases from windows-triage-mcp (same SIFT workstation)
- Remote: Batch MCP calls via gateway (opensearch-mcp on different VM)

Mode is auto-detected: local DBs found → local. Gateway reachable → remote.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_KG_PATH: Path | None = None  # known_good.db
_CTX_PATH: Path | None = None  # context.db
_KG_CONN: sqlite3.Connection | None = None
_CTX_CONN: sqlite3.Connection | None = None
_MODE: str = "unavailable"  # "local", "remote", "unavailable"


def init_triage_db(kg_path: Path | None = None, ctx_path: Path | None = None) -> bool:
    """Initialize triage DB connections. Returns True if at least known_good available."""
    global _KG_PATH, _CTX_PATH

    if kg_path and kg_path.exists():
        _KG_PATH = kg_path
    if ctx_path and ctx_path.exists():
        _CTX_PATH = ctx_path

    if _KG_PATH and _CTX_PATH:
        return True

    # Auto-discover from common locations
    from opensearch_mcp.paths import vhir_dir

    search_dirs = [
        vhir_dir() / "data",
        Path("/opt/vhir/data"),
    ]
    # Also check sibling of opensearch-mcp (sift-mcp/packages/windows-triage/data/)
    pkg_data = (
        Path(__file__).parent.parent.parent.parent
        / "sift-mcp"
        / "packages"
        / "windows-triage"
        / "data"
    )
    if pkg_data.is_dir():
        search_dirs.insert(0, pkg_data)

    for d in search_dirs:
        if not _KG_PATH and (d / "known_good.db").exists():
            _KG_PATH = d / "known_good.db"
        if not _CTX_PATH and (d / "context.db").exists():
            _CTX_PATH = d / "context.db"
        if _KG_PATH and _CTX_PATH:
            break

    if _KG_PATH is not None:
        _MODE = "local"
        return True

    # No local DB — check if gateway is reachable for remote mode
    try:
        from opensearch_mcp.wintools import _call_gateway_tool, _load_gateway_config

        config = _load_gateway_config()
        if config and config.get("url"):
            base_url = config["url"].split("/mcp/")[0]
            _call_gateway_tool(
                base_url,
                config.get("token", ""),
                "mcp__windows-triage__get_health",
                {},
            )
            _MODE = "remote"
            return True
    except Exception:
        pass

    _MODE = "unavailable"
    return False


def get_triage_mode() -> str:
    """Return current triage mode: 'local', 'remote', or 'unavailable'."""
    return _MODE


def _kg() -> sqlite3.Connection | None:
    """Lazy known_good.db connection."""
    global _KG_CONN
    if _KG_CONN is not None:
        return _KG_CONN
    if _KG_PATH is None:
        return None
    _KG_CONN = sqlite3.connect(str(_KG_PATH), check_same_thread=False)
    _KG_CONN.row_factory = sqlite3.Row
    return _KG_CONN


def _ctx() -> sqlite3.Connection | None:
    """Lazy context.db connection."""
    global _CTX_CONN
    if _CTX_CONN is not None:
        return _CTX_CONN
    if _CTX_PATH is None:
        return None
    _CTX_CONN = sqlite3.connect(str(_CTX_PATH), check_same_thread=False)
    _CTX_CONN.row_factory = sqlite3.Row
    return _CTX_CONN


def check_file(filename: str, directory: str = "") -> dict:
    """Check a filename against baseline + context DBs."""
    conn = _kg()
    if conn is None:
        return {}

    result: dict = {"triage.checked": True}
    filename_lower = filename.lower()

    # Baseline file lookup
    row = conn.execute(
        "SELECT * FROM baseline_files WHERE filename_lower = ?",
        (filename_lower,),
    ).fetchone()

    if row is None:
        result["triage.verdict"] = "UNKNOWN"
    else:
        result["triage.verdict"] = "EXPECTED"
        # Path check — verify directory matches baseline
        if directory and row["directory_normalized"]:
            dir_lower = directory.lower().replace("/", "\\").rstrip("\\")
            expected_dir = row["directory_normalized"].lower().rstrip("\\")
            if not dir_lower.endswith(expected_dir):
                result["triage.verdict"] = "SUSPICIOUS"
                result["triage.reason"] = f"unexpected path: {directory}"

    # LOLBin check from context.db
    ctx = _ctx()
    if ctx:
        lol = ctx.execute(
            "SELECT * FROM lolbins WHERE filename_lower = ?",
            (filename_lower,),
        ).fetchone()
        if lol:
            result["triage.lolbin"] = True
            if lol["expected_paths"]:
                import json

                try:
                    result["triage.expected_paths"] = json.loads(lol["expected_paths"])
                except (json.JSONDecodeError, TypeError):
                    pass
            if result.get("triage.verdict") == "EXPECTED":
                result["triage.verdict"] = "EXPECTED_LOLBIN"

    # Suspicious filename check from context.db
    if ctx and result.get("triage.verdict") == "UNKNOWN":
        sus = ctx.execute(
            "SELECT * FROM suspicious_filenames WHERE filename_pattern = ?",
            (filename_lower,),
        ).fetchone()
        if sus:
            result["triage.verdict"] = "SUSPICIOUS"
            result["triage.reason"] = f"known tool: {sus['tool_name']} ({sus['category']})"

    return result


def check_service(service_name: str, image_path: str = "") -> dict:
    """Check a service against baseline DB."""
    conn = _kg()
    if conn is None:
        return {}

    result: dict = {"triage.checked": True}

    row = conn.execute(
        "SELECT * FROM baseline_services WHERE service_name_lower = ?",
        (service_name.lower(),),
    ).fetchone()

    if row is None:
        result["triage.verdict"] = "UNKNOWN"
        return result

    result["triage.verdict"] = "EXPECTED"
    if image_path and row.get("binary_path_pattern"):
        if image_path.lower() != row["binary_path_pattern"].lower():
            result["triage.verdict"] = "SUSPICIOUS"
            result["triage.reason"] = f"binary mismatch: {image_path}"

    return result


def enrich_document(doc: dict, artifact_type: str) -> dict:
    """Add triage.* fields to a document based on artifact type.

    Modifies doc in place. Returns the triage result dict.
    """
    triage: dict = {}

    if artifact_type == "shimcache":
        path = doc.get("Path", "")
        if path:
            parts = path.replace("/", "\\").rsplit("\\", 1)
            filename = parts[-1] if parts else ""
            directory = parts[0] if len(parts) > 1 else ""
            triage = check_file(filename, directory)

    elif artifact_type == "amcache":
        full_path = doc.get("FullPath", "")
        if full_path:
            parts = full_path.replace("/", "\\").rsplit("\\", 1)
            filename = parts[-1] if parts else ""
            directory = parts[0] if len(parts) > 1 else ""
            triage = check_file(filename, directory)

    elif artifact_type == "registry":
        key_path = doc.get("KeyPath", "")
        if "\\Run\\" in key_path or key_path.endswith("\\Run"):
            value_data = doc.get("ValueData", "")
            if value_data:
                clean = value_data.strip().strip('"').strip("'")
                parts = clean.replace("/", "\\").rsplit("\\", 1)
                filename = parts[-1].split()[0] if parts else ""
                triage = check_file(filename)
        elif "\\Services\\" in key_path:
            service = key_path.rsplit("\\", 1)[-1] if "\\" in key_path else ""
            image_path = doc.get("ValueData", "") if doc.get("ValueName") == "ImagePath" else ""
            if service:
                triage = check_service(service, image_path)

    elif artifact_type == "tasks":
        command = doc.get("task.command", "")
        if command:
            parts = command.replace("/", "\\").rsplit("\\", 1)
            filename = parts[-1].split()[0] if parts else ""
            triage = check_file(filename)

    elif artifact_type == "evtx":
        event_id = doc.get("event.code")
        if event_id in (4688, 1):
            proc_name = doc.get("process.name", "")
            if proc_name:
                parts = proc_name.replace("/", "\\").rsplit("\\", 1)
                filename = parts[-1] if parts else ""
                directory = parts[0] if len(parts) > 1 else ""
                triage = check_file(filename, directory)
        elif event_id == 7045:
            event_data = doc.get("winlog.event_data", {})
            if isinstance(event_data, dict):
                service_name = event_data.get("ServiceName", "")
                image_path = event_data.get("ImagePath", "")
                if service_name:
                    triage = check_service(service_name, image_path)

    elif artifact_type in ("vol-pslist", "vol-pstree", "vol-psscan"):
        filename = doc.get("ImageFileName", "")
        if filename:
            triage = check_file(filename)

    elif artifact_type == "vol-dlllist":
        dll_name = doc.get("Name", "")
        dll_path = doc.get("Path", "")
        if dll_name:
            directory = dll_path.rsplit("\\", 1)[0] if "\\" in dll_path else ""
            triage = check_file(dll_name, directory)

    elif artifact_type == "vol-svcscan":
        name = doc.get("Name", "")
        binary = doc.get("Binary", "")
        if name:
            triage = check_service(name, binary)

    if triage:
        doc.update(triage)
    return triage
