"""Track ingest operation status for CLI and MCP visibility."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from opensearch_mcp.paths import vhir_dir

_STATUS_DIR = vhir_dir() / "ingest-status"


def write_status(
    case_id: str,
    pid: int,
    run_id: str,
    status: str,
    hosts: list[dict],
    totals: dict,
    started: str,
    error: str = "",
    bulk_failed: int = 0,
    bulk_failed_reason: str = "",
    elapsed_seconds: float = 0.0,
    log_file: str = "",
) -> None:
    """Write ingest progress atomically."""
    _STATUS_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "run_id": run_id,
        "pid": pid,
        "status": status,
        "case_id": case_id,
        "started": started,
        "updated": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
        "totals": totals,
        "error": error,
        "bulk_failed": bulk_failed,
        "bulk_failed_reason": bulk_failed_reason,
        "elapsed_seconds": round(elapsed_seconds, 1),
    }
    if log_file:
        data["log_file"] = log_file
    path = _status_path_safe(case_id, pid)
    fd, tmp = tempfile.mkstemp(dir=str(_STATUS_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# Error-prefix convention (replaces removed halt-state taxonomy).
# Refuse sites write status="failed" via write_status() with the
# error field prefixed by one of these tokens so the portal can
# startswith()-render the halt reason without a separate schema.
HALT_SHARD_CAPACITY = "shard_capacity_exhausted"
HALT_CIRCUIT_BREAKER = "circuit_breaker_tripped"
HALT_HAYABUSA_NO_RULES = "hayabusa_no_rules"


def read_active_ingests() -> list[dict]:
    """Read all ingest status files. Detects dead processes."""
    cleanup_old()
    if not _STATUS_DIR.exists():
        return []
    results = []
    for f in sorted(_STATUS_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        # Skip orphaned PID-0 placeholders
        if data.get("pid") == 0:
            continue
        if data.get("status") == "running":
            pid = data.get("pid", 0)
            run_id = data.get("run_id", "")
            if pid and not _is_process_alive(pid, run_id):
                data["status"] = "killed"
        results.append(data)
    return results


def _status_path_safe(case_id: str, pid: int) -> Path:
    """Safe status path — sanitize case_id to prevent path traversal."""
    safe_id = case_id.replace("/", "_").replace("\\", "_").replace("..", "_")
    return _STATUS_DIR / f"{safe_id}-{pid}.json"


def _is_process_alive(pid: int, run_id: str) -> bool:
    """Check if a process is alive AND is our ingest process (not PID reuse)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but belongs to another user — treat as alive
        # (conservative: don't report "killed" for a running process)
        return True
    # PID exists — verify it's our process via /proc environ
    if run_id:
        try:
            environ = Path(f"/proc/{pid}/environ").read_bytes()
            expected = f"VHIR_INGEST_RUN_ID={run_id}".encode()
            return expected in environ
        except OSError:
            # /proc not readable — fall back to PID-only check
            pass
    return True


def cleanup_old(max_age_hours: int = 24) -> None:
    """Remove status files older than max_age_hours, logs older than 7 days."""
    if not _STATUS_DIR.exists():
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
    for f in _STATUS_DIR.glob("*.json"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
        except OSError:
            pass
    # Log file cleanup (7 days — longer retention for post-mortem)
    log_dir = _STATUS_DIR.parent / "ingest-logs"
    if log_dir.exists():
        log_cutoff = datetime.now(timezone.utc).timestamp() - (7 * 24 * 3600)
        for f in log_dir.glob("*.log"):
            try:
                if f.stat().st_mtime < log_cutoff:
                    f.unlink(missing_ok=True)
            except OSError:
                pass
