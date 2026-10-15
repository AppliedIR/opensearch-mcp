"""Track ingest operation status for CLI and MCP visibility."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from opensearch_mcp.paths import vhir_dir

AWAITING = "awaiting host confirmation"  # the run writes nothing until its hosts are confirmed
CANCELLED = "cancelled"  # by the examiner, while it waited
_LIVE = ("running", "starting", AWAITING)  # a worker owns these: the sweep checks it lives

_STATUS_DIR = vhir_dir() / "ingest-status"

MAX_RUNNING = 3  # ingests running at once; a run waiting for its hosts takes no place
SLOT_WAIT = (
    f"Its hosts are confirmed. It starts when one of the {MAX_RUNNING} running ingests ends."
)


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
    message: str = "",
) -> None:
    """Write ingest progress atomically. `message` is what the run asks of
    the examiner (while it waits for host confirmation).

    UAT 2026-04-23: terminal states (`complete`, `failed`) are
    monotonic and must not be downgraded by a later `running` or
    `starting` write. The specific race that surfaced this: a fast
    worker (empty-walk) writes its terminal `complete` before the
    MCP server's post-spawn `write_status(pid=proc.pid,
    status="running", ...)` lands — and that later write clobbered
    the terminal into `running`, after which the sweep saw a dead
    PID on a `running` record and stamped `failed:
    process_died_unexpectedly`. The guard below rejects any attempt
    to regress from a terminal state so Fix 3.1's worker-side
    terminal write always survives.
    """
    _STATUS_DIR.mkdir(parents=True, exist_ok=True)
    path = _status_path_safe(case_id, pid, run_id)
    # Monotonic transition guard: terminal → running/starting is not
    # a valid downgrade. Read-before-write is only best-effort (a
    # race between the read and the atomic replace still allows one
    # stale overwrite), but the window is orders of magnitude
    # narrower than the unguarded case and closes the observed bug.
    if status == "starting" and path.exists():
        return  # the launcher's record never replaces one the worker wrote
    confirmed = False
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            if status in _LIVE and existing.get("status") in ("complete", "failed", CANCELLED):
                return
            confirmed = existing.get("hosts_confirmed") is True
        except (json.JSONDecodeError, OSError):
            pass  # Unreadable existing file — fall through to write
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
    if run_id and pid == os.getpid() and not _in_own_environ(run_id):
        # A run id the worker made itself (a CLI run, or one image of an
        # archive) isn't in its /proc/<pid>/environ, so the sweep can't
        # confirm it there.
        data["run_id_from_env"] = False
    if message:
        data["message"] = message
    if confirmed and status != AWAITING:  # kept: the launcher reads it once
        data["hosts_confirmed"] = True
    if not log_file and run_id:
        # The launcher writes the worker's log here; workers don't pass it.
        launched = _STATUS_DIR.parent / "ingest-logs" / f"{run_id}.log"
        if launched.is_file():
            log_file = str(launched)
    if log_file:
        data["log_file"] = log_file
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


def mark_hosts_confirmed(case_id: str, pid: int, run_id: str) -> None:
    """Note on the run's status that its hosts passed the gate, so the
    launcher can answer that the run started (rather than waits)."""
    path = _status_path_safe(case_id, pid, run_id)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        data = {"run_id": run_id, "pid": pid, "status": "running", "case_id": case_id,
                "hosts": [], "totals": {}}  # fmt: skip
    if data.get("status") == AWAITING:
        data["status"] = "running"
    data["hosts_confirmed"] = True
    _STATUS_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(_STATUS_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def take_slot(case_id: str, pid: int, run_id: str, waiting) -> bool:
    """Start a run whose hosts passed the gate if fewer than MAX_RUNNING other
    runs are running, marking it confirmed; else call `waiting()`, which
    writes its waiting status. Both happen under one lock, so runs confirmed
    together never start past the cap. The lock goes with the process."""
    import fcntl

    _STATUS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_STATUS_DIR / "slots.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # the caller's own process isn't another ingest: an archive's images
        # run inside the process of the archive's own run
        running = [r for r in active_runs()
                   if r.get("status") != AWAITING and r.get("pid") != pid]  # fmt: skip
        if len(running) >= MAX_RUNNING:
            waiting()
            return False
        mark_hosts_confirmed(case_id, pid, run_id)
        return True


def finish_status(
    case_id: str, pid: int, notes: list[tuple[str, str]] | None = None, run_id: str = ""
) -> None:
    """Write a run's own last status again as `complete`: the terminal write
    after a last phase that kept it `running`. Leaves any other state.
    Each `(label, note)` in `notes` (triage that didn't finish, a partition
    that didn't mount) is shown as a warning, not an artifact."""
    try:
        data = json.loads(_status_path_safe(case_id, pid, run_id).read_text())
    except (OSError, json.JSONDecodeError):
        return
    if data.get("status") != "running":
        return
    hosts = data.get("hosts", []) + _note_hosts(notes)
    write_status(
        case_id,
        pid,
        data.get("run_id", ""),
        "complete",
        hosts,
        data.get("totals", {}),
        data.get("started", ""),
        error=data.get("error", ""),
        bulk_failed=data.get("bulk_failed", 0),
        bulk_failed_reason=data.get("bulk_failed_reason", ""),
        elapsed_seconds=data.get("elapsed_seconds", 0.0),
        log_file=data.get("log_file", ""),
    )


def _note_hosts(notes: list[tuple[str, str]] | None) -> list[dict]:
    """Status entries that show each `(label, note)` as a warning."""
    return [
        {"hostname": label, "artifacts": [{"name": label, "note": note, "warnings_only": True}]}
        for label, note in notes or []
    ]


def add_notes(case_id: str, pid: int, notes: list[tuple[str, str]], run_id: str = "") -> None:
    """Add `notes` as warnings to a run's status that hasn't ended: a run that
    stops before its terminal write (an early exit or an exception) keeps
    them, and the terminal-status guard that then marks it failed leaves them.
    A run that has ended is left as it is."""
    if not notes:
        return
    path = _status_path_safe(case_id, pid, run_id)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return
    if data.get("status") not in ("starting", "running"):
        return
    data["hosts"] = data.get("hosts", []) + _note_hosts(notes)
    data["updated"] = datetime.now(timezone.utc).isoformat()
    fd, tmp = tempfile.mkstemp(dir=str(_STATUS_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, str(path))
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# Error-prefix convention (replaces removed halt-state taxonomy).
# Refuse sites write status="failed" via write_status() with the
# error field prefixed by one of these tokens so the portal can
# startswith()-render the halt reason without a separate schema.
HALT_SHARD_CAPACITY = "shard_capacity_exhausted"
HALT_CIRCUIT_BREAKER = "circuit_breaker_tripped"
HALT_HAYABUSA_NO_RULES = "hayabusa_no_rules"
# Not a halt: the run finished, and OpenSearch rejected every record it sent.
ALL_RECORDS_REJECTED = "all_records_rejected"
# Not a halt either: the transport gave up, so nothing was delivered to reject.
TRANSPORT_FAILED = "transport_failed"
# Files were given and not one of them was read (each failed, or was refused).
NOTHING_READ = "no_file_read"


def read_active_ingests() -> list[dict]:
    """Read all ingest status files. Detects dead processes.

    UAT 2026-04-22 fixes applied:
    - Sweep inspects both "running" AND "starting" states (worker
      that crashes during the brief pre-running phase used to stay
      stuck forever and block the concurrency cap).
    - Dead-pid finding is now PERSISTED to the status file on disk,
      not just mutated in memory. External consumers (portal, CLI,
      `jq`) reading the disk state directly see the update.
    - `_is_process_alive` now detects zombie (Z-state) processes
      via `/proc/{pid}/status` — `os.kill(pid, 0)` passes for
      zombies and missed the exact UAT failure mode.
    - "killed" consolidated to "failed" with a prefixed error token
      (`process_died_unexpectedly:`) so portal/CLI don't juggle a
      third terminal state; diagnostic preserved via the prefix.
    """
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
        if data.get("status") in _LIVE:
            pid = data.get("pid", 0)
            # A self-made run id gets the PID-only check (alive, not a zombie).
            run_id = data.get("run_id", "") if data.get("run_id_from_env", True) else ""
            if pid and not _is_process_alive(pid, run_id):
                data["status"] = "failed"
                prev_error = data.get("error") or ""
                data["error"] = "process_died_unexpectedly: " + (
                    prev_error if prev_error else "detected by sweep"
                )
                # Persist the sweep finding so external consumers
                # reading the disk state directly see the update.
                try:
                    tmp = f.with_suffix(".json.tmp")
                    tmp.write_text(json.dumps(data))
                    os.replace(str(tmp), str(f))
                except OSError:
                    pass  # Best-effort — in-memory result is still correct
        results.append(data)
    return results


def active_runs() -> list[dict]:
    """Every run a worker still owns: running, starting, or waiting for the
    examiner to confirm its hosts (it holds devices and a place in the queue)."""
    return [i for i in read_active_ingests() if i.get("status") in _LIVE]


def _in_own_environ(run_id: str) -> bool:
    """Whether this process started with `run_id`: what the sweep reads from
    /proc/<pid>/environ, which a change to os.environ doesn't reach."""
    try:
        return f"VHIR_INGEST_RUN_ID={run_id}".encode() in Path("/proc/self/environ").read_bytes()
    except OSError:
        return os.environ.get("VHIR_INGEST_RUN_ID") == run_id


def _status_path_safe(case_id: str, pid: int, run_id: str = "") -> Path:
    """Safe status path — sanitize case_id to prevent path traversal. One
    file per run: the runs one process makes (an archive's images) each
    keep their own."""
    safe_id = case_id.replace("/", "_").replace("\\", "_").replace("..", "_")
    run = re.sub(r"[^A-Za-z0-9_.-]", "_", run_id).replace("..", "_")[:80]
    return _STATUS_DIR / (f"{safe_id}-{pid}-{run}.json" if run else f"{safe_id}-{pid}.json")


def _is_process_alive(pid: int, run_id: str) -> bool:
    """Check if a process is alive AND is our ingest process (not PID reuse).

    UAT 2026-04-22: `os.kill(pid, 0)` succeeds for zombies (reparented
    processes awaiting reap), so the prior check returned True for
    crashed-but-not-yet-reaped workers. Now parses /proc/{pid}/status
    and returns False on `State: Z` so sweep correctly flags them.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but belongs to another user — treat as alive
        # (conservative: don't report "killed" for a running process)
        return True
    # Zombie detection — os.kill(pid, 0) passes for Z-state processes.
    # Parse /proc/{pid}/status explicitly.
    try:
        with open(f"/proc/{pid}/status") as status_f:
            for line in status_f:
                if line.startswith("State:"):
                    # Format: "State:\tR (running)" / "State:\tZ (zombie)"
                    parts = line.split()
                    if len(parts) >= 2 and "Z" in parts[1]:
                        return False
                    break
    except OSError:
        # /proc not readable — fall through to existing run_id/PID logic.
        pass
    # PID exists (and isn't zombie) — verify it's our process via
    # /proc environ to guard against PID reuse.
    if run_id:
        try:
            environ = Path(f"/proc/{pid}/environ").read_bytes()
            if not environ:  # mid-execve: nothing to check yet, not a sign of death
                return True
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
