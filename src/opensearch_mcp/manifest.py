"""Ingest manifest generation and verification."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from opensearch_mcp import __version__


def sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file using 64KB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _manifest_hash(data: dict) -> str:
    """Compute SHA-256 of manifest with manifest_sha256 set to empty."""
    copy = dict(data)
    copy["manifest_sha256"] = ""
    canonical = json.dumps(copy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _find_previous_manifest(manifest_dir: Path, index_name: str) -> str | None:
    """Find the most recent manifest for the same index."""
    if not manifest_dir.exists():
        return None
    candidates = sorted(
        (
            f
            for f in manifest_dir.iterdir()
            if f.name.startswith(index_name + "-") and f.suffix == ".json"
        ),
        reverse=True,
    )
    return candidates[0].name if candidates else None


def write_manifest(
    manifest_dir: Path,
    case_id: str,
    hostname: str,
    index_name: str,
    examiner: str,
    file_results: list[dict],
    filters: dict,
    elapsed_seconds: float,
    parser_version: str = "",
) -> Path:
    """Write an ingest manifest. Returns the manifest file path."""
    manifest_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    filename = f"{index_name}-{ts}.json"

    # Check for previous manifest (re-ingest chain)
    previous = _find_previous_manifest(manifest_dir, index_name)
    if previous:
        prev_path = manifest_dir / previous
        if not prev_path.exists():
            import sys

            print(
                f"WARNING: Previous manifest {previous} referenced but not found",
                file=sys.stderr,
            )

    totals = {
        "files_processed": len(file_results),
        "files_failed": sum(1 for f in file_results if f.get("status") == "failed"),
        "events_indexed": sum(f.get("events_indexed", 0) for f in file_results),
        "events_skipped": sum(f.get("events_skipped", 0) for f in file_results),
        "elapsed_seconds": round(elapsed_seconds, 1),
    }

    try:
        import evtx

        evtx_version = evtx.__version__
    except (ImportError, AttributeError):
        evtx_version = "unknown"

    data = {
        "manifest_version": 1,
        "timestamp": now.isoformat(),
        "case_id": case_id,
        "hostname": hostname,
        "index_name": index_name,
        "examiner": examiner,
        "replaces": previous,
        "pipeline_version": f"opensearch-mcp-{__version__}",
        "parser": {"name": "pyevtx-rs", "version": parser_version or evtx_version},
        "normalization": {
            "version": f"opensearch-mcp-{__version__}",
            "ecs_fields_mapped": [
                "event.code",
                "winlog.event_id",
                "@timestamp",
                "winlog.channel",
                "winlog.provider_name",
                "host.name",
                "user.name",
                "user.effective.name",
                "source.ip",
                "winlog.logon.type",
                "process.name",
                "process.command_line",
                "process.parent.name",
                "file.path",
                "script_block_text",
            ],
            "flat_object_field": "winlog.event_data",
            "user_data_fallback": True,
        },
        "filters": filters,
        "files": file_results,
        "totals": totals,
        "manifest_sha256": "",
    }

    data["manifest_sha256"] = _manifest_hash(data)

    # Atomic write
    manifest_path = manifest_dir / filename
    fd, tmp_path = tempfile.mkstemp(dir=str(manifest_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(manifest_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return manifest_path


def verify_manifest(manifest_path: Path) -> tuple[bool, str]:
    """Verify a manifest's self-hash. Returns (valid, message)."""
    data = json.loads(manifest_path.read_text())
    stored_hash = data.get("manifest_sha256", "")
    if not stored_hash:
        return False, "No manifest_sha256 field"
    computed = _manifest_hash(data)
    if computed == stored_hash:
        return True, "OK"
    return False, f"Hash mismatch: stored={stored_hash[:16]}... computed={computed[:16]}..."
