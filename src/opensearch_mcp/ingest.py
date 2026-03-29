"""Core ingest orchestrator — shared by CLI and MCP entry points."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from opensearchpy import OpenSearch
from sift_common.audit import AuditWriter

from opensearch_mcp import __version__
from opensearch_mcp.discover import DiscoveredHost, scan_triage_directory
from opensearch_mcp.ingest_status import write_status
from opensearch_mcp.manifest import sha256_file
from opensearch_mcp.parse_evtx import parse_and_index
from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult
from opensearch_mcp.tools import TOOLS, get_active_tools, run_and_ingest

_PIPELINE_VERSION = f"opensearch-mcp-{__version__}"


def _artifact_to_tool(artifact_name: str) -> str | None:
    """Map discovery artifact name to tool name."""
    mapping = {
        "amcache": "amcache",
        "shimcache": "shimcache",
        "registry_system": "registry",
        "registry_software": "registry",
        "registry_sam": "registry",
        "registry_security": "registry",
        "mft": "mft",
        "usn": "usn",
        "recyclebin": "recyclebin",
        "shellbags": "shellbags",
        "jumplists": "jumplists",
        "lnk": "lnk",
        "timeline": "timeline",
    }
    return mapping.get(artifact_name)


def discover(path: Path, hostname: str | None = None) -> list[DiscoveredHost]:
    """Discover hosts and artifacts in a directory."""
    hosts = scan_triage_directory(path)

    # --hostname override: if exactly one host found and hostname provided, use it
    if hosts and hostname and len(hosts) == 1:
        hosts[0].hostname = hostname

    if not hosts and hostname:
        from opensearch_mcp.discover import discover_artifacts, find_volume_root

        vr = find_volume_root(path)
        if vr is not None:
            host = DiscoveredHost(hostname=hostname, volume_root=vr)
            discover_artifacts(host)
            if host.artifacts or host.evtx_dir:
                hosts = [host]

        # Flat evtx directory — no Windows tree, just loose evtx files
        if not hosts:
            evtx_files = [f for f in path.iterdir() if f.suffix.lower() == ".evtx" and f.is_file()]
            if evtx_files:
                host = DiscoveredHost(hostname=hostname, volume_root=path)
                host.evtx_dir = path
                hosts = [host]

    return hosts


def ingest(
    hosts: list[DiscoveredHost],
    client: OpenSearch,
    audit: AuditWriter,
    case_id: str,
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    time_from=None,
    time_to=None,
    status_pid: int = 0,
    status_run_id: str = "",
    on_progress: object = None,
) -> IngestResult:
    """Ingest artifacts for discovered hosts.

    on_progress: optional callable(event, **kwargs) for CLI output.
      Events: "host_start", "evtx_file", "evtx_done", "artifact_start",
              "artifact_done", "artifact_failed"
    status_pid/status_run_id: if nonzero, write progress to status file.
    """
    active_tools = get_active_tools(include=include, exclude=exclude)
    active_names = {t.cli_name for t in active_tools}
    start = time.monotonic()
    started_ts = datetime.now(timezone.utc).isoformat()
    result = IngestResult(pipeline_version=_PIPELINE_VERSION)

    # Build status host structure for tracking
    status_hosts = _build_status_hosts(hosts, active_names)

    def _progress(event: str, **kwargs) -> None:
        if callable(on_progress):
            on_progress(event, **kwargs)

    def _update_status(error: str = "") -> None:
        if not status_pid:
            return
        totals = _compute_totals(status_hosts)
        write_status(
            case_id=case_id,
            pid=status_pid,
            run_id=status_run_id,
            status="running",
            hosts=status_hosts,
            totals=totals,
            started=started_ts,
            error=error,
            elapsed_seconds=time.monotonic() - start,
        )

    _update_status()

    for host_idx, host in enumerate(hosts):
        host_result = HostResult(hostname=host.hostname, volume_root=str(host.volume_root))
        _progress("host_start", hostname=host.hostname)

        # Evtx files
        if host.evtx_dir:
            evtx_files = sorted(f for f in host.evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
            if evtx_files:
                index_name = f"case-{case_id}-evtx-{host.hostname}".lower()
                existing = _safe_count(client, index_name)
                ar = ArtifactResult(
                    artifact="evtx",
                    index=index_name,
                    existing_before=existing,
                )

                # Find evtx entry in status
                evtx_status = _find_artifact_status(status_hosts, host_idx, "evtx")
                if evtx_status:
                    evtx_status["status"] = "running"
                    evtx_status["files_total"] = len(evtx_files)
                    _update_status()

                for file_idx, evtx_file in enumerate(evtx_files):
                    file_hash = sha256_file(evtx_file)
                    aid = audit._next_audit_id()
                    try:
                        cnt, sk, bf = parse_and_index(
                            evtx_path=evtx_file,
                            client=client,
                            index_name=index_name,
                            source_file=str(evtx_file),
                            ingest_audit_id=aid,
                            time_from=time_from,
                            time_to=time_to,
                        )
                        ar.indexed += cnt
                        ar.skipped += sk
                        ar.bulk_failed += bf
                        ar.source_files.append(str(evtx_file))
                        audit.log(
                            tool="ingest_evtx",
                            audit_id=aid,
                            params={
                                "hostname": host.hostname,
                                "index_name": index_name,
                                "file": str(evtx_file),
                            },
                            result_summary=f"{cnt} indexed, {sk} skipped"
                            + (f", {bf} bulk failed" if bf else ""),
                            input_files=[str(evtx_file)],
                            input_sha256s=[file_hash],
                            source_evidence=str(evtx_file),
                        )
                        # Per-file status update
                        if evtx_status:
                            evtx_status["indexed"] = ar.indexed
                            evtx_status["skipped"] = ar.skipped
                            evtx_status["bulk_failed"] = ar.bulk_failed
                            evtx_status["files_done"] = file_idx + 1
                            _update_status()
                        _progress(
                            "evtx_file",
                            hostname=host.hostname,
                            filename=evtx_file.name,
                            file_num=file_idx + 1,
                            file_total=len(evtx_files),
                            count=cnt,
                        )
                    except Exception as e:
                        if ar.error:
                            ar.error += f"; {evtx_file.name}: {e}"
                        else:
                            ar.error = f"{evtx_file.name}: {e}"

                if evtx_status:
                    evtx_status["status"] = "failed" if ar.error else "complete"
                    evtx_status["indexed"] = ar.indexed
                    _update_status()
                _progress(
                    "evtx_done",
                    hostname=host.hostname,
                    indexed=ar.indexed,
                    skipped=ar.skipped,
                    bulk_failed=ar.bulk_failed,
                    error=ar.error,
                )

                host_result.artifacts.append(ar)

        # EZ tool artifacts
        seen_runs: set[tuple[str, str]] = set()
        for artifact_name, artifact_path in host.artifacts:
            tool_name = _artifact_to_tool(artifact_name)
            if tool_name is None or tool_name not in active_names:
                continue

            # Deduplicate: RECmd runs on the directory (config/), not individual
            # hive files. Use parent dir for registry to avoid 4 runs.
            if tool_name == "registry":
                run_key = (tool_name, str(artifact_path.parent))
            else:
                run_key = (tool_name, str(artifact_path))
            if run_key in seen_runs:
                continue
            seen_runs.add(run_key)

            cfg = TOOLS[tool_name]
            index_name = f"case-{case_id}-{cfg.index_suffix}-{host.hostname}".lower()
            existing = _safe_count(client, index_name)
            file_hash = sha256_file(artifact_path) if artifact_path.is_file() else ""
            aid = audit._next_audit_id()

            ar = ArtifactResult(
                artifact=tool_name,
                index=index_name,
                existing_before=existing,
                source_files=[str(artifact_path)],
            )

            # Update status
            tool_status = _find_artifact_status(status_hosts, host_idx, tool_name)
            if tool_status:
                tool_status["status"] = "running"
                _update_status()
            _progress("artifact_start", hostname=host.hostname, artifact=tool_name)

            try:
                cnt, sk, bf = run_and_ingest(
                    tool_name=tool_name,
                    artifact_path=artifact_path,
                    client=client,
                    case_id=case_id,
                    hostname=host.hostname,
                    source_file=str(artifact_path),
                    ingest_audit_id=aid,
                    pipeline_version=_PIPELINE_VERSION,
                    time_from=time_from,
                    time_to=time_to,
                )
                ar.indexed = cnt
                ar.skipped = sk
                ar.bulk_failed = bf
                audit.log(
                    tool=f"ingest_{tool_name}",
                    audit_id=aid,
                    params={
                        "hostname": host.hostname,
                        "tool": tool_name,
                        "file": str(artifact_path),
                    },
                    result_summary=f"{cnt} indexed"
                    + (f", {sk} skipped" if sk else "")
                    + (f", {bf} bulk failed" if bf else ""),
                    input_files=[str(artifact_path)],
                    input_sha256s=[file_hash] if file_hash else [],
                    source_evidence=str(artifact_path),
                )
                if tool_status:
                    tool_status["status"] = "complete"
                    tool_status["indexed"] = cnt
                    tool_status["skipped"] = sk
                    tool_status["bulk_failed"] = bf
                    _update_status()
                _progress(
                    "artifact_done",
                    hostname=host.hostname,
                    artifact=tool_name,
                    indexed=cnt,
                    skipped=sk,
                )
            except Exception as e:
                ar.error = str(e)
                if tool_status:
                    tool_status["status"] = "failed"
                    tool_status["error"] = str(e)
                    _update_status()
                _progress(
                    "artifact_failed",
                    hostname=host.hostname,
                    artifact=tool_name,
                    error=str(e),
                )

            host_result.artifacts.append(ar)

        result.hosts.append(host_result)

    result.elapsed_seconds = time.monotonic() - start

    # Final status
    if status_pid:
        totals = _compute_totals(status_hosts)
        has_errors = any(
            a.get("status") == "failed" for h in status_hosts for a in h.get("artifacts", [])
        )
        write_status(
            case_id=case_id,
            pid=status_pid,
            run_id=status_run_id,
            status="complete",
            hosts=status_hosts,
            totals=totals,
            started=started_ts,
            error="Some artifacts failed" if has_errors else "",
            elapsed_seconds=result.elapsed_seconds,
        )

    return result


def _safe_count(client: OpenSearch, index_name: str) -> int:
    try:
        r = client.count(index=index_name)
        return r["count"]
    except Exception:
        return 0


def _build_status_hosts(hosts: list[DiscoveredHost], active_names: set[str]) -> list[dict]:
    """Build the initial status host structure with all artifacts pending."""
    status_hosts = []
    for host in hosts:
        artifacts = []
        if host.evtx_dir:
            artifacts.append({"name": "evtx", "status": "pending"})
        seen = set()
        for aname, _ in host.artifacts:
            tool = _artifact_to_tool(aname)
            if tool and tool in active_names and tool not in seen:
                seen.add(tool)
                artifacts.append({"name": tool, "status": "pending"})
        status_hosts.append({"hostname": host.hostname, "artifacts": artifacts})
    return status_hosts


def _find_artifact_status(
    status_hosts: list[dict], host_idx: int, artifact_name: str
) -> dict | None:
    """Find an artifact entry in the status structure."""
    if host_idx >= len(status_hosts):
        return None
    for a in status_hosts[host_idx].get("artifacts", []):
        if a["name"] == artifact_name:
            return a
    return None


def _compute_totals(status_hosts: list[dict]) -> dict:
    """Compute aggregate totals from status host data."""
    total_indexed = 0
    artifacts_complete = 0
    artifacts_total = 0
    hosts_complete = 0

    for h in status_hosts:
        host_done = True
        for a in h.get("artifacts", []):
            artifacts_total += 1
            total_indexed += a.get("indexed", 0)
            if a.get("status") in ("complete", "failed"):
                artifacts_complete += 1
            else:
                host_done = False
        if host_done and h.get("artifacts"):
            hosts_complete += 1

    return {
        "indexed": total_indexed,
        "hosts_complete": hosts_complete,
        "hosts_total": len(status_hosts),
        "artifacts_complete": artifacts_complete,
        "artifacts_total": artifacts_total,
    }
