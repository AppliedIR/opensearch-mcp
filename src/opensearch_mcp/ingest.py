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
from opensearch_mcp.paths import sanitize_index_component as _sanitize_index_component
from opensearch_mcp.paths import vhir_dir
from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult
from opensearch_mcp.tools import TOOLS, get_active_tools, run_and_ingest

_PIPELINE_VERSION = f"opensearch-mcp-{__version__}"


def _register_evidence(
    file_path: str, hostname: str, artifact_type: str, sha256: str = "", doc_count: int = 0
) -> None:
    """Best-effort evidence registration via gateway.

    Writes a manifest to the case directory, then registers it via
    evidence_register. The manifest path is inside the case dir, so
    path validation in evidence_register succeeds.
    """
    try:
        import json as _json
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.gateway import call_tool
        from opensearch_mcp.paths import vhir_dir

        # Resolve case directory — active_case contains full path
        active_case_file = vhir_dir() / "active_case"
        if not active_case_file.exists():
            return
        case_dir = Path(active_case_file.read_text().strip())
        if not case_dir.is_dir():
            return

        # Write manifest to case evidence directory
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        safe_host = hostname.replace("/", "_").replace("\\", "_")
        safe_type = artifact_type.replace("/", "_").replace("\\", "_")
        # Include file stem to prevent overwrite when multiple files per artifact type
        safe_file = Path(file_path).stem.replace("/", "_").replace("\\", "_")[:50]
        manifest_name = f"{safe_host}-{safe_type}-{safe_file}.manifest.json"
        manifest_path = evidence_dir / manifest_name
        manifest = {
            "source_path": file_path,
            "hostname": hostname,
            "artifact_type": artifact_type,
            "registered_at": _dt.now(_tz.utc).isoformat(),
        }
        if sha256:
            manifest["sha256"] = sha256
        manifest["doc_count"] = doc_count
        manifest_path.write_text(_json.dumps(manifest, indent=2))

        # Register the in-case manifest path
        call_tool(
            "evidence_register",
            {
                "path": str(manifest_path),
                "description": f"Ingest manifest: {artifact_type} from {hostname}",
            },
        )
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug("Evidence registration skipped: %s", e)


# Artifacts handled by Plaso/wintools (not EZ tools on Linux)
_PLASO_ARTIFACTS = {"prefetch", "srum"}

# Artifacts with custom parsers (not EZ tools, not Plaso)
_CUSTOM_ARTIFACTS = {
    "transcripts",
    "defender",
    "iis",
    "httperr",
    "tasks",
    "wer",
    "firewall",
    "ssh",
}


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
        "prefetch": "prefetch",
        "srum": "srum",
        "transcripts": "transcripts",
        "defender": "defender",
        "iis": "iis",
        "httperr": "httperr",
        "tasks": "tasks",
        "wer": "wer",
        "firewall": "firewall",
        "ssh": "ssh",
    }
    return mapping.get(artifact_name)


def discover(
    path: Path, hostname: str | None = None, force_hostname: bool = False
) -> list[DiscoveredHost]:
    """Discover hosts and artifacts in a directory."""
    hosts = scan_triage_directory(path)

    # --hostname override
    if hosts and hostname:
        if force_hostname:
            for h in hosts:
                h.hostname = hostname
        elif len(hosts) == 1:
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
    full: bool = False,
    time_from=None,
    time_to=None,
    reduced_ids: set[int] | None = None,
    reduced_log_names: set[str] | None = None,
    status_pid: int = 0,
    status_run_id: str = "",
    on_progress: object = None,
) -> IngestResult:
    """Ingest artifacts for discovered hosts.

    on_progress: optional callable(event, **kwargs) for CLI output.
      Events: "host_start", "evtx_file", "evtx_done", "artifact_start",
              "artifact_done", "artifact_failed"
    status_pid/status_run_id: if nonzero, write progress to status file.
    reduced_ids: if set, only ingest evtx events with these Event IDs.
    reduced_log_names: if set, only parse evtx files matching these names.
    """
    active_tools = get_active_tools(include=include, exclude=exclude, full=full)
    active_names = {t.cli_name for t in active_tools}

    # Plaso artifacts: enabled unless explicitly excluded
    active_plaso = set()
    for pa in _PLASO_ARTIFACTS:
        if exclude and pa in exclude:
            continue
        if include and pa not in include:
            continue
        active_plaso.add(pa)

    # Custom artifacts (transcripts): tier 2 — enabled by default
    active_custom = set()
    for ca in _CUSTOM_ARTIFACTS:
        if exclude and ca in exclude:
            continue
        if include and ca not in include:
            continue
        active_custom.add(ca)

    start = time.monotonic()
    started_ts = datetime.now(timezone.utc).isoformat()
    result = IngestResult(pipeline_version=_PIPELINE_VERSION)

    # Build status host structure for tracking
    status_hosts = _build_status_hosts(hosts, active_names, active_plaso, active_custom)

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

    _ingest_hosts(
        hosts=hosts,
        client=client,
        audit=audit,
        case_id=case_id,
        active_names=active_names,
        active_plaso=active_plaso,
        active_custom=active_custom,
        full=full,
        time_from=time_from,
        time_to=time_to,
        reduced_ids=reduced_ids,
        reduced_log_names=reduced_log_names,
        status_hosts=status_hosts,
        _progress=_progress,
        _update_status=_update_status,
        result=result,
        start=start,
    )

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


def run_hayabusa_batch(
    hosts,
    client,
    case_id: str,
    audit=None,
    on_progress=None,
) -> dict:
    """Run Hayabusa on all hosts' evtx dirs, ingest CSV results.

    Called as a post-ingest phase — evtx data is already indexed.
    """
    import shutil
    import subprocess

    from opensearch_mcp.parse_delimited import ingest_delimited

    hayabusa = shutil.which("hayabusa")
    if not hayabusa:
        return {"skipped": "hayabusa not installed"}

    output_dir = vhir_dir() / "hayabusa-output"
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}

    for host in hosts:
        if not host.evtx_dir:
            continue
        _cid = _sanitize_index_component(case_id)
        _hn = _sanitize_index_component(host.hostname)
        csv_output = output_dir / f"hayabusa-{_cid}-{_hn}.csv"
        cmd = [
            hayabusa,
            "csv-timeline",
            "-d",
            str(host.evtx_dir),
            "-o",
            str(csv_output),
            "-p",
            "verbose",
            "--no-wizard",
        ]
        if callable(on_progress):
            on_progress("hayabusa_start", hostname=host.hostname)
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=3600)
            if result.returncode != 0:
                stderr = result.stderr.decode(errors="replace")[:200]
                if callable(on_progress):
                    on_progress(
                        "hayabusa_failed",
                        hostname=host.hostname,
                        error=f"exit {result.returncode}: {stderr}",
                    )
                continue
        except Exception as e:
            if callable(on_progress):
                on_progress("hayabusa_failed", hostname=host.hostname, error=str(e))
            continue

        if not csv_output.exists() or csv_output.stat().st_size == 0:
            if callable(on_progress):
                on_progress("hayabusa_failed", hostname=host.hostname, error="no output")
            continue

        index_name = f"case-{_cid}-hayabusa-{_hn}"
        try:
            cnt, sk, bf, hr = ingest_delimited(
                csv_output,
                client,
                index_name,
                host.hostname,
                source_file=str(csv_output),
                pipeline_version=_PIPELINE_VERSION,
            )
            results[host.hostname] = cnt
            if callable(on_progress):
                on_progress("hayabusa_done", hostname=host.hostname, count=cnt)
        except Exception as e:
            if callable(on_progress):
                on_progress(
                    "hayabusa_failed",
                    hostname=host.hostname,
                    error=f"ingest failed: {e}",
                )
        if audit:
            audit.log(
                tool="ingest_hayabusa",
                params={"hostname": host.hostname, "evtx_dir": str(host.evtx_dir)},
                result_summary=f"{cnt} alerts indexed",
            )

    return results


_MIN_EVTX_SIZE = 69632  # One 64KB chunk + header — files under this are empty


def _ingest_hosts(
    hosts,
    client,
    audit,
    case_id,
    active_names,
    active_plaso,
    active_custom,
    full,
    time_from,
    time_to,
    reduced_ids,
    reduced_log_names,
    status_hosts,
    _progress,
    _update_status,
    result,
    start,
):
    """Inner ingest loop — processes all hosts and artifacts."""
    for host_idx, host in enumerate(hosts):
        host_result = HostResult(hostname=host.hostname, volume_root=str(host.volume_root))
        _progress("host_start", hostname=host.hostname)

        # Evtx files — filter by log name and size
        if host.evtx_dir:
            all_evtx = sorted(f for f in host.evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
            if not all_evtx:
                import sys

                print(
                    f"WARNING: {host.hostname}: evtx directory found but no .evtx files",
                    file=sys.stderr,
                )

            # Apply log file filter (--reduced-logs, ON by default)
            evtx_files = all_evtx
            if reduced_log_names is not None:
                evtx_files = [f for f in evtx_files if f.stem.lower() in reduced_log_names]

            # Skip empty files (header-only, no events)
            evtx_files = [f for f in evtx_files if f.stat().st_size >= _MIN_EVTX_SIZE]

            if evtx_files:
                _cid = _sanitize_index_component(case_id)
                _hn = _sanitize_index_component(host.hostname)
                index_name = f"case-{_cid}-evtx-{_hn}"
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
                        from opensearch_mcp.paths import relative_evidence_path

                        rel_path = relative_evidence_path(evtx_file, host.volume_root)
                        cnt, sk, bf = parse_and_index(
                            evtx_path=evtx_file,
                            client=client,
                            index_name=index_name,
                            source_file=rel_path,
                            ingest_audit_id=aid,
                            time_from=time_from,
                            time_to=time_to,
                            reduced_ids=reduced_ids,
                            vss_id=host.vss_id,
                        )
                        ar.indexed += cnt
                        ar.skipped += sk
                        ar.bulk_failed += bf
                        ar.source_files.append(str(evtx_file))
                        _register_evidence(
                            str(evtx_file),
                            host.hostname,
                            "evtx",
                            sha256=file_hash,
                            doc_count=cnt,
                        )
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
                        audit.log(
                            tool="ingest_evtx",
                            audit_id=aid,
                            params={"file": str(evtx_file)},
                            result_summary=f"FAILED: {e}",
                            input_files=[str(evtx_file)],
                            input_sha256s=[file_hash],
                        )

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

        # EZ tool artifacts + Plaso artifacts
        seen_runs: set[tuple[str, str]] = set()
        for artifact_name, artifact_path in host.artifacts:
            tool_name = _artifact_to_tool(artifact_name)
            if tool_name is None:
                continue

            # Route Plaso artifacts separately
            if tool_name in _PLASO_ARTIFACTS:
                if tool_name not in active_plaso:
                    continue
                _ingest_plaso_artifact(
                    tool_name=tool_name,
                    artifact_path=artifact_path,
                    client=client,
                    audit=audit,
                    case_id=case_id,
                    host=host,
                    host_idx=host_idx,
                    host_result=host_result,
                    status_hosts=status_hosts,
                    _progress=_progress,
                    _update_status=_update_status,
                )
                continue

            # Route custom artifacts (transcripts, defender, IIS, etc.)
            if tool_name in _CUSTOM_ARTIFACTS:
                if tool_name not in active_custom:
                    continue
                _ingest_custom_artifact(
                    tool_name=tool_name,
                    artifact_path=artifact_path,
                    client=client,
                    audit=audit,
                    case_id=case_id,
                    host=host,
                    host_idx=host_idx,
                    host_result=host_result,
                    status_hosts=status_hosts,
                    _progress=_progress,
                    _update_status=_update_status,
                    time_from=time_from,
                    time_to=time_to,
                )
                continue

            if tool_name not in active_names:
                continue

            # Deduplicate: RECmd runs on the directory (config/), not individual
            # hive files. Use parent dir for registry to avoid 4 runs.
            # Discovery always returns individual hive files for registry.
            if tool_name == "registry":
                run_key = (tool_name, str(artifact_path.parent))
            else:
                run_key = (tool_name, str(artifact_path))
            if run_key in seen_runs:
                continue
            seen_runs.add(run_key)

            cfg = TOOLS[tool_name]
            _cid = _sanitize_index_component(case_id)
            _hn = _sanitize_index_component(host.hostname)
            index_name = f"case-{_cid}-{cfg.index_suffix}-{_hn}"
            existing = _safe_count(client, index_name)
            file_hash = sha256_file(artifact_path) if artifact_path.is_file() else ""
            aid = audit._next_audit_id()

            # MFT natural key: add vss_id as 5th component when VSS is active
            natural_key = cfg.natural_key
            if tool_name == "mft" and host.vss_id and natural_key:
                natural_key = natural_key + ":vhir.vss_id"

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
                from opensearch_mcp.paths import relative_evidence_path

                _rel_src = relative_evidence_path(artifact_path, host.volume_root)
                cnt, sk, bf = run_and_ingest(
                    tool_name=tool_name,
                    artifact_path=artifact_path,
                    client=client,
                    case_id=case_id,
                    hostname=host.hostname,
                    source_file=_rel_src,
                    ingest_audit_id=aid,
                    pipeline_version=_PIPELINE_VERSION,
                    time_from=time_from,
                    time_to=time_to,
                    vss_id=host.vss_id,
                    natural_key_override=natural_key,
                )
                ar.indexed = cnt
                ar.skipped = sk
                ar.bulk_failed = bf
                _register_evidence(
                    str(artifact_path),
                    host.hostname,
                    tool_name,
                    sha256=file_hash,
                    doc_count=cnt,
                )
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
                audit.log(
                    tool=f"ingest_{tool_name}",
                    audit_id=aid,
                    params={"hostname": host.hostname, "tool": tool_name},
                    result_summary=f"FAILED: {e}",
                    input_files=[str(artifact_path)],
                    input_sha256s=[file_hash] if file_hash else [],
                )
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


def _ingest_plaso_artifact(
    tool_name: str,
    artifact_path: Path,
    client: OpenSearch,
    audit: AuditWriter,
    case_id: str,
    host: DiscoveredHost,
    host_idx: int,
    host_result: HostResult,
    status_hosts: list[dict],
    _progress,
    _update_status,
) -> None:
    """Ingest a prefetch or SRUM artifact (wintools-first, Plaso fallback)."""
    from opensearch_mcp.parse_prefetch import parse_prefetch
    from opensearch_mcp.parse_srum import parse_srum

    _cid = _sanitize_index_component(case_id)
    _hn = _sanitize_index_component(host.hostname)
    index_name = f"case-{_cid}-{tool_name}-{_hn}"
    existing = _safe_count(client, index_name)
    plaso_hash = sha256_file(artifact_path) if artifact_path.is_file() else ""
    aid = audit._next_audit_id()

    ar = ArtifactResult(
        artifact=tool_name,
        index=index_name,
        existing_before=existing,
        source_files=[str(artifact_path)],
    )

    tool_status = _find_artifact_status(status_hosts, host_idx, tool_name)
    if tool_status:
        tool_status["status"] = "running"
        _update_status()
    _progress("artifact_start", hostname=host.hostname, artifact=tool_name)

    try:
        from opensearch_mcp.paths import relative_evidence_path as _rel

        _plaso_src = _rel(artifact_path, host.volume_root)
        if tool_name == "prefetch":
            cnt, bf = parse_prefetch(
                prefetch_dir=artifact_path,
                client=client,
                index_name=index_name,
                hostname=host.hostname,
                ingest_audit_id=aid,
                pipeline_version=_PIPELINE_VERSION,
                vss_id=host.vss_id,
                source_file=_plaso_src,
            )
        else:
            cnt, bf = parse_srum(
                srum_path=artifact_path,
                client=client,
                index_name=index_name,
                hostname=host.hostname,
                case_id=case_id,
                ingest_audit_id=aid,
                pipeline_version=_PIPELINE_VERSION,
                vss_id=host.vss_id,
                source_file=_plaso_src,
            )
        ar.indexed = cnt
        ar.bulk_failed = bf
        _register_evidence(str(artifact_path), host.hostname, tool_name, doc_count=cnt)
        audit.log(
            tool=f"ingest_{tool_name}",
            audit_id=aid,
            params={
                "hostname": host.hostname,
                "tool": tool_name,
                "path": str(artifact_path),
            },
            result_summary=f"{cnt} indexed" + (f", {bf} bulk failed" if bf else ""),
            input_files=[str(artifact_path)],
            input_sha256s=[plaso_hash] if plaso_hash else [],
            source_evidence=str(artifact_path),
        )
        if tool_status:
            tool_status["status"] = "complete"
            tool_status["indexed"] = cnt
            tool_status["bulk_failed"] = bf
            _update_status()
        _progress(
            "artifact_done",
            hostname=host.hostname,
            artifact=tool_name,
            indexed=cnt,
            skipped=0,
        )
    except Exception as e:
        ar.error = str(e)
        audit.log(
            tool=f"ingest_{tool_name}",
            audit_id=aid,
            params={"hostname": host.hostname, "tool": tool_name},
            result_summary=f"FAILED: {e}",
            input_files=[str(artifact_path)],
            input_sha256s=[plaso_hash] if plaso_hash else [],
        )
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


def _ingest_custom_artifact(
    tool_name: str,
    artifact_path: Path,
    client: OpenSearch,
    audit: AuditWriter,
    case_id: str,
    host: DiscoveredHost,
    host_idx: int,
    host_result: HostResult,
    status_hosts: list[dict],
    _progress,
    _update_status,
    time_from=None,
    time_to=None,
) -> None:
    """Ingest a custom-parsed artifact (transcripts, defender, IIS, etc.)."""
    _cid = _sanitize_index_component(case_id)
    _hn = _sanitize_index_component(host.hostname)
    index_name = f"case-{_cid}-{tool_name}-{_hn}"
    existing = _safe_count(client, index_name)
    file_hash = sha256_file(artifact_path) if artifact_path.is_file() else ""
    aid = audit._next_audit_id()

    ar = ArtifactResult(
        artifact=tool_name,
        index=index_name,
        existing_before=existing,
        source_files=[str(artifact_path)],
    )

    tool_status = _find_artifact_status(status_hosts, host_idx, tool_name)
    if tool_status:
        tool_status["status"] = "running"
        _update_status()
    _progress("artifact_start", hostname=host.hostname, artifact=tool_name)

    try:
        cnt, sk, bf = _run_custom_parser(
            tool_name,
            artifact_path,
            client,
            index_name,
            host,
            aid,
            time_from,
            time_to,
        )
        ar.indexed = cnt
        ar.skipped = sk
        ar.bulk_failed = bf
        _register_evidence(str(artifact_path), host.hostname, tool_name, doc_count=cnt)
        audit.log(
            tool=f"ingest_{tool_name}",
            audit_id=aid,
            params={"hostname": host.hostname, "path": str(artifact_path)},
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
        audit.log(
            tool=f"ingest_{tool_name}",
            audit_id=aid,
            params={"hostname": host.hostname, "tool": tool_name},
            result_summary=f"FAILED: {e}",
            input_files=[str(artifact_path)],
            input_sha256s=[file_hash] if file_hash else [],
        )
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


def _run_custom_parser(
    tool_name, artifact_path, client, index_name, host, aid, time_from, time_to
):
    """Dispatch to the correct custom parser. Returns (indexed, skipped, bulk_failed)."""
    from opensearch_mcp.paths import relative_evidence_path

    kw: dict = {
        "client": client,
        "index_name": index_name,
        "hostname": host.hostname,
        "ingest_audit_id": aid,
        "pipeline_version": _PIPELINE_VERSION,
    }
    if host.vss_id:
        kw["vss_id"] = host.vss_id
    vr = host.volume_root

    if tool_name == "transcripts":
        from opensearch_mcp.parse_transcripts import ingest_transcripts

        cnt, bf = ingest_transcripts(
            transcript_dir=artifact_path,
            volume_root=vr,
            system_timezone=host.system_timezone,
            **kw,
        )
        return cnt, 0, bf

    if tool_name == "defender":
        from opensearch_mcp.parse_defender import parse_mplog

        return parse_mplog(
            mplog_dir=artifact_path,
            system_timezone=host.system_timezone,
            volume_root=vr,
            time_from=time_from,
            time_to=time_to,
            **kw,
        )

    if tool_name == "iis":
        from opensearch_mcp.parse_w3c import parse_w3c_log

        cnt = sk = bf = 0
        for log_file in sorted(artifact_path.rglob("u_ex*.log")):
            c, s, b = parse_w3c_log(
                log_file,
                timestamp_is_utc=True,
                time_from=time_from,
                time_to=time_to,
                source_file=relative_evidence_path(log_file, vr),
                parse_method="iis-w3c",
                **kw,
            )
            cnt += c
            sk += s
            bf += b
        return cnt, sk, bf

    if tool_name == "httperr":
        from opensearch_mcp.parse_w3c import parse_w3c_log

        cnt = sk = bf = 0
        for log_file in sorted(artifact_path.rglob("httperr*.log")):
            c, s, b = parse_w3c_log(
                log_file,
                timestamp_is_utc=True,
                time_from=time_from,
                time_to=time_to,
                source_file=relative_evidence_path(log_file, vr),
                parse_method="httperr-w3c",
                **kw,
            )
            cnt += c
            sk += s
            bf += b
        return cnt, sk, bf

    if tool_name == "tasks":
        from opensearch_mcp.parse_tasks import parse_tasks_dir

        return parse_tasks_dir(
            tasks_dir=artifact_path,
            system_timezone=host.system_timezone,
            volume_root=vr,
            **kw,
        )

    if tool_name == "wer":
        from opensearch_mcp.parse_wer import parse_wer_dir

        return parse_wer_dir(wer_dir=artifact_path, volume_root=vr, **kw)

    if tool_name == "firewall":
        from opensearch_mcp.parse_w3c import parse_w3c_log

        return parse_w3c_log(
            artifact_path,
            timestamp_is_utc=False,
            system_timezone=host.system_timezone,
            time_from=time_from,
            time_to=time_to,
            source_file=relative_evidence_path(artifact_path, vr),
            parse_method="firewall-w3c",
            **kw,
        )

    if tool_name == "ssh":
        from opensearch_mcp.parse_ssh import parse_ssh_log

        return parse_ssh_log(
            ssh_dir=artifact_path,
            system_timezone=host.system_timezone,
            volume_root=vr,
            time_from=time_from,
            time_to=time_to,
            **kw,
        )

    raise ValueError(f"Unknown custom artifact: {tool_name}")


def _safe_count(client: OpenSearch, index_name: str) -> int:
    try:
        r = client.count(index=index_name)
        return r["count"]
    except Exception:
        return 0


def _build_status_hosts(
    hosts: list[DiscoveredHost],
    active_names: set[str],
    active_plaso: set[str] | None = None,
    active_custom: set[str] | None = None,
) -> list[dict]:
    """Build the initial status host structure with all artifacts pending."""
    if active_plaso is None:
        active_plaso = set()
    if active_custom is None:
        active_custom = set()
    status_hosts = []
    for host in hosts:
        artifacts = []
        if host.evtx_dir:
            artifacts.append({"name": "evtx", "status": "pending"})
        seen = set()
        for aname, _ in host.artifacts:
            tool = _artifact_to_tool(aname)
            if not tool or tool in seen:
                continue
            if tool in _PLASO_ARTIFACTS:
                if tool in active_plaso:
                    seen.add(tool)
                    artifacts.append({"name": tool, "status": "pending"})
            elif tool in _CUSTOM_ARTIFACTS:
                if tool in active_custom:
                    seen.add(tool)
                    artifacts.append({"name": tool, "status": "pending"})
            elif tool in active_names:
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
