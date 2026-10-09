"""Core ingest orchestrator — shared by CLI and MCP entry points."""

from __future__ import annotations

import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from opensearchpy import OpenSearch
from sift_common.audit import AuditWriter

from opensearch_mcp import __version__, ops
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost, scan_triage_directory
from opensearch_mcp.ingest_status import write_status
from opensearch_mcp.manifest import sha256_file
from opensearch_mcp.ops import NO_ENTRY
from opensearch_mcp.parse_evtx import evtx_truncation, parse_and_index
from opensearch_mcp.paths import vhir_dir
from opensearch_mcp.results import ArtifactResult, HostResult, IngestResult
from opensearch_mcp.tools import TOOLS, get_active_tools, run_and_ingest

_PIPELINE_VERSION = f"opensearch-mcp-{__version__}"


def _sha256_or_empty(path: Path) -> str:
    try:
        return sha256_file(path)
    except OSError:
        return ""


def _write_ingest_manifest(
    file_path: str, hostname: str, artifact_type: str, sha256: str = "", doc_count: int = 0
) -> None:
    """Write per-artifact ingest provenance manifest to case audit dir.

    One JSON file per parsed source artifact, recording which parser ran on
    which file, when, with what SHA256 and doc count. Does NOT go through
    evidence_register — these are internal audit records, not forensic
    evidence. `case/evidence/` is reserved for operator-registered forensic
    evidence (VHDXs, ISOs, memory dumps); ingest manifests belong in
    `case/audit/ingest-manifests/`.

    Readers: none yet. Preserved for future integrity-verification tooling
    and human debugging.
    """
    try:
        import hashlib as _hashlib
        import json as _json
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.paths import vhir_dir

        active_case_file = vhir_dir() / "active_case"
        if not active_case_file.exists():
            return
        case_dir = Path(active_case_file.read_text().strip())
        if not case_dir.is_dir():
            return

        manifests_dir = case_dir / "audit" / "ingest-manifests"
        manifests_dir.mkdir(parents=True, exist_ok=True)

        # Name includes path-hash suffix to disambiguate stems that collide
        # under the 50-char truncation. Real collision: Defender EVTX
        # "Microsoft-Windows-TerminalServices-LocalSessionManager%4Admin"
        # and ".../LocalSessionManager%4Operational" both truncate to
        # "Microsoft-Windows-TerminalServices-LocalSessionMan" — without
        # the suffix, one silently overwrites the other on every ingest.
        safe_host = hostname.replace("/", "_").replace("\\", "_")
        safe_type = artifact_type.replace("/", "_").replace("\\", "_")
        safe_file = Path(file_path).stem.replace("/", "_").replace("\\", "_")[:50]
        path_sig = _hashlib.sha1(file_path.encode("utf-8", "replace")).hexdigest()[:8]
        manifest_name = f"{safe_host}-{safe_type}-{safe_file}-{path_sig}.manifest.json"

        manifest = {
            "source_path": file_path,
            "hostname": hostname,
            "artifact_type": artifact_type,
            "written_at": _dt.now(_tz.utc).isoformat(),
            "doc_count": doc_count,
        }
        if sha256:
            manifest["sha256"] = sha256

        (manifests_dir / manifest_name).write_text(_json.dumps(manifest, indent=2))
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug("Ingest manifest write skipped: %s", e)


# Artifacts handled by Plaso/wintools (not EZ tools on Linux)
_PLASO_ARTIFACTS = {"prefetch", "srum", "plaso"}

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
        "registry_user": "registry_user",
        "mft": "mft",
        "usn": "usn",
        "recyclebin": "recyclebin",
        "shellbags": "shellbags",
        "jumplists": "jumplists",
        "lnk": "lnk",
        "timeline": "timeline",
        "prefetch": "prefetch",
        "srum": "srum",
        "plaso": "plaso",
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
    path: Path,
    hostname: str | None = None,
    force_hostname: bool = False,
    skipped: list[str] | None = None,
) -> list[DiscoveredHost]:
    """Discover hosts and artifacts in a directory. `skipped` gets the
    subdirectories left out for having no recognised root."""
    hosts = scan_triage_directory(path, skipped)

    # --hostname override
    if hosts and hostname:
        if force_hostname:
            for h in hosts:
                h.hostname = hostname
        elif len(hosts) == 1:
            hosts[0].hostname = hostname

    if not hosts and hostname:
        from opensearch_mcp.discover import find_volume_root, make_host

        vr = find_volume_root(path)
        if vr is not None:
            host = make_host(hostname, vr)
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
    host_dict=None,
    final_status: str = "complete",
    case_dir: Path | None = None,
) -> IngestResult:
    """Ingest artifacts for discovered hosts.

    on_progress: optional callable(event, **kwargs) for CLI output.
      Events: "host_start", "evtx_file", "evtx_done", "artifact_start",
              "artifact_done", "artifact_failed"
    status_pid/status_run_id: if nonzero, write progress to status file.
    reduced_ids: if set, only ingest evtx events with these Event IDs.
    reduced_log_names: if set, only parse evtx files matching these names.
    final_status: the status of the last write; "running" when the caller
      has a later phase (hayabusa, triage) that writes the terminal one.
    case_dir: the case the records belong to; each host is one evidence
      unit in it (see host_context).
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
    from opensearch_mcp.bulk import get_already_present

    present_before = get_already_present()

    def _totals() -> dict:
        totals = _compute_totals(status_hosts)
        kept = get_already_present() - present_before
        if kept:
            totals["already_present"] = kept
        return totals

    # Build status host structure for tracking
    status_hosts = _build_status_hosts(hosts, active_names, active_plaso, active_custom)

    def _progress(event: str, **kwargs) -> None:
        if callable(on_progress):
            on_progress(event, **kwargs)

    def _update_status(error: str = "") -> None:
        if not status_pid:
            return
        from opensearch_mcp.bulk import get_last_bulk_reason

        totals = _totals()
        write_status(
            case_id=case_id,
            pid=status_pid,
            run_id=status_run_id,
            status="running",
            hosts=status_hosts,
            totals=totals,
            started=started_ts,
            error=error,
            bulk_failed=totals.get("bulk_failed", 0),
            bulk_failed_reason=get_last_bulk_reason(),
            elapsed_seconds=time.monotonic() - start,
        )

    _update_status()

    with wc.restoring():
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
            run_id=status_run_id,
            host_dict=host_dict,
            case_dir=case_dir,
        )

    result.elapsed_seconds = time.monotonic() - start
    result.already_present = get_already_present() - present_before

    # Final status
    if status_pid:
        from opensearch_mcp.bulk import get_last_bulk_reason

        totals = _totals()
        has_errors = any(
            a.get("status") == "failed" for h in status_hosts for a in h.get("artifacts", [])
        )
        write_status(
            case_id=case_id,
            pid=status_pid,
            run_id=status_run_id,
            status=final_status,
            hosts=status_hosts,
            totals=totals,
            started=started_ts,
            error="Some artifacts failed" if has_errors else "",
            bulk_failed=totals.get("bulk_failed", 0),
            bulk_failed_reason=get_last_bulk_reason(),
            elapsed_seconds=result.elapsed_seconds,
        )

    return result


_HAYABUSA_RULES_CANDIDATES = (
    "/usr/local/share/hayabusa-rules",
    "/usr/share/hayabusa-rules",  # Debian / Ubuntu packaging
    "/opt/hayabusa/rules",
    "/opt/hayabusa-rules",
)


def _resolve_hayabusa_rules_dir() -> Path | None:
    """Locate hayabusa rules directory.

    Precedence:
      1. $HAYABUSA_RULES_DIR env var
      2. Standard install paths (see _HAYABUSA_RULES_CANDIDATES)
      3. /opt/hayabusa*/rules (nested layout)
      4. /opt/hayabusa* (direct layout — rules dir at the top level)
      5. rules/ beside the hayabusa binary on PATH, links resolved (SIFT
         links ~/.local/bin/hayabusa into its own install directory)

    Returns None if nothing found. Only returns paths where the
    directory AND a 'config' subdirectory both exist — hayabusa
    needs both to function.
    """
    env_dir = os.environ.get("HAYABUSA_RULES_DIR", "").strip()
    if env_dir:
        p = Path(env_dir)
        if p.is_dir() and (p / "config").is_dir():
            return p
    for candidate in _HAYABUSA_RULES_CANDIDATES:
        p = Path(candidate)
        if p.is_dir() and (p / "config").is_dir():
            return p
    opt = Path("/opt")
    if opt.is_dir():
        # Nested layout: /opt/hayabusa*/rules/
        for sibling in sorted(opt.glob("hayabusa*")):
            p = sibling / "rules"
            if p.is_dir() and (p / "config").is_dir():
                return p
        # Direct layout: /opt/hayabusa*/ (no /rules subdir)
        for sibling in sorted(opt.glob("hayabusa*")):
            if sibling.is_dir() and (sibling / "config").is_dir():
                return sibling
    binary = shutil.which("hayabusa")
    if binary:
        p = Path(binary).resolve().parent / "rules"
        if p.is_dir() and (p / "config").is_dir():
            return p
    return None


def hayabusa_staging_stem(ctx) -> str:
    """One Hayabusa output file per case, evidence unit and run: two runs
    never share one, and neither do two hosts with one name."""
    run = os.environ.get("VHIR_INGEST_RUN_ID") or str(os.getpid())
    return f"hayabusa-{ctx.c12}-{ctx.unit}-{run}"


def _run_root_of(host, run_tmpdir) -> Path | None:
    """`run_tmpdir` when the host's logs are under it (an image or archive
    extracted or mounted for this run); None for a folder."""
    if run_tmpdir is None or not host.evtx_dir:
        return None
    try:
        Path(host.evtx_dir).relative_to(run_tmpdir)
    except ValueError:
        return None
    return Path(run_tmpdir)


def run_hayabusa_batch(
    hosts,
    client,
    case_id: str,
    audit=None,
    on_progress=None,
    host_dict=None,
    case_dir=None,
    run_tmpdir=None,
    run_id: str = "",
) -> dict:
    """Run Hayabusa on all hosts' evtx dirs, ingest CSV results.

    Called as a post-ingest phase — evtx data is already indexed.
    run_tmpdir: the run's extract/mount directory, for an image or archive.
    run_id: the ingest run's id, recorded on each host's Hayabusa entry.
    """
    with wc.restoring():
        return _run_hayabusa_batch(
            hosts, client, case_id, audit, on_progress, host_dict, case_dir, run_tmpdir,
            run_id,
        )  # fmt: skip


def _run_hayabusa_batch(
    hosts, client, case_id, audit, on_progress, host_dict, case_dir, run_tmpdir=None,
    run_id="",
):  # fmt: skip
    import shutil
    import subprocess

    from opensearch_mcp.parse_delimited import ingest_delimited

    hayabusa = shutil.which("hayabusa")
    if not hayabusa:
        return {"skipped": "hayabusa not installed"}

    output_dir = vhir_dir() / "hayabusa-output"
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    # Hayabusa 4.0.0 replaced csv-timeline with dfir-timeline (CSV by default).
    try:
        probe = subprocess.run(
            [hayabusa, "dfir-timeline", "--help"], capture_output=True, timeout=60
        )
        timeline = "dfir-timeline" if probe.returncode == 0 else "csv-timeline"
    except Exception:
        timeline = "csv-timeline"

    def failed(host, error: str, **counts) -> None:
        results[host.hostname] = {"status": "failed", "error": error, **counts}
        if callable(on_progress):
            on_progress("hayabusa_failed", hostname=host.hostname, error=error)

    def evtx_inputs(host) -> tuple[list, list]:
        """Each evtx Hayabusa read, with its place: by the registry, or the
        manifest of the extraction that wrote it, or hashed."""
        inputs, regs = [], []
        try:
            files = sorted(
                f for f in Path(host.evtx_dir).iterdir()
                if f.is_file() and f.suffix.lower() == ".evtx"
            )  # fmt: skip
        except OSError:
            files = []
        for f in files:
            try:
                entry, reg = ops.file_input(case_dir, f)
            except OSError:
                entry, reg = ops.place(f), None  # unreadable: named, not hashed
            inputs.append(entry)
            regs += [reg] if reg else []
        return inputs, regs

    for host in hosts:
        if not host.evtx_dir:
            continue

        # Per-host rules-dir re-resolve. Environment state can change
        # mid-case (external media unmounted, etc.) so don't cache
        # once-per-batch. Fail loud if rules missing — previous
        # silent-skip behavior caused the UAT-observed empty
        # detection phase across an entire case.
        rules_dir = _resolve_hayabusa_rules_dir()
        if rules_dir is None:
            if audit is not None:
                audit.log(
                    tool="ingest_hayabusa",
                    params={"hostname": host.hostname},
                    result_summary=(
                        "SKIPPED: hayabusa rules directory not found. "
                        "Set HAYABUSA_RULES_DIR env var or install rules "
                        "to /usr/local/share/hayabusa-rules or /opt/hayabusa*."
                    ),
                )
            if callable(on_progress):
                on_progress(
                    "hayabusa_failed",
                    hostname=host.hostname,
                    error="rules_not_found",
                )
            results[host.hostname] = {
                "status": "failed",
                "error": "rules_not_found",
            }
            continue

        ctx = wc.host_context(case_dir, case_id, host)
        wc.set_current(ctx)
        stem = hayabusa_staging_stem(ctx)
        csv_output = output_dir / f"{stem}.csv"
        cmd = [
            hayabusa,
            timeline,
            "-r",
            str(rules_dir),
            "-c",
            str(rules_dir / "config"),
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
        params = {"hostname": host.hostname, "evtx_dir": str(host.evtx_dir), "run_id": run_id,
                  "rules_dir": str(rules_dir)}  # fmt: skip

        def record(summary: str, outputs=None) -> str:
            """The run's one step: the evtx it read and the CSV it wrote."""
            if audit is None:
                return ""
            inputs, regs = evtx_inputs(host)
            return ops.write(
                audit, "ingest_hayabusa", params=params, summary=summary, inputs=inputs,
                input_registered=regs or None, outputs=outputs,
            )  # fmt: skip

        try:
            # Hayabusa won't overwrite an existing output (it says so and
            # exits 0), so move the previous run's CSV aside: a run that
            # writes nothing then fails the output check below.
            if csv_output.exists():
                csv_output.replace(output_dir / f"{stem}.prev.csv")
            result = subprocess.run(cmd, capture_output=True, timeout=3600)
            stderr = result.stderr.decode(errors="replace")
            if result.returncode != 0:
                failed(host, f"exit {result.returncode}: {stderr[:200]}")
                record(f"FAILED: exit {result.returncode}: {stderr[:200]}")
                continue
            # Hayabusa exits 0 on some errors; it says so on stderr
            errors = [ln.strip() for ln in stderr.splitlines() if "[ERROR]" in ln]
            if errors:
                failed(host, errors[0][:200])
                record(f"FAILED: {errors[0][:200]}")
                continue
        except Exception as e:  # it couldn't run, timed out, or the move failed
            failed(host, str(e)[:200])
            record(f"FAILED: {str(e)[:200]}")
            continue

        if not csv_output.exists() or csv_output.stat().st_size == 0:
            # Not a failure, and not "0 alerts" either: Hayabusa writes nothing
            # both when no rule matched and when no event could be read.
            note = (
                f"{host.hostname}: Hayabusa wrote no detections: no rule matched, "
                "or no event could be read"
            )
            results[host.hostname] = {"status": "empty", "note": note}
            record("no detections written: no rule matched, or no event could be read")
            if callable(on_progress):
                on_progress("hayabusa_empty", hostname=host.hostname, note=note)
            continue

        index_name = wc.index_name("hayabusa")
        cnt = 0
        # the run's step, before its detections: each carries its id, so it
        # traces to the logs it came from and the CSV it was read from
        aid = record("recorded before its detections were indexed", [ops.output(csv_output)])
        if audit is not None and not aid:
            failed(host, NO_ENTRY)
            continue
        try:
            with wc.op(aid):
                cnt, sk, bf, hr = ingest_delimited(
                    csv_output,
                    client,
                    index_name,
                    host.hostname,
                    time_field="Timestamp",
                    source_file=str(csv_output),
                    ingest_audit_id=aid,
                    pipeline_version=_PIPELINE_VERSION,
                    host_dict=host_dict,
                    id_root=_run_root_of(host, run_tmpdir),
                )
                if bf:
                    from opensearch_mcp.bulk import get_last_bulk_reason

                    reason = get_last_bulk_reason()
                    failed(
                        host,
                        f"{bf:,} of {cnt + bf:,} alerts rejected by OpenSearch"
                        + (f" ({reason[:200]})" if reason else ""),
                        indexed=cnt,
                        bulk_failed=bf,
                    )
                else:
                    results[host.hostname] = cnt
                    if callable(on_progress):
                        on_progress("hayabusa_done", hostname=host.hostname, count=cnt)
        except Exception as e:
            failed(host, f"ingest failed: {e}"[:200])
        if aid and host.hostname in results:  # what became of it: an entry of its own
            outcome = results[host.hostname]
            ops.later(
                audit, aid, "ingest_hayabusa",
                f"FAILED: {outcome['error']}" if isinstance(outcome, dict)
                else f"{cnt} alerts indexed",
                params,
            )  # fmt: skip

    return results


_MIN_EVTX_SIZE = 69632  # One 64KB chunk + header — files under this are empty


def _row_label(artifact_name: str) -> str:
    """An artifact's rows in words: `shellbags` -> "shellbag"."""
    label = artifact_name.replace("_", " ")
    return label[:-1] if label.endswith("s") and not label.endswith("ss") else label


def _indices_filled_by_several_files(hosts, active_names) -> set[str]:
    """The EZ-tool artifact types (each one case index, every host's records
    in it) this run fills from more than one evidence file (a content-hash
    id; a natural key names its own row), after the registry's
    one-run-per-folder dedup."""
    from opensearch_mcp.paths import relative_evidence_path

    sources: dict[str, set[str]] = {}
    for host in hosts:
        runs = set()
        for artifact_name, artifact_path in host.artifacts:
            tool_name = _artifact_to_tool(artifact_name)
            cfg = TOOLS.get(tool_name) if tool_name else None
            if cfg is None or tool_name not in active_names or cfg.natural_key:
                continue
            folder = artifact_path.parent if tool_name == "registry" else artifact_path
            if (tool_name, str(folder)) in runs:
                continue
            runs.add((tool_name, str(folder)))
            source = relative_evidence_path(artifact_path, host.volume_root)
            sources.setdefault(cfg.index_suffix, set()).add(source)
    return {index for index, files in sources.items() if len(files) > 1}


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
    run_id="",
    host_dict=None,
    case_dir=None,
):
    """Inner ingest loop — processes all hosts and artifacts."""
    # Rows two files of this run write under one id: the later replaces the
    # earlier. Tracked only for an index more than one file fills.
    shared = _indices_filled_by_several_files(hosts, active_names)
    id_seen: dict[str, dict] = {}
    for host_idx, host in enumerate(hosts):
        ctx = wc.host_context(case_dir, case_id, host, run_id)
        wc.set_current(ctx)
        host_result = HostResult(hostname=host.hostname, volume_root=str(host.volume_root))
        _progress("host_start", hostname=host.hostname)
        device = _device(host.volume_root)  # still there, the same volume, when it's done?

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
            small = [f for f in evtx_files if f.stat().st_size < _MIN_EVTX_SIZE]
            evtx_files = [f for f in evtx_files if f.stat().st_size >= _MIN_EVTX_SIZE]

            # The status names what these filters dropped (idx_ingest_status).
            out_of_set = [
                f.name
                for f in all_evtx
                if reduced_log_names is not None and f.stem.lower() not in reduced_log_names
            ]
            if out_of_set:
                host_result.evtx_dropped["not_in_log_set"] = out_of_set
            if small:
                host_result.evtx_dropped["under_one_chunk"] = [f.name for f in small]
            dropped = _find_artifact_status(status_hosts, host_idx, "evtx")
            if dropped is not None:
                dropped.update(host_result.evtx_dropped)

            if evtx_files:
                index_name = wc.index_name("evtx")
                existing = _safe_count(client, index_name, ctx.unit)
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
                    params = {"hostname": host.hostname, "index_name": index_name,
                              "run_id": run_id}  # fmt: skip
                    aid = ""
                    try:
                        aid, file_hash = ops.read_step(
                            audit, "ingest_evtx", evtx_file, case_dir=case_dir, params=params
                        )
                        from opensearch_mcp.paths import relative_evidence_path

                        rel_path = relative_evidence_path(evtx_file, host.volume_root)
                        cut = "; ".join(evtx_truncation(evtx_file))
                        if cut:  # its readable records are still indexed below
                            truncated = host_result.evtx_dropped.setdefault("truncated", [])
                            truncated.append(f"{evtx_file.name}: {cut}")
                            if evtx_status:
                                evtx_status["truncated"] = truncated
                        with wc.op(aid):
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
                                host_dict=host_dict,
                            )
                        ar.indexed += cnt
                        ar.skipped += sk
                        ar.bulk_failed += bf
                        ar.source_files.append(str(evtx_file))
                        _write_ingest_manifest(
                            str(evtx_file),
                            host.hostname,
                            "evtx",
                            sha256=file_hash,
                            doc_count=cnt,
                        )
                        ops.later(
                            audit,
                            aid,
                            "ingest_evtx",
                            f"{cnt} indexed, {sk} skipped"
                            + (f", truncated: {cut}" if cut else "")
                            + (f", {bf} bulk failed" if bf else ""),
                            {**params, "file": str(evtx_file), "bulk_failed": bf},
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
                        if aid:  # one that failed before its step: read_step recorded it
                            ops.later(audit, aid, "ingest_evtx", f"FAILED: {e}",
                                      {**params, "file": str(evtx_file)})  # fmt: skip

                if evtx_status:
                    evtx_status["status"] = "failed" if ar.error else "complete"
                    evtx_status["indexed"] = ar.indexed
                    if ar.error:  # the status names what failed, not "unknown error"
                        evtx_status["error"] = ar.error
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
                if tool_name == "plaso":
                    _ingest_plaso_volume(
                        client=client,
                        audit=audit,
                        case_id=case_id,
                        host=host,
                        host_idx=host_idx,
                        host_result=host_result,
                        status_hosts=status_hosts,
                        _progress=_progress,
                        _update_status=_update_status,
                        run_id=run_id,
                        host_dict=host_dict,
                        case_dir=case_dir,
                    )
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
                    run_id=run_id,
                    host_dict=host_dict,
                    case_dir=case_dir,
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
                    run_id=run_id,
                    host_dict=host_dict,
                    case_dir=case_dir,
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
            index_name = wc.index_name(cfg.index_suffix)
            existing = _safe_count(client, index_name, wc.current().unit)

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

            unread: list[str] = []
            hives: list[str] = []
            params = {"hostname": host.hostname, "tool": tool_name, "index_name": index_name,
                      "run_id": run_id}  # fmt: skip
            aid = ""
            try:
                # RECmd reads the whole config folder: the folder is what the step reads
                read = artifact_path.parent if tool_name == "registry" else artifact_path
                aid, file_hash = ops.read_step(
                    audit, f"ingest_{tool_name}", read, case_dir=case_dir, params=params
                )
                from opensearch_mcp.paths import relative_evidence_path

                # RECmd reads the whole config folder; each row then names its own hive
                _rel_src = relative_evidence_path(
                    artifact_path.parent if tool_name == "registry" else artifact_path,
                    host.volume_root,
                )
                collided: dict = {}
                seen = id_seen.setdefault(index_name, {}) if cfg.index_suffix in shared else None
                with wc.op(aid):
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
                        host_dict=host_dict,
                        not_read=unread,
                        hives_read=hives,
                        seen=seen,
                        collided=collided,
                    )
                # The audit lists every hive RECmd read, each with its hash
                inputs = hives or [str(artifact_path)]
                hashes = [_sha256_or_empty(Path(p)) for p in hives] if hives else []
                if not hives and file_hash:
                    hashes = [file_hash]
                replaced = [
                    f"{n} {_row_label(artifact_name)} rows from {loser} are identical to "
                    f"rows from {winner} (a later file in this run) and are stored once, "
                    f"under the last file that has them; a search for {loser} won't find them"
                    for (loser, winner), n in sorted(collided.items())
                ]
                ar.indexed = cnt
                ar.not_read = unread
                ar.skipped = sk
                ar.bulk_failed = bf
                _write_ingest_manifest(
                    str(artifact_path),
                    host.hostname,
                    tool_name,
                    sha256=file_hash,
                    doc_count=cnt,
                )
                ops.later(
                    audit,
                    aid,
                    f"ingest_{tool_name}",
                    f"{cnt} indexed"
                    + (f", {len(unread)} not read" if unread else "")
                    + (f", {sk} skipped" if sk else "")
                    + (f", {bf} bulk failed" if bf else "")
                    + "".join(f"; {r}" for r in replaced),
                    {**params, "file": str(artifact_path), "bulk_failed": bf},
                    # every hive RECmd read, each with its hash and place
                    inputs=[{**ops.place(p), "sha256": h} for p, h in zip(inputs, hashes)]
                    if hives
                    else None,
                )
                if tool_status:
                    tool_status["status"] = "failed" if "error" in tool_status else "complete"
                    tool_status["indexed"] = tool_status.get("indexed", 0) + cnt
                    tool_status["skipped"] = sk
                    tool_status["bulk_failed"] = tool_status.get("bulk_failed", 0) + bf
                    if unread:
                        tool_status.setdefault("not_read", []).extend(unread)
                    if replaced:  # appended, never replacing a note already there
                        tool_status["note"] = "; ".join(
                            filter(None, [tool_status.get("note"), *replaced])
                        )
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
                ar.not_read = unread
                if aid:  # one that failed before its step: read_step recorded it
                    ops.later(
                        audit,
                        aid,
                        f"ingest_{tool_name}",
                        f"FAILED: {e}" + (f", {len(unread)} not read" if unread else ""),
                        params,
                    )
                if tool_status:
                    tool_status["status"] = "failed"
                    tool_status["error"] = str(e)
                    if unread:
                        tool_status.setdefault("not_read", []).extend(unread)
                    _update_status()
                _progress(
                    "artifact_failed",
                    hostname=host.hostname,
                    artifact=tool_name,
                    error=str(e),
                )

            host_result.artifacts.append(ar)

        _add_second_copy_notes(host, host_idx, host_result, status_hosts)
        _check_volume_still_there(
            host, device, host_idx, host_result, status_hosts, _update_status
        )
        result.hosts.append(host_result)


def _ingest_plaso_volume(
    client: OpenSearch,
    audit: AuditWriter,
    case_id: str,
    host: DiscoveredHost,
    host_idx: int,
    host_result: HostResult,
    status_hosts: list[dict],
    _progress,
    _update_status,
    run_id: str = "",
    host_dict=None,
    case_dir=None,
) -> None:
    """A host's Plaso runs (the OS preset on Linux and macOS, the narrow set
    on Windows) into case-<id>-plaso-<host>. Each run's work folder is under
    the case's tmp and removed after indexing. A failed run fails the
    artifact and indexes nothing; the others' events are kept."""
    import shutil
    import tempfile

    from opensearch_mcp.discover import EXAMINER_ZONE, _valid_zone
    from opensearch_mcp.parse_plaso import (
        _ingest_jsonl,
        can_sudo,
        plaso_runs,
        plaso_status,
        run_plaso_volume,
    )
    from opensearch_mcp.paths import vhir_dir

    index_name = wc.index_name("plaso")
    ar = ArtifactResult(
        artifact="plaso",
        index=index_name,
        existing_before=_safe_count(client, index_name, wc.current().unit),
        source_files=[str(host.volume_root)],
    )
    tool_status = _find_artifact_status(status_hosts, host_idx, "plaso")
    if tool_status:
        tool_status["status"] = "running"
        _update_status()
    _progress("artifact_start", hostname=host.hostname, artifact="plaso")
    runs, run_note = plaso_runs(host)
    image = host.image_path is not None  # read off the image: no root
    # Off an image, Plaso applies each volume's own zone, unless the examiner
    # gave --source-timezone, which wins for every host.
    override = host.timezone_source == EXAMINER_ZONE
    zone = None if image and not override else _valid_zone(host.system_timezone)
    zone_note = "" if override and not image else host.zone_note
    # Linux and macOS: root's read capability when sudo is there, so files
    # only root can read (auth.log, /root) are parsed; else the examiner.
    read_as_root = not image and host.os != "windows" and can_sudo()
    run_kw = {"extra": tuple(host.image_args)} if image else {}
    notes = [run_note] if run_note else []
    if not image and not read_as_root and host.os != "windows":
        notes.append("read as the examiner: files it can't read are listed as not read")
    errors: list[str] = []
    base = vhir_dir() / "cases" / case_id / "tmp"
    base.mkdir(parents=True, exist_ok=True)
    params = {"hostname": host.hostname, "tool": "plaso", "index_name": index_name,
              "run_id": run_id}  # fmt: skip
    for parsers, source in runs:
        workdir = Path(tempfile.mkdtemp(prefix=f"plaso-{host.hostname}-", dir=base))
        aid = ""
        try:
            jsonl, pinfo = run_plaso_volume(parsers, source, workdir, read_as_root, zone, **run_kw)
            # one step per Plaso run: what it read and the JSONL it wrote,
            # recorded before the JSONL's records are indexed
            src_in, src_reg = ops.file_input(case_dir, source)
            aid = ops.write(
                audit,
                "ingest_plaso",
                params={**params, "parsers": parsers, "source": str(source)},
                summary="recorded before its records were indexed",
                inputs=[src_in],
                input_registered=[src_reg] if src_reg else None,
                outputs=[ops.output(jsonl)],
            )
            if not aid:
                raise RuntimeError(NO_ENTRY)
            with wc.op(aid):
                cnt, bf = _ingest_jsonl(
                    jsonl,
                    client,
                    index_name,
                    host.hostname,
                    ingest_audit_id=aid,
                    pipeline_version=_PIPELINE_VERSION,
                    vss_id=host.vss_id,
                    host_dict=host_dict,
                    volume_root=None if image else host.volume_root,
                    volume=host.volume_label if image else None,
                )
            ar.indexed += cnt
            ar.bulk_failed += bf
            unread, note = plaso_status(
                pinfo, host.volume_root, host.os, zone, host.timezone_source, zone_note
            )
            ar.not_read += unread
            notes.append(note)
            ops.later(
                audit,
                aid,
                "ingest_plaso",
                f"{cnt} indexed"
                + (f", {len(unread)} not read" if unread else "")
                + (f", {bf} bulk failed" if bf else ""),
                params,
            )
        except Exception as e:
            errors.append(f"{parsers} over {source}: {e}")
            failed = {**params, "parsers": parsers, "source": str(source)}
            if aid:
                ops.later(audit, aid, "ingest_plaso", f"FAILED: {e}", failed)
            else:  # it failed before its step was recorded: the failure is its entry
                ops.write(audit, "ingest_plaso", params=failed, summary=f"FAILED: {e}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    ar.note = "; ".join(dict.fromkeys(notes))
    ar.error = "\n".join(errors)
    if tool_status:
        tool_status["status"] = "failed" if errors else "complete"
        tool_status["indexed"] = ar.indexed
        tool_status["bulk_failed"] = ar.bulk_failed
        if ar.note:
            tool_status["note"] = ar.note
        if ar.not_read:
            tool_status["not_read"] = ar.not_read
        if errors:
            tool_status["error"] = ar.error
        _update_status()
    if errors:
        _progress("artifact_failed", hostname=host.hostname, artifact="plaso", error=ar.error)
    else:
        _progress(
            "artifact_done",
            hostname=host.hostname,
            artifact="plaso",
            indexed=ar.indexed,
            skipped=0,
        )
    host_result.artifacts.append(ar)


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
    run_id: str = "",
    host_dict=None,
    case_dir=None,
) -> None:
    """Ingest a prefetch or SRUM artifact (wintools-first, Plaso fallback)."""
    from opensearch_mcp.parse_prefetch import parse_prefetch
    from opensearch_mcp.parse_srum import parse_srum

    index_name = wc.index_name(tool_name)
    existing = _safe_count(client, index_name, wc.current().unit)
    params = {"hostname": host.hostname, "tool": tool_name, "index_name": index_name,
              "run_id": run_id}  # fmt: skip

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
        # the parser records each file its records come from: the tool's CSV
        # (with the staging and wintools steps that made it) or Plaso's JSONL
        with ops.recording(audit, case_dir, f"ingest_{tool_name}", params):
            if tool_name == "prefetch":
                cnt, bf, _note, outcome, rows = parse_prefetch(
                    prefetch_dir=artifact_path,
                    client=client,
                    index_name=index_name,
                    hostname=host.hostname,
                    pipeline_version=_PIPELINE_VERSION,
                    vss_id=host.vss_id,
                    source_file=_plaso_src,
                    host_dict=host_dict,
                )
            else:
                cnt, bf, _note, outcome, rows = parse_srum(
                    srum_path=artifact_path,
                    client=client,
                    index_name=index_name,
                    hostname=host.hostname,
                    case_id=case_id,
                    pipeline_version=_PIPELINE_VERSION,
                    vss_id=host.vss_id,
                    source_file=_plaso_src,
                    host_dict=host_dict,
                )
        # The parser's final attempt decides: it failed, or it produced no
        # rows from inputs that are there (Plaso exits 0 on a damaged file,
        # and its errors return 0). Its rows count records already in the
        # case (a shadow copy's, all on live); an earlier attempt's never do.
        from opensearch_mcp.results import PARSER_FAILED

        if outcome == PARSER_FAILED or not rows:
            if artifact_path.is_dir():
                n = sum(1 for f in artifact_path.iterdir() if f.suffix.lower() == ".pf")
                what = f"{n} .pf file(s)"
            else:
                n, what = 1, artifact_path.name
            if n:
                raise RuntimeError(
                    f"no records read from {what}: damaged or unreadable, or the parser "
                    "failed (see the ingest log); nothing from them was indexed"
                )
        ar.indexed = cnt
        ar.bulk_failed = bf
        if _note:
            ar.note = _note
        _write_ingest_manifest(str(artifact_path), host.hostname, tool_name, doc_count=cnt)
        ops.write(
            audit,
            f"ingest_{tool_name}",
            params={**params, "path": str(artifact_path), "bulk_failed": bf},
            summary=f"{cnt} indexed" + (f", {bf} bulk failed" if bf else ""),
        )
        if bf:  # records OpenSearch rejected: the artifact is incomplete
            from opensearch_mcp.bulk import get_last_bulk_reason

            reason = get_last_bulk_reason()
            ar.error = f"{bf:,} of {cnt + bf:,} records rejected by OpenSearch" + (
                f" ({reason[:200]})" if reason else ""
            )
        if tool_status:
            tool_status["status"] = "failed" if ar.error else "complete"
            tool_status["indexed"] = cnt
            tool_status["bulk_failed"] = bf
            if ar.error:
                tool_status["error"] = ar.error
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
        ops.write(
            audit,
            f"ingest_{tool_name}",
            params={**params, "path": str(artifact_path)},
            summary=f"FAILED: {e}",
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
    run_id: str = "",
    host_dict=None,
    case_dir=None,
) -> None:
    """Ingest a custom-parsed artifact (transcripts, defender, IIS, etc.)."""
    index_name = wc.index_name(tool_name)
    existing = _safe_count(client, index_name, wc.current().unit)
    params = {"hostname": host.hostname, "tool": tool_name, "index_name": index_name,
              "run_id": run_id}  # fmt: skip

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
        notes: list[str] = []
        # each file the parser reads is its own step, before its records
        with ops.recording(audit, case_dir, f"ingest_{tool_name}", params):
            cnt, sk, bf = _run_custom_parser(
                tool_name,
                artifact_path,
                client,
                index_name,
                host,
                "",
                time_from,
                time_to,
                host_dict=host_dict,
                notes=notes,
            )
        ar.indexed = cnt
        ar.skipped = sk
        ar.bulk_failed = bf
        note = "; ".join(notes)
        if note:  # appended, never replacing a note already there
            ar.note = "; ".join(filter(None, [ar.note, note]))
            print(f"  {host.hostname}: {tool_name}: {note}", file=sys.stderr)
        _write_ingest_manifest(str(artifact_path), host.hostname, tool_name, doc_count=cnt)
        ops.write(
            audit,
            f"ingest_{tool_name}",
            params={**params, "path": str(artifact_path), "bulk_failed": bf},
            summary=f"{cnt} indexed"
            + (f", {sk} skipped" if sk else "")
            + (f", {bf} bulk failed" if bf else "")
            + (f"; {note}" if note else ""),
        )
        if tool_status:
            if note:
                tool_status["note"] = "; ".join(filter(None, [tool_status.get("note"), note]))
            tool_status["status"] = "failed" if "error" in tool_status else "complete"
            tool_status["indexed"] = tool_status.get("indexed", 0) + cnt
            tool_status["bulk_failed"] = tool_status.get("bulk_failed", 0) + bf
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
        ops.write(
            audit,
            f"ingest_{tool_name}",
            params={**params, "path": str(artifact_path)},
            summary=f"FAILED: {e}",
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
    tool_name,
    artifact_path,
    client,
    index_name,
    host,
    aid,
    time_from,
    time_to,
    host_dict=None,
    notes: list[str] | None = None,
):
    """Dispatch to the correct custom parser. Returns (indexed, skipped, bulk_failed).

    A parser that has something to report (tasks) appends it to `notes`.
    """
    from opensearch_mcp.paths import relative_evidence_path

    kw: dict = {
        "client": client,
        "index_name": index_name,
        "hostname": host.hostname,
        "ingest_audit_id": aid,
        "pipeline_version": _PIPELINE_VERSION,
        "host_dict": host_dict,
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
            with ops.step(log_file) as sid:
                c, s, b = parse_w3c_log(
                    log_file,
                    **{**kw, "ingest_audit_id": sid},
                    timestamp_is_utc=True,
                    time_from=time_from,
                    time_to=time_to,
                    source_file=relative_evidence_path(log_file, vr),
                    parse_method="iis-w3c",
                )
            cnt += c
            sk += s
            bf += b
        return cnt, sk, bf

    if tool_name == "httperr":
        from opensearch_mcp.parse_w3c import parse_w3c_log

        cnt = sk = bf = 0
        for log_file in sorted(artifact_path.rglob("httperr*.log")):
            with ops.step(log_file) as sid:
                c, s, b = parse_w3c_log(
                    log_file,
                    **{**kw, "ingest_audit_id": sid},
                    timestamp_is_utc=True,
                    time_from=time_from,
                    time_to=time_to,
                    source_file=relative_evidence_path(log_file, vr),
                    parse_method="httperr-w3c",
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
            notes=notes,
            **kw,
        )

    if tool_name == "wer":
        from opensearch_mcp.parse_wer import parse_wer_dir

        return parse_wer_dir(wer_dir=artifact_path, volume_root=vr, **kw)

    if tool_name == "firewall":
        from opensearch_mcp.parse_w3c import parse_w3c_log

        with ops.step(artifact_path) as sid:
            return parse_w3c_log(
                artifact_path,
                **{**kw, "ingest_audit_id": sid},
                timestamp_is_utc=False,
                system_timezone=host.system_timezone,
                time_from=time_from,
                time_to=time_to,
                source_file=relative_evidence_path(artifact_path, vr),
                parse_method="firewall-w3c",
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


def _add_second_copy_notes(host, host_idx, host_result, status_hosts) -> None:
    """In a case from before 0.7: say on each artifact of the host that
    already had pre-0.7 data of its type that this ingest added a second copy.
    In any case: say how many reserved identity fields its evidence carried."""
    for ar in host_result.artifacts:
        ctx = getattr(host, "write_ctx", None)
        atype, c12 = wc.artifact_type_of(ar.index or ""), ctx.c12 if ctx else ""
        notes = (
            wc.second_copy_note(host.hostname, atype, c12),
            wc.removed_note(host.hostname, atype, c12) if atype else "",
        )
        note = "; ".join(n for n in notes if n)
        if not note:
            continue
        ar.note = "; ".join(n for n in (ar.note, note) if n)
        entry = _find_artifact_status(status_hosts, host_idx, ar.artifact)
        if entry is not None:
            entry["note"] = "; ".join(n for n in (entry.get("note"), note) if n)


def _safe_count(client: OpenSearch, index_name: str, unit: str = "") -> int:
    """Documents in `index_name`; with `unit`, only that evidence unit's."""
    try:
        if unit:
            body = {"query": {"term": {"vhir.unit": unit}}}
            r = client.count(index=index_name, body=body)
        else:
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


def _device(path) -> int | None:
    """The device a path is on, or None when it isn't there. A device, not an
    inode: FUSE and some network mounts don't keep inode numbers stable."""
    try:
        return os.stat(path).st_dev
    except OSError:
        return None


def _check_volume_still_there(host, device, host_idx, host_result, status_hosts, update) -> None:
    """A volume root gone when the host started (a volume several hosts share,
    lost during an earlier one), or gone or on another device once its
    artifacts are done (unmounted mid-ingest): the host gets a failed
    `evidence` row, in the status file and its results, as what was read
    after it went is missing."""
    now = _device(host.volume_root)
    if device is not None and now == device:
        return
    if device is None:
        gone = "was gone when this host's ingest started"
    else:
        gone = "is gone" if now is None else "is now on another device"
    error = (
        f"the evidence volume at {host.volume_root} {gone} (unmounted during the "
        "ingest?): artifacts read after that are missing or incomplete. Re-run the "
        "ingest once it is mounted again"
    )
    host_result.artifacts.append(ArtifactResult(artifact="evidence", index="", error=error))
    if host_idx < len(status_hosts):
        status_hosts[host_idx].setdefault("artifacts", []).append(
            {"name": "evidence", "status": "failed", "error": error}
        )
        update()


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
    total_bulk_failed = 0
    artifacts_complete = 0
    artifacts_total = 0
    hosts_complete = 0

    for h in status_hosts:
        host_done = True
        for a in h.get("artifacts", []):
            artifacts_total += 1
            total_indexed += a.get("indexed", 0)
            total_bulk_failed += a.get("bulk_failed", 0)
            if a.get("status") in ("complete", "failed"):
                artifacts_complete += 1
            else:
                host_done = False
        if host_done and h.get("artifacts"):
            hosts_complete += 1

    return {
        "indexed": total_indexed,
        "bulk_failed": total_bulk_failed,
        "hosts_complete": hosts_complete,
        "hosts_total": len(status_hosts),
        "artifacts_complete": artifacts_complete,
        "artifacts_total": artifacts_total,
    }
