"""CLI for ingesting forensic evidence into OpenSearch."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sift_common.audit import AuditWriter

from opensearch_mcp.client import get_client
from opensearch_mcp.ingest import discover, ingest
from opensearch_mcp.ingest_status import write_status
from opensearch_mcp.manifest import sha256_file
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import vhir_dir
from opensearch_mcp.tools import TOOLS

_ACTIVE_CASE_FILE = vhir_dir() / "active_case"


def _case_dir_for(case_id: str) -> Path | None:
    """Resolve the on-disk case directory for `case_id`.

    Prefers `VHIR_CASES_DIR` env, falls back to `~/cases/`. Returns None
    if the directory doesn't exist — callers (batch-discovery) treat
    that as "no dict available, proceed with current behavior" rather
    than aborting.
    """
    cases_root = Path(os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases")))
    case_dir = cases_root / case_id
    return case_dir if case_dir.is_dir() else None


def _load_case_host_dict(case_id: str):
    """Load `<case>/host-dictionary.yaml` if it exists. Returns None if
    the case dir or file is absent — which keeps pre-C1 cases working
    (no dict = no fail-loud binding; status quo).
    """
    case_dir = _case_dir_for(case_id)
    if case_dir is None:
        return None
    path = case_dir / "host-dictionary.yaml"
    if not path.exists():
        return None
    try:
        from opensearch_mcp.host_dictionary import HostDictionary

        return HostDictionary.load(path)
    except Exception as e:
        print(
            f"Warning: could not load {path}: {e}; proceeding without host-dictionary validation.",
            file=sys.stderr,
        )
        return None


def _preflight_shard_capacity(
    client,
    ingest_type: str,
    host_count: int = 1,
    case_id: str = "",
    run_id: str = "",
) -> None:
    """Refuse to start ingest if cluster shard capacity is exhausted.

    On refusal, writes a terminal status file via write_status with the
    error field prefixed by HALT_SHARD_CAPACITY so portal /
    idx_ingest_status can startswith()-render the halt reason. Calls
    sys.exit(1) after. Fail-open on stats-query errors (handled inside
    check_shard_headroom).

    Template installation is handled at MCP server boot
    (server._get_os) and must run before ingest — no install performed
    here.
    """
    from opensearch_mcp.ingest_status import HALT_SHARD_CAPACITY
    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    ok, reason = check_shard_headroom(
        client,
        expected_new_shards=_estimate_new_shards(ingest_type, host_count=host_count),
        min_headroom_pct=10.0,
    )
    if not ok:
        if case_id:
            write_status(
                case_id=case_id,
                pid=os.getpid(),
                run_id=run_id,
                status="failed",
                hosts=[],
                totals={},
                started=datetime.now(timezone.utc).isoformat(),
                error=f"{HALT_SHARD_CAPACITY}: {reason}",
            )
        print(f"ABORT: {reason}", file=sys.stderr)
        sys.exit(1)


def _write_bg_status(
    case_id,
    run_id,
    status,
    hostname,
    artifact_name,
    started,
    elapsed=0.0,
    indexed=0,
    files_done=0,
    files_total=0,
    error="",
):
    """Write status for background ingest (delimited/json/accesslog/enrich).

    UAT 2026-04-23 follow-up: `status` is now passed through verbatim
    instead of being coerced to "complete"/"running". Callers can pass
    "failed" and populate `error` so the terminal failure record lands
    in the status file with the real exception text — previously the
    except-path in cmd_enrich_intel landed as a "running" record and
    the excepthook guard later rewrote it as
    "failed: process_died_unexpectedly: …" which misrepresented a
    caught exception as an uncaught crash.
    """
    from opensearch_mcp.bulk import get_last_bulk_reason

    art = {"name": artifact_name, "status": status, "indexed": indexed}
    if files_total:
        art["files_total"] = files_total
    if files_done:
        art["files_done"] = files_done
    done = 1 if status == "complete" else 0
    write_status(
        case_id=case_id,
        pid=os.getpid(),
        run_id=run_id,
        status=status,
        hosts=[{"hostname": hostname, "artifacts": [art]}],
        totals={
            "indexed": indexed,
            "artifacts_complete": done,
            "artifacts_total": 1,
            "hosts_total": 1,
            "hosts_complete": done,
        },
        started=started,
        error=error,
        elapsed_seconds=elapsed,
        bulk_failed_reason=get_last_bulk_reason(),
    )


_VHIR_CONFIG = vhir_dir() / "config.yaml"


def _resolve_case_id(args_case: str | None) -> str:
    if args_case:
        # Canonical case directory resolution matches aiir/vhir_cli:
        # $VHIR_CASES_DIR (env) or ~/cases/. Previously hard-coded to
        # ~/.vhir/cases/ which is the wrong path — caused a false
        # "Case not found in case system" warning on every CLI ingest
        # against the real cases root.
        cases_root = Path(os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases")))
        case_dir = cases_root / args_case
        # Suppress warning in background mode (parent already validated)
        if not case_dir.is_dir() and not os.environ.get("VHIR_INGEST_RUN_ID"):
            print(
                f"Warning: Case '{args_case}' not found in case system. "
                f"Ingesting with '{args_case}' as index prefix.",
                file=sys.stderr,
            )
        return args_case
    if _ACTIVE_CASE_FILE.exists():
        raw = _ACTIVE_CASE_FILE.read_text().strip()
        if raw:
            return Path(raw).name
    print("Error: No case ID. Use --case or run 'vhir case init' first.", file=sys.stderr)
    sys.exit(1)


def _ensure_case_active(case_id: str) -> None:
    """Ensure the case is active and SMB share is configured.

    Tries gateway case_activate first (handles SMB + wintools).
    Falls back to setting active_case file + inline SMB repoint.
    """
    active_case = vhir_dir() / "active_case"
    if active_case.exists():
        current = Path(active_case.read_text().strip()).name
        if current == case_id:
            return

    # Try gateway (handles SMB + wintools notification)
    try:
        from opensearch_mcp.gateway import call_tool

        call_tool("case_activate", {"case_id": case_id})
        return
    except Exception:
        pass

    # Fallback: set active_case file + try inline SMB repoint
    case_path = vhir_dir() / "cases" / case_id
    if case_path.is_dir():
        active_case.parent.mkdir(parents=True, exist_ok=True)
        active_case.write_text(str(case_path))
    _repoint_samba_if_configured(case_id)


def _repoint_samba_if_configured(case_id: str) -> None:
    """Repoint SMB [cases] share to the case directory. No-op if Samba not configured."""
    import os
    import subprocess

    samba_yaml = vhir_dir() / "samba.yaml"
    if not samba_yaml.is_file():
        return
    case_dir = vhir_dir() / "cases" / case_id
    if not case_dir.is_dir():
        return
    target = str(case_dir)
    doc = yaml.safe_load(samba_yaml.read_text()) or {}
    if doc.get("active_share_target") == target:
        return
    conf_path = "/etc/samba/smb.conf.d/vhir-cases.conf"
    username = doc.get("force_user", os.environ.get("USER", "sansforensics"))
    conf = (
        f"[cases]\n    path = {target}\n    valid users = vhir-smb\n"
        f"    read only = no\n    force user = {username}\n"
        f"    create mask = 0644\n    directory mask = 0755\n    browseable = yes\n"
    )
    try:
        Path(conf_path).write_text(conf)
        subprocess.run(["smbcontrol", "all", "reload-config"], capture_output=True)
    except PermissionError:
        subprocess.run(["sudo", "tee", conf_path], input=conf.encode(), capture_output=True)
        subprocess.run(["smbcontrol", "all", "reload-config"], capture_output=True)
    doc["active_share_target"] = target
    samba_yaml.write_text(yaml.dump(doc))


def _parse_date(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_set(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {v.strip().lower() for v in value.split(",")}


def _load_config(config_path: str | None) -> dict:
    """Load YAML config file if specified."""
    if not config_path:
        return {}
    p = Path(config_path)
    if not p.is_file():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    return yaml.safe_load(p.read_text()) or {}


def _sum_hayabusa_alerts(hb_results) -> int:
    """Sum per-host Hayabusa alert counts, tolerating failed-host dict values.

    `run_hayabusa_batch` (ingest.py:338) returns one of three shapes:

    1. `{"skipped": "hayabusa not installed"}` — caller-wide skip marker.
    2. `{hostname: <int>}` — happy path: per-host alert count.
    3. `{hostname: {"status": "failed", "error": "rules_not_found"}}` —
       per-host failure on missing rules (ingest.py:389-392).

    Any of the three can land in the dict simultaneously on a multi-host
    scan where some hosts succeed and others fail. Prior code summed
    `hb_results.values()` directly, which raised `TypeError` on mixed
    int+dict values and crashed `cmd_scan` *after* every parser had
    already completed — UAT 2026-04-24 B84. Filtering to `int` values
    treats per-host failures as zero-alert contributions rather than
    fatal.
    """
    if not isinstance(hb_results, dict) or "skipped" in hb_results:
        return 0
    return sum(v for v in hb_results.values() if isinstance(v, int))


def _merge_config(args: argparse.Namespace, config: dict) -> None:
    """Merge config file values into args (CLI takes precedence)."""
    if not config:
        return

    if not getattr(args, "include", None) and config.get("include"):
        args.include = ",".join(config["include"])
    if not getattr(args, "exclude", None) and config.get("exclude"):
        args.exclude = ",".join(config["exclude"])

    time_range = config.get("time_range", {})
    if not getattr(args, "time_from", None) and time_range.get("from"):
        args.time_from = str(time_range["from"])
    if not getattr(args, "time_to", None) and time_range.get("to"):
        args.time_to = str(time_range["to"])

    evtx_config = config.get("evtx", {})
    if not getattr(args, "reduced_ids", False) and evtx_config.get("reduced_ids"):
        args.reduced_ids = True
    if not getattr(args, "all_logs", False) and evtx_config.get("all_logs"):
        args.all_logs = True

    if not getattr(args, "password", None):
        # Prefer env var (set by server.py to avoid process list exposure)
        env_pw = os.environ.get("VHIR_ARCHIVE_PASSWORD", "")
        if env_pw:
            args.password = env_pw
        elif config.get("password"):
            args.password = config["password"]


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> None:
    """Scan a directory for artifacts, run EZ tools, index."""
    from opensearch_mcp.containers import (
        MountContext,
        cleanup_orphaned_mounts,
        cleanup_tmpdir,
        detect_container,
        extract_container,
        is_velociraptor_collection,
        make_ingest_tmpdir,
        mount_image,
        mount_vss,
        normalize_velociraptor,
        read_velociraptor_hostname,
    )

    input_path = Path(args.path)
    case_id = _resolve_case_id(getattr(args, "case", None))
    _ensure_case_active(case_id)

    # Load config file and merge
    config = _load_config(getattr(args, "config", None))
    _merge_config(args, config)

    time_from = _parse_date(args.time_from) if getattr(args, "time_from", None) else None
    time_to = _parse_date(args.time_to) if getattr(args, "time_to", None) else None
    include = _parse_set(getattr(args, "include", None))
    exclude = _parse_set(getattr(args, "exclude", None))
    hostname = getattr(args, "hostname", None)
    vss_flag = getattr(args, "vss", False)
    password = getattr(args, "password", None)
    tz_override = getattr(args, "source_timezone", None)
    if tz_override:
        from opensearch_mcp.paths import resolve_timezone

        resolved = resolve_timezone(tz_override)
        if resolved:
            tz_override = resolved
        else:
            print(
                f"WARNING: Unknown timezone '{tz_override}' — "
                f"local-time artifacts will be skipped",
                file=sys.stderr,
            )
            tz_override = None

    # Log file filter — ON by default, --all-logs disables
    reduced_log_names = None
    if not getattr(args, "all_logs", False):
        from opensearch_mcp.reduced import load_reduced_logs

        reduced_log_names = load_reduced_logs()
        print(f"Forensic logs mode: {len(reduced_log_names)} log types (use --all-logs for all)")

    # Event ID filter — OFF by default, --reduced-ids enables
    reduced_ids = None
    if getattr(args, "reduced_ids", False):
        from opensearch_mcp.reduced import load_reduced_ids

        reduced_ids = load_reduced_ids()
        print(f"Reduced IDs mode: {len(reduced_ids)} high-value Event IDs")

    # Detect container type and clean up orphaned mounts from prior failures
    container_type = detect_container(input_path)
    if container_type in ("ewf", "raw", "nbd", "archive"):
        cleanup_orphaned_mounts()
    mount_ctx = MountContext()
    tmpdir = None
    scan_root = input_path
    vss_volumes: list = []

    # Register cleanup for abnormal exit (OOM kill, unhandled exception)
    import atexit

    atexit.register(mount_ctx.cleanup)

    try:
        if container_type == "archive":
            tmpdir = make_ingest_tmpdir(case_id)
            print(f"Extracting {input_path.name}...")
            extract_container(input_path, tmpdir, password=password)

            # Check for Velociraptor offline collector
            if is_velociraptor_collection(tmpdir):
                print("Detected Velociraptor offline collector")
                if not hostname:
                    hostname = read_velociraptor_hostname(tmpdir)
                    if hostname:
                        print(f"  Hostname from collection: {hostname}")
                scan_root = normalize_velociraptor(tmpdir)
            else:
                # Check if extraction produced a disk image (e.g., VHDX.7z, E01.7z)
                _IMAGE_EXTS = {".vhdx", ".vhd", ".vmdk", ".e01", ".ex01", ".dd", ".raw", ".img"}
                extracted_images = [
                    f for f in tmpdir.iterdir() if f.is_file() and f.suffix.lower() in _IMAGE_EXTS
                ]
                if extracted_images:
                    img = extracted_images[0]
                    print(f"  Found disk image: {img.name}")
                    # Archive-basename stamp removed per host-identity spec
                    # (silent "admin01-triage" pollution). Registry detect
                    # against the mounted volume happens below after mount.
                    volumes = mount_image(img, tmpdir, mount_ctx)
                    if not volumes:
                        print(
                            "Error: No NTFS partitions in extracted image.",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    print(f"  Mounted {len(volumes)} volume(s)")

                    if vss_flag:
                        vss_volumes = mount_vss(img, tmpdir, mount_ctx)
                        if vss_volumes:
                            print(f"  Found {len(vss_volumes)} volume shadow copies")

                    # Priority-2 registry detect — reads ComputerName+Domain
                    # from the mounted volume's SYSTEM hive. Replaces the
                    # removed archive-basename fallback with a grounded
                    # source of truth. When it fails, warn the operator
                    # explicitly — control falls through to discover()
                    # which derives hostname from directory/mount names,
                    # a weaker signal that can still pollute host.name
                    # (silently-wrong of a different shape). C1 closes
                    # this via batch-discovery + host-unmapped.yaml.
                    if not hostname and volumes:
                        from opensearch_mcp.hostname import detect_hostname_from_volume

                        detected = detect_hostname_from_volume(volumes[0])
                        if detected:
                            hostname = detected
                            print(f"  Hostname from volume registry: {hostname}")
                        else:
                            print(
                                "  WARNING: could not detect hostname from registry; "
                                "falling back to directory-scan (weaker signal — "
                                "consider passing --hostname <canonical> explicitly)",
                                file=sys.stderr,
                            )

                scan_root = tmpdir

        elif container_type in ("ewf", "raw", "nbd"):
            tmpdir = make_ingest_tmpdir(case_id)
            print(f"Mounting {input_path.name}...")
            volumes = mount_image(input_path, tmpdir, mount_ctx)
            if not volumes:
                print("Error: No NTFS partitions found in disk image.", file=sys.stderr)
                sys.exit(1)
            print(f"  Mounted {len(volumes)} volume(s)")

            # Priority-2 registry detect on the mounted volume. Takes
            # precedence over the previous input_path.stem fallback so
            # disk images get the real ComputerName, not the filename.
            # Warn on miss — see the archive-path block above for why.
            if not hostname:
                from opensearch_mcp.hostname import detect_hostname_from_volume

                detected = detect_hostname_from_volume(volumes[0])
                if detected:
                    hostname = detected
                    print(f"  Hostname from volume registry: {hostname}")
                else:
                    print(
                        "  WARNING: could not detect hostname from registry; "
                        "falling back to directory-scan (weaker signal — "
                        "consider passing --hostname <canonical> explicitly)",
                        file=sys.stderr,
                    )

            # VSS handling
            if vss_flag:
                # Get the raw path for VSS scanning
                # For EWF: the ewf1 file under the FUSE mount
                # For raw/nbd: the original file or nbd device
                ewf_raw = tmpdir / "_ewf" / "ewf1"
                if ewf_raw.exists():
                    vss_raw = ewf_raw
                else:
                    vss_raw = input_path
                vss_volumes = mount_vss(vss_raw, tmpdir, mount_ctx)
                if vss_volumes:
                    print(f"  Found {len(vss_volumes)} volume shadow copies")
                else:
                    print("  No volume shadow copies found")

            scan_root = tmpdir

        elif container_type == "directory":
            scan_root = input_path
        elif container_type == "unknown" and input_path.is_dir():
            scan_root = input_path
        else:
            print(f"Error: Unsupported input: {input_path}", file=sys.stderr)
            sys.exit(1)

        # Discover hosts
        print("Scanning...")
        force_hn = container_type in ("ewf", "raw", "nbd") or (
            container_type == "archive" and hostname
        )
        hosts = discover(scan_root, hostname=hostname, force_hostname=force_hn)

        # --- Pre-classify peek (spec Rev 5 Fix C step 3 fallback) ---
        # When registry detect missed AND discover() produced hosts with
        # directory/mount-scan-derived names (junk like `_mnt_1` because
        # the scan_root happens to be the tmpdir), peek at the first
        # parseable CSV/JSON artifact to pull a real hostname from the
        # priority list. Feeds classify_host below with a meaningful raw
        # name so host-unmapped.yaml is actionable for the operator.
        if not hostname and hosts:
            from opensearch_mcp.hostname import peek_hostname_from_evidence

            peeked = peek_hostname_from_evidence(scan_root)
            if peeked:
                print(f"  Hostname from first parseable artifact: {peeked}")
                for h in hosts:
                    # Only overwrite directory/mount-scan-derived values;
                    # never stomp on anything discover() pulled from real
                    # per-host evidence subdirs.
                    if not h.hostname or h.hostname.startswith("_"):
                        h.hostname = peeked

        # --- Batch-discovery + fail-loud (spec Rev 5 Fix C Part 2) ---
        # Before any parser runs, classify every discovered host's name
        # against the case host-dictionary. If ANY host is unmapped:
        # collect the full set, write <case>/host-unmapped.yaml with
        # actionable `vhir case host add` commands, exit with a
        # structured hostname_unmapped error. Operator resolves all in
        # one pass, re-runs; the archive_resolved_unmapped_yaml call
        # below renames the file on the clean re-run.
        _host_dict = _load_case_host_dict(case_id)
        if _host_dict is not None and hosts:
            from opensearch_mcp.hostname import (
                archive_resolved_unmapped_yaml,
                classify_host,
                write_host_unmapped_yaml,
            )

            unmapped_entries: list[dict] = []
            now_iso = datetime.now(timezone.utc).isoformat()
            for h in hosts:
                status, raw, proposed, conf = classify_host(h.hostname, _host_dict)
                if status in ("unmapped-with-proposal", "unmapped-no-proposal"):
                    flag = f"--alias-of {proposed}" if proposed else "--new-canonical"
                    unmapped_entries.append(
                        {
                            "raw": raw,
                            "first_seen": now_iso,
                            "sources": [f"ingest:{input_path.name}"],
                            "proposed_canonical": proposed,
                            "confidence": conf,
                            "action_required": (f"vhir case host add {raw} {flag}"),
                        }
                    )

            case_dir = _case_dir_for(case_id)
            if unmapped_entries:
                if case_dir is not None:
                    yaml_path = write_host_unmapped_yaml(case_dir, unmapped_entries)
                    yaml_ref = str(yaml_path)
                else:
                    yaml_ref = "(case dir unavailable — see stderr entries below)"
                print(
                    "Error: hostname_unmapped — "
                    f"{len(unmapped_entries)} host(s) not in dictionary. "
                    f"See {yaml_ref}",
                    file=sys.stderr,
                )
                for e in unmapped_entries:
                    print(f"  - {e['raw']!r}: {e['action_required']}", file=sys.stderr)
                sys.exit(2)  # distinct from generic error (1) so scripts can route
            elif case_dir is not None:
                # All mapped — clean up any prior host-unmapped.yaml left
                # over from a previous failed ingest on the same case.
                archive_resolved_unmapped_yaml(case_dir)

        # For disk images with VSS, create additional hosts per shadow copy
        if vss_flag and container_type in ("ewf", "raw", "nbd") and tmpdir and vss_volumes:
            from opensearch_mcp.discover import (
                DiscoveredHost,
                discover_artifacts,
                find_volume_root,
            )

            # Tag the primary host(s) as "live"
            for h in hosts:
                if not h.vss_id:
                    h.vss_id = "live"

            # Use mount_vss return value directly (vss_id, mount_path)
            for v_id, vss_mp in vss_volumes:
                vr = find_volume_root(vss_mp)
                if vr is None:
                    continue
                base_hostname = hosts[0].hostname if hosts else (hostname or "unknown")
                vss_host = DiscoveredHost(hostname=base_hostname, volume_root=vr, vss_id=v_id)
                discover_artifacts(vss_host)
                if vss_host.artifacts or vss_host.evtx_dir:
                    hosts.append(vss_host)

        if not hosts:
            if not hostname:
                print(
                    "Error: No host directories found. Use --hostname for flat evidence dirs.",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"Error: No Windows artifacts found in {scan_root}", file=sys.stderr)
            sys.exit(1)

        # Show summary
        for host in hosts:
            artifact_names = sorted({a[0] for a in host.artifacts})
            evtx_note = ""
            if host.evtx_dir:
                evtx_count = sum(1 for f in host.evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
                evtx_note = f"{evtx_count} evtx, "
            arts = ", ".join(artifact_names)
            vss_tag = f" [{host.vss_id}]" if host.vss_id else ""
            print(f"  {host.hostname}{vss_tag}: {evtx_note}{arts}")

        # Apply --source-timezone override to all hosts (priority 1)
        if tz_override:
            print(f"  Source timezone: {tz_override}")
            for h in hosts:
                h.system_timezone = tz_override

        if not getattr(args, "yes", False):
            try:
                answer = input(f"\nIngest {len(hosts)} host(s)? [y/N] ")
                if answer.lower() not in ("y", "yes"):
                    print("Aborted.")
                    return
            except EOFError:
                print(
                    "Non-interactive mode. Use --yes to skip confirmation.",
                    file=sys.stderr,
                )
                sys.exit(1)

        # Ingest with status tracking
        import os
        import uuid

        run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or str(uuid.uuid4())

        client = get_client()
        _preflight_shard_capacity(
            client,
            "evtx",
            host_count=len(hosts) or 1,
            case_id=case_id,
            run_id=run_id,
        )

        audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")

        def _cli_progress(event: str, **kw) -> None:
            if event == "host_start":
                print(f"\n{kw['hostname']}:")
            elif event == "evtx_file":
                c = kw["count"]
                if c == 0:
                    return  # skip empty files silently
                fn = kw["filename"]
                n, t = kw["file_num"], kw["file_total"]
                print(f"  evtx [{n}/{t}] {fn}... {c:,} events")
            elif event == "evtx_done":
                idx = kw["indexed"]
                sk = kw.get("skipped", 0)
                bf = kw.get("bulk_failed", 0)
                parts = [f"{idx:,} total"]
                if sk:
                    parts.append(f"{sk} skipped")
                if bf:
                    parts.append(f"{bf} bulk failed")
                err = kw.get("error", "")
                if err:
                    parts.append(f"ERRORS: {err}")
                print(f"  evtx: {', '.join(parts)}")
            elif event == "artifact_start":
                print(f"  {kw['artifact']}...", end=" ", flush=True)
            elif event == "artifact_done":
                idx = kw["indexed"]
                sk = kw.get("skipped", 0)
                parts = [f"{idx:,} entries"]
                if sk:
                    parts.append(f"{sk} skipped")
                print(", ".join(parts))
            elif event == "artifact_failed":
                print(f"FAILED: {kw['error']}")

        from opensearch_mcp.bulk import ShardCapacityExhausted
        from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER

        try:
            result = ingest(
                hosts=hosts,
                client=client,
                audit=audit,
                case_id=case_id,
                status_pid=os.getpid(),
                status_run_id=run_id,
                include=include,
                exclude=exclude,
                full=getattr(args, "full", False),
                time_from=time_from,
                time_to=time_to,
                reduced_ids=reduced_ids,
                reduced_log_names=reduced_log_names,
                on_progress=_cli_progress,
            )
        except ShardCapacityExhausted as _sce:
            # Circuit-breaker trip mid-run. Write a terminal status so
            # idx_ingest_status surfaces the halt reason via the
            # error-prefix convention (replaces pre-0.6.2 halt-state
            # taxonomy; portal startswith()-renders the prefix).
            write_status(
                case_id=case_id,
                pid=os.getpid(),
                run_id=run_id,
                status="failed",
                hosts=[],
                totals={},
                started=datetime.now(timezone.utc).isoformat(),
                error=f"{HALT_CIRCUIT_BREAKER}: {_sce}",
            )
            print(f"ABORT: {HALT_CIRCUIT_BREAKER}: {_sce}", file=sys.stderr)
            raise

        # Summary
        errors = []
        total_bulk_failed = 0
        for h in result.hosts:
            for a in h.artifacts:
                if a.error:
                    errors.append(f"{h.hostname}/{a.artifact}: {a.error}")
                if a.bulk_failed:
                    total_bulk_failed += a.bulk_failed
                    errors.append(
                        f"{h.hostname}/{a.artifact}: {a.bulk_failed:,} events not indexed"
                    )
        minutes = result.elapsed_seconds / 60
        print(f"\nDone in {minutes:.1f} minutes. ", end="")
        print(f"{len(result.hosts)} host(s), {result.total_indexed:,} entries indexed.")
        if total_bulk_failed:
            # Primary action: presume loss until proven otherwise
            # (safer default — matches operator mental model that
            # "failed" means "re-run"). Secondary: offer the
            # verification path because some rejections are recoverable
            # via pipeline on_failure (e.g., Data.#text mapping
            # conflicts). Structural answer is Part 5 #17 (source vs
            # indexed count verification).
            print(
                f"\n*** {total_bulk_failed:,} events failed to index. ***"
                f"\n  Re-run ingest on the same evidence to recover"
                f" — dedup prevents duplicates."
                f"\n  To verify before re-running, run idx_search on"
                f" the expected timestamp range."
            )
        if errors:
            print(f"\n{len(errors)} issue(s):")
            for msg in errors:
                print(f"  {msg}")

        # Post-ingest Hayabusa detection
        if not getattr(args, "no_hayabusa", False):
            import shutil

            if shutil.which("hayabusa") and any(h.evtx_dir for h in hosts):
                # Layer 6: update status to show Hayabusa phase
                from opensearch_mcp.ingest import run_hayabusa_batch

                hayabusa_started = datetime.now(timezone.utc).isoformat()
                # BUG-4 fix: preserve full host/artifact checklist, append hayabusa
                existing_hosts = [
                    {
                        "hostname": h.hostname,
                        "artifacts": [
                            {
                                "name": a.artifact,
                                "status": "failed" if a.error else "complete",
                                "indexed": a.indexed,
                            }
                            for a in h.artifacts
                        ],
                    }
                    for h in result.hosts
                ]
                existing_hosts.append(
                    {
                        "hostname": "hayabusa",
                        "artifacts": [{"name": "hayabusa-detection", "status": "running"}],
                    }
                )
                n_arts = sum(len(h["artifacts"]) for h in existing_hosts)
                n_done = sum(
                    1 for h in existing_hosts for a in h["artifacts"] if a["status"] == "complete"
                )
                write_status(
                    case_id,
                    os.getpid(),
                    run_id,
                    "running",
                    existing_hosts,
                    {
                        "indexed": result.total_indexed,
                        "artifacts_total": n_arts,
                        "artifacts_complete": n_done,
                        "hosts_total": len(existing_hosts),
                        "hosts_complete": sum(
                            1
                            for h in existing_hosts
                            if all(a["status"] == "complete" for a in h["artifacts"])
                        ),
                    },
                    hayabusa_started,
                    elapsed_seconds=result.elapsed_seconds,
                )

                def _hayabusa_progress(event, **kw):
                    if event == "hayabusa_start":
                        print(f"  hayabusa: {kw['hostname']}...", end=" ", flush=True)
                    elif event == "hayabusa_done":
                        print(f"{kw['count']:,} alerts")
                    elif event == "hayabusa_failed":
                        print(f"failed ({kw.get('error', 'unknown')})")

                print("\nRunning Hayabusa detection...")
                hb_results = run_hayabusa_batch(
                    hosts,
                    client,
                    case_id,
                    audit=audit,
                    on_progress=_hayabusa_progress,
                )
                total_alerts = _sum_hayabusa_alerts(hb_results)
                # Post-B84 visibility (UAT 2026-04-24): surface the
                # per-host failure count alongside indexed-total so
                # operators see that a partial-success summary actually
                # had failures, not the silent "N alerts" post-B84-guard
                # framing. Hayabusa failure dicts are values shaped
                # {"status": "failed", "error": "..."} per ingest.py:389.
                failed_hosts = (
                    sum(1 for v in hb_results.values() if isinstance(v, dict))
                    if isinstance(hb_results, dict)
                    else 0
                )
                if total_alerts or failed_hosts:
                    line = f"Hayabusa: {total_alerts:,} alerts indexed"
                    if failed_hosts:
                        noun = "host" if failed_hosts == 1 else "hosts"
                        line += f" ({failed_hosts} {noun} failed — see progress log)"
                    print(line)

                # Layer 6: update status after Hayabusa (preserve full checklist)
                existing_hosts[-1]["artifacts"][0].update(
                    {"status": "complete", "indexed": total_alerts}
                )
                write_status(
                    case_id,
                    os.getpid(),
                    run_id,
                    "complete",
                    existing_hosts,
                    {
                        "indexed": result.total_indexed + total_alerts,
                        "artifacts_total": n_arts,
                        "artifacts_complete": n_arts,
                        "hosts_total": len(existing_hosts),
                        "hosts_complete": len(existing_hosts),
                    },
                    hayabusa_started,
                    elapsed_seconds=result.elapsed_seconds,
                )

        # Post-ingest triage enrichment
        if not getattr(args, "skip_triage", False):
            try:
                print("\nRunning triage enrichment...")
                from opensearch_mcp.triage_remote import enrich_remote

                def _triage_progress(event, **kw):
                    if event == "triage_start":
                        print(
                            f"  {kw['artifact']}: checking {kw['unique_values']} unique values...",
                            end=" ",
                            flush=True,
                        )
                    elif event == "triage_done":
                        print(f"{kw['enriched']} enriched")

                triage_results = enrich_remote(
                    client=client, case_id=case_id, on_progress=_triage_progress
                )
                if "_gateway" in triage_results:
                    print(f"  Triage: {triage_results['_gateway']}")
                total_enriched = sum(
                    r.get("enriched", 0) for r in triage_results.values() if isinstance(r, dict)
                )
                print(f"Triage enrichment complete: {total_enriched} documents updated")
            except Exception as e:
                print(f"  Triage enrichment failed: {e}")

    finally:
        mount_ctx.cleanup()
        if tmpdir:
            cleanup_tmpdir(tmpdir)


# ---------------------------------------------------------------------------
# csv subcommand
# ---------------------------------------------------------------------------


def cmd_csv(args: argparse.Namespace) -> None:
    """Ingest a pre-parsed CSV (examiner identifies the tool)."""
    tool_name = args.tool_name
    csv_path = Path(args.csv_path)

    if tool_name not in TOOLS:
        valid = ", ".join(sorted(TOOLS))
        print(f"Error: Unknown tool '{tool_name}'. Valid: {valid}", file=sys.stderr)
        sys.exit(1)
    if not csv_path.is_file():
        print(f"Error: {csv_path} is not a file.", file=sys.stderr)
        sys.exit(1)

    hostname = args.hostname
    if not hostname:
        print("Error: --hostname is required for csv subcommand.", file=sys.stderr)
        sys.exit(1)

    case_id = _resolve_case_id(getattr(args, "case", None))
    from opensearch_mcp import __version__

    cfg = TOOLS[tool_name]
    from opensearch_mcp.paths import build_index_name as _build_idx

    index_name = _build_idx(case_id, cfg.index_suffix, hostname)

    client = get_client()
    audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
    pipeline_version = f"opensearch-mcp-{__version__}"

    file_hash = sha256_file(csv_path)
    aid = audit._next_audit_id()

    print(f"Ingesting {csv_path.name} as {tool_name} -> {index_name}")

    count, sk, bf = ingest_csv(
        csv_path=csv_path,
        client=client,
        index_name=index_name,
        hostname=hostname,
        source_file=str(csv_path),
        ingest_audit_id=aid,
        pipeline_version=pipeline_version,
        natural_key=cfg.natural_key,
        time_field=cfg.time_field,
    )

    audit.log(
        tool=f"idx_ingest_csv_{tool_name}",
        audit_id=aid,
        params={
            "hostname": hostname,
            "tool": tool_name,
            "file": str(csv_path),
            "bulk_failed": bf,
        },
        result_summary=f"{count} indexed"
        + (f", {sk} skipped" if sk else "")
        + (f", {bf} bulk failed" if bf else ""),
        input_files=[str(csv_path)],
        input_sha256s=[file_hash],
        source_evidence=str(csv_path),
    )

    print(f"Indexed {count:,} entries" + (f" ({sk} skipped)" if sk else ""))


# ---------------------------------------------------------------------------
# cmd_ingest — entry point for vhir plugin
# ---------------------------------------------------------------------------


def cmd_ingest(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Entry point for vhir plugin.

    Accepts pre-parsed args from vhir (unlike main() which parses its own).
    Delegates to cmd_scan with the right attribute mapping.
    """
    from opensearch_mcp.bulk import reset_circuit_breaker

    reset_circuit_breaker()
    # Ensure all expected attributes exist with defaults
    if not hasattr(args, "examiner"):
        args.examiner = examiner
    if not hasattr(args, "yes"):
        args.yes = False

    # If subcommand is csv, route there
    if hasattr(args, "subcommand") and args.subcommand == "csv":
        cmd_csv(args)
    else:
        cmd_scan(args)


# ---------------------------------------------------------------------------
# cmd_ingest_json — generic JSON/JSONL ingest
# ---------------------------------------------------------------------------


def cmd_ingest_json(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Ingest JSON/JSONL files."""
    from opensearch_mcp import __version__
    from opensearch_mcp.bulk import reset_circuit_breaker
    from opensearch_mcp.parse_json import ingest_json

    reset_circuit_breaker()

    input_path = Path(args.path)
    case_id = _resolve_case_id(getattr(args, "case", None))
    _ensure_case_active(case_id)
    hostname = args.hostname
    time_field = getattr(args, "time_field", None)
    time_from = _parse_date(args.time_from) if getattr(args, "time_from", None) else None
    time_to = _parse_date(args.time_to) if getattr(args, "time_to", None) else None
    batch_size = getattr(args, "batch_size", 1000)

    if getattr(args, "dry_run", False):
        print(f"Dry run: {input_path}")
        return

    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or None
    start_mono = time.monotonic()
    started_ts = datetime.now(timezone.utc).isoformat()

    client = get_client()
    _preflight_shard_capacity(client, "json", case_id=case_id, run_id=run_id or "")
    audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
    aid = audit._next_audit_id()

    files = (
        [input_path]
        if input_path.is_file()
        else sorted(
            f for f in input_path.iterdir() if f.suffix.lower() in (".json", ".jsonl", ".ndjson")
        )
    )

    # Silent-zero diagnostic (UAT 2026-04-24): when an operator points
    # the walker at a directory that yields zero matching files, the
    # result was `Done. 0 indexed, 0 skipped, 0 bulk failed.` with no
    # indication of WHY. Surface this explicitly — the walker is non-
    # recursive (one level only), so a deep tree like Velociraptor's
    # `datastore/clients/C.*/collections/F.*/` returns zero matches
    # when pointed at `datastore/`. Operator sees the reason without
    # having to re-read the docstring.
    if input_path.is_dir() and not files:
        subdirs = [d for d in input_path.iterdir() if d.is_dir()]
        total_entries = len(list(input_path.iterdir()))
        print(
            f"No .json/.jsonl/.ndjson files directly under {input_path} "
            f"(non-recursive walker: {total_entries} entries, "
            f"{len(subdirs)} subdirectories ignored). "
            "Point at a directory that contains JSON files directly, "
            "or ingest per-subdirectory.",
            file=sys.stderr,
        )

    if run_id:
        _write_bg_status(
            case_id,
            run_id,
            "running",
            hostname,
            "json",
            started_ts,
            files_total=len(files),
        )

    from opensearch_mcp.bulk import ShardCapacityExhausted
    from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER

    total = total_sk = total_bf = 0
    _json_failed_files: list[tuple[str, str]] = []
    try:
        for idx, f in enumerate(files):
            suffix = getattr(args, "index_suffix", None) or f"json-{f.stem}"
            if not suffix.startswith("json-"):
                suffix = f"json-{suffix}"
            from opensearch_mcp.paths import build_index_name as _build_idx_j

            index_name = _build_idx_j(case_id, suffix, hostname)
            print(f"  {f.name} -> {index_name}...", end=" ", flush=True)
            try:
                cnt, sk, bf, hr = ingest_json(
                    f,
                    client,
                    index_name,
                    hostname,
                    time_field=time_field,
                    source_file=str(f),
                    ingest_audit_id=aid,
                    pipeline_version=f"opensearch-mcp-{__version__}",
                    time_from=time_from,
                    time_to=time_to,
                    batch_size=batch_size,
                )
                print(f"{cnt:,} entries")
                if hr:
                    print(
                        "    NOTE: 'host' field renamed to 'source_host' "
                        "(conflicts with host.name)"
                    )
                total += cnt
                total_sk += sk
                total_bf += bf
            except ShardCapacityExhausted:
                # Re-raise so the outer circuit-breaker handler fires
                # — halting walk is the correct response to cluster
                # capacity exhaustion. `except Exception` below must
                # NOT swallow this.
                raise
            except Exception as e:  # noqa: BLE001 — per-file isolation (UAT 2026-04-22)
                # parse_json imports _doc_id from parse_csv; identical
                # TypeError crash class as delimited. Broad Exception
                # ensures JSONL files with pathological rows skip-and-
                # continue instead of aborting the walk.
                _json_failed_files.append((str(f), str(e)[:200]))
                print(f"skipped ({e})")
            if run_id:
                _write_bg_status(
                    case_id,
                    run_id,
                    "running",
                    hostname,
                    "json",
                    started_ts,
                    time.monotonic() - start_mono,
                    indexed=total,
                    files_done=idx + 1,
                    files_total=len(files),
                )
    except ShardCapacityExhausted as _sce:
        write_status(
            case_id=case_id,
            pid=os.getpid(),
            run_id=run_id or "",
            status="failed",
            hosts=[],
            totals={},
            started=datetime.now(timezone.utc).isoformat(),
            error=f"{HALT_CIRCUIT_BREAKER}: {_sce}",
        )
        print(f"ABORT: {HALT_CIRCUIT_BREAKER}: {_sce}", file=sys.stderr)
        raise

    print(f"Done. {total:,} indexed, {total_sk} skipped, {total_bf} bulk failed.")
    if _json_failed_files:
        print(f"*** {len(_json_failed_files)} files failed to parse; continuing walk: ***")
        for path, err in _json_failed_files[:10]:
            print(f"  {path}: {err}")
        if len(_json_failed_files) > 10:
            print(f"  ... and {len(_json_failed_files) - 10} more")
    audit.log(
        tool="idx_ingest_json",
        audit_id=aid,
        params={
            "path": str(input_path),
            "hostname": hostname,
            "bulk_failed": total_bf,
            "failed_files_count": len(_json_failed_files),
        },
        result_summary=f"{total} indexed"
        + (f", {total_bf} bulk failed" if total_bf else "")
        + (f", {len(_json_failed_files)} files skipped" if _json_failed_files else ""),
        input_files=[str(input_path)],
    )
    if run_id:
        final_status = "complete"
        if total_bf > 0 and total == 0:
            final_status = "failed"
        _write_bg_status(
            case_id,
            run_id,
            final_status,
            hostname,
            "json",
            started_ts,
            time.monotonic() - start_mono,
            indexed=total,
        )


# ---------------------------------------------------------------------------
# cmd_ingest_delimited — generic CSV/TSV/Zeek/bodyfile ingest
# ---------------------------------------------------------------------------


def cmd_ingest_delimited(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Ingest delimited files."""
    from opensearch_mcp import __version__
    from opensearch_mcp.bulk import reset_circuit_breaker

    reset_circuit_breaker()
    from opensearch_mcp.parse_delimited import ingest_delimited

    input_path = Path(args.path)
    case_id = _resolve_case_id(getattr(args, "case", None))
    _ensure_case_active(case_id)
    hostname = getattr(args, "hostname", "") or ""
    is_recursive = getattr(args, "recursive", False)
    auto_hosts_str = getattr(args, "auto_hosts", "") or ""

    if not hostname and not is_recursive and not auto_hosts_str:
        print(
            "Error: --hostname is required (or use --recursive / --auto-hosts).",
            file=sys.stderr,
        )
        sys.exit(1)

    # Hoisted so the recursive/auto_hosts wrappers below can write a
    # terminal "complete" status before returning. UAT 2026-04-23: Fix
    # 3.1's atexit guard otherwise stamps `failed:
    # process_died_unexpectedly` on clean no-op walks (empty subdirs
    # list or auto_hosts list) because no inner call ever wrote a
    # terminal status.
    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or None
    started_ts = datetime.now(timezone.utc).isoformat()

    # Auto-hosts mode: flat directory, iterate detected hostnames sequentially
    if auto_hosts_str and input_path.is_dir():
        import copy

        auto_hosts = [h.strip() for h in auto_hosts_str.split(",") if h.strip()]
        for h in auto_hosts:
            sub_args = copy.copy(args)
            sub_args.hostname = h
            sub_args.auto_hosts = ""
            print(f"\n--- Host: {h} ---")
            cmd_ingest_delimited(sub_args, examiner=examiner)
        # Wrapper writes complete unconditionally on loop exit; partial-
        # failure accounting is in inner calls' audit logs, not the
        # process-level status. Matches the non-recursive path's pattern
        # (writes "complete" even when _delim_failed_files is non-empty).
        if run_id:
            _write_bg_status(
                case_id,
                run_id,
                "complete",
                "(auto-hosts)",
                "delimited",
                started_ts,
            )
        return

    # Recursive mode: iterate subdirs as hosts in a single process
    if is_recursive and input_path.is_dir():
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        subdirs = sorted(
            d
            for d in input_path.iterdir()
            if d.is_dir()
            and not d.name.startswith(".")
            and any(f.suffix.lower() in exts for f in d.iterdir() if f.is_file())
        )
        import copy

        from opensearch_mcp.bulk import ShardCapacityExhausted as _SCE

        _failed_subdirs: list[tuple[str, str]] = []  # (path, error[:200])
        for d in subdirs:
            sub_args = copy.copy(args)
            sub_args.path = str(d)
            sub_args.hostname = d.name
            sub_args.recursive = False
            print(f"\n--- Host: {d.name} ---")
            try:
                cmd_ingest_delimited(sub_args, examiner=examiner)
            except _SCE:
                # Cluster capacity exhausted: halt the entire recursive
                # walk, not just the current subdir. Re-raise past the
                # except Exception below so the caller's halt-status
                # path runs.
                raise
            except Exception as e:  # noqa: BLE001 — subdir-level isolation
                # Subdir-level resilience (UAT 2026-04-22): a crash in
                # one subdir must not abort the walk across sibling
                # subdirs. Per-file isolation (fix inside the
                # non-recursive path) covers within-subdir crashes;
                # this wrapper covers subdir-level catastrophic failure.
                _failed_subdirs.append((str(d), str(e)[:200]))
                print(f"  SUBDIR SKIPPED ({d.name}): {e}", file=sys.stderr)
        if _failed_subdirs:
            print(f"\n*** {len(_failed_subdirs)} subdirs failed; walk continued: ***")
            for path, err in _failed_subdirs:
                print(f"  {path}: {err}")
        # Wrapper writes complete unconditionally on loop exit; partial-
        # failure accounting is in _failed_subdirs and inner audit logs,
        # not the process-level status. Matches the non-recursive path's
        # pattern (writes "complete" even when _delim_failed_files is
        # non-empty). This is also the defense against UAT 2026-04-23's
        # regression where an empty-subdirs walk exits without writing
        # any terminal status and the atexit guard mislabels it failed.
        if run_id:
            _write_bg_status(
                case_id,
                run_id,
                "complete",
                hostname or "(recursive)",
                "delimited",
                started_ts,
            )
        return
    time_field = getattr(args, "time_field", None)
    delimiter = getattr(args, "delimiter", None)
    format_override = getattr(args, "format", None)
    time_from = _parse_date(args.time_from) if getattr(args, "time_from", None) else None
    time_to = _parse_date(args.time_to) if getattr(args, "time_to", None) else None
    batch_size = getattr(args, "batch_size", 1000)

    if getattr(args, "dry_run", False):
        print(f"Dry run: {input_path}")
        return

    # run_id and started_ts were hoisted above the wrapper branches.
    start_mono = time.monotonic()

    client = get_client()
    _preflight_shard_capacity(client, "delimited", case_id=case_id, run_id=run_id or "")
    audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
    aid = audit._next_audit_id()

    exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
    files = (
        [input_path]
        if input_path.is_file()
        else sorted(f for f in input_path.iterdir() if f.suffix.lower() in exts)
    )

    from opensearch_mcp.parse_delimited import _detect_delimited_format

    if run_id:
        _write_bg_status(
            case_id,
            run_id,
            "running",
            hostname,
            "delimited",
            started_ts,
            files_total=len(files),
        )

    # Progress callback for intra-file updates on large single files
    def _on_progress(indexed_so_far):
        if run_id:
            _write_bg_status(
                case_id,
                run_id,
                "running",
                hostname,
                "delimited",
                started_ts,
                time.monotonic() - start_mono,
                indexed=indexed_so_far,
            )

    from opensearch_mcp.bulk import ShardCapacityExhausted
    from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER

    total = total_sk = total_bf = 0
    _delim_failed_files: list[tuple[str, str]] = []  # (path, error[:200])
    try:
        for idx, f in enumerate(files):
            fmt = {"format": format_override} if format_override else _detect_delimited_format(f)
            detected = fmt.get("format", "csv")
            user_suffix = getattr(args, "index_suffix", None)
            if user_suffix:
                suffix = user_suffix
                if not suffix.startswith(("delim-", "zeek-", "bodyfile-")):
                    suffix = f"delim-{suffix}"
            elif detected == "zeek":
                suffix = f"zeek-{f.stem}"
            elif detected == "bodyfile":
                suffix = f"bodyfile-{f.stem}"
            else:
                suffix = f"delim-{f.stem}"
            from opensearch_mcp.paths import build_index_name as _build_idx_d

            index_name = _build_idx_d(case_id, suffix, hostname)
            print(f"  {f.name} ({detected}) -> {index_name}...", end=" ", flush=True)
            if detected == "unknown":
                print("skipped (unrecognized format)")
                continue
            try:
                cnt, sk, bf, hr = ingest_delimited(
                    f,
                    client,
                    index_name,
                    hostname,
                    fmt=fmt,
                    delimiter=delimiter,
                    time_field=time_field,
                    source_file=str(f),
                    ingest_audit_id=aid,
                    pipeline_version=f"opensearch-mcp-{__version__}",
                    time_from=time_from,
                    time_to=time_to,
                    batch_size=batch_size,
                    on_progress=_on_progress if run_id else None,
                )
                print(f"{cnt:,} entries")
                if hr:
                    print("    NOTE: 'host' renamed to 'source_host' (conflicts with host.name)")
                total += cnt
                total_sk += sk
                total_bf += bf
                if run_id:
                    _write_bg_status(
                        case_id,
                        run_id,
                        "running",
                        hostname,
                        "delimited",
                        started_ts,
                        time.monotonic() - start_mono,
                        indexed=total,
                        files_done=idx + 1,
                        files_total=len(files),
                    )
            except ShardCapacityExhausted:
                # Re-raise so the outer circuit-breaker handler fires.
                # `except Exception` below must NOT swallow this; the
                # whole walk must halt when cluster capacity is gone.
                raise
            except Exception as e:  # noqa: BLE001 — per-file isolation
                # Walker resilience (UAT 2026-04-22): one bad file
                # must not abort the walk. TypeError from _doc_id on
                # prose-shaped content was the original crash; broad
                # Exception covers that class + OSError + anything
                # else. Failed files accumulate in _delim_failed_files
                # (tracked below) so operators see "N skipped" in the
                # summary, not silent data loss.
                _delim_failed_files.append((str(f), str(e)[:200]))
                print(f"skipped ({e})")
    except ShardCapacityExhausted as _sce:
        write_status(
            case_id=case_id,
            pid=os.getpid(),
            run_id=run_id or "",
            status="failed",
            hosts=[],
            totals={},
            started=datetime.now(timezone.utc).isoformat(),
            error=f"{HALT_CIRCUIT_BREAKER}: {_sce}",
        )
        print(f"ABORT: {HALT_CIRCUIT_BREAKER}: {_sce}", file=sys.stderr)
        raise

    print(f"Done. {total:,} indexed, {total_sk} skipped, {total_bf} bulk failed.")
    if _delim_failed_files:
        print(f"*** {len(_delim_failed_files)} files failed to parse; continuing walk: ***")
        for path, err in _delim_failed_files[:10]:
            print(f"  {path}: {err}")
        if len(_delim_failed_files) > 10:
            print(f"  ... and {len(_delim_failed_files) - 10} more")
    audit.log(
        tool="idx_ingest_delimited",
        audit_id=aid,
        params={
            "path": str(input_path),
            "hostname": hostname,
            "bulk_failed": total_bf,
            "failed_files_count": len(_delim_failed_files),
        },
        result_summary=f"{total} indexed"
        + (f", {total_bf} bulk failed" if total_bf else "")
        + (f", {len(_delim_failed_files)} files skipped" if _delim_failed_files else ""),
        input_files=[str(input_path)],
    )
    if run_id:
        final_status = "complete"
        if total_bf > 0 and total == 0:
            final_status = "failed"
        _write_bg_status(
            case_id,
            run_id,
            final_status,
            hostname,
            "delimited",
            started_ts,
            time.monotonic() - start_mono,
            indexed=total,
        )


# ---------------------------------------------------------------------------
# cmd_ingest_accesslog — Apache/Nginx access log ingest
# ---------------------------------------------------------------------------


def cmd_ingest_accesslog(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Ingest Apache/Nginx access logs."""
    from opensearch_mcp import __version__
    from opensearch_mcp.bulk import reset_circuit_breaker
    from opensearch_mcp.parse_accesslog import ingest_accesslog

    reset_circuit_breaker()

    input_path = Path(args.path)
    case_id = _resolve_case_id(getattr(args, "case", None))
    _ensure_case_active(case_id)
    hostname = args.hostname
    time_from = _parse_date(args.time_from) if getattr(args, "time_from", None) else None
    time_to = _parse_date(args.time_to) if getattr(args, "time_to", None) else None

    if getattr(args, "dry_run", False):
        print(f"Dry run: {input_path}")
        return

    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or None
    start_mono = time.monotonic()
    started_ts = datetime.now(timezone.utc).isoformat()

    client = get_client()
    _preflight_shard_capacity(client, "accesslog", case_id=case_id, run_id=run_id or "")
    audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
    aid = audit._next_audit_id()
    suffix = getattr(args, "index_suffix", None) or "accesslog"

    files = (
        [input_path]
        if input_path.is_file()
        else sorted(
            f
            for f in input_path.iterdir()
            if f.suffix.lower() in (".log", ".txt") or "access" in f.name.lower()
        )
    )

    if run_id:
        _write_bg_status(
            case_id,
            run_id,
            "running",
            hostname,
            "accesslog",
            started_ts,
            files_total=len(files),
        )

    from opensearch_mcp.bulk import ShardCapacityExhausted
    from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER

    total = total_sk = total_bf = 0
    _alog_failed_files: list[tuple[str, str]] = []
    try:
        for idx, f in enumerate(files):
            from opensearch_mcp.paths import build_index_name as _build_idx_a

            index_name = _build_idx_a(case_id, suffix, hostname)
            print(f"  {f.name} -> {index_name}...", end=" ", flush=True)
            try:
                cnt, sk, bf = ingest_accesslog(
                    f,
                    client,
                    index_name,
                    hostname,
                    time_from=time_from,
                    time_to=time_to,
                    source_file=str(f),
                    ingest_audit_id=aid,
                    pipeline_version=f"opensearch-mcp-{__version__}",
                )
                print(f"{cnt:,} entries ({sk} skipped)")
                total += cnt
                total_sk += sk
                total_bf += bf
            except ShardCapacityExhausted:
                # Re-raise so the outer circuit-breaker handler fires.
                raise
            except Exception as e:  # noqa: BLE001 — per-file isolation (UAT 2026-04-22)
                # General exception hygiene — OSError, UnicodeDecodeError,
                # or unexpected parser failure. parse_accesslog uses its
                # own hashlib.sha256 (not _doc_id) so it's not TypeError-
                # vulnerable, but any crash should still skip-and-continue.
                _alog_failed_files.append((str(f), str(e)[:200]))
                print(f"skipped ({e})")
            if run_id:
                _write_bg_status(
                    case_id,
                    run_id,
                    "running",
                    hostname,
                    "accesslog",
                    started_ts,
                    time.monotonic() - start_mono,
                    indexed=total,
                    files_done=idx + 1,
                    files_total=len(files),
                )
    except ShardCapacityExhausted as _sce:
        write_status(
            case_id=case_id,
            pid=os.getpid(),
            run_id=run_id or "",
            status="failed",
            hosts=[],
            totals={},
            started=datetime.now(timezone.utc).isoformat(),
            error=f"{HALT_CIRCUIT_BREAKER}: {_sce}",
        )
        print(f"ABORT: {HALT_CIRCUIT_BREAKER}: {_sce}", file=sys.stderr)
        raise

    print(f"Done. {total:,} indexed, {total_sk} skipped, {total_bf} bulk failed.")
    if _alog_failed_files:
        print(f"*** {len(_alog_failed_files)} files failed to parse; continuing walk: ***")
        for path, err in _alog_failed_files[:10]:
            print(f"  {path}: {err}")
        if len(_alog_failed_files) > 10:
            print(f"  ... and {len(_alog_failed_files) - 10} more")
    audit.log(
        tool="idx_ingest_accesslog",
        audit_id=aid,
        params={
            "path": str(input_path),
            "hostname": hostname,
            "bulk_failed": total_bf,
            "failed_files_count": len(_alog_failed_files),
        },
        result_summary=f"{total} indexed"
        + (f", {total_bf} bulk failed" if total_bf else "")
        + (f", {len(_alog_failed_files)} files skipped" if _alog_failed_files else ""),
        input_files=[str(input_path)],
    )
    if run_id:
        final_status = "complete"
        if total_bf > 0 and total == 0:
            final_status = "failed"
        _write_bg_status(
            case_id,
            run_id,
            final_status,
            hostname,
            "accesslog",
            started_ts,
            time.monotonic() - start_mono,
            indexed=total,
        )


# ---------------------------------------------------------------------------
# cmd_enrich_intel — OpenCTI threat intel enrichment
# ---------------------------------------------------------------------------


def cmd_enrich_intel(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Enrich indexed data with OpenCTI threat intel.

    Progress is written to the shared `ingest-status` dir with
    `artifact_name="intel"` so the async MCP entry point
    (`idx_enrich_intel` via `_launch_enrich_background`) can surface
    it through `idx_ingest_status`.
    """
    case_id = _resolve_case_id(getattr(args, "case", None))
    force = getattr(args, "force", False)

    from opensearch_mcp.paths import sanitize_index_component
    from opensearch_mcp.threat_intel import enrich_case, extract_unique_iocs

    client = get_client()

    if getattr(args, "dry_run", False):
        safe_case = sanitize_index_component(case_id)
        iocs = extract_unique_iocs(client, f"case-{safe_case}-*", force=force)
        print(f"Case: {case_id}")
        print(f"  External IPs: {len(iocs['ip'])}")
        print(f"  Hashes: {len(iocs['hash'])}")
        print(f"  Domains: {len(iocs['domain'])}")
        total = sum(len(v) for v in iocs.values())
        print(f"  Total unique IOCs: {total}")
        if not force:
            print("  (excluding already-enriched documents; use --force to include)")
        return

    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or None
    start_mono = time.monotonic()
    started_ts = datetime.now(timezone.utc).isoformat()

    def _write_enrich_status(status, indexed=0, files_done=0, files_total=0, error=""):
        """Write enrichment status record. No-op if not running under run_id."""
        if not run_id:
            return
        _write_bg_status(
            case_id,
            run_id,
            status,
            "(enrich)",
            "intel",
            started_ts,
            time.monotonic() - start_mono,
            indexed=indexed,
            files_done=files_done,
            files_total=files_total,
            error=error,
        )

    # Initial "running" write — idempotent under monotonic protection
    # (server.py post-spawn also writes running; both values are equal).
    _write_enrich_status("running")

    # Closure state for the progress callback so we can thread total/done
    # counts through to the status file without another arg passthrough.
    _progress_state = {"total": 0, "done": 0}

    def _progress(event, **kw):
        if event == "extracting":
            print("Extracting unique IOCs from indexed data...")
        elif event == "extracted":
            print(f"  IPs: {kw['ips']}, Hashes: {kw['hashes']}, Domains: {kw['domains']}")
        elif event == "looking_up":
            total = kw.get("total", 0) or _progress_state["total"]
            done = kw.get("done", 0)
            if done:
                _progress_state["done"] = done
                print(f"  Looked up {done}/{total}...", flush=True)
                _write_enrich_status("running", indexed=done, files_done=done, files_total=total)
            else:
                _progress_state["total"] = total
                print(f"Looking up {total} IOCs via OpenCTI...")
                _write_enrich_status("running", files_total=total)
        elif event == "stamping":
            print(f"Stamping {kw['matched']} matched IOCs to documents...")

    try:
        result = enrich_case(client, case_id, force=force, on_progress=_progress)
    except Exception as e:  # noqa: BLE001
        # Terminal failed write with the real exception text so
        # idx_ingest_status surfaces *why* enrichment failed without
        # forcing the operator into the log file. The excepthook guard
        # would otherwise stamp "process_died_unexpectedly: …" which
        # misframes a caught exception as an uncaught crash.
        # Length-cap so a verbose stacktrace doesn't bloat the status
        # JSON beyond ~1KB.
        _write_enrich_status(
            "failed",
            error=f"{type(e).__name__}: {e}"[:500],
        )
        print(f"Enrichment failed: {e}", file=sys.stderr)
        raise

    if result["status"] == "no_iocs":
        print("No external IOCs found in indexed data.")
        _write_enrich_status("complete")
        return

    print(f"\nDone. {result['documents_updated']} documents updated.")
    print(f"  MALICIOUS: {result['malicious']}")
    print(f"  SUSPICIOUS: {result['suspicious']}")

    _write_enrich_status(
        "complete",
        indexed=result.get("documents_updated", 0),
        files_done=_progress_state["done"] or result.get("iocs_looked_up", 0),
        files_total=_progress_state["total"] or result.get("iocs_extracted", 0),
    )

    audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
    audit.log(
        tool="enrich_intel",
        params={"case_id": case_id, "force": force},
        result_summary=(
            f"{result['documents_updated']} docs updated, "
            f"{result['malicious']} malicious, {result['suspicious']} suspicious"
        ),
    )


# ---------------------------------------------------------------------------
# cmd_ingest_memory — memory forensics entry point
# ---------------------------------------------------------------------------


def cmd_ingest_memory(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Parse a memory image with Volatility 3 and index results."""
    from opensearch_mcp import __version__
    from opensearch_mcp.bulk import ShardCapacityExhausted, reset_circuit_breaker
    from opensearch_mcp.parse_memory import TIER_1, TIER_2, TIER_3, ingest_memory

    reset_circuit_breaker()

    image_path = Path(args.path)
    _mem_extract_dir = None  # Track for cleanup

    # Extract from archive if needed
    if image_path.suffix.lower() in (".7z", ".zip"):
        import shutil
        import subprocess
        import tempfile

        _mem_extract_dir = Path(tempfile.mkdtemp(prefix="vhir-mem-"))
        try:
            password = os.environ.get("VHIR_ARCHIVE_PASSWORD", "")
            cmd = ["7z", "x", f"-o{_mem_extract_dir}", str(image_path)]
            if password:
                cmd.insert(2, f"-p{password}")
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)
            memory_exts = {".img", ".raw", ".vmem", ".dmp", ".mem", ".bin", ".lime"}
            extracted = [f for f in _mem_extract_dir.iterdir() if f.suffix.lower() in memory_exts]
            if not extracted:
                shutil.rmtree(_mem_extract_dir, ignore_errors=True)
                print(f"Error: No memory image found in {image_path}", file=sys.stderr)
                sys.exit(1)
            image_path = extracted[0]
            print(f"Extracted: {image_path} ({image_path.stat().st_size / (1024**3):.1f} GB)")
        except subprocess.CalledProcessError as e:
            shutil.rmtree(_mem_extract_dir, ignore_errors=True)
            print(f"Error: Failed to extract {image_path}: {e}", file=sys.stderr)
            sys.exit(1)

    if not image_path.is_file():
        print(f"Error: {image_path} is not a file.", file=sys.stderr)
        sys.exit(1)

    case_id = _resolve_case_id(getattr(args, "case", None))
    _ensure_case_active(case_id)
    hostname = args.hostname
    tier = getattr(args, "tier", 1)
    plugins_str = getattr(args, "plugins", None)
    plugins = [p.strip() for p in plugins_str.split(",")] if plugins_str else None

    # Show what will run
    if plugins:
        plugin_list = plugins
    elif tier >= 3:
        plugin_list = TIER_3
    elif tier >= 2:
        plugin_list = TIER_2
    else:
        plugin_list = TIER_1

    print(f"Memory image: {image_path.name}")
    print(f"Hostname: {hostname}")
    print(f"Tier {tier}: {len(plugin_list)} plugins")

    if not getattr(args, "yes", False):
        try:
            answer = input(f"\nRun {len(plugin_list)} vol3 plugins? [y/N] ")
            if answer.lower() not in ("y", "yes"):
                print("Aborted.")
                return
        except EOFError:
            print("Non-interactive mode. Use --yes to skip.", file=sys.stderr)
            sys.exit(1)

    # Derive run_id BEFORE pre-flight so halt-status has correlation.
    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or str(uuid.uuid4())
    started_ts = datetime.now(timezone.utc).isoformat()
    start_mono = time.monotonic()

    client = get_client()
    _preflight_shard_capacity(client, "memory", case_id=case_id, run_id=run_id)

    audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
    aid = audit._next_audit_id()

    # Build plugin checklist for status
    status_plugins = [{"name": p, "status": "pending"} for p in plugin_list]
    status_host = {
        "hostname": hostname,
        "artifacts": status_plugins,
    }

    def _write_mem_status(status: str, error: str = "") -> None:
        from opensearch_mcp.bulk import get_last_bulk_reason

        total_indexed = sum(r.get("indexed", 0) for r in _plugin_results.values())
        n_done = sum(1 for a in status_plugins if a["status"] == "complete")
        write_status(
            case_id,
            os.getpid(),
            run_id,
            status,
            [status_host],
            {
                "indexed": total_indexed,
                "artifacts_total": len(status_plugins),
                "artifacts_complete": n_done,
                "hosts_total": 1,
                "hosts_complete": 1 if n_done == len(status_plugins) else 0,
            },
            started_ts,
            error=error,
            elapsed_seconds=time.monotonic() - start_mono,
            bulk_failed_reason=get_last_bulk_reason(),
        )

    _plugin_results: dict = {}

    def _progress(event: str, **kw) -> None:
        if event == "plugin_start":
            print(f"  {kw['plugin']}...", end=" ", flush=True)
            for a in status_plugins:
                if a["name"] == kw["plugin"]:
                    a["status"] = "running"
                    break
            _write_mem_status("running")
        elif event == "plugin_done":
            cnt = kw.get("indexed", 0)
            plugin = kw.get("plugin", "")
            _plugin_results[plugin] = {"indexed": cnt, "status": "done"}
            for a in status_plugins:
                if a["name"] == plugin:
                    a["status"] = "complete"
                    a["indexed"] = cnt
                    break
            if cnt:
                print(f"{cnt:,} entries")
            else:
                print("empty")
        elif event == "plugin_failed":
            plugin = kw.get("plugin", "")
            _plugin_results[plugin] = {"status": "failed", "error": kw.get("error", "")}
            for a in status_plugins:
                if a["name"] == plugin:
                    a["status"] = "failed"
                    a["error"] = kw.get("error", "")
                    break
            print(f"FAILED: {kw['error']}")

    def _audit_log(tool, params, result_summary, input_files=None):
        audit.log(
            tool=tool,
            audit_id=aid,
            params=params,
            result_summary=result_summary,
            input_files=input_files,
        )

    # Initial status
    _write_mem_status("running")

    timeout = getattr(args, "timeout", 3600)
    try:
        results = ingest_memory(
            image_path=image_path,
            client=client,
            case_id=case_id,
            hostname=hostname,
            tier=tier,
            plugins=plugins,
            timeout=timeout,
            ingest_audit_id=aid,
            run_id=run_id,
            pipeline_version=f"opensearch-mcp-{__version__}",
            on_progress=_progress,
            audit_log=_audit_log,
        )
    except ShardCapacityExhausted as e:
        # Distinct status so monitoring can differentiate capacity
        # failures from generic errors. The _write_mem_status helper
        # wraps write_status — the prefixed error string carries the
        # halt reason (error-prefix convention replaces pre-0.6.2
        # halt-state taxonomy).
        from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER

        _write_mem_status("failed", error=f"{HALT_CIRCUIT_BREAKER}: {e}")
        raise
    except Exception as e:
        _write_mem_status("failed", error=str(e))
        raise

    # Summary
    total = sum(r.get("indexed", 0) for r in results.values())
    failed = [p for p, r in results.items() if r.get("status") == "failed"]
    print(f"\nDone. {total:,} entries indexed from {len(results)} plugins.")
    if failed:
        print(f"{len(failed)} plugin(s) failed: {', '.join(failed)}")

    # Final status
    _write_mem_status("complete")

    # Audit the overall operation
    # Aggregate bulk rejections across all plugins for visibility.
    total_bulk_failed = sum(r.get("bulk_failed", 0) for r in results.values())
    audit.log(
        tool="idx_ingest_memory",
        audit_id=aid,
        params={
            "image": str(image_path),
            "hostname": hostname,
            "tier": tier,
            "run_id": run_id,
            "bulk_failed": total_bulk_failed,
        },
        result_summary=(f"{total} indexed, {len(failed)} failed, {total_bulk_failed} bulk failed"),
        input_files=[str(image_path)],
    )

    # Clean up extracted temp dir (multi-GB memory image)
    if _mem_extract_dir and _mem_extract_dir.exists():
        import shutil

        shutil.rmtree(_mem_extract_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _install_terminal_status_guards() -> None:
    """Worker terminal-status guards (UAT 2026-04-22 Fix 3.1).

    On abnormal termination (uncaught Python exception, clean
    sys.exit), write a terminal `failed` status before the worker
    exits. Without this, the per-PID status file stays `running`
    indefinitely, the concurrency cap blocks new ingests, and
    operators must manually scrub the registry.

    - `sys.excepthook`: captures uncaught exceptions with traceback
    - `atexit`: idempotent fallback on clean interpreter shutdown —
      only writes `failed` if the status file still says
      `running`/`starting` (won't overwrite a clean `complete` or a
      prior terminal write).

    Signal coverage (verified live 2026-04-23):
    - SIGINT (Ctrl-C): raises KeyboardInterrupt → excepthook fires
    - SIGTERM: Python's default handler does NOT run atexit; process
      exits silently. The liveness sweep in
      `ingest_status.read_active_ingests()` is the backstop that
      transitions `running`/`starting` → `failed`.
    - SIGKILL, OOM-kill: no atexit, no excepthook. Same sweep backstop.
    """
    import atexit
    import sys

    def _write_terminal_if_running(error_prefix: str, detail: str) -> None:
        try:
            from opensearch_mcp.ingest_status import _STATUS_DIR

            # Find our status file by PID — look for any JSON in
            # _STATUS_DIR with our PID (ingest can be on any case).
            pid = os.getpid()
            for f in _STATUS_DIR.glob(f"*-{pid}.json"):
                try:
                    data = json.loads(f.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                if data.get("status") not in ("running", "starting"):
                    continue  # Idempotent: don't overwrite terminal
                data["status"] = "failed"
                prev_err = data.get("error") or ""
                data["error"] = f"{error_prefix}: {detail}" + (
                    f" | prior: {prev_err[:200]}" if prev_err else ""
                )
                try:
                    tmp = f.with_suffix(".json.tmp")
                    tmp.write_text(json.dumps(data))
                    os.replace(str(tmp), str(f))
                except OSError:
                    pass  # Best-effort; process is dying anyway
        except Exception:  # noqa: BLE001
            pass  # Absolutely must not raise from atexit/excepthook

    def _excepthook(exc_type, exc_value, exc_tb):
        _write_terminal_if_running(
            "process_died_unexpectedly",
            f"{exc_type.__name__}: {exc_value}",
        )
        # Also log traceback to stderr (default behavior preserved).
        sys.__excepthook__(exc_type, exc_value, exc_tb)

    def _atexit_guard():
        _write_terminal_if_running(
            "process_died_unexpectedly",
            "worker exited without writing terminal status",
        )

    sys.excepthook = _excepthook
    atexit.register(_atexit_guard)


def main() -> None:
    # Install terminal-status guards before any subcommand runs so
    # that crashes after VHIR_INGEST_RUN_ID is set are captured.
    _install_terminal_status_guards()

    parser = argparse.ArgumentParser(
        prog="opensearch-ingest",
        description="Ingest forensic evidence into OpenSearch",
    )
    sub = parser.add_subparsers(dest="command")

    # scan subcommand
    p_scan = sub.add_parser("scan", help="Scan directory for artifacts, run EZ tools, index")
    _add_scan_args(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    # csv subcommand
    p_csv = sub.add_parser("csv", help="Ingest a pre-parsed CSV (examiner identifies tool)")
    p_csv.add_argument("tool_name", help=f"Tool ({', '.join(sorted(TOOLS))})")
    p_csv.add_argument("csv_path", help="Path to the CSV file")
    p_csv.add_argument("--hostname", required=True, help="Source hostname")
    p_csv.add_argument("--case", help="Case ID")
    p_csv.add_argument("--examiner", help="Examiner name")
    p_csv.set_defaults(func=cmd_csv)

    # memory subcommand
    p_mem = sub.add_parser("memory", help="Parse memory image with Volatility 3")
    p_mem.add_argument("path", help="Path to memory image")
    p_mem.add_argument("--hostname", required=True, help="Source hostname")
    p_mem.add_argument("--case", help="Case ID")
    p_mem.add_argument("--tier", type=int, default=1, choices=[1, 2, 3], help="Analysis depth")
    p_mem.add_argument("--plugins", help="Specific plugins (comma-separated)")
    p_mem.add_argument("--timeout", type=int, default=3600, help="Per-plugin timeout")
    p_mem.add_argument("--yes", action="store_true", help="Skip confirmation")
    p_mem.set_defaults(func=cmd_ingest_memory)

    # json subcommand
    p_json = sub.add_parser("json", help="Ingest JSON/JSONL files")
    p_json.add_argument("path", help="JSON/JSONL file or directory")
    p_json.add_argument("--hostname", required=True)
    p_json.add_argument("--index-suffix")
    p_json.add_argument("--time-field")
    p_json.add_argument("--case")
    p_json.add_argument("--from", dest="time_from")
    p_json.add_argument("--to", dest="time_to")
    p_json.add_argument("--batch-size", type=int, default=1000)
    p_json.add_argument("--dry-run", action="store_true")
    p_json.set_defaults(func=cmd_ingest_json)

    # delimited subcommand
    p_delim = sub.add_parser("delimited", help="Ingest CSV/TSV/Zeek/bodyfile")
    p_delim.add_argument("path", help="Delimited file or directory")
    p_delim.add_argument("--hostname")
    p_delim.add_argument(
        "--recursive",
        action="store_true",
        help=(
            "Treat immediate subdirectories as hosts (one level only; "
            "nested subdirectories are not walked). Top-level files "
            "directly under the path are ignored."
        ),
    )
    p_delim.add_argument("--auto-hosts", help="Comma-separated hostnames to ingest sequentially")
    p_delim.add_argument("--index-suffix")
    p_delim.add_argument("--time-field")
    p_delim.add_argument("--delimiter")
    p_delim.add_argument("--format", choices=["csv", "tsv", "zeek", "bodyfile"])
    p_delim.add_argument("--case")
    p_delim.add_argument("--from", dest="time_from")
    p_delim.add_argument("--to", dest="time_to")
    p_delim.add_argument("--batch-size", type=int, default=1000)
    p_delim.add_argument("--dry-run", action="store_true")
    p_delim.set_defaults(func=cmd_ingest_delimited)

    # accesslog subcommand
    p_alog = sub.add_parser("accesslog", help="Ingest Apache/Nginx access logs")
    p_alog.add_argument("path", help="Access log file or directory")
    p_alog.add_argument("--hostname", required=True)
    p_alog.add_argument("--index-suffix", default="accesslog")
    p_alog.add_argument("--case")
    p_alog.add_argument("--from", dest="time_from")
    p_alog.add_argument("--to", dest="time_to")
    p_alog.add_argument("--dry-run", action="store_true")
    p_alog.set_defaults(func=cmd_ingest_accesslog)

    # enrich-intel subcommand
    p_enrich = sub.add_parser("enrich-intel", help="Enrich indexed data with OpenCTI threat intel")
    p_enrich.add_argument("--case", help="Case ID")
    p_enrich.add_argument("--force", action="store_true", help="Re-enrich already-enriched docs")
    p_enrich.add_argument(
        "--dry-run", action="store_true", help="Show IOC counts without enriching"
    )
    p_enrich.set_defaults(func=cmd_enrich_intel)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    """Add scan subcommand arguments (shared by CLI and plugin)."""
    p.add_argument("path", help="Triage directory, archive, or disk image")
    p.add_argument("--case", help="Case ID")
    p.add_argument("--hostname", help="Override hostname (flat dirs)")
    p.add_argument("--password", help="Archive password")
    p.add_argument("--from", dest="time_from", help="Start date (ISO)")
    p.add_argument("--to", dest="time_to", help="End date (ISO)")
    p.add_argument(
        "--all-logs",
        action="store_true",
        help="Parse all evtx files (default: forensic logs only)",
    )
    p.add_argument(
        "--reduced-ids",
        action="store_true",
        help="Filter to ~78 high-value Event IDs",
    )
    p.add_argument(
        "--reduced",
        action="store_true",
        dest="reduced_ids",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--source-timezone",
        help="Evidence system's local timezone (e.g., 'Eastern Standard Time'). "
        "Used to convert local-time artifacts (SSH, transcripts, tasks, firewall) to UTC.",
    )
    p.add_argument("--include", help="Artifact types (comma-sep)")
    p.add_argument("--exclude", help="Artifact types (comma-sep)")
    p.add_argument("--full", action="store_true", help="Include all tiers (MFT, USN, timeline)")
    p.add_argument("--config", help="YAML config file for complex filtering")
    p.add_argument("--vss", action="store_true", help="Include volume shadow copies")
    p.add_argument(
        "--parallel",
        type=int,
        default=4,
        help="Reserved — parallel parsing not yet implemented",
    )
    p.add_argument("--yes", action="store_true", help="Skip confirmation")
    p.add_argument(
        "--skip-triage",
        action="store_true",
        help="Skip post-ingest triage baseline enrichment",
    )
    p.add_argument(
        "--no-hayabusa",
        action="store_true",
        help="Skip Hayabusa detection after evtx ingest",
    )


if __name__ == "__main__":
    main()
