"""CLI for ingesting forensic evidence into OpenSearch."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sift_common.audit import AuditWriter

from opensearch_mcp.client import get_client
from opensearch_mcp.ingest import discover, ingest
from opensearch_mcp.manifest import sha256_file
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import vhir_dir
from opensearch_mcp.tools import TOOLS

_ACTIVE_CASE_FILE = vhir_dir() / "active_case"
_VHIR_CONFIG = vhir_dir() / "config.yaml"


def _resolve_case_id(args_case: str | None) -> str:
    if args_case:
        case_dir = vhir_dir() / "cases" / args_case
        if not case_dir.is_dir():
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
        from opensearch_mcp.wintools import _call_gateway_tool, _load_gateway_config

        config = _load_gateway_config()
        if config and config.get("url"):
            base_url = config["url"].split("/mcp/")[0]
            _call_gateway_tool(
                base_url,
                config.get("token", ""),
                "mcp__case-mcp__case_activate",
                {"case_id": case_id},
            )
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


def _resolve_examiner(args_examiner: str | None) -> str:
    if args_examiner:
        return args_examiner
    if _VHIR_CONFIG.exists():
        try:
            config = yaml.safe_load(_VHIR_CONFIG.read_text()) or {}
            if config.get("examiner"):
                return config["examiner"]
        except Exception:
            pass
    import os

    return os.environ.get("USER", "unknown")


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

    if not getattr(args, "password", None) and config.get("password"):
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
                    if not hostname:
                        hostname = input_path.stem.split(".")[0]
                        print(f"  Hostname from archive: {hostname}")
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

                scan_root = tmpdir

        elif container_type in ("ewf", "raw", "nbd"):
            # Default hostname from filename for disk images (B21)
            if not hostname:
                hostname = input_path.stem
                print(f"  Hostname from filename: {hostname}")
            tmpdir = make_ingest_tmpdir(case_id)
            print(f"Mounting {input_path.name}...")
            volumes = mount_image(input_path, tmpdir, mount_ctx)
            if not volumes:
                print("Error: No NTFS partitions found in disk image.", file=sys.stderr)
                sys.exit(1)
            print(f"  Mounted {len(volumes)} volume(s)")

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

        client = get_client()
        audit = AuditWriter(mcp_name="opensearch-mcp")
        run_id = str(uuid.uuid4())

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
            elif event == "sigma_paused":
                print("  Sigma detection paused during ingest")
            elif event == "sigma_resumed":
                print("  Sigma detection re-enabled")
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
            print(
                f"\n*** {total_bulk_failed:,} events failed to index. ***"
                f"\n  Re-run ingest on the same evidence to recover"
                f" — dedup prevents duplicates."
            )
        if errors:
            print(f"\n{len(errors)} issue(s):")
            for msg in errors:
                print(f"  {msg}")

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
    index_name = f"case-{case_id}-{cfg.index_suffix}-{hostname}".lower()

    client = get_client()
    audit = AuditWriter(mcp_name="opensearch-mcp")
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
        tool=f"ingest_csv_{tool_name}",
        audit_id=aid,
        params={"hostname": hostname, "tool": tool_name, "file": str(csv_path)},
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
# cmd_ingest_memory — memory forensics entry point
# ---------------------------------------------------------------------------


def cmd_ingest_memory(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Parse a memory image with Volatility 3 and index results."""
    from opensearch_mcp import __version__
    from opensearch_mcp.parse_memory import TIER_1, TIER_2, TIER_3, ingest_memory

    image_path = Path(args.path)
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

    client = get_client()
    audit = AuditWriter(mcp_name="opensearch-mcp")
    aid = audit._next_audit_id()

    def _progress(event: str, **kw) -> None:
        if event == "plugin_start":
            print(f"  {kw['plugin']}...", end=" ", flush=True)
        elif event == "plugin_done":
            cnt = kw.get("indexed", 0)
            if cnt:
                print(f"{cnt:,} entries")
            else:
                print("empty")
        elif event == "plugin_failed":
            print(f"FAILED: {kw['error']}")

    def _audit_log(tool, params, result_summary):
        audit.log(tool=tool, audit_id=aid, params=params, result_summary=result_summary)

    timeout = getattr(args, "timeout", 3600)
    results = ingest_memory(
        image_path=image_path,
        client=client,
        case_id=case_id,
        hostname=hostname,
        tier=tier,
        plugins=plugins,
        timeout=timeout,
        ingest_audit_id=aid,
        pipeline_version=f"opensearch-mcp-{__version__}",
        on_progress=_progress,
        audit_log=_audit_log,
    )

    # Summary
    total = sum(r.get("indexed", 0) for r in results.values())
    failed = [p for p, r in results.items() if r.get("status") == "failed"]
    print(f"\nDone. {total:,} entries indexed from {len(results)} plugins.")
    if failed:
        print(f"{len(failed)} plugin(s) failed: {', '.join(failed)}")

    # Audit the overall operation
    audit.log(
        tool="ingest_memory",
        audit_id=aid,
        params={
            "image": str(image_path),
            "hostname": hostname,
            "tier": tier,
        },
        result_summary=f"{total} indexed, {len(failed)} failed",
        input_files=[str(image_path)],
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
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


if __name__ == "__main__":
    main()
