"""EZ Tool wrappers: run tool → collect CSV → call ingest_csv."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml
from opensearchpy import OpenSearch

from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import resolve_case_insensitive


@dataclass
class ToolConfig:
    """Configuration for an EZ tool."""

    cli_name: str  # canonical name for --include/--exclude
    binary: str  # executable name
    tier: int  # 1=always, 2=default, 3=opt-in
    index_suffix: str  # e.g., "amcache" → case-{id}-amcache-{host}
    time_field: str | None  # primary timestamp column for --from/--to
    natural_key: str | None  # for MFT dedup; None = content hash
    multi_csv: bool  # glob("*.csv") for multi-output tools


TOOLS: dict[str, ToolConfig] = {
    "amcache": ToolConfig(
        cli_name="amcache",
        binary="AmcacheParser",
        tier=1,
        index_suffix="amcache",
        time_field="FileKeyLastWriteTimestamp",  # Verified
        natural_key=None,
        multi_csv=True,
    ),
    "shimcache": ToolConfig(
        cli_name="shimcache",
        binary="AppCompatCacheParser",
        tier=1,
        index_suffix="shimcache",
        time_field="LastModifiedTimeUTC",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "registry": ToolConfig(
        cli_name="registry",
        binary="RECmd",
        tier=1,
        index_suffix="registry",
        time_field="LastWriteTimestamp",  # Verified
        natural_key=None,
        multi_csv=True,
    ),
    "registry_user": ToolConfig(  # each profile's NTUSER.DAT and UsrClass.dat
        cli_name="registry_user",
        binary="RECmd",
        tier=1,
        index_suffix="registry",
        time_field="LastWriteTimestamp",
        natural_key=None,
        multi_csv=True,
    ),
    "shellbags": ToolConfig(
        cli_name="shellbags",
        binary="SBECmd",
        tier=1,
        index_suffix="shellbags",
        time_field="LastInteracted",  # Verified by Test agent
        natural_key=None,
        multi_csv=False,
    ),
    "jumplists": ToolConfig(
        cli_name="jumplists",
        binary="JLECmd",
        tier=2,
        index_suffix="jumplists",
        time_field="LastModified",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "lnk": ToolConfig(
        cli_name="lnk",
        binary="LECmd",
        tier=2,
        index_suffix="lnk",
        time_field="TargetModified",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "recyclebin": ToolConfig(
        cli_name="recyclebin",
        binary="RBCmd",
        tier=2,
        index_suffix="recyclebin",
        time_field="DeletedOn",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "mft": ToolConfig(
        cli_name="mft",
        binary="MFTECmd",
        tier=3,
        index_suffix="mft",
        time_field="Created0x10",  # Verified
        natural_key="EntryNumber:SequenceNumber:FileName:ParentEntryNumber",
        multi_csv=False,
    ),
    "usn": ToolConfig(
        cli_name="usn",
        binary="MFTECmd",
        tier=3,
        index_suffix="usn",
        time_field="UpdateTimestamp",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "timeline": ToolConfig(
        cli_name="timeline",
        binary="WxTCmd",
        tier=3,
        index_suffix="timeline",
        time_field="LastModifiedTime",  # Verified
        natural_key=None,
        multi_csv=False,
    ),
    "evtxecmd": ToolConfig(
        cli_name="evtxecmd",
        binary="",  # CSV-only — no binary to run
        tier=1,
        index_suffix="evtx",  # same index as pyevtx-rs output
        time_field="TimeCreated",
        natural_key=None,
        multi_csv=False,
    ),
}

# RECmd batch file path
_RECMD_BATCH = "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb"
# The keys the registry triage rules read, which Kroll's batch doesn't extract
_TRIAGE_KEYS = Path(__file__).with_name("recmd_triage_keys.reb")


def _registry_batch(tmpdir: str) -> str:
    """Kroll's batch plus the triage keys, as one batch file for one RECmd run.

    Kroll's text is kept as it is and the keys' entries are appended to its
    `Keys` list (a parse and dump would rewrite some of its values). The file
    keeps Kroll's name, so the output CSV and every Kroll row's document id
    stay the same. Kroll's batch alone when either can't be read or the
    result isn't Kroll's keys followed by the triage keys."""
    try:
        kroll = Path(_RECMD_BATCH).read_text(encoding="utf-8")
        triage = _TRIAGE_KEYS.read_text(encoding="utf-8")
        entries = triage[triage.index("\nKeys:\n") + len("\nKeys:\n") :]
        combined = kroll.rstrip("\n") + "\n" + entries
        want = yaml.safe_load(kroll)["Keys"] + yaml.safe_load(triage)["Keys"]
        if yaml.safe_load(combined)["Keys"] != want:
            raise ValueError("Kroll's Keys list isn't the batch's last block")
        out = Path(tmpdir) / "batch" / Path(_RECMD_BATCH).name
        out.parent.mkdir()
        out.write_text(combined, encoding="utf-8")
        return str(out)
    except (OSError, ValueError, yaml.YAMLError, KeyError, TypeError):
        return _RECMD_BATCH  # Kroll alone, as before; triage then names the rules that saw no data


_TOOL_TIMEOUT = 7200  # 2 hours — generous for MFT/large artifacts

# SIFT's /usr/local/bin wrappers expand their arguments unquoted, which splits any
# path containing a space. Run the tool's .dll with dotnet directly when it is there.
_EZ_TOOLS_DIR = Path("/opt/zimmermantools")


def _launcher(binary: str) -> list[str]:
    dotnet = shutil.which("dotnet")
    dlls = [_EZ_TOOLS_DIR / f"{binary}.dll"]
    try:  # its own folder, whatever its case (SIFT has EvtxeCmd/EvtxECmd.dll)
        dlls += [d / f"{binary}.dll" for d in sorted(_EZ_TOOLS_DIR.iterdir())
                 if d.is_dir() and d.name.lower() == binary.lower()]  # fmt: skip
    except OSError:
        pass
    for dll in dlls:
        if dotnet and dll.is_file():
            return [dotnet, str(dll)]
    return [binary]


def _run_tool(cmd: list[str], label: str) -> tuple[str, str]:
    """Run an EZ tool subprocess, raising on failure.

    Returns (stdout, stderr) captured from the subprocess so callers
    can surface diagnostics when the tool exits 0 but produces no
    output (UAT 2026-04-23 BUG 6: previously stderr was discarded on
    success, leaving operators no way to root-cause a silent-empty
    run).
    """
    cmd = _launcher(cmd[0]) + cmd[1:]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TOOL_TIMEOUT)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed (exit {result.returncode}): {result.stderr[:500]}")
    return result.stdout, result.stderr


def _silent_failure_diagnostic(binary: str, artifact_path: Path, stderr: str) -> str:
    """Build a diagnostic line for the "tool exited 0 but produced no
    output" case. Includes file size, magic bytes, associated log
    files (for registry hives: LOG1/LOG2 indicate dirty hive needing
    log replay), and any captured stderr. Operators previously had to
    re-collect evidence blind; this line tells them whether the hive
    is empty/truncated (size), malformed (magic), dirty (LOG files),
    or the tool itself emitted a stderr message that used to be
    silently discarded.

    Applies to every EZ tool in TOOLS (AmcacheParser, PECmd, RECmd,
    SBECmd, EvtxECmd, SrumECmd, etc.) — not just AmcacheParser. The
    framing is artifact-agnostic so it works across Zimmerman binaries.
    """
    parts = [f"path={artifact_path}"]
    try:
        size = artifact_path.stat().st_size if artifact_path.exists() else -1
        parts.append(f"size={size}")
    except OSError as e:
        parts.append(f"size=stat-failed({e})")

    # Read only the first 8 bytes — artifacts here can be multi-GB
    # ($MFT, SRUDB.dat) and the prior `read_bytes()[:8]` loaded the
    # entire file into memory before slicing. This diagnostic already
    # fires on a degraded path; allocating gigabytes here is what
    # turns a "silent failure" into a crash.
    if artifact_path.is_file():
        try:
            with artifact_path.open("rb") as fh:
                magic = fh.read(8)
            parts.append(f"magic={magic!r}")
        except OSError:
            pass

    # Registry hive LOG files (dirty hive → needs log replay). Only
    # check when the artifact is a file (skips directory-shaped
    # artifacts like EvtxECmd's per-channel dir input).
    if artifact_path.is_file():
        try:
            log_files = sorted(
                p.name for p in artifact_path.parent.glob(f"{artifact_path.name}.LOG*")
            )
            if log_files:
                parts.append(f"logs={log_files}")
        except OSError:
            pass

    if stderr and stderr.strip():
        parts.append(f"stderr={stderr[:500]!r}")

    return f"{binary} completed but produced no CSV output: " + " ".join(parts)


def _failed_files(stdout: str, tool_name: str) -> list[str]:
    """The tool's own "Failed files" list: files it found and could not read."""
    lines = stdout.splitlines()
    if "Failed files" not in lines:
        return []
    out = []
    for line in lines[lines.index("Failed files") + 1 :]:
        if not line.startswith("  "):
            break
        path, _, why = line.strip().partition(" ==> ")
        if tool_name == "lnk" and not path.lower().endswith(".lnk"):
            continue  # --all also tries desktop.ini, .website and jump lists
        out.append(f"{path} {why}".strip())
    return out


# Lines the EZ tools print on stdout, while still exiting 0, when an input could not be read.
_TOOL_ERROR_LINES = (
    "There was an error",  # AmcacheParser, AppCompatCacheParser, RECmd, SBECmd
    "Data in byte array is not a Registry hive",  # RECmd
    "Unknown file type!",  # MFTECmd
)


def _tool_errors(stdout: str, artifact_path: Path) -> list[str]:
    """Inputs the tool said it could not read, as "path (message)"."""
    out, current, cause = [], str(artifact_path), ""
    for line in stdout.splitlines():
        text = line.strip()
        if text.startswith("Processing "):
            current = text.removeprefix("Processing ").removeprefix("hive ").strip("'")
            cause = ""
        elif text.endswith("Aborting!!"):
            cause = text  # SBECmd says why before its generic error line
        elif text.startswith(_TOOL_ERROR_LINES):
            out.append(f"{current} ({cause or text})")
    return out


def _recased_ntuser(profile: Path, view: Path) -> tuple[Path, Path] | None:
    """Copy a dirty NTUSER.DAT whose logs Windows named in another case (ntuser.dat.LOG1),
    with its logs under the hive's own name, the only one SBECmd looks for on Linux. The
    logs are copied too, so a replay never opens a file in the evidence."""
    try:
        hive = resolve_case_insensitive(profile, "NTUSER.DAT")
        if hive is None or not hive.is_file():
            return None
        want = [hive.name + ".LOG1", hive.name + ".LOG2"]
        logs = [p for p in hive.parent.iterdir() if p.name.upper() in [w.upper() for w in want]]
        with hive.open("rb") as fh:
            head = fh.read(12)
        if not logs or any(p.name in want for p in logs) or head[4:8] == head[8:12]:
            return None
        view.mkdir()
        shutil.copyfile(hive, view / hive.name)
        for p in logs:
            shutil.copyfile(p, view / (hive.name + p.name[len(hive.name) :].upper()))
        return hive, view
    except OSError:
        return None  # SBECmd's own run already reported what it couldn't read


def run_and_ingest(
    tool_name: str,
    artifact_path: Path,
    client: OpenSearch,
    case_id: str,
    hostname: str,
    source_file: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    time_from=None,
    time_to=None,
    vss_id: str = "",
    natural_key_override: str | None = None,
    host_dict=None,
    not_read: list | None = None,
    hives_read: list | None = None,
    seen: dict | None = None,
    collided: dict | None = None,
) -> tuple[int, int, int]:
    """Run an EZ tool against an artifact and ingest the CSV output.

    Returns (count_indexed, count_skipped, count_bulk_failed).
    natural_key_override: if set, overrides cfg.natural_key (used for VSS MFT).
    """
    cfg = TOOLS.get(tool_name)
    if cfg is None:
        raise ValueError(f"Unknown tool: {tool_name}")

    from opensearch_mcp.write_context import index_name as _index_name

    index_name = _index_name(cfg.index_suffix)
    tmpdir = tempfile.mkdtemp(prefix=f"vhir-{tool_name}-")
    natural_key = natural_key_override if natural_key_override is not None else cfg.natural_key

    try:
        # Build command
        cmd = _build_command(cfg, tool_name, artifact_path, tmpdir)
        _stdout, _stderr = _run_tool(cmd, cfg.binary)
        row_source = None
        if tool_name == "registry":
            # RECmd reads every hive under the folder: each row names its own
            reg_dir = artifact_path if artifact_path.is_dir() else artifact_path.parent

            def row_source(row):
                try:
                    hive = Path(row.get("HivePath") or "").relative_to(reg_dir)
                except ValueError:
                    return ""  # outside the folder (or none): the folder itself
                return str(Path(source_file) / hive) if hive.parts else ""

            if hives_read is not None:
                hives_read.extend(
                    ln.removeprefix("Processing hive ").strip()
                    for ln in _stdout.splitlines()
                    if ln.startswith("Processing hive ")
                )
        fixed = (
            _recased_ntuser(artifact_path, Path(tmpdir) / "hive")
            if tool_name == "shellbags"
            else None
        )
        replay_failed = ""
        if fixed:
            hive, view = fixed
            replay = Path(tmpdir) / "replay"
            cmd = [cfg.binary, "-d", str(view), "--csv", str(replay)]
            try:
                replay.mkdir()
                more = _run_tool(cmd, cfg.binary)[0].replace(str(view / hive.name), str(hive))
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                # The first run's rows (UsrClass) are still ingested; NTUSER is named
                why = str(e).replace(str(view / hive.name), str(hive)).replace(tmpdir, "…")
                replay_failed = f"{hive} (its transaction logs couldn't be replayed: {why})"
            else:  # only a replay that finished adds its rows, beside the first run's
                for csv_file in replay.glob("*.csv"):
                    csv_file.rename(Path(tmpdir) / f"replay-{csv_file.name}")
        if not_read is not None:
            not_read.extend(_failed_files(_stdout, tool_name))
            errors = _tool_errors(_stdout, artifact_path)
            if fixed:
                errors = [e for e in errors if not e.startswith(f"{hive} (")]
                errors += [replay_failed] if replay_failed else _tool_errors(more, hive)
            not_read.extend(errors)
            if tool_name in ("lnk", "jumplists"):
                walk = os.walk(
                    artifact_path,
                    onerror=lambda e: not_read.append(f"{e.filename} ({e.strerror})"),
                )
                for _ in walk:
                    pass

        # Collect CSV output — warn with diagnostics if tool exited 0
        # but produced nothing (UAT 2026-04-23 BUG 6). Previously this
        # was a one-line warning with no context; operators had to
        # re-collect evidence blind. Now emits artifact path, size,
        # magic bytes, associated LOG files (dirty hive signal), and
        # captured stderr (which `_run_tool` now returns on success).
        csv_files = sorted(Path(tmpdir).glob("*.csv"))

        if not csv_files:
            import sys

            print(
                "WARNING: " + _silent_failure_diagnostic(cfg.binary, artifact_path, _stderr),
                file=sys.stderr,
            )
            return 0, 0, 0

        total_count = 0
        total_skipped = 0
        total_bulk_failed = 0

        for csv_file in csv_files:
            table_name = ""
            if cfg.multi_csv:
                # EZ tools prefix with timestamp: 20260329224802_Amcache_DeviceContainers
                # Strip the timestamp prefix (digits + underscore) to get meaningful name
                stem = csv_file.stem
                parts = stem.split("_", 1)
                if len(parts) > 1 and parts[0].isdigit():
                    table_name = parts[1]
                else:
                    table_name = stem
            count, sk, bf = ingest_csv(
                hive=(source_file or str(artifact_path)) if tool_name == "registry_user" else "",
                # per-profile tools put the profile path they read in the id
                id_source=(source_file or str(artifact_path))
                if tool_name in ("shellbags", "jumplists", "lnk", "timeline")
                else "",
                csv_path=csv_file,
                client=client,
                index_name=index_name,
                hostname=hostname,
                source_file=source_file or str(artifact_path),
                ingest_audit_id=ingest_audit_id,
                pipeline_version=pipeline_version,
                table_name=table_name,
                natural_key=natural_key,
                time_field=cfg.time_field,
                time_from=time_from,
                time_to=time_to,
                vss_id=vss_id,
                parse_method=cfg.cli_name,
                host_dict=host_dict,
                row_host=tool_name != "jumplists",
                row_source=row_source if source_file else None,
                seen=seen,
                collided=collided,
            )
            total_count += count
            total_skipped += sk
            total_bulk_failed += bf

        return total_count, total_skipped, total_bulk_failed

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_command(cfg: ToolConfig, tool_name: str, artifact_path: Path, tmpdir: str) -> list[str]:
    """Build the command line for an EZ tool."""
    binary = cfg.binary

    if tool_name == "amcache":
        # --nl: skip transaction log check (dirty hives from live collection)
        return [binary, "-f", str(artifact_path), "--csv", tmpdir, "--nl"]

    if tool_name == "shimcache":
        # --nl: skip transaction log check (dirty hives from live collection)
        return [
            binary,
            "-f",
            str(artifact_path),
            "--csv",
            tmpdir,
            "--csvf",
            "shimcache.csv",
            "--nl",
        ]

    if tool_name == "registry":
        # RECmd -d expects a DIRECTORY, not a file. Discovery returns
        # individual hive file paths (SYSTEM, SOFTWARE, etc.) — use
        # the parent directory (Windows/System32/config/).
        reg_dir = artifact_path if artifact_path.is_dir() else artifact_path.parent
        # --nl: skip transaction log check (dirty hives from live collection)
        return [
            binary,
            "-d",
            str(reg_dir),
            "--csv",
            tmpdir,
            "--nl",
            "--bn",
            _registry_batch(tmpdir),
        ]

    if tool_name == "registry_user":
        # One hive per run (-f): -d on a profile would walk it and parse app hives too.
        return [binary, "-f", str(artifact_path), "--csv", tmpdir, "--nl", "--bn", _RECMD_BATCH]

    if tool_name == "shellbags":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir]

    if tool_name == "jumplists":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir]

    if tool_name == "lnk":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir, "--all"]

    if tool_name == "recyclebin":
        return [binary, "-d", str(artifact_path), "--csv", tmpdir]

    if tool_name == "mft":
        return [binary, "-f", str(artifact_path), "--csv", tmpdir, "--csvf", "mft.csv"]

    if tool_name == "usn":
        # USN Journal needs the $MFT for resolution — check for it
        mft_path = artifact_path.parent / "$MFT"
        cmd = [binary, "-f", str(artifact_path), "--csv", tmpdir, "--csvf", "usn.csv"]
        if mft_path.is_file():
            cmd.extend(["-m", str(mft_path)])
        return cmd

    if tool_name == "timeline":
        return [binary, "-f", str(artifact_path), "--csv", tmpdir]

    raise ValueError(f"No command builder for tool: {tool_name}")


def get_active_tools(
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    full: bool = False,
) -> list[ToolConfig]:
    """Get the list of tools to run based on tier and include/exclude flags.

    full=True includes all tiers (1+2+3), equivalent to --full flag.
    """
    active = []
    for name, cfg in TOOLS.items():
        # CSV-only tools (no binary) are excluded from scan mode
        if not cfg.binary:
            continue
        # --full: include all tiers
        if full:
            if exclude and name in exclude:
                continue
            active.append(cfg)
            continue
        # Tier 3 only if explicitly included
        if cfg.tier == 3 and (not include or name not in include):
            continue
        # Tier 1-2 unless explicitly excluded
        if exclude and name in exclude:
            continue
        if exclude and name == "registry_user" and "registry" in exclude:
            continue
        # If --include specified, only run those + tier 1
        if include and name not in include and cfg.tier != 1:
            continue
        active.append(cfg)
    return active
