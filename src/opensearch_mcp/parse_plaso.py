"""Parse forensic artifacts with Plaso and index into OpenSearch."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import signal
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk
from opensearch_mcp.parse_csv import _doc_id

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Plaso internal metadata fields — excluded from content hash for dedup stability.
_PLASO_VOLATILE_KEYS = {
    "__container_type__",
    "__type__",
    "pathspec",
    "sha256_hash",  # Plaso storage hash, not evidence hash
    "vhir.vss_id",
}


def _run_plaso(
    parser: str,
    input_path: Path,
    tmpdir: Path,
) -> Path:
    """Run log2timeline + psort, return path to JSONL output."""
    plaso_file = tmpdir / "output.plaso"
    jsonl_file = tmpdir / "output.jsonl"

    # log2timeline: --unattended prevents interactive prompts
    # NOTE: --output_time_zone is a psort flag, NOT log2timeline
    subprocess.run(
        [
            "log2timeline.py",
            "--unattended",
            "--parsers",
            parser,
            "--storage_file",
            str(plaso_file),
            str(input_path),
        ],
        check=True,
        capture_output=True,
        timeout=7200,
    )

    # psort: convert to JSONL with UTC timestamps
    subprocess.run(
        [
            "psort.py",
            "--output_time_zone",
            "UTC",
            "-o",
            "json_line",
            "-w",
            str(jsonl_file),
            str(plaso_file),
        ],
        check=True,
        capture_output=True,
        timeout=7200,
    )

    return jsonl_file


def _ingest_jsonl(
    jsonl_file: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    source_dir: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    host_dict=None,
    volume_root: Path | None = None,
    volume: str | None = None,
) -> tuple[int, int]:
    """Index Plaso JSONL records into OpenSearch.

    volume_root (a run over a whole volume): filename and display_name are
    made relative to it, so vhir.source_file is the path on the evidence and
    the _id doesn't change with where the volume was mounted. Plaso reports
    the resolved path, so the resolved root is stripped. _event_values_hash
    carries the mount path too and is left out of the _id. @timestamp is set
    from the microsecond timestamp, so time-bounded searches find the events.

    volume (a run straight off a disk image): Plaso's paths are already
    inside the file system; vhir.source_file drops the leading "/", and
    vhir.volume (the run's partition or volume) is part of the _id, so two
    volumes with the same files stay apart.

    Returns (count_indexed, count_bulk_failed).
    """
    volatile = _PLASO_VOLATILE_KEYS
    prefix = ""
    if volume_root is not None or volume is not None:
        volatile = _PLASO_VOLATILE_KEYS | {"_event_values_hash"}
    if volume_root is not None:
        prefix = str(volume_root.resolve()).rstrip("/") + "/"
    count = 0
    bulk_failed = 0
    actions: list[dict] = []

    with open(jsonl_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if prefix:
                for key in ("filename", "display_name"):
                    value = record.get(key)
                    if isinstance(value, str) and prefix in value:
                        record[key] = value.replace(prefix, "", 1)
            if volume is not None:
                record["vhir.volume"] = volume
            record["host.name"] = hostname
            if hostname:
                if host_dict is not None:
                    _resolved = host_dict.resolve(hostname)
                    record["host.id"] = _resolved if _resolved else hostname
                else:
                    record["host.id"] = hostname

            # Dedup: compute ID BEFORE adding provenance fields.
            # host.name is stable (same host = same value). Plaso-native
            # fields (filename, display_name) come from evidence and are stable.
            # But ingest_audit_id, pipeline_version, and source_dir change per run.
            _id = _doc_id(index_name, record, volatile_keys=volatile)

            # Provenance fields (added AFTER ID computation — same pattern as
            # parse_csv.py and parse_evtx.py)
            source = record.get("filename") or record.get("display_name") or source_dir
            if volume is not None and isinstance(source, str):
                source = source.lstrip("/")
            record["vhir.source_file"] = source
            if ingest_audit_id:
                record["vhir.ingest_audit_id"] = ingest_audit_id
            if pipeline_version:
                record["pipeline_version"] = pipeline_version
            if vss_id:
                record["vhir.vss_id"] = vss_id
            record["vhir.parse_method"] = "plaso"
            ts = record.get("timestamp")
            if (prefix or volume is not None) and isinstance(ts, int) and ts:
                try:  # exact to the microsecond; a value out of range is left unset
                    record["@timestamp"] = (_EPOCH + timedelta(microseconds=ts)).isoformat()
                except OverflowError:
                    pass
            actions.append({"_index": index_name, "_id": _id, "_source": record})

            if len(actions) >= 1000:
                flushed, failed = flush_bulk(client, actions)
                count += flushed
                bulk_failed += failed
                actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, bulk_failed


def parse_prefetch(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int]:
    """Parse .pf files with Plaso, index into OpenSearch.

    Returns (count_indexed, count_bulk_failed).
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="vhir-plaso-prefetch-"))
    try:
        jsonl_file = _run_plaso("prefetch", prefetch_dir, tmpdir)
        return _ingest_jsonl(
            jsonl_file,
            client,
            index_name,
            hostname,
            source_dir=source_file or str(prefetch_dir),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
            host_dict=host_dict,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_srum(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int]:
    """Parse SRUM database with Plaso, index into OpenSearch.

    The SRUM parser in Plaso is a plugin under the esedb parser.
    The correct specification is 'esedb/srum' (parser/plugin syntax).

    Returns (count_indexed, count_bulk_failed).
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="vhir-plaso-srum-"))
    try:
        jsonl_file = _run_plaso("esedb/srum", srum_path, tmpdir)
        return _ingest_jsonl(
            jsonl_file,
            client,
            index_name,
            hostname,
            source_dir=source_file or str(srum_path),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
            host_dict=host_dict,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# Plaso drops these without a warning; the README's "Plaso fallback: known
# gaps" section has the detail.
_KNOWN_GAPS = (
    "Plaso gives no events, and no warning, for dpkg.log under the linux preset, "
    "bash history lines without #epoch times, InstallHistory.plist, and launchd "
    "plists missing a key; year-less syslog takes its year from the file's time "
    "(see the README, Plaso fallback: known gaps)"
)


def plaso_status(
    pinfo: dict,
    volume_root: Path,
    os_name: str,
    zone: str | None,
    zone_source: str,
    zone_note: str = "",
) -> tuple[list[str], str]:
    """The not_read list and the note for one host's Plaso status entry.

    not_read: each file Plaso warned about while extracting, relative to the
    volume, with its warning count. The note: events per parser, the time
    zone the run used and where it came from, and for Linux and macOS the
    gaps Plaso leaves silently."""
    counters = pinfo.get("storage_counters", {})
    prefix = str(volume_root.resolve()).rstrip("/") + "/"
    not_read = []
    for spec, n in sorted(counters.get("warnings_by_path_spec", {}).items()):
        # The innermost location: on an image, the outer ones are the image's
        # own path and its partitions.
        locations = [
            line.partition("location: ")[2]  # last on its line; a path may hold ", "
            for line in spec.strip().splitlines()
            if "location: " in line
        ]
        location = locations[-1] if locations else spec.strip()
        if location.startswith(prefix):
            location = location[len(prefix) :]
        elif location.startswith("/"):
            location = location.lstrip("/")
        not_read.append(f"{location} ({n} extraction warnings)")
    parsers = {k: v for k, v in counters.get("parsers", {}).items() if k != "total"}
    events = ", ".join(f"{k} {v}" for k, v in sorted(parsers.items())) or "none"
    if zone_note:  # a run off an image: Plaso applies the volume's own zone
        tz = zone_note
    elif zone:
        tz = f"time zone {zone} ({zone_source})"
    else:
        tz = "time zone unknown: local-time events (SetupAPI, syslog, apt) stored as recorded"
    note = f"events by parser: {events}; {tz}"
    if os_name in ("linux", "macos"):
        note += f"; {_KNOWN_GAPS}"
    return not_read, note


WINDOWS_PARSERS = "sqlite/chrome_27_history,esedb/msie_webcache,text/setupapi"


def plaso_runs(host) -> tuple[list[tuple[str, Path]], str]:
    """The (parser expression, source) runs for a host's plaso artifact, and
    a note for its status (empty when none).

    Both keep filestat, Plaso's file timeline. On a mounted image its times
    are the file system's; on a folder they may be the copy's, and the note
    says so."""
    from opensearch_mcp.discover import PLASO_WINDOWS_DIRS
    from opensearch_mcp.paths import resolve_case_insensitive

    vr = host.volume_root
    if host.os == "windows":
        dirs = [resolve_case_insensitive(vr, d) for d in PLASO_WINDOWS_DIRS]
        return [(WINDOWS_PARSERS, d) for d in dirs if d is not None and d.is_dir()], ""
    # A Mac's unified logs (.tracev3) aren't in Plaso's macos preset.
    preset = "macos,unified_logging" if host.os == "macos" else host.os
    if host.image_path is not None:  # Plaso reads the volume off the image
        return [(preset, host.image_path)], ""
    if host.from_image:
        return [(preset, vr)], ""
    return [(preset, vr)], "file times may reflect the copy, not the original system"


_PLASO_TIMEOUT = 7200


def _process_tree(pid: int) -> set[int]:
    """pid and every process descended from it, read from /proc."""
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        ppid = int(stat.rpartition(")")[2].split()[1])
        children.setdefault(ppid, []).append(int(entry.name))
    tree, todo = set(), [pid]
    while todo:
        p = todo.pop()
        if p not in tree:
            tree.add(p)
            todo += children.get(p, [])
    return tree


def _kill_tree(pid: int) -> None:
    """KILL the process groups of pid and its descendants. Plaso's workers
    can outlive a TERM to their parent, so the whole group is killed; they
    run as the examiner, so no sudo is needed. Groups we can't signal (sudo's
    own process) are skipped. pid leads its own session, so its group is
    included even after pid exits and its workers are re-parented."""
    groups = {pid}
    for p in _process_tree(pid):
        try:
            groups.add(os.getpgid(p))
        except OSError:
            pass
    groups.discard(os.getpgrp())  # never our own (the ingest worker's) group
    for g in groups:
        try:
            os.killpg(g, signal.SIGKILL)
        except OSError:
            pass


def _log_tail(workdir: Path, lines: int = 20) -> str:
    """The last lines of log2timeline's log and its stderr, for a failure."""
    out = []
    try:
        with gzip.open(workdir / "l2t.log.gz", "rt", errors="replace") as f:
            out = f.read().splitlines()
    except (OSError, EOFError):
        pass
    try:
        out += (workdir / "l2t.out").read_text(errors="replace").splitlines()
    except OSError:
        pass
    return "\n".join(out[-lines:])


def can_sudo() -> bool:
    """Whether sudo runs here without a password prompt."""
    try:
        return (
            subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def run_plaso_volume(
    parsers: str,
    source: Path,
    workdir: Path,
    read_as_root: bool = False,
    timezone_name: str | None = None,
    timeout: int = _PLASO_TIMEOUT,
    extra: tuple[str, ...] = (),
) -> tuple[Path, dict]:
    """Run log2timeline over source, then psort and pinfo; return the JSONL
    path and pinfo's events and warnings sections.

    Everything Plaso writes (storage, logs, its temporary folders) is inside
    workdir, which is also every tool's working folder. read_as_root: the
    examiner with root's read capability only (sudo starts setpriv), so
    files only root can read are parsed, and nothing written is root's.
    log2timeline runs in its own session; on timeout its process tree is
    KILLed. A timeout or non-zero exit raises with the log's last lines."""
    tmp = workdir / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)  # Plaso refuses a missing one
    storage = workdir / "out.plaso"
    cmd = []
    if read_as_root:
        cmd = ["sudo", "-n", "setpriv", "--reuid", str(os.getuid()), "--regid"]
        cmd += [str(os.getgid()), "--init-groups", "--inh-caps", "+dac_read_search"]
        cmd += ["--ambient-caps", "+dac_read_search"]
    workers = max(1, min(8, (os.cpu_count() or 2) - 1))
    cmd += ["log2timeline.py", "--unattended", "--status_view", "none", "--workers"]
    cmd += [str(workers), "--parsers", parsers, "--logfile", str(workdir / "l2t.log.gz")]
    cmd += ["--temporary_directory", str(tmp), "--storage_file", str(storage)]
    if timezone_name:
        cmd += ["--timezone", timezone_name]
    cmd += [*extra, str(source)]
    with open(workdir / "l2t.out", "wb") as out:
        proc = subprocess.Popen(cmd, cwd=workdir, stdout=out, stderr=out, start_new_session=True)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc.pid)
            try:
                proc.wait(timeout=30)
                what = "killed"
            except subprocess.TimeoutExpired:  # the kill didn't take; never hang here
                what = f"still running (pid {proc.pid}) after a kill"
            raise RuntimeError(
                f"log2timeline {what} after {timeout} s; nothing from this run was "
                f"indexed. Log:\n{_log_tail(workdir)}"
            )
    if rc != 0:
        _kill_tree(proc.pid)  # workers left behind by a failed run
        raise RuntimeError(
            f"log2timeline exited {rc}; nothing from this run was indexed. "
            f"Log:\n{_log_tail(workdir)}"
        )
    jsonl = workdir / "out.jsonl"
    for tool_cmd in (
        ["psort.py", "--status_view", "none", "--logfile", str(workdir / "psort.log.gz")]
        + ["-o", "json_line", "--output_time_zone", "UTC", "-w", str(jsonl), str(storage)],
        ["pinfo.py", "--logfile", str(workdir / "pinfo.log.gz"), "--output_format", "json"]
        + ["--sections", "events,warnings", "-w", str(workdir / "pinfo.json"), str(storage)],
    ):
        subprocess.run(tool_cmd, cwd=workdir, check=True, capture_output=True, timeout=timeout)
    return jsonl, json.loads((workdir / "pinfo.json").read_text())


_INVENTORY = Path(__file__).with_name("volume_inventory.py")


def plaso_python() -> str:
    """The interpreter log2timeline.py runs under (its shebang), which has
    the dfVFS Plaso uses; the product's own venv doesn't."""
    path = shutil.which("log2timeline.py")
    try:
        first = Path(path).read_text(errors="replace").splitlines()[0] if path else ""
    except (OSError, IndexError):
        first = ""
    if first.startswith("#!") and "python" in first:
        return first[2:].split()[0]
    return "/usr/bin/python3"


def volume_inventory(image: Path, timeout: int = 300) -> tuple[list[dict], str]:
    """The image's volumes as the helper lists them, or ([], why not)."""
    try:
        result = subprocess.run(
            [plaso_python(), "-I", str(_INVENTORY), str(image)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return [], f"volumes not listed ({e}); the image is parsed from its mounts only"
    if result.returncode != 0:
        why = (result.stderr.strip().splitlines() or [f"exit {result.returncode}"])[-1]
        return [], f"volumes not listed ({why}); the image is parsed from its mounts only"
    leaves = []
    for line in result.stdout.splitlines():
        try:
            leaves.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return leaves, ""


def _selector_number(value: str) -> int | None:
    digits = "".join(c for c in value if c.isdigit())
    return int(digits) if digits else None


def plan_image_runs(leaves: list[dict]) -> tuple[list[dict], list[tuple[int, str]]]:
    """Plaso runs straight off the image for its Linux and macOS volumes,
    and a note for each volume no run covers.

    A run: {"label", "args", "os", "offset", "zone", "localtime"}. One per
    Linux or macOS file system: a plain partition, an LVM volume, or a whole
    APFS container (--volumes all; a container with a locked volume isn't
    run). Plaso reads a selector one character at a time, so a partition or
    volume numbered 10 or higher would select the wrong one: it isn't run.
    Windows volumes are left to the mounts. Each note comes with its byte
    offset, so a volume a mount went on to parse can be left out."""
    runs: list[dict] = []
    notes: list[tuple[int, str]] = []
    apfs: dict[str, list[dict]] = {}
    for leaf in leaves:
        sel = leaf.get("selector", {})
        if leaf.get("fs") == "APFS" or leaf.get("type") == "APFS_CONTAINER":
            apfs.setdefault(sel.get("partitions", ""), []).append(leaf)
            continue
        where = "/".join(v for v in (sel.get("partitions"), sel.get("volumes")) if v) or "image"
        off = leaf.get("offset", 0)
        at = f"{where} at offset {off}"
        if leaf.get("kind") == "locked":
            notes.append((off, f"{at}: locked (encrypted); not parsed"))
            continue
        if leaf.get("kind") != "filesystem":
            notes.append((off, f"{at}: no file system found; not parsed"))
            continue
        if leaf.get("os") == "windows":
            continue
        if leaf.get("os") not in ("linux", "macos"):
            notes.append(
                (off, f"{at}: {leaf.get('fs', '')} with no OS root; not parsed from the image")
            )
            continue
        args, ok = [], True
        for flag, key in (("--partitions", "partitions"), ("--volumes", "volumes")):
            if key in sel:
                n = _selector_number(sel[key])
                if n is None or n >= 10:
                    why = f"Plaso can't select {key} numbered 10 or higher; not parsed"
                    notes.append((off, f"{at}: {why}"))
                    ok = False
                    break
                args += [flag, str(n)]
        if ok:
            label = ":".join(v for v in (sel.get("partitions"), sel.get("volumes")) if v) or "fs"
            runs.append(_run(label, args, leaf))
    for part, group in apfs.items():
        off = group[0].get("offset", 0)
        at = f"APFS container {part or 'image'} at offset {off}"
        if any(g.get("kind") == "locked" for g in group):
            notes.append((off, f"{at}: a volume is locked (encrypted); not parsed"))
            continue
        n = _selector_number(part) if part else None
        if part and (n is None or n >= 10):
            notes.append(
                (off, f"{at}: Plaso can't select partitions numbered 10 or higher; not parsed")
            )
            continue
        args = (["--partitions", str(n)] if part else []) + ["--volumes", "all"]
        os_leaf = next((g for g in group if g.get("os") == "macos"), group[0])
        runs.append(_run(f"{part}:apfs" if part else "apfs", args, {**os_leaf, "os": "macos"}))
    return runs, notes


def _run(label: str, args: list[str], leaf: dict) -> dict:
    return {
        "label": label,
        "args": args + ["--vss_stores", "none"],
        "os": leaf["os"],
        "offset": leaf.get("offset", 0),
        "zone": leaf.get("zone"),
        "localtime": leaf.get("localtime", ""),
    }
