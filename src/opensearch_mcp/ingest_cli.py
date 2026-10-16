"""CLI for ingesting forensic evidence into OpenSearch."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sift_common.audit import AuditWriter

from opensearch_mcp import write_context as wc
from opensearch_mcp.client import get_client
from opensearch_mcp.ingest import discover, ingest
from opensearch_mcp.ingest_counts import describe, stored_counts
from opensearch_mcp.ingest_status import left_out, write_status
from opensearch_mcp.memory_tiers import TIERS
from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.paths import (
    NO_TIME_FIELD,
    TIME_NOT_UNDERSTOOD,
    members,
    no_time_field_note,
    vhir_dir,
)
from opensearch_mcp.tools import PER_PROFILE, TOOLS, scan_id_source

_ACTIVE_CASE_FILE = vhir_dir() / "active_case"
_SLOT_POLL = 2.0  # seconds between looks for a free place, while a confirmed run waits


def _case_dir_for(case_id: str) -> Path | None:
    """The on-disk case directory for `case_id` (`VHIR_CASES_DIR`, default
    `~/cases`), or None. Only a bare directory name is accepted."""
    from opensearch_mcp.write_context import case_dir_for

    return case_dir_for(case_id)


_gated = threading.local()  # units a walk already took through the gate, on this thread
_walking = threading.local()  # set while a walk's leaves run: they never end its run


def _scan_unit(case_id: str, path, hostname: str, source: str, origin: str = "argument",
               files=None):  # fmt: skip
    """The scan half of opening a unit: its host names recorded, and its
    write context opened (no write yet). Exits when the case has no
    directory, since no record may be stored without its machine."""
    from sift_common.host_identity import unit_locator

    from opensearch_mcp import names_scan
    from opensearch_mcp import write_context as wc

    case_dir = _case_dir_for(case_id)
    if case_dir is None or not (case_dir / "CASE.yaml").is_file():
        print(
            f"Error: no case directory for {case_id!r}: records can't be given their machine.",
            file=sys.stderr,
        )
        sys.exit(1)
    scanned = names_scan.files_unit(Path(path), hostname, list(files or []), case_dir)
    for u in names_scan.record(case_dir, [scanned]):
        print(f"  host names: {u['locator']}: {', '.join(u['names']) or '(none)'}")
    return wc.open_unit(
        case_dir,
        unit_locator(path, case_dir),
        hostname,
        source=source,
        origin=origin,
        run_id=os.environ.get("VHIR_INGEST_RUN_ID", ""),
        input_path=path,
    )


def _open_unit(
    case_id: str, path, hostname: str, source: str, origin: str = "argument", files=None
):
    """Scan one evidence argument (a file or folder) for host names, record
    them, open its write context, and hold the run at the gate until its
    hosts are confirmed: every record written until the next one belongs to
    this unit. A walk over several leaves gates them all at once first."""
    from opensearch_mcp import write_context as wc

    ctx = _scan_unit(case_id, path, hostname, source, origin, files)
    wc.set_current(ctx)
    if ctx.unit not in getattr(_gated, "units", ()):
        _gate(case_id, [ctx.unit])
    return ctx


def _gate_walk(case_id: str, leaves: list[tuple], run_id: str = "") -> None:
    """A walk's leaves, (path, hostname, files) each: every one scanned, then
    the run held at the gate once for all of them, so the examiner confirms
    the whole walk together; the leaves then go through without waiting."""
    units = [_scan_unit(case_id, p, h, "delimited", files=f).unit for p, h, f in leaves]
    _gate(case_id, units, run_id)
    _gated.units = set(units) | set(getattr(_gated, "units", ()))


# Every link a folder listing skipped in this run, by path: said once each as
# it is skipped, and named in the run's status
_linked_skipped: list[str] = []


def _listed(folder: Path, keep) -> list[Path]:
    """`folder`'s entries a folder ingest reads: `keep(entry)`, and not a link
    (the gate's walk skips links). A link `keep` would take is skipped and
    named, never dropped silently."""
    kept, links = members(folder)
    skipped = sorted(str(p) for p in links if keep(p) and str(p) not in _linked_skipped)
    if skipped:
        _linked_skipped.extend(skipped)
        print(
            f"Skipped {len(skipped)} linked file(s) in {folder}: a link isn't followed, "
            f"as the case's evidence walk skips it: {', '.join(Path(p).name for p in skipped)}"
        )
    return [p for p in kept if keep(p)]


def _delim_files(input_path: Path, only_files=None) -> list:
    """The files a delimited ingest of `input_path` reads."""
    exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
    files = (
        [input_path]
        if input_path.is_file()
        else sorted(_listed(input_path, lambda f: f.suffix.lower() in exts))
    )
    if only_files is not None:  # an auto-hosts sub-run: this host's files only
        files = [f for f in files if f in only_files]
    return files


def _gate(case_id: str, units: list[str], run_id: str = "") -> None:
    """Hold the run, writing nothing, until every unit's host names belong to
    a machine the examiner confirmed (or chose Start now for) in the Hosts
    tab; then take the case lock shared for the rest of the run, so no host
    rename can change machines under it. A cancelled run ends here."""
    from sift_common import host_gate
    from sift_common import host_identity as hi

    from opensearch_mcp import write_context as wc
    from opensearch_mcp.ingest_status import AWAITING, CANCELLED, write_status

    case_dir = _case_dir_for(case_id)
    if case_dir is None:
        return  # every caller has refused a case with no directory already
    run = run_id or os.environ.get("VHIR_INGEST_RUN_ID", "")
    started = datetime.now(timezone.utc).isoformat()

    def refused(why: str):
        if run:
            write_status(case_id, os.getpid(), run, "failed", [], {}, started, error=why)
        print(f"Error: {why}; nothing was written.", file=sys.stderr)
        sys.exit(1)

    # an unfinished host operation refuses the run at once: its hosts can't be
    # confirmed meanwhile, so it would only wait
    try:
        op = hi.unfinished_op(case_dir)
    except hi.HostLogError as e:
        op = {"error": str(e)}
    if op:
        from opensearch_mcp.host_ops import unfinished_note

        refused(op.get("error") or unfinished_note(op))

    shown: list = []

    def on_wait(summary: dict) -> None:
        # said once per change; the status is written on every poll, so it
        # stays fresh (a cleanup by age never takes it) and a launcher's
        # write over it is repaired within one poll
        if summary != (shown[-1] if shown else None):
            shown.append(summary)
            print(
                f"Waiting for host confirmation ({summary['unresolved']} host name(s)): "
                f"{summary['message']}.",
                file=sys.stderr,
            )
            for h in summary["hosts"]:
                print(f"  {h['locator']}: {h['raw'] or '(none)'}: {h['reason']}", file=sys.stderr)
        if run:  # the note is the line above; raw and locator as fields too
            hosts = [
                {"hostname": h["raw"] or h["locator"],
                 "artifacts": [{"name": "host confirmation", "status": "awaiting",
                                "note": f"{h['locator']}: {h['raw'] or '(none)'}: {h['reason']}",
                                "raw": h["raw"], "locator": h["locator"]}]}
                for h in summary["hosts"]
            ]  # fmt: skip
            write_status(case_id, os.getpid(), run, AWAITING, hosts,
                         {"unresolved": summary["unresolved"]}, started,
                         message=summary["message"])  # fmt: skip

    try:
        host_gate.wait_for_hosts(case_dir, run or f"cli-{os.getpid()}", units, on_wait)
    except host_gate.RunCancelled as e:
        if run:
            write_status(case_id, os.getpid(), run, CANCELLED, [], {}, started, error=str(e))
        print(f"Cancelled: {e}", file=sys.stderr)
        sys.exit(1)
    if run:
        _take_slot(case_dir, case_id, run, started)
    try:
        wc.hold(hi.case_lock(case_dir, shared=True))
        op = hi.unfinished_op(case_dir)
    except (hi.CaseLockBusy, hi.HostLogError) as e:
        op = {"error": str(e)}
    if op:
        from opensearch_mcp.host_ops import unfinished_note

        refused(op.get("error") or unfinished_note(op))
    if run:  # the run goes on: the launcher answers "started"
        from opensearch_mcp.ingest_status import mark_hosts_confirmed

        mark_hosts_confirmed(case_id, os.getpid(), run)


def _take_slot(case_dir, case_id: str, run: str, started: str) -> None:
    """Start the run once fewer than the most runs are running. Until then it
    waits, says so in its status, and a cancel in the Hosts tab ends it."""
    from sift_common import host_identity as hi

    from opensearch_mcp.ingest_status import (
        AWAITING,
        CANCELLED,
        SLOT_WAIT,
        take_slot,
        write_status,
    )

    def waiting():
        write_status(case_id, os.getpid(), run, AWAITING, [], {}, started, message=SLOT_WAIT)

    said = False
    while True:
        took = take_slot(case_id, os.getpid(), run, waiting)
        # a cancel made while it slept counts even when a place has just freed
        if run in hi.load(case_dir).cancelled:
            why = f"run {run} was cancelled in the Hosts tab"
            write_status(case_id, os.getpid(), run, CANCELLED, [], {}, started, error=why)
            print(f"Cancelled: {why}", file=sys.stderr)
            sys.exit(1)
        if took:
            return
        if not said:
            print(f"Waiting: {SLOT_WAIT}", file=sys.stderr)
            said = True
        time.sleep(_SLOT_POLL)


def _confirmed_name(case_dir, ctx) -> str:
    """For a unit opened with no host name: the name its confirmed machine
    holds for it, which its records then carry."""
    from sift_common import host_identity as hi

    state = hi.load(case_dir)
    named = sorted(raw for (unit, raw) in state.bindings if unit == ctx.unit)
    own = [r for r in named if r == state.machine_of_pair(ctx.unit, r).canonical]
    raw = (own or named or [""])[0]  # the machine's own name when it is one of them
    ctx.unit_raw = raw
    return raw


def _closes_write_context(fn):
    """Close any write context `fn` opened when it returns or raises."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        from opensearch_mcp import write_context as wc

        gated = getattr(_gated, "units", set())
        walking = getattr(_walking, "active", False)
        try:
            with wc.restoring():
                return fn(*args, **kwargs)
        finally:
            _gated.units = gated  # a walk's pass through the gate ends with it
            _walking.active = walking

    return wrapper


_run = threading.local()  # the run open on this thread: its writer and its step


def _run_writer():
    """The open run's audit writer, which wrote its step; a new one outside a run."""
    audit = getattr(_run, "audit", None)
    return audit if audit is not None else AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")


def _run_step(tool: str, input_attr: str):
    """A worker command's run: one entry, written before any of its steps or
    records, naming the input it was given (by the registry when it is
    registered evidence) and its place. A run inside a run (an archive's
    images) is part of it; a dry run writes nothing."""
    import functools

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(args, *a, **kw):
            if getattr(_run, "audit", None) is not None or getattr(args, "dry_run", False):
                return fn(args, *a, **kw)
            from opensearch_mcp import ops

            raw = getattr(args, input_attr, None)
            case_id = _resolve_case_id(getattr(args, "case", None))
            case_dir = _case_dir_for(case_id)
            audit = AuditWriter(mcp_name=f"opensearch-ingest-{os.getpid()}")
            if case_dir is not None and hasattr(audit, "_case_dir_resolver"):
                audit._case_dir_resolver = lambda: case_dir  # the run's case, active or not
            params = {
                "case_id": case_id,
                "input": str(raw or ""),
                "hostname": getattr(args, "hostname", "") or "",
                "run_id": os.environ.get("VHIR_INGEST_RUN_ID", ""),
            }
            # only registered evidence is ingested: the input must trace FULL
            # to it before anything of it is read or sent
            try:
                roots, folder = ops.gate(case_dir, raw) if raw else ([], {})
            except ops.Refused as r:
                ops.write(audit, tool, params=params, summary=f"REFUSED: {r.why}",
                          inputs=[ops.place(raw)], extra={"refused": {"path": r.path,
                          "reason": r.why, "fix": r.fix}})  # fmt: skip
                fix = f"\n  {r.fix}" if r.fix else ""
                if params["run_id"]:  # the status the examiner reads says why, and the fix
                    from opensearch_mcp.ingest_status import write_status

                    started = datetime.now(timezone.utc).isoformat()
                    why = f"not ingested: {r.why}" + (f"; {r.fix}" if r.fix else "")
                    write_status(case_id, os.getpid(), params["run_id"], "failed", [], {},
                                 started, error=why)  # fmt: skip
                print(f"Error: not ingested: {r.why}{fix}", file=sys.stderr)
                sys.exit(2)
            reg = ops.registered(case_dir, raw) if raw else None
            extra: dict = {"roots": roots}
            if folder:  # a registered folder: the manifest its files are read by
                extra["manifest_path"] = folder.get("manifest_path", "")
                extra["manifest_sha256"] = folder.get("manifest_sha256", "")
            step = ops.write(
                audit,
                tool,
                params=params,
                summary="the run, recorded before any of its steps",
                # an input an earlier operation wrote, by the hash it recorded
                inputs=[ops.place(raw) if reg else ops.large_input(case_dir, raw)]
                if raw
                else None,
                input_registered=[reg] if reg else None,
                extra=extra,
            )
            if not step:
                print(f"Error: {raw}: {ops.NO_ENTRY}.", file=sys.stderr)
                sys.exit(1)
            _run.audit, _run.step = audit, step
            ops.set_run(audit, case_dir, roots)
            try:
                return fn(args, *a, **kw)
            finally:
                _run.audit = _run.step = None
                ops.set_run(None, None)
                ops.reset_extracted()

        return wrapper

    return deco


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

    The index templates are installed by the process's first write
    (write_context.prepare_index, once per process), not here.
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


def _halt_hosts(hostname: str, artifact: str, failed_files: list) -> list:
    """A halted run's status hosts: the files it couldn't read before the halt."""
    if not failed_files:
        return []
    not_read = [f"{p} ({e})" for p, e in failed_files]
    entry = {"name": artifact, "not_read": not_read, "warnings_only": True}
    return [{"hostname": hostname, "artifacts": [entry]}]


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
    bulk_failed=0,
    bulk_failed_reason=None,
    counts=None,
    skipped_files=None,
    not_read=None,
    note="",
    rows_skipped=None,
    files_not_read=0,
    hosts_total=1,
    hosts_failed=0,
):
    """Write status for background ingest (delimited/json/accesslog/enrich).

    `rows_skipped` (a run's end) puts what it left out in the artifact: its
    rows skipped and its `files_not_read`. `hosts_total`: the hosts a split
    by host ingested (`hosts_failed` of them failed), 1 for one host.

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
    from opensearch_mcp.write_context import removed_note, second_copy_note

    if getattr(_walking, "active", False) and status in ("complete", "failed"):
        status = "running"  # a walk's leaf: the walk ends the run, once
    art = {"name": artifact_name, "status": status, "indexed": indexed, **(counts or {})}
    notes = [no_time_field_note()] if status != "running" else []
    notes.append(second_copy_note(hostname))
    notes.append(removed_note(hostname))
    notes.append(note)  # appended, never replacing a note already there
    if _linked_skipped:
        shown = ", ".join(_linked_skipped[:10]) + (", …" if len(_linked_skipped) > 10 else "")
        notes.append(
            f"{len(_linked_skipped)} linked file(s) or folder(s) skipped: a link "
            f"isn't followed, as the case's evidence walk skips it ({shown})"
        )
    if any(notes):
        art["note"] = "; ".join(n for n in notes if n)
    if error:
        art["error"] = error
    if skipped_files:  # not ingested, and the status has to say so
        art["skipped_files"] = list(skipped_files)
    if not_read:  # files that failed, or were not recognized: "path (reason)"
        art["not_read"] = list(not_read)
    if files_total:
        art["files_total"] = files_total
    if files_done:
        art["files_done"] = files_done
    if rows_skipped is not None:
        art["rows_skipped"] = rows_skipped
        art["files_not_read"] = files_not_read
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
            "hosts_total": hosts_total,
            "hosts_complete": max(hosts_total - hosts_failed, 0) if done else 0,
            **_kept_now(),
        },
        started=started,
        error=error,
        elapsed_seconds=elapsed,
        bulk_failed=bulk_failed,
        bulk_failed_reason=(
            get_last_bulk_reason() if bulk_failed_reason is None else bulk_failed_reason
        ),
    )


def _sum_counts(runs: list[tuple]) -> dict:
    """The sub-runs' counts summed, or {} when one that indexed has none
    (no partial totals)."""
    total: dict = {"stored": 0, "ignored_docs": 0, "ignored": {}}
    for indexed, counts in runs:
        if indexed and not counts:
            return {}
        for k in ("stored", "ignored_docs"):
            total[k] += counts.get(k, 0)
        for f, n in counts.get("ignored", {}).items():
            total["ignored"][f] = total["ignored"].get(f, 0) + n
    return total if any(indexed for indexed, _ in runs) else {}


def _filename_host(path: Path, hosts=()) -> str:
    """The host a file's name gives (names_scan.filename_host, knowing the
    hosts the run splits by: Kansa's <host>-<Module>.csv gives the host),
    lower-cased; "" when there is none."""
    from opensearch_mcp.names_scan import filename_host

    return filename_host(path, hosts).lower()


def _terminal_status(
    indexed: int, bulk_failed: int, reason: str, files: int = 0, not_read: list | tuple = ()
) -> tuple[str, str]:
    """(status, error) for a finished run: `failed` when no record was
    indexed and some failed, or when `files` were given and every one is in
    `not_read` ("path (why)": none was read), else `complete`. The token says
    which: records OpenSearch rejected, batches the transport gave up on (an
    outage must not read as a rejection), or no file read. The status reader
    takes the text before the first colon as the reason token, so the reason
    goes after it."""
    from opensearch_mcp.bulk import TRANSPORT_REASON_PREFIX
    from opensearch_mcp.ingest_status import ALL_RECORDS_REJECTED, NOTHING_READ, TRANSPORT_FAILED

    if bulk_failed > 0 and indexed == 0:
        if reason.startswith(TRANSPORT_REASON_PREFIX):
            return "failed", f"{TRANSPORT_FAILED}: {reason[len(TRANSPORT_REASON_PREFIX) :]}"
        return "failed", f"{ALL_RECORDS_REJECTED}: {reason or 'no reason recorded'}"
    if files and indexed == 0 and len(not_read) >= files:
        return "failed", f"{NOTHING_READ}: none of {files} file(s) was read, e.g. {not_read[0]}"
    return "complete", ""


def _exit_if_failed(status: str, error: str) -> None:
    """A run whose terminal status is `failed` (no file read, every record
    rejected, the transport gave up) exits 1, once its status is written (a
    walk's leaf leaves that to the walk), so a script or an MCP caller never
    reads a run that ingested nothing as success. A partial run is
    `complete`."""
    if status == "failed" and not getattr(_walking, "active", False):
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)


_VHIR_CONFIG = vhir_dir() / "config.yaml"


def _resolve_case_id(args_case: str | None) -> str:
    if args_case:
        # M1 path-traversal guard — hard-fail loud, not silent None
        # (WSL2 Test round-3 UX nit). A case_id with path components is
        # never legitimate; reject at entry so operator sees the error
        # immediately rather than the downstream "case dir not found".
        if Path(args_case).name != args_case:
            print(
                f"Error: invalid case_id {args_case!r} — must be a bare "
                "directory name, no path components.",
                file=sys.stderr,
            )
            sys.exit(2)
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


def _active_case_name() -> str:
    """The case `active_case` names, or "" when none is set."""
    active_case = vhir_dir() / "active_case"
    if not active_case.exists():
        return ""
    raw = active_case.read_text().strip()
    return Path(raw).name if raw else ""


def _ensure_case_active(case_id: str) -> None:
    """Make `case_id` the active case through the gateway's case_activate
    (which also moves the evidence share), and say on stderr what happened.

    Whether it worked is read from the active case pointer afterwards, never
    from the call's return. Nothing here writes the pointer or Samba itself.
    """
    previous = _active_case_name()
    if previous == case_id:
        return

    reason = ""
    try:
        from opensearch_mcp.gateway import call_tool

        result = call_tool("case_activate", {"case_id": case_id})
        if isinstance(result, dict) and result.get("error"):
            reason = str(result["error"])
    except Exception as e:
        reason = f"the gateway couldn't be reached: {e}"

    if _active_case_name() == case_id:
        was = f"it was {previous}" if previous else "no case was active"
        print(
            f"Case {case_id} is now the active case ({was}); "
            f"findings recorded from now on go to {case_id}.",
            file=sys.stderr,
        )
    else:
        reason = reason or "the active case didn't change"
        print(
            f"Case {case_id} wasn't made active ({reason}); run `vhir case activate {case_id}`.",
            file=sys.stderr,
        )


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
    """The alerts Hayabusa indexed, over `run_hayabusa_batch`'s results:
    `{"skipped": …}` for the whole run, else per host an int (its count), a
    failed dict (`status`, `error`, and `indexed`/`bulk_failed` when its
    alerts were rejected) or an empty dict (`status: empty`, `note`). A
    failed host's indexed alerts still count."""
    if not isinstance(hb_results, dict) or "skipped" in hb_results:
        return 0
    return sum(
        v if isinstance(v, int) else int(v.get("indexed") or 0)
        for v in hb_results.values()
        if isinstance(v, (int, dict))
    )


def _hayabusa_failed(hb_results) -> dict:
    """{host: outcome} of the hosts Hayabusa failed for."""
    if not isinstance(hb_results, dict):
        return {}
    return {
        h: v for h, v in hb_results.items() if isinstance(v, dict) and v.get("status") == "failed"
    }


def _merge_config(args: argparse.Namespace, config: dict) -> None:
    """Merge config file values into args (CLI takes precedence)."""
    # Before the no-config return: an MCP ingest passes no config file, and
    # its password arrives only in the environment.
    if not getattr(args, "password", None):
        # Prefer env var (set by server.py to avoid process list exposure)
        env_pw = os.environ.get("VHIR_ARCHIVE_PASSWORD", "")
        if env_pw:
            args.password = env_pw
        elif config and config.get("password"):
            args.password = config["password"]
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


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------


def _set_units(
    hosts,
    case_id: str,
    input_path: Path,
    tmpdir,
    hostname,
    name_origin: str,
    offsets=None,
    archive: tuple[Path, str] | None = None,
) -> None:
    """Give each discovered host its evidence unit: the input, plus the
    host's place in it when the input is an image or an archive (the volume
    offset, the volume Plaso reads, or the path inside the extraction), never
    the temporary mount, so a re-ingest is the same unit. `archive` is
    (archive, member) for an image that came out of an archive: its units
    are named by the archive and the image's name in it."""
    from sift_common.host_identity import unit_locator as _locator

    from opensearch_mcp import names_scan
    from opensearch_mcp.discover import find_volume_root

    case_dir = _case_dir_for(case_id)
    root, prefix = archive if archive else (input_path, "")

    def unit_locator(_input, _case_dir, member="", offset=None):
        member = "/".join(x for x in (prefix, member) if x and x != ".") or "."
        return _locator(root, _case_dir, member=member, offset=offset)

    def inside(path, root) -> str | None:
        try:
            return Path(path).relative_to(root).as_posix()
        except ValueError:
            return None

    for h in hosts:
        if name_origin and hostname and h.hostname == hostname and h.name_origin == "folder":
            h.name_origin = name_origin
        if h.unit_locator or tmpdir is None and h.image_path is None and not archive:
            continue  # a folder: its own volume root
        if h.image_path is not None:  # read straight off the image
            where = inside(h.image_path, tmpdir) if tmpdir is not None else None
            if archive and where == prefix:
                where = None  # the extracted image itself: the archive's member already
            if h.volume_offset is not None:  # a volume: as the dry run names it
                pre = "/".join(x for x in (prefix, where) if x and x != ".")
                h.unit_locator = names_scan.volume_locator(
                    root, case_dir, h.volume_offset, h.volume_label, prefix=pre
                )
                continue
            member = "/".join(x for x in (where, h.volume_label) if x and x != ".")
            h.unit_locator = unit_locator(input_path, case_dir, member=member or ".")
            continue
        vol = next((v for v in (offsets or {}) if inside(h.volume_root, v) is not None), None)
        if vol is not None:
            rest = inside(h.volume_root, vol)
            if find_volume_root(Path(vol)) == Path(h.volume_root):
                rest = "."  # its drive-letter folder (KAPE) is the volume, as the dry run keys it
            pre = "/".join(x for x in (prefix, "" if rest == "." else rest) if x)
            h.unit_locator = names_scan.volume_locator(root, case_dir, offsets[vol], prefix=pre)
        else:
            h.unit_locator = unit_locator(
                input_path, case_dir, member=inside(h.volume_root, tmpdir) or "."
            )


def _run_summary(result) -> str:
    """The scan's closing line: hosts, entries written, and the entries kept
    because the case already held them."""
    line = f"{len(result.hosts)} host(s), {result.total_indexed:,} entries indexed."
    if result.already_present:
        line += (
            f" {result.already_present:,} entries were already in the case"
            " and kept their first ingest."
        )
    return line


def _kept_now() -> dict:
    """The status totals' count of entries this run kept (the count is reset
    as each run starts), when there are any."""
    from opensearch_mcp.bulk import get_already_present

    return {"already_present": n} if (n := get_already_present()) else {}


def _kept_total(result) -> dict:
    """The status totals' count of entries kept, when there are any."""
    return {"already_present": result.already_present} if result.already_present else {}


def _record_scan(
    case_id: str, input_path: Path, hosts: list, image_notes: list, extra=(), archive=None
) -> list[dict]:
    """Record the scan's units and names in the case's host logs, print them,
    and return the summary. Volumes no reader covers are recorded as unnamed
    candidates, with why."""
    from opensearch_mcp import names_scan

    case_dir = _case_dir_for(case_id)
    if case_dir is None:
        return []
    units = list(extra)
    for h in hosts:  # one host's unreadable evidence never stops the scan
        try:
            units.append(
                names_scan.host_folder_unit(h, case_dir, archive[0] if archive else input_path)
            )
        except Exception as e:
            unit = names_scan.Unit(
                locator=h.unit_locator or str(h.volume_root), source="host folder"
            )
            unit.note = f"names couldn't be read: {type(e).__name__}: {e}"
            units.append(unit)
    # under the evidence it came from, never the run's temporary copy
    image, prefix = archive if archive else (input_path, "")
    units += [
        names_scan.noted_volume_unit(image, offset, note, case_dir, prefix=prefix)
        for offset, note in image_notes
    ]
    summary = names_scan.record(case_dir, units)
    for u in summary:
        names = ", ".join(u["names"]) or "(no name yet)"
        print(f"  host names: {u['locator']}: {names}")
        for key in ("note", "names_not_sampled", "names_sampled"):
            if u.get(key):
                print(f"    {u[key]}")
    return summary


def _ingest_each_extracted(command, args, archive: Path, images: list, examiner: str) -> None:
    """Ingest every image an archive held, one run each: each is its own
    evidence unit (the archive and the image's name in it) with its own run
    status, under the caller's run id plus the image's number."""
    import copy
    from datetime import datetime, timezone

    from opensearch_mcp.ingest_status import write_status

    base_run = os.environ.get("VHIR_INGEST_RUN_ID", "") or str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    failed = []
    outcome = []  # each image's run, for the archive's own status
    for n, image in enumerate(sorted(images), 1):
        sub = copy.copy(args)
        sub.path, sub.from_archive, sub.archive_member = str(image), str(archive), image.name
        print(f"\n--- {archive.name}: image {n} of {len(images)}: {image.name} ---")
        os.environ["VHIR_INGEST_RUN_ID"] = f"{base_run}-{n}"
        before = len(failed)
        try:
            command(sub, examiner=examiner)
        except SystemExit as e:  # one image's failure doesn't stop the others
            if e.code:
                failed.append(f"{image.name} (exit {e.code})")
        except Exception as e:
            failed.append(f"{image.name} ({type(e).__name__}: {e})")
        finally:
            os.environ["VHIR_INGEST_RUN_ID"] = base_run
        ok = len(failed) == before
        art = {"name": "image run", "status": "complete" if ok else "failed",
               "note": f"run {base_run}-{n}"}  # fmt: skip
        if not ok:
            art["error"] = failed[-1]
        outcome.append({"hostname": image.name, "artifacts": [art]})
    write_status(
        _resolve_case_id(getattr(args, "case", None)),
        os.getpid(),
        base_run,
        "failed" if failed else "complete",
        outcome,
        {"images": len(images), "images_failed": len(failed)},
        started,
        error=f"images that failed: {'; '.join(failed)}" if failed else "",
    )
    if failed:
        print(f"Images that failed: {'; '.join(failed)}", file=sys.stderr)
        sys.exit(1)


def _rebuilt_status_host(h) -> dict:
    """A host's status entry rebuilt from its result for the hayabusa phase,
    keeping the evtx files it dropped before parsing."""
    arts = [
        {
            "name": a.artifact,
            "status": "failed" if a.error else "complete",
            "indexed": a.indexed,
            **({"error": a.error} if a.error else {}),
            **({"not_read": a.not_read} if a.not_read else {}),
            **({"note": a.note} if a.note else {}),
        }
        for a in h.artifacts
    ]
    if h.evtx_dropped:
        evtx = next((a for a in arts if a["name"] == "evtx"), None)
        if evtx is None:  # every evtx file was dropped: nothing to parse
            evtx = {"name": "evtx", "status": "complete", "indexed": 0}
            arts.insert(0, evtx)
        evtx.update(h.evtx_dropped)
    return {"hostname": h.hostname, "artifacts": arts}


def _image_id(stem: str, key: Path, case_dir: Path | None = None) -> str:
    """A disk image's name for its volume hosts: its stem and a short hash of
    its path, the same on every ingest of that file and different for any
    other file (another folder, or a stem that differs only in case or
    punctuation). Inside the case directory the path is case-relative, so a
    renamed case folder keeps the name. For an image from an archive, `key`
    is the archive's path joined with the image's name, since its extracted
    copy moves every run."""
    from sift_common.host_identity import unit_locator

    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-.") or "image"
    digest = hashlib.sha256(unit_locator(key, case_dir).encode()).hexdigest()[:8]
    return f"{clean}-{digest}"


def _volume_host_name(image_id: str, volume: Path) -> str:
    """A volume's host name when the image gives no one name, so two images'
    vol1 never become one host."""
    return f"{image_id}-{volume.name}"


def _hostname_from_volumes(
    volumes: list[Path], notes: list[tuple[str, str]], image_id: str, names: dict | None = None
) -> str | None:
    """The registry hostname, taken only when exactly one volume holds an OS
    install and it is Windows. With two or more installs of any OS (a dual
    boot), no name is forced: each is ingested as its own host, named for the
    image and its volume, and a warning lists them. A Linux or macOS install
    is named for the image and its volume."""
    from opensearch_mcp.discover import find_volume_root, os_of_root
    from opensearch_mcp.hostname import detect_hostname_from_volume

    # the install on each volume: at its root, or under its drive-letter folder (KAPE)
    roots = {v: find_volume_root(v) or v for v in volumes}
    installs = [(v, kind) for v in volumes if (kind := os_of_root(roots[v]))]

    def native(v: Path, kind: str) -> str:
        return (detect_hostname_from_volume(roots[v]) if kind == "windows" else None) or "?"

    if len(installs) > 1:
        found = ", ".join(f"{v.name}: {kind} {native(v, kind)}" for v, kind in installs)
        # a volume an image run reads is that run's host, not <image>-vol<N>
        hosts = ", ".join(
            (names or {}).get(v) or _volume_host_name(image_id, v) for v, _ in installs
        )
        note = (
            f"{len(installs)} OS installs on this image ({found}); each is ingested "
            f"as its own host ({hosts}). The names come from the evidence: confirm in the "
            "Portal's Hosts tab whether they are one machine"
        )
        notes.append(("hostname", note))
        print(f"  WARNING: {note}", file=sys.stderr)
        return None
    if installs and installs[0][1] != "windows":
        v, kind = installs[0]
        print(f"  {kind} install on {v.name}: host {_volume_host_name(image_id, v)}")
        return None
    detected = detect_hostname_from_volume(roots[installs[0][0]]) if installs else None
    if detected:
        print(f"  Hostname from volume registry: {detected}")
    else:
        print(
            "  WARNING: could not detect hostname from registry; the host names come "
            "from the evidence's folder and file names (a weaker signal): confirm them "
            "in the Portal's Hosts tab",
            file=sys.stderr,
        )
    return detected


def _image_hosts(image: Path, image_id: str, examiner_hostname) -> tuple[list, dict, list]:
    """The Linux and macOS volumes Plaso reads straight off the image.

    Returns the hosts, {byte offset a run covers: its host's name}, and (offset, note)
    pairs for the volumes no run covers. A host is named from the examiner's
    --hostname or else for the image and its volume, never from a registry.
    """
    from opensearch_mcp.discover import DiscoveredHost, _valid_zone
    from opensearch_mcp.parse_plaso import plan_image_runs, volume_inventory

    leaves, error = volume_inventory(image)
    if error:
        print(f"  WARNING: {error}", file=sys.stderr)
        return [], {}, [(-1, error)]
    runs, notes = plan_image_runs(leaves)
    hosts = []
    for run in runs:
        name = examiner_hostname or f"{image_id}-{run['label'].replace(':', '-')}"
        host = DiscoveredHost(hostname=name, volume_root=image)
        host.os, host.image_path, host.image_args = run["os"], image, run["args"]
        host.volume_label = run["label"]
        host.volume_offset = run["offset"]
        host.artifacts.append(("plaso", image))
        if run["localtime"] == "link" and _valid_zone(run["zone"]):
            host.system_timezone, host.timezone_source = run["zone"], "etc/localtime"
            host.zone_note = (
                f"time zone {run['zone']} (the volume's etc/localtime, as Plaso read it)"
            )
        elif run["localtime"] == "link" and run["zone"]:  # Plaso can't use it either
            host.zone_note = (
                f"the volume's etc/localtime names a zone that can't be used ({run['zone']}): "
                "local-time events stored as recorded"
            )
        elif run["localtime"] == "file":
            host.zone_note = (
                "etc/localtime is not a link: Plaso may have used UTC or a "
                "fixed-offset abbreviation"
            )
        else:
            host.zone_note = "time zone unknown: local-time events stored as recorded"
        if run.get("zone_volume") and host.timezone_source == "etc/localtime":
            host.zone_note += (
                f"; zone from {run['zone_volume']}: this volume's zone applies to that volume; "
                "other volumes in the container without a zone file are stored as UTC"
            )
        hosts.append(host)
        print(f"  {name} ({run['os']}): {run['label']} read straight off the image")
    return hosts, {run["offset"]: h.hostname for run, h in zip(runs, hosts)}, notes


def _apply_zone_override(hosts: list, zone: str) -> None:
    """The examiner's --source-timezone, for every host it can reach. Plaso
    applies a zone it finds on an image volume (an etc/localtime link) ahead
    of --timezone, so there the override isn't passed, and the status says
    which zone was used."""
    from opensearch_mcp.discover import EXAMINER_ZONE

    for h in hosts:
        if h.image_path is not None and h.timezone_source == "etc/localtime":
            zone_from = h.zone_note.partition("; zone from ")[2]
            h.zone_note = (
                "examiner time-zone override not applied: Plaso used this volume's own "
                f"zone ({h.system_timezone}, from etc/localtime)"
            ) + (f"; zone from {zone_from}" if zone_from else "")
            continue
        if h.image_path is not None:  # passed to Plaso; a copied etc/localtime may still win
            copy = h.zone_note.startswith("etc/localtime is not a link")
            h.zone_note = f"time zone {zone} (examiner override)" + (
                "; this volume's etc/localtime is a copy, and a zone Plaso reads from it "
                "would be used instead"
                if copy
                else ""
            )
        h.system_timezone, h.timezone_source = zone, EXAMINER_ZONE


def _covered_names(mount_ctx, covered: dict) -> dict:
    """{mounted volume: the image host that reads it instead}."""
    return {v: covered[off] for v, off in mount_ctx.offsets.items() if off in covered}


def _under(path, folder) -> bool:
    try:
        Path(path).relative_to(folder)
    except ValueError:
        return False
    return True


def _volume_offsets(mount_ctx) -> dict[str, int]:
    """Each mounted volume's name and byte offset in its image."""
    return {mp.name: off for mp, off in mount_ctx.offsets.items() if off is not None and off >= 0}


def _discover_volumes(
    volumes: list[Path],
    hostname,
    force_hostname: bool,
    image_id: str,
    notes: list[tuple[str, str]] | None = None,
    offsets: dict | None = None,
    covered: set | None = None,
    parsed_offsets: set | None = None,
) -> list:
    """Hosts on each mounted volume of a disk image, so every install is found
    (a scan of their shared parent finds only the first). With no hostname for
    the image, a host named after its volume (vol1) is named for the image too.
    A volume with no host on it is noted: nothing on it is parsed.

    A Linux or macOS host on a volume whose offset an image run covered
    (`covered`) is left to that run. parsed_offsets gets the offset of every
    volume a host is kept for."""
    hosts = []
    for v in volumes:
        found = discover(v, hostname=hostname, force_hostname=force_hostname)
        offset = (offsets or {}).get(v)
        if covered and offset in covered:
            found = [h for h in found if h.os == "windows"]
        if found and parsed_offsets is not None and offset is not None:
            parsed_offsets.add(offset)
        if not found and notes is not None and not (covered and offset in covered):
            note = (
                f"{v.name} mounted; no Windows, Linux or macOS root found; "
                "nothing on it was parsed"
            )
            notes.append(("volume", note))
            print(f"  WARNING: {note}", file=sys.stderr)
        for h in found:
            h.from_image = True
            if not hostname and h.hostname == v.name:
                h.hostname = _volume_host_name(image_id, v)
        hosts += found
    return hosts


@_closes_write_context
@_run_step("idx_ingest", "path")
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

    # Absolute: Plaso and the volume helper run in their own work folders
    input_path = Path(args.path).resolve()
    from opensearch_mcp import names_scan

    # An image another run extracted from an archive: its units and image id
    # are named by the archive and the image's name in it.
    from_archive = None
    if getattr(args, "from_archive", None):
        from_archive = (Path(args.from_archive), args.archive_member)
    image_key = Path(args.from_archive) / args.archive_member if from_archive else input_path
    velociraptor = None
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
    # Where the scan's host name came from: an argument, or the evidence.
    name_origin = "argument" if hostname else ""
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
    volumes: list = []  # a disk image's mounted volumes
    image_id = ""  # the disk image's name for its volume hosts (_image_id)
    status_notes: list[tuple[str, str]] = []  # warnings for the run's status
    # Linux and macOS volumes Plaso reads straight off the image
    image_hosts: list = []
    image_covered: dict = {}  # their byte offsets: host names
    image_notes: list = []  # (offset, note) for volumes no image run covers
    examiner_hostname = getattr(args, "hostname", None)  # never the registry's

    # Register cleanup for abnormal exit (OOM kill, unhandled exception)
    import atexit

    atexit.register(mount_ctx.cleanup)
    finished = False  # the run's terminal status write, with its notes
    run_id = ""  # set when the ingest starts; a run stopped before then is the launcher's

    try:
        if container_type == "archive":
            tmpdir = make_ingest_tmpdir(case_id)
            print(f"Extracting {input_path.name}...")
            extract_container(input_path, tmpdir, password=password)
            from opensearch_mcp import ops
            from opensearch_mcp.containers import extraction_command

            try:  # the extraction, with every file it wrote, before any is read
                ops.extraction_step(
                    _run_writer(), _case_dir_for(case_id), input_path, tmpdir,
                    extraction_command(input_path, tmpdir),
                )  # fmt: skip
            except ops.NoEntry as e:
                print(f"Error: {input_path}: {e}.", file=sys.stderr)
                sys.exit(1)

            # Check for Velociraptor offline collector
            if is_velociraptor_collection(tmpdir):
                print("Detected Velociraptor offline collector")
                if not hostname:
                    hostname = read_velociraptor_hostname(tmpdir)
                    if hostname:
                        name_origin = "artifact"
                        print(f"  Hostname from collection: {hostname}")
                velociraptor = names_scan.velociraptor_unit(
                    tmpdir, input_path, _case_dir_for(case_id)
                )
                scan_root = normalize_velociraptor(tmpdir)
            else:
                # Check if extraction produced a disk image (e.g., VHDX.7z, E01.7z)
                _IMAGE_EXTS = {".vhdx", ".vhd", ".vmdk", ".e01", ".ex01", ".dd", ".raw", ".img"}
                _IMAGE_EXTS |= {".dmg", ".sparseimage"}  # read by Plaso, never mounted
                extracted_images = [
                    f for f in tmpdir.iterdir() if f.is_file() and f.suffix.lower() in _IMAGE_EXTS
                ]
                if len(extracted_images) > 1:  # each image: its own unit, mount and run
                    _ingest_each_extracted(
                        lambda a, examiner="": cmd_scan(a), args, input_path, extracted_images, ""
                    )
                    return
                if extracted_images:
                    img = extracted_images[0]
                    # its units: the archive and the image's name in it, as for
                    # an archive of several images
                    from_archive = (input_path, img.name)
                    image_id = _image_id(img.stem, input_path / img.name, _case_dir_for(case_id))
                    print(f"  Found disk image: {img.name}")
                    # Archive-basename stamp removed per host-identity spec
                    # (silent "admin01-triage" pollution). Registry detect
                    # against the mounted volume happens below after mount.
                    if detect_container(img) != "dmg":
                        volumes = mount_image(img, tmpdir, mount_ctx)
                    image_hosts, image_covered, image_notes = _image_hosts(
                        img, image_id, examiner_hostname
                    )
                    if not volumes and not image_hosts:
                        print(
                            "Error: no partition could be mounted or read from the extracted "
                            "image.",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    print(f"  Mounted {len(volumes)} volume(s)")

                    # shadow copies are read from a mount, never from extracted folders
                    if vss_flag and volumes and not mount_ctx.extracted:
                        # An E01's volumes are read from its raw stream, as mount_image does
                        ewf = img.suffix.lower() in (".e01", ".ex01")
                        vss_volumes = mount_vss(
                            tmpdir / "_ewf" / "ewf1" if ewf else img,
                            tmpdir,
                            mount_ctx,
                            _volume_offsets(mount_ctx),
                            status_notes,
                        )
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
                        hostname = _hostname_from_volumes(
                            volumes,
                            status_notes,
                            image_id,
                            _covered_names(mount_ctx, image_covered),
                        )
                        if hostname:
                            name_origin = "artifact"

                scan_root = tmpdir

        elif container_type in ("ewf", "raw", "nbd"):
            tmpdir = make_ingest_tmpdir(case_id)
            print(f"Mounting {input_path.name}...", flush=True)
            image_id = _image_id(input_path.stem, image_key, _case_dir_for(case_id))
            volumes = mount_image(input_path, tmpdir, mount_ctx)
            image_hosts, image_covered, image_notes = _image_hosts(
                input_path, image_id, examiner_hostname
            )
            if not volumes and not image_hosts:
                print(
                    "Error: no partition could be mounted or read from the disk image.",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"  Mounted {len(volumes)} volume(s)")

            # Priority-2 registry detect on the mounted volume. Takes
            # precedence over the previous input_path.stem fallback so
            # disk images get the real ComputerName, not the filename.
            # Warn on miss — see the archive-path block above for why.
            if not hostname and volumes:
                hostname = _hostname_from_volumes(
                    volumes, status_notes, image_id, _covered_names(mount_ctx, image_covered)
                )
                if hostname:
                    name_origin = "artifact"

            # VSS handling (from a mount, never from extracted folders)
            if vss_flag and not mount_ctx.extracted:
                # Get the raw path for VSS scanning
                # For EWF: the ewf1 file under the FUSE mount
                # For raw/nbd: the original file or nbd device
                ewf_raw = tmpdir / "_ewf" / "ewf1"
                if ewf_raw.exists():
                    vss_raw = ewf_raw
                else:
                    vss_raw = input_path
                unread_before = len(mount_ctx.failures)
                vss_volumes = mount_vss(
                    vss_raw, tmpdir, mount_ctx, _volume_offsets(mount_ctx), status_notes
                )
                if vss_volumes:
                    print(f"  Found {len(vss_volumes)} volume shadow copies")
                elif len(mount_ctx.failures) == unread_before:  # read, and none there
                    print("  No volume shadow copies found")

            scan_root = tmpdir

        elif container_type == "dmg":  # read by Plaso alone: no mount, no sudo
            tmpdir = make_ingest_tmpdir(case_id)
            image_id = _image_id(input_path.stem, image_key, _case_dir_for(case_id))
            image_hosts, image_covered, image_notes = _image_hosts(
                input_path, image_id, examiner_hostname
            )
            if not image_hosts:
                for _, note in image_notes:
                    print(f"  {note}", file=sys.stderr)
                print("Error: no Linux or macOS volume could be read from the image.")
                sys.exit(1)
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
        if volumes:  # a disk image: each mounted volume is scanned on its own
            parsed_offsets: set = set()
            hosts = _discover_volumes(
                volumes,
                hostname,
                force_hn,
                image_id,
                status_notes,
                offsets=mount_ctx.offsets,
                covered=image_covered,
                parsed_offsets=parsed_offsets,
            )
            image_notes = [(off, n) for off, n in image_notes if off not in parsed_offsets]
        else:
            skipped: list[str] = []
            hosts = discover(
                scan_root, hostname=hostname, force_hostname=force_hn, skipped=skipped
            )
            if skipped:
                note = (
                    f"{', '.join(skipped)}: no Windows, Linux or macOS root found; "
                    "nothing in them was parsed"
                )
                print(f"warning: {note}", file=sys.stderr)
                status_notes.append(("discovery", note))

        # --- Peek fallback ---
        # When registry detect missed AND discover() produced hosts with
        # directory/mount-scan-derived names (junk like `_mnt_1` because
        # the scan_root happens to be the tmpdir), peek at the first
        # parseable CSV/JSON artifact to pull a real hostname from the
        # priority list, so the names scan records a meaningful name
        # instead of mount-path junk.
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
                        h.name_origin = "artifact"

        # Preflight host discovery — auto-apply exact decisions to
        # the case dictionary BEFORE parsers run. v1 always proceeds;
        # response carries the proposal block so AI/operator can review.
        # Replaces the prior fail-loud `_classify_or_fail`.
        # Image hosts join before the host dictionary is consulted
        hosts += image_hosts
        if velociraptor is not None:  # the collection is one unit: its client
            for h in hosts:
                h.unit_locator = velociraptor.locator
        _set_units(
            hosts,
            case_id,
            input_path,
            tmpdir,
            hostname,
            name_origin,
            offsets=mount_ctx.offsets,
            archive=from_archive,
        )
        # The names scan: every unit and the host names its evidence gives,
        # recorded before anything is written. Records get their machine from
        # these logs, so the v1 host dictionary is no longer written.
        case_host_dict = None
        unread = image_notes + [  # partitions that didn't mount and no image run read
            (off, why) for off, why in mount_ctx.failed_offsets.items() if off not in image_covered
        ]
        _record_scan(
            case_id,
            input_path,
            hosts,
            unread,
            [velociraptor] if velociraptor else [],
            archive=from_archive,
        )

        # For disk images with VSS, create additional hosts per shadow copy
        if vss_flag and tmpdir and vss_volumes:  # a disk image, or one from an archive
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
                # The host and unit of the volume the shadow copy came from
                source = mount_ctx.vss_sources.get(v_id)
                live = [h for h in hosts if h.vss_id == "live"]
                base = next(
                    (h for h in live if source and _under(h.volume_root, tmpdir / source)),
                    None,
                )
                if base is not None:
                    name, unit, origin = base.hostname, base.unit_locator, base.name_origin
                else:  # no live host on its volume: that volume's own name and unit
                    from sift_common.host_identity import unit_locator

                    volume = tmpdir / (source or v_id)
                    name = examiner_hostname or _volume_host_name(image_id or "image", volume)
                    unit = unit_locator(
                        input_path,
                        _case_dir_for(case_id),
                        offset=_volume_offsets(mount_ctx).get(source or ""),
                    )
                    origin = "argument" if examiner_hostname else "folder"
                vss_host = DiscoveredHost(
                    hostname=name,
                    volume_root=vr,
                    vss_id=v_id,
                    unit_locator=unit,
                    name_origin=origin,
                )
                discover_artifacts(vss_host)
                if vss_host.artifacts or vss_host.evtx_dir:
                    hosts.append(vss_host)

        for _, note in image_notes:
            status_notes.append(("volume", note))
            print(f"  WARNING: {note}", file=sys.stderr)

        if exclude and "evtx" in exclude:  # event logs (and hayabusa) skipped
            for h in hosts:
                h.evtx_dir = None

        if not hosts:
            if not hostname:
                print(
                    "Error: No host directories found. Use --hostname for flat evidence dirs.",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(
                f"Error: No Windows, Linux or macOS artifacts found in {scan_root}",
                file=sys.stderr,
            )
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
            os_tag = f" ({host.os})" if host.os != "windows" else ""
            print(f"  {host.hostname}{os_tag}{vss_tag}: {evtx_note}{arts}")

        # Apply --source-timezone override to all hosts (priority 1)
        if tz_override:
            print(f"  Source timezone: {tz_override}")
            _apply_zone_override(hosts, tz_override)

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

        # Every host's unit and name recorded, then nothing written until
        # they're confirmed
        from opensearch_mcp import write_context as wc

        _scan_case_dir = _case_dir_for(case_id)
        _gate(
            case_id,
            [
                wc.host_context(
                    _scan_case_dir,
                    case_id,
                    h,
                    run_id,
                    input_path=from_archive[0] if from_archive else input_path,
                ).unit
                for h in hosts
            ],
            run_id,
        )

        client = get_client()
        _preflight_shard_capacity(
            client,
            "evtx",
            host_count=len(hosts) or 1,
            case_id=case_id,
            run_id=run_id,
        )

        audit = _run_writer()

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
                print(", ".join(parts) + describe(kw))
            elif event == "artifact_failed":
                print(f"FAILED: {kw['error']}")

        from opensearch_mcp.bulk import ShardCapacityExhausted
        from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER

        # The end of the run writes the terminal status, with its notes, so
        # every write before it stays `running`: a terminal status can't go
        # back to `running`.
        hayabusa_follows = not getattr(args, "no_hayabusa", False) and any(
            h.evtx_dir for h in hosts
        )
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
                host_dict=case_host_dict,
                final_status="running",  # finished below, with the run's notes
                case_dir=_case_dir_for(case_id),
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
        print(_run_summary(result))
        from opensearch_mcp.write_context import print_fill_report

        print_fill_report()
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
        if hayabusa_follows:
            # Not gated on hayabusa being installed: the batch reports that
            # itself, and the status then says detections were skipped.
            if any(h.evtx_dir for h in hosts):
                # Layer 6: update status to show Hayabusa phase
                from opensearch_mcp.bulk import get_last_bulk_reason
                from opensearch_mcp.ingest import run_hayabusa_batch

                # The ingest's own reason: hayabusa's bulk writes replace it.
                ingest_bulk_reason = get_last_bulk_reason()

                hayabusa_started = datetime.now(timezone.utc).isoformat()
                # BUG-4 fix: preserve full host/artifact checklist, append hayabusa
                existing_hosts = [_rebuilt_status_host(h) for h in result.hosts]
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
                        **_kept_total(result),
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
                    elif event == "hayabusa_empty":
                        print("no detections written")

                print("\nRunning Hayabusa detection...")
                hb_results = run_hayabusa_batch(
                    hosts,
                    client,
                    case_id,
                    audit=audit,
                    on_progress=_hayabusa_progress,
                    host_dict=case_host_dict,
                    case_dir=_case_dir_for(case_id),
                    run_tmpdir=tmpdir,
                    run_id=run_id,
                )
                total_alerts = _sum_hayabusa_alerts(hb_results)
                # Post-B84 visibility (UAT 2026-04-24): surface the
                # per-host failure count alongside indexed-total so
                # operators see that a partial-success summary actually
                # had failures, not the silent "N alerts" post-B84-guard
                # framing. Hayabusa failure dicts are values shaped
                # {"status": "failed", "error": "..."} per ingest.py:389.
                failed_by_host = _hayabusa_failed(hb_results)
                failed_hosts = len(failed_by_host)
                empty_notes = [
                    v["note"]
                    for v in (hb_results.values() if isinstance(hb_results, dict) else ())
                    if isinstance(v, dict) and v.get("status") == "empty"
                ]
                hb_rejected = sum(int(v.get("bulk_failed") or 0) for v in failed_by_host.values())
                if hb_rejected:  # the run's rejections include Hayabusa's alerts
                    total_bulk_failed += hb_rejected
                    if not ingest_bulk_reason:
                        from opensearch_mcp.bulk import get_last_bulk_reason

                        ingest_bulk_reason = get_last_bulk_reason()
                if total_alerts or failed_hosts:
                    line = f"Hayabusa: {total_alerts:,} alerts indexed"
                    if failed_hosts:
                        noun = "host" if failed_hosts == 1 else "hosts"
                        line += f" ({failed_hosts} {noun} failed — see progress log)"
                    print(line)

                # Layer 6: update status after Hayabusa (preserve full checklist)
                skipped = hb_results.get("skipped") if isinstance(hb_results, dict) else None
                if skipped or failed_hosts:
                    why = (
                        f"detections skipped: {skipped}. Install it with "
                        "`vhir setup hayabusa` (the current Hayabusa release; the "
                        "current SIFT release doesn't include it), then re-run the "
                        "ingest."
                        if skipped
                        else "; ".join(
                            f"{host}: {v.get('error', 'failed')}"
                            for host, v in failed_by_host.items()
                        )
                    )
                    existing_hosts[-1]["artifacts"][0].update(
                        {"status": "failed", "indexed": total_alerts, "error": why}
                    )
                    print(f"Hayabusa: {why}")
                else:
                    existing_hosts[-1]["artifacts"][0].update(
                        {"status": "complete", "indexed": total_alerts}
                    )
                if empty_notes:  # neither a failure nor "0 alerts": say what it may be
                    existing_hosts[-1]["artifacts"][0]["note"] = "; ".join(empty_notes)
                write_status(
                    case_id,
                    os.getpid(),
                    run_id,
                    "running",  # finished below, with the run's notes
                    existing_hosts,
                    {
                        "indexed": result.total_indexed + total_alerts,
                        **_kept_total(result),
                        "artifacts_total": n_arts,
                        "artifacts_complete": n_arts - (1 if skipped or failed_hosts else 0),
                        "hosts_total": len(existing_hosts),
                        "hosts_complete": len(existing_hosts)
                        - (1 if skipped or failed_hosts else 0),
                    },
                    hayabusa_started,
                    bulk_failed=total_bulk_failed,
                    bulk_failed_reason=ingest_bulk_reason,
                    elapsed_seconds=result.elapsed_seconds,
                )

        # Post-ingest triage enrichment
        if not getattr(args, "skip_triage", False):
            triage_note = ""
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
                    client=client, case_id=case_id, on_progress=_triage_progress, audit=audit
                )
                if "_gateway" in triage_results:
                    print(f"  Triage: {triage_results['_gateway']}")
                total_enriched = sum(
                    r.get("enriched", 0) for r in triage_results.values() if isinstance(r, dict)
                )
                failed = [
                    f"{k} ({r.get('reason', '')})"
                    for k, r in triage_results.items()
                    if isinstance(r, dict) and r.get("status") == "failed"
                ]
                if failed:
                    print(
                        f"Triage enrichment incomplete: {total_enriched} documents updated;"
                        f" not complete: {'; '.join(failed)}"
                    )
                    triage_note = f"enrichment incomplete: {'; '.join(failed)}"
                else:
                    print(f"Triage enrichment complete: {total_enriched} documents updated")
            except Exception as e:
                print(f"  Triage enrichment failed: {e}")
            if triage_note:
                status_notes.insert(0, ("triage", triage_note))

        # The run's one terminal write, with its notes, whether or not triage ran
        from opensearch_mcp.ingest_status import finish_status

        status_notes += [("mount", f) for f in mount_ctx.failures + mount_ctx.not_mounted]
        finish_status(case_id, os.getpid(), notes=status_notes, run_id=run_id)
        finished = True

    finally:
        if not finished:  # stopped early: the status keeps what the run had to say
            import os as _os  # `os` is bound later in this function

            from opensearch_mcp.ingest_status import add_notes

            mounts = [("mount", f) for f in mount_ctx.failures + mount_ctx.not_mounted]
            rid = run_id or _os.environ.get("VHIR_INGEST_RUN_ID", "")
            add_notes(case_id, _os.getpid(), status_notes + mounts, run_id=rid)
        mount_ctx.cleanup()
        if tmpdir:
            cleanup_tmpdir(tmpdir)


# ---------------------------------------------------------------------------
# csv subcommand
# ---------------------------------------------------------------------------


def _file_entry(
    audit, tool: str, f: Path, hostname: str, index_name: str, run_id, extra: dict | None = None
) -> str:
    """Write this file's entry (the file, its place, its hash or the registry's,
    and the run) before any of its records is indexed, so every id a record
    carries names the file it came from, even if the run stops part-way.
    ``(audit id, "")``, or ``("", why)`` when the file can't be read or its
    entry couldn't be written: it is then not indexed."""
    from sift_common import resolve_case_dir

    from opensearch_mcp import ops

    params = {"hostname": hostname, "index_name": index_name, "run_id": run_id or ""}
    run = ops.current_run()  # the run's own case (active or not), as it started
    case_dir = run[1] if run is not None else (resolve_case_dir() or None)
    try:
        aid, _sha = ops.read_step(
            audit, tool, f, case_dir=case_dir, params={**params, **(extra or {})}
        )
    except ops.NoEntry as e:  # unreadable (its failure recorded) or not recorded
        return "", str(e)
    return aid, ""


def _file_outcome(audit, aid: str, tool: str, summary: str, f: Path) -> None:
    """What became of a file after its entry: an entry of its own about it."""
    from opensearch_mcp import ops

    ops.later(audit, aid, tool, summary, {"file": str(f)})


@_closes_write_context
@_run_step("idx_ingest_csv", "csv_path")
def cmd_csv(args: argparse.Namespace) -> None:
    """Ingest a pre-parsed CSV (examiner identifies the tool).

    Single-file CSV ingest with explicit operator `--hostname`: the file is
    one evidence unit, scanned for names like any other.
    """
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
    from opensearch_mcp.write_context import index_name as _index_name

    _open_unit(case_id, csv_path, hostname, source=f"{tool_name} csv", files=[csv_path])
    index_name = _index_name(cfg.index_suffix)

    client = get_client()
    audit = _run_writer()
    pipeline_version = f"opensearch-mcp-{__version__}"

    run_id = os.environ.get("VHIR_INGEST_RUN_ID", "") or None
    print(f"Ingesting {csv_path.name} as {tool_name} -> {index_name}")
    entry = f"idx_ingest_csv_{tool_name}"
    aid, why = _file_entry(
        audit, entry, csv_path, hostname, index_name, run_id, {"tool": tool_name}
    )
    if not aid:
        print(f"Error: {csv_path}: {why}.", file=sys.stderr)
        sys.exit(1)

    case_host_dict = _load_case_host_dict(case_id)

    # a per-profile tool's row gets the scan route's id, from the file it read;
    # a row that can't is counted: by scan as well, it would be stored twice
    no_scan_id = [0]

    def id_source(row: dict) -> str:
        found = scan_id_source(tool_name, str(row.get("SourceFile") or ""))
        no_scan_id[0] += not found
        return found

    with wc.op(aid):
        count, sk, bf = ingest_csv(
            id_source=id_source if tool_name in PER_PROFILE else "",
            csv_path=csv_path,
            client=client,
            index_name=index_name,
            hostname=hostname,
            source_file=str(csv_path),
            ingest_audit_id=aid,
            pipeline_version=pipeline_version,
            natural_key=cfg.natural_key,
            time_field=cfg.time_field,
            host_dict=case_host_dict,
            row_host=tool_name != "jumplists",
            # the evtx index is searched and charted by @timestamp
            timestamp_from=cfg.time_field if cfg.index_suffix == "evtx" else "",
        )

    outcome = f"{count} indexed, {sk} skipped, {bf} bulk failed"
    twice = (
        f"{no_scan_id[0]} rows of {tool_name} couldn't be given a per-profile id: if the same "
        "profile is also ingested by scan they're stored twice, and identical rows from "
        "different profiles are stored as one"
    )
    _file_outcome(audit, aid, entry, f"{outcome}; {twice}" if no_scan_id[0] else outcome, csv_path)
    print(
        f"Indexed {count:,} entries"
        + (f" ({sk} skipped)" if sk else "")
        + (f", {bf} bulk failed" if bf else "")
    )
    if no_scan_id[0]:
        print(twice)


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


@_closes_write_context
@_run_step("idx_ingest_json", "path")
def cmd_ingest_json(args: argparse.Namespace, examiner: str = "unknown") -> None:
    NO_TIME_FIELD.clear()  # this run's files only
    TIME_NOT_UNDERSTOOD.clear()
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
    audit = _run_writer()
    case_host_dict = _load_case_host_dict(case_id)

    files = (
        [input_path]
        if input_path.is_file()
        else sorted(
            _listed(input_path, lambda f: f.suffix.lower() in (".json", ".jsonl", ".ndjson"))
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
        kept, links = members(input_path)
        subdirs = [d for d in kept if d.is_dir()]
        json_links = [p for p in links if p.suffix.lower() in (".json", ".jsonl", ".ndjson")]
        print(
            f"No .json/.jsonl/.ndjson files directly under {input_path} "
            f"(non-recursive walker: {len(kept)} entries, "
            f"{len(subdirs)} subdirectories ignored"
            + (
                f"; {len(json_links)} linked file(s) skipped: a link isn't followed"
                if json_links
                else ""
            )  # fmt: skip
            + "). "
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
    from opensearch_mcp.paths import stem_type
    from opensearch_mcp.write_context import index_name as _index_name

    _open_unit(case_id, input_path, hostname, source="json", files=files)
    total = total_sk = total_bf = 0
    _json_failed_files: list[tuple[str, str]] = []
    try:
        for idx, f in enumerate(files):
            suffix = stem_type("json", getattr(args, "index_suffix", None) or f.stem)
            index_name = _index_name(suffix)
            print(f"  {f.name} -> {index_name}...", end=" ", flush=True)
            aid, why = _file_entry(audit, "ingest_json", f, hostname, index_name, run_id)
            if not aid:
                _json_failed_files.append((str(f), why))
                print(f"skipped ({why})")
                continue
            try:
                with wc.op(aid):
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
                        host_dict=case_host_dict,
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
                _file_outcome(
                    audit, aid, "ingest_json", f"{cnt} indexed, {sk} skipped, {bf} bulk failed", f
                )
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
                _file_outcome(audit, aid, "ingest_json", f"FAILED: {str(e)[:200]}", f)
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
            hosts=_halt_hosts(hostname, "json", _json_failed_files),
            totals={},
            started=datetime.now(timezone.utc).isoformat(),
            error=f"{HALT_CIRCUIT_BREAKER}: {_sce}",
        )
        print(f"ABORT: {HALT_CIRCUIT_BREAKER}: {_sce}", file=sys.stderr)
        raise

    print(
        f"Done. {total:,} indexed, {left_out(total_sk, len(_json_failed_files))}, "
        f"{total_bf} bulk failed."
    )
    if no_time_field_note():
        print(no_time_field_note())
    if _json_failed_files:
        print(f"*** {len(_json_failed_files)} files failed to parse; continuing walk: ***")
        for path, err in _json_failed_files[:10]:
            print(f"  {path}: {err}")
        if len(_json_failed_files) > 10:
            print(f"  ... and {len(_json_failed_files) - 10} more")
    from opensearch_mcp.bulk import get_last_bulk_reason

    not_read = [f"{p} ({e})" for p, e in _json_failed_files]
    final_status, final_error = _terminal_status(
        total, total_bf, get_last_bulk_reason(), len(files), not_read
    )
    if run_id:
        _write_bg_status(
            case_id,
            run_id,
            final_status,
            hostname,
            "json",
            started_ts,
            time.monotonic() - start_mono,
            indexed=total,
            error=final_error,
            bulk_failed=total_bf,
            not_read=not_read,
            rows_skipped=total_sk,
            files_not_read=len(_json_failed_files),
        )
    _exit_if_failed(final_status, final_error)


# ---------------------------------------------------------------------------
# cmd_ingest_delimited — generic CSV/TSV/Zeek/bodyfile ingest
# ---------------------------------------------------------------------------


@_closes_write_context
@_run_step("idx_ingest_delimited", "path")
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
        # Each host's sub-run reads only the files named for it; a file named
        # for no listed host is left out, and said so. (A recursive walk names
        # its hosts from its subdirectories instead.)
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        flat = (
            [] if is_recursive else sorted(_listed(input_path, lambda f: f.suffix.lower() in exts))
        )
        wanted = {h.lower() for h in auto_hosts}
        unattributed = [f.name for f in flat if _filename_host(f, wanted) not in wanted]
        if unattributed:
            print(
                f"Skipped {len(unattributed)} file(s) whose name gives none of the hosts "
                f"({', '.join(sorted(wanted))}): {', '.join(unattributed)}"
            )
        hosts_indexed = hosts_failed = hosts_files = hosts_sk = 0
        hosts_reason = ""
        host_counts: list[tuple] = []
        missed: list[str] = []  # each sub-run starts its own list
        not_understood: list[tuple[str, str, int]] = []
        not_read: list[str] = []
        if not is_recursive and not getattr(args, "dry_run", False):
            # (a recursive sub-run gates its own walk; a dry run writes nothing)
            _gate_walk(case_id, [
                (input_path, h, _delim_files(input_path, [f for f in flat
                                                          if _filename_host(f, wanted)
                                                          == h.lower()]))
                for h in auto_hosts
            ], run_id or "")  # fmt: skip
        was_walking, _walking.active = getattr(_walking, "active", False), True
        for h in auto_hosts:
            sub_args = copy.copy(args)
            sub_args.hostname = h
            sub_args.auto_hosts = ""
            if not is_recursive:
                sub_args.only_files = [f for f in flat if _filename_host(f, wanted) == h.lower()]
            print(f"\n--- Host: {h} ---")
            result = cmd_ingest_delimited(sub_args, examiner=examiner)
            missed.extend(NO_TIME_FIELD)
            not_understood.extend(TIME_NOT_UNDERSTOOD)
            if result:
                hosts_indexed += result[0]
                hosts_failed += result[1]
                hosts_reason = hosts_reason or result[2]
                host_counts.append((result[0], result[3]))
                not_read.extend(result[4])
                hosts_files += result[5]
                hosts_sk += result[6]
        _walking.active = was_walking
        # Each host's own final write lands in this same status file, so the
        # last one would stand for the whole run; write the sum. A clean
        # no-op (no hosts) still ends `complete`.
        NO_TIME_FIELD[:] = list(dict.fromkeys(missed))
        TIME_NOT_UNDERSTOOD[:] = not_understood
        final_status, final_error = _terminal_status(
            hosts_indexed, hosts_failed, hosts_reason, hosts_files, not_read
        )
        if run_id:
            _write_bg_status(
                case_id,
                run_id,
                final_status,
                "(auto-hosts)",
                "delimited",
                started_ts,
                indexed=hosts_indexed,
                error=final_error,
                bulk_failed=hosts_failed,
                bulk_failed_reason=hosts_reason,
                counts=_sum_counts(host_counts),
                skipped_files=unattributed,
                not_read=not_read,
                rows_skipped=hosts_sk,
                files_not_read=len(not_read) + len(unattributed),
                hosts_total=len(auto_hosts),
            )
        _exit_if_failed(final_status, final_error)
        counts = _sum_counts(host_counts)
        return hosts_indexed, hosts_failed, hosts_reason, counts, not_read, hosts_files, hosts_sk

    # Recursive mode: iterate subdirs as hosts in a single process
    if is_recursive and input_path.is_dir():
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        subdirs = sorted(
            d
            for d in _listed(input_path, lambda d: d.is_dir())
            if d.is_dir()
            and not d.name.startswith(".")
            and any(f.is_file() for f in _listed(d, lambda f: f.suffix.lower() in exts))
        )
        import copy

        from opensearch_mcp.bulk import ShardCapacityExhausted as _SCE

        _failed_subdirs: list[tuple[str, str]] = []  # (path, error[:200])
        walk_indexed = walk_failed = walk_files = walk_sk = 0  # a failed subdir counts as one
        walk_reason = ""
        walk_counts: list[tuple] = []
        walk_missed: list[str] = []  # each sub-run starts its own list
        walk_not_understood: list[tuple[str, str, int]] = []
        not_read: list[str] = []
        if not getattr(args, "dry_run", False):  # a dry run writes nothing: no gate
            _gate_walk(case_id, [(d, d.name, _delim_files(d)) for d in subdirs], run_id or "")
        was_walking, _walking.active = getattr(_walking, "active", False), True
        for d in subdirs:
            sub_args = copy.copy(args)
            sub_args.path = str(d)
            sub_args.hostname = d.name
            sub_args.recursive = False
            print(f"\n--- Host: {d.name} ---")
            try:
                result = cmd_ingest_delimited(sub_args, examiner=examiner)
                walk_missed.extend(NO_TIME_FIELD)
                walk_not_understood.extend(TIME_NOT_UNDERSTOOD)
                if result:
                    walk_indexed += result[0]
                    walk_failed += result[1]
                    walk_reason = walk_reason or result[2]
                    walk_counts.append((result[0], result[3]))
                    not_read.extend(result[4])
                    walk_files += result[5]
                    walk_sk += result[6]
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
                not_read.append(f"{d} ({str(e)[:200]})")
                walk_files += 1
                print(f"  SUBDIR SKIPPED ({d.name}): {e}", file=sys.stderr)
        _walking.active = was_walking
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
        NO_TIME_FIELD[:] = list(dict.fromkeys(walk_missed))
        TIME_NOT_UNDERSTOOD[:] = walk_not_understood
        final_status, final_error = _terminal_status(
            walk_indexed, walk_failed, walk_reason, walk_files, not_read
        )
        if run_id:
            # Each subdir's own final write lands in this same status file,
            # so the last one would stand for the whole walk; write the sum.
            _write_bg_status(
                case_id,
                run_id,
                final_status,
                hostname or "(recursive)",
                "delimited",
                started_ts,
                indexed=walk_indexed,
                error=final_error,
                bulk_failed=walk_failed,
                bulk_failed_reason=walk_reason,
                counts=_sum_counts(walk_counts),
                not_read=not_read,
                rows_skipped=walk_sk,
                files_not_read=len(not_read),
                hosts_total=len(subdirs),
                hosts_failed=len(_failed_subdirs),
            )
        _exit_if_failed(final_status, final_error)
        # A caller summing hosts (`--auto-hosts` with `--recursive`) reads these.
        counts = _sum_counts(walk_counts)
        return walk_indexed, walk_failed, walk_reason, counts, not_read, walk_files, walk_sk
    NO_TIME_FIELD.clear()  # this run's files only (a wrapper collects them)
    TIME_NOT_UNDERSTOOD.clear()
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
    audit = _run_writer()
    file_aids: list[str] = []
    case_host_dict = _load_case_host_dict(case_id)

    files = _delim_files(input_path, getattr(args, "only_files", None))

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
    from opensearch_mcp.paths import stem_type
    from opensearch_mcp.write_context import index_name as _index_name

    _open_unit(case_id, input_path, hostname, source="delimited", files=files)
    total = total_sk = total_bf = 0
    touched: set[str] = set()
    _delim_failed_files: list[tuple[str, str]] = []  # (path, error[:200])
    try:
        for idx, f in enumerate(files):
            fmt = {"format": format_override} if format_override else _detect_delimited_format(f)
            detected = fmt.get("format", "csv")
            user_suffix = getattr(args, "index_suffix", None)
            if user_suffix:
                prefix, _, stem = user_suffix.partition("-")
                if prefix not in ("delim", "zeek", "bodyfile") or not stem:
                    prefix, stem = "delim", user_suffix
            elif detected in ("zeek", "bodyfile"):
                prefix, stem = detected, f.stem
            else:
                prefix, stem = "delim", f.stem
            suffix = stem_type(prefix, stem)
            index_name = _index_name(suffix)
            print(f"  {f.name} ({detected}) -> {index_name}...", end=" ", flush=True)
            if detected == "unknown":
                print("skipped (unrecognized format)")
                _delim_failed_files.append((str(f), "unrecognized format"))
                continue
            aid, why = _file_entry(audit, "ingest_delimited", f, hostname, index_name, run_id)
            if not aid:
                _delim_failed_files.append((str(f), why))
                print(f"skipped ({why})")
                continue
            file_aids.append(aid)
            try:
                with wc.op(aid):
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
                        host_dict=case_host_dict,
                    )
                print(f"{cnt:,} entries")
                if hr:
                    print("    NOTE: 'host' renamed to 'source_host' (conflicts with host.name)")
                total += cnt
                total_sk += sk
                total_bf += bf
                touched.add(index_name)
                _file_outcome(
                    audit,
                    aid,
                    "ingest_delimited",
                    f"{cnt} indexed, {sk} skipped, {bf} bulk failed",
                    f,
                )
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
                _file_outcome(audit, aid, "ingest_delimited", f"FAILED: {str(e)[:200]}", f)
    except ShardCapacityExhausted as _sce:
        write_status(
            case_id=case_id,
            pid=os.getpid(),
            run_id=run_id or "",
            status="failed",
            hosts=_halt_hosts(hostname, "delimited", _delim_failed_files),
            totals={},
            started=datetime.now(timezone.utc).isoformat(),
            error=f"{HALT_CIRCUIT_BREAKER}: {_sce}",
        )
        print(f"ABORT: {HALT_CIRCUIT_BREAKER}: {_sce}", file=sys.stderr)
        raise

    counts = stored_counts(client, ",".join(sorted(touched)), file_aids) if touched else {}
    print(
        f"Done. {total:,} indexed, {left_out(total_sk, len(_delim_failed_files))}, "
        f"{total_bf} bulk failed{describe(counts)}."
    )
    if no_time_field_note():
        print(no_time_field_note())
    if _delim_failed_files:
        print(f"*** {len(_delim_failed_files)} files failed to parse; continuing walk: ***")
        for path, err in _delim_failed_files[:10]:
            print(f"  {path}: {err}")
        if len(_delim_failed_files) > 10:
            print(f"  ... and {len(_delim_failed_files) - 10} more")
    from opensearch_mcp.bulk import get_last_bulk_reason

    reason = get_last_bulk_reason()
    not_read = [f"{p} ({e})" for p, e in _delim_failed_files]
    final_status, final_error = _terminal_status(total, total_bf, reason, len(files), not_read)
    if run_id:
        _write_bg_status(
            case_id,
            run_id,
            final_status,
            hostname,
            "delimited",
            started_ts,
            time.monotonic() - start_mono,
            indexed=total,
            error=final_error,
            bulk_failed=total_bf,
            counts=counts,
            not_read=not_read,
            rows_skipped=total_sk,
            files_not_read=len(_delim_failed_files),
        )
    _exit_if_failed(final_status, final_error)
    # The recursive walk shares this run's status file and sums these.
    return total, total_bf, reason, counts, not_read, len(files), total_sk


# ---------------------------------------------------------------------------
# cmd_ingest_accesslog — Apache/Nginx access log ingest
# ---------------------------------------------------------------------------


def accesslog_suffix(wanted: str | None) -> str:
    """An access-log index's type: `accesslog`, or a suffix of the caller's own
    kept under `accesslog-`, so the index always takes the access-log template
    (keyword identity fields)."""
    from opensearch_mcp.paths import stem_type

    if not wanted or wanted == "accesslog":
        return "accesslog"
    return stem_type("accesslog", wanted)


@_closes_write_context
@_run_step("idx_ingest_accesslog", "path")
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
    audit = _run_writer()
    case_host_dict = _load_case_host_dict(case_id)
    suffix = accesslog_suffix(getattr(args, "index_suffix", None))

    files = (
        [input_path]
        if input_path.is_file()
        else sorted(
            f
            for f in _listed(
                input_path,
                lambda f: f.suffix.lower() in (".log", ".txt") or "access" in f.name.lower(),
            )
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

    from sift_common.host_identity import unit_locator

    from opensearch_mcp.bulk import ShardCapacityExhausted
    from opensearch_mcp.ingest_status import HALT_CIRCUIT_BREAKER
    from opensearch_mcp.write_context import index_name as _index_name

    ctx = _open_unit(case_id, input_path, hostname, source="access log", files=files)
    total = total_sk = total_bf = 0
    _alog_failed_files: list[tuple[str, str]] = []
    _alog_unindexed: list[str] = []  # read, but no line of it indexed
    try:
        for idx, f in enumerate(files):
            index_name = _index_name(suffix)
            print(f"  {f.name} -> {index_name}...", end=" ", flush=True)
            aid, why = _file_entry(audit, "ingest_accesslog", f, hostname, index_name, run_id)
            if not aid:
                _alog_failed_files.append((str(f), why))
                print(f"skipped ({why})")
                continue
            try:
                with wc.op(aid):
                    cnt, sk, bf = ingest_accesslog(
                        f,
                        client,
                        index_name,
                        hostname,
                        time_from=time_from,
                        time_to=time_to,
                        source_file=unit_locator(f, ctx.case_dir),
                        ingest_audit_id=aid,
                        pipeline_version=f"opensearch-mcp-{__version__}",
                        host_dict=case_host_dict,
                    )
                print(f"{cnt:,} entries ({sk} skipped)")
                total += cnt
                total_sk += sk
                total_bf += bf
                if not cnt and sk:  # read, and not one line indexed
                    why = f"no line indexed: {sk} line(s) unrecognised"
                    if time_from or time_to:
                        why += " or outside the time window"
                    _alog_unindexed.append(f"{f} ({why})")
                _file_outcome(
                    audit,
                    aid,
                    "ingest_accesslog",
                    f"{cnt} indexed, {sk} skipped, {bf} bulk failed",
                    f,
                )
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
                _file_outcome(audit, aid, "ingest_accesslog", f"FAILED: {str(e)[:200]}", f)
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

    print(
        f"Done. {total:,} indexed, {left_out(total_sk, len(_alog_failed_files))}, "
        f"{total_bf} bulk failed."
    )
    from opensearch_mcp.write_context import print_fill_report

    print_fill_report()
    if _alog_failed_files:
        print(f"*** {len(_alog_failed_files)} files failed to parse; continuing walk: ***")
        for path, err in _alog_failed_files[:10]:
            print(f"  {path}: {err}")
        if len(_alog_failed_files) > 10:
            print(f"  ... and {len(_alog_failed_files) - 10} more")
    from opensearch_mcp.bulk import get_last_bulk_reason

    reason = get_last_bulk_reason()
    failed = [f"{path} ({err})" for path, err in _alog_failed_files]
    final_status, error = _terminal_status(total, total_bf, reason, len(files), failed)
    if run_id:
        _write_bg_status(
            case_id,
            run_id,
            final_status,
            hostname,
            "accesslog",
            started_ts,
            time.monotonic() - start_mono,
            indexed=total,
            error=error,
            bulk_failed=total_bf,
            bulk_failed_reason=reason,
            not_read=failed + _alog_unindexed,
            rows_skipped=total_sk,
            files_not_read=len(failed),
        )
    _exit_if_failed(final_status, error)


# ---------------------------------------------------------------------------
# cmd_enrich_intel — threat intel enrichment
# ---------------------------------------------------------------------------


def cmd_enrich_intel(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Enrich indexed data with threat intel (lookup_ioc, each platform's records).

    Progress is written to the shared `ingest-status` dir with
    `artifact_name="intel"` so the async MCP entry point
    (`idx_enrich_intel` via `_launch_enrich_background`) can surface
    it through `idx_ingest_status`.
    """
    case_id = _resolve_case_id(getattr(args, "case", None))
    force = getattr(args, "force", False)
    include_filesystem = getattr(args, "include_filesystem", False)

    from opensearch_mcp.threat_intel import (
        IntelEnrichmentHalted,
        enrich_case,
        extract_unique_iocs,
    )

    client = get_client()

    if getattr(args, "dry_run", False):
        from opensearch_mcp.case_scope import case_read_scope

        iocs = extract_unique_iocs(
            client,
            case_read_scope(case_id, client),
            force=force,
            include_filesystem=include_filesystem,
        )
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

    def _write_enrich_status(status, indexed=0, files_done=0, files_total=0, error="", note=""):
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
            note=note,
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
                print(f"Looking up {total} IOCs with lookup_ioc (threat intel)...")
                _write_enrich_status("running", files_total=total)
        elif event == "stamping":
            print(f"Stamping {kw['matched']} matched IOCs to documents...")

    from opensearch_mcp.host_ops import case_writes
    from opensearch_mcp.write_context import case_dir_for

    case_dir = case_dir_for(case_id)
    try:
        with case_writes(case_dir) if case_dir is not None else contextlib.nullcontext():
            result = enrich_case(
                client,
                case_id,
                force=force,
                on_progress=_progress,
                include_filesystem=include_filesystem,
                audit=_run_writer(),
            )
    except Exception as e:  # noqa: BLE001
        # Terminal failed write with the real exception text so
        # idx_ingest_status surfaces *why* enrichment failed without
        # forcing the operator into the log file. The excepthook guard
        # would otherwise stamp "process_died_unexpectedly: …" which
        # misframes a caught exception as an uncaught crash.
        # Length-cap so a verbose stacktrace doesn't bloat the status
        # JSON beyond ~1KB.
        # A run halted after stamping modified documents: its counts go
        # to the status and the audit trail before the failure is raised.
        halted = e.summary if isinstance(e, IntelEnrichmentHalted) else None
        for warning in (halted or {}).get("warnings", []):
            print(f"WARNING: {warning}", file=sys.stderr)
        _write_enrich_status(
            "failed",
            indexed=halted["documents_updated"] if halted else 0,
            error=f"{type(e).__name__}: {e}"[:500],
            note="; ".join((halted or {}).get("warnings", [])),
        )
        if halted:
            _audit_enrichment(case_id, force, halted, incomplete=str(e))
        print(f"Enrichment failed: {e}", file=sys.stderr)
        raise

    if result["status"] == "no_iocs":
        print("No external IOCs found in indexed data.")
        _write_enrich_status("complete")
        return

    print(f"\nDone. {result['documents_updated']} documents updated.")
    print(f"  Matched: {result['matched']} IOC(s)")
    print(f"  Not found: {result['not_found']} IOC(s)")
    print(f"  Unavailable: {result['unavailable']} IOC(s)")
    for warning in result.get("warnings", []):
        print(f"WARNING: {warning}", file=sys.stderr)

    _write_enrich_status(
        "complete",
        indexed=result.get("documents_updated", 0),
        files_done=_progress_state["done"] or result.get("iocs_looked_up", 0),
        files_total=_progress_state["total"] or result.get("iocs_extracted", 0),
        note="; ".join(result.get("warnings", [])),
    )

    _audit_enrichment(case_id, force, result)


def _audit_enrichment(case_id: str, force: bool, result: dict, incomplete: str = "") -> None:
    """What an enrichment run that stamped documents did: an entry about its
    reference step, which was written before its first write."""
    summary = (
        f"{result['documents_updated']} docs updated, "
        f"{result.get('matched', 0)} matched, {result.get('not_found', 0)} not found, "
        f"{result.get('unavailable', 0)} unavailable"
    )
    if result.get("warnings"):
        summary += "; " + " ".join(result["warnings"])
    if incomplete:
        summary += f"; incomplete: {incomplete[:300]}"
    from opensearch_mcp import ops

    # what the run did: a later fact about its reference step
    ops.later(_run_writer(), result.get("reference_op", ""), "enrich_intel", summary,
              {"case_id": case_id, "force": force})  # fmt: skip


# ---------------------------------------------------------------------------
# cmd_ingest_memory — memory forensics entry point
# ---------------------------------------------------------------------------


@_closes_write_context
@_run_step("idx_ingest_memory", "path")
def cmd_ingest_memory(args: argparse.Namespace, examiner: str = "unknown") -> None:
    """Parse a memory image with Volatility 3 and index results."""
    from opensearch_mcp import __version__
    from opensearch_mcp.bulk import ShardCapacityExhausted, reset_circuit_breaker
    from opensearch_mcp.parse_memory import (
        TIER_1,
        TIER_2,
        TIER_3,
        all_failed_error,
        ingest_memory,
    )

    reset_circuit_breaker()

    image_path = Path(args.path)
    given_path = image_path
    _mem_extract_dir = None  # Track for cleanup

    # Extract from archive if needed
    if image_path.suffix.lower() in (".7z", ".zip"):
        import atexit
        import shutil
        import subprocess
        import tempfile

        _mem_extract_dir = Path(tempfile.mkdtemp(prefix="vhir-mem-"))
        atexit.register(shutil.rmtree, _mem_extract_dir, True)  # every exit, not only success
        try:
            password = os.environ.get("VHIR_ARCHIVE_PASSWORD", "")
            from opensearch_mcp.containers import seven_zip_password

            cmd = ["7z", "x", f"-o{_mem_extract_dir}", str(image_path)]
            subprocess.run(cmd, check=True, capture_output=True, timeout=600,
                           **seven_zip_password(password))  # fmt: skip
            from opensearch_mcp import ops

            try:  # the extraction, with every file it wrote, before any is read
                ops.extraction_step(
                    _run_writer(), _case_dir_for(_resolve_case_id(getattr(args, "case", None))),
                    image_path, _mem_extract_dir, cmd,
                )  # fmt: skip
            except ops.NoEntry as e:
                shutil.rmtree(_mem_extract_dir, ignore_errors=True)
                print(f"Error: {image_path}: {e}.", file=sys.stderr)
                sys.exit(1)
            memory_exts = {".img", ".raw", ".vmem", ".dmp", ".mem", ".bin", ".lime"}
            extracted = [f for f in _mem_extract_dir.iterdir() if f.suffix.lower() in memory_exts]
            if not extracted:
                shutil.rmtree(_mem_extract_dir, ignore_errors=True)
                print(f"Error: No memory image found in {image_path}", file=sys.stderr)
                sys.exit(1)
            if len(extracted) > 1:  # each image is its own unit and its own run
                _ingest_each_extracted(cmd_ingest_memory, args, given_path, extracted, examiner)
                return
            image_path = extracted[0]
            print(f"Extracted: {image_path} ({image_path.stat().st_size / (1024**3):.1f} GB)")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            shutil.rmtree(_mem_extract_dir, ignore_errors=True)
            # Not the exception's text: it quotes the command, password and all.
            if isinstance(e, subprocess.TimeoutExpired):
                why = f"7z timed out after {e.timeout:.0f}s"
            else:
                why = f"7z exited {e.returncode}"
            said = (e.stderr or b"").decode(errors="replace")
            if password:  # before cutting it short, or a piece of it survives the cut
                said = said.replace(password, "***")
            said = said.strip()[-500:]
            print(f"Error: Failed to extract {image_path}: {why}. {said}", file=sys.stderr)
            sys.exit(1)

    if not image_path.is_file():
        print(f"Error: {image_path} is not a file.", file=sys.stderr)
        sys.exit(1)

    case_id = _resolve_case_id(getattr(args, "case", None))
    _ensure_case_active(case_id)
    hostname = getattr(args, "hostname", "") or ""
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
    print(f"Hostname: {hostname or '(none given: the examiner confirms it)'}")
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

    audit = _run_writer()

    # Build plugin checklist for status
    status_plugins = [{"name": p, "status": "pending"} for p in plugin_list]
    status_host = {
        "hostname": hostname or image_path.name,
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
                **_kept_now(),
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
                    a.update({k: kw[k] for k in ("stored", "ignored_docs", "ignored") if k in kw})
                    if kw.get("implausible_time"):
                        a["implausible_time"] = kw["implausible_time"]
                    from opensearch_mcp.parse_memory import _plugin_to_index_suffix

                    old = wc.second_copy_note(hostname, _plugin_to_index_suffix(plugin))
                    if old:
                        a["note"] = "; ".join(n for n in (a.get("note"), old) if n)
                    break
            if cnt:
                print(f"{cnt:,} entries" + describe(kw))
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

    # Initial status
    _write_mem_status("running")

    _mem_host_dict = _load_case_host_dict(case_id)

    timeout = getattr(args, "timeout", 3600)
    from sift_common.host_identity import unit_locator

    from opensearch_mcp import names_scan

    member = image_path.name if image_path != given_path else ""
    if getattr(args, "from_archive", None):  # one image of several in an archive
        given_path, member = Path(args.from_archive), args.archive_member
    case_dir = _case_dir_for(case_id)
    if case_dir is None or not (case_dir / "CASE.yaml").is_file():
        print(
            f"Error: no case directory for {case_id!r}: records can't be given their machine.",
            file=sys.stderr,
        )
        sys.exit(1)
    from opensearch_mcp import write_context as wc

    scanned = names_scan.memory_unit(image_path, given_path, member, hostname, case_dir)
    names_scan.record(case_dir, [scanned])
    wc.set_current(
        wc.open_unit(
            case_dir,
            unit_locator(given_path, case_dir, member=member),
            hostname,
            source="memory image",
            origin="argument",
            run_id=run_id or "",
            input_path=given_path,
        )
    )
    _gate(case_id, [wc.current().unit], run_id or "")
    if not hostname:  # the name the examiner confirmed for this image
        hostname = _confirmed_name(case_dir, wc.current())
        status_host["hostname"] = hostname
    try:
        results = ingest_memory(
            image_path=image_path,
            client=client,
            case_id=case_id,
            hostname=hostname,
            tier=tier,
            plugins=plugins,
            timeout=timeout,
            run_id=run_id,
            pipeline_version=f"opensearch-mcp-{__version__}",
            on_progress=_progress,
            audit=audit,
            host_dict=_mem_host_dict,
            case_dir=case_dir,
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
    from opensearch_mcp.write_context import print_fill_report

    print_fill_report()
    if failed:
        print(f"{len(failed)} plugin(s) failed: {', '.join(failed)}")

    # Final status: a run where every plugin failed indexed nothing, so it failed
    error = all_failed_error(results)
    if error:
        print(error)
        _write_mem_status("failed", error=error)
    else:
        _write_mem_status("complete")

    # Clean up extracted temp dir (multi-GB memory image)
    if _mem_extract_dir and _mem_extract_dir.exists():
        import shutil

        shutil.rmtree(_mem_extract_dir, ignore_errors=True)
    if error:  # as every failed ingest does, so an archive's loop counts it
        sys.exit(1)


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
            for f in [*_STATUS_DIR.glob(f"*-{pid}.json"), *_STATUS_DIR.glob(f"*-{pid}-*.json")]:
                try:
                    data = json.loads(f.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                if data.get("status") not in ("running", "starting"):
                    continue  # Idempotent: don't overwrite terminal
                if data.get("pid") != pid:
                    continue  # the pid only matched a number in another run's name
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
    p_mem.add_argument(
        "--hostname", default="", help="Source hostname (else the examiner names it)"
    )
    p_mem.add_argument("--case", help="Case ID")
    p_mem.add_argument("--tier", type=int, default=1, choices=sorted(TIERS), help="Analysis depth")
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
    p_enrich = sub.add_parser("enrich-intel", help="Enrich indexed data with threat intel")
    p_enrich.add_argument("--case", help="Case ID")
    p_enrich.add_argument("--force", action="store_true", help="Re-enrich already-enriched docs")
    p_enrich.add_argument(
        "--dry-run", action="store_true", help="Show IOC counts without enriching"
    )
    p_enrich.add_argument(
        "--include-filesystem",
        action="store_true",
        help="Also look up bulk filesystem hashes (bodyfile; about 140,000 per host)",
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
    p.add_argument(
        "--vss",
        action="store_true",
        help=(
            "Include volume shadow copies. vhir.vss_id is 'live' if the record exists "
            "on the live volume, otherwise the earliest shadow copy that holds it"
        ),
    )
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
