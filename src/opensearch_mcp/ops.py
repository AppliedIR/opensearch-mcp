"""Operations: each step an ingest takes is one audit entry with its own id.

A step's entry is written before what it produces: a file's entry before any
of its records, a tool run's before its output is read. A later fact about a
step (it failed, its counts, an unmount) is an entry of its own that names the
step it is about (``about``); no two entries share an id.

Entries use the field contract the audit's readers share:
- ``inputs``: each read as ``{path, realpath, st_dev, mnt_id}``, with its
  ``sha256`` when it is a copy or an output (hashed fresh, or taken from the
  manifest of the step that produced it) and ``produced_by`` when known;
- ``input_registered``: a registered evidence file, by its registered path and
  the registry's SHA-256, never hashed again;
- ``outputs``: each written file as ``{path, sha256, size}``.
``input_files``/``input_sha256s`` stay for today's readers.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import threading
from pathlib import Path

from opensearch_mcp.manifest import sha256_file

NO_ENTRY = "its audit entry couldn't be written, so it wasn't indexed"


def mnt_id(realpath: str) -> int | None:
    """The mount id (``/proc/self/mountinfo``) of the mount holding ``realpath``."""
    best, best_len = None, -1
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        point = parts[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        inside = realpath == point or realpath.startswith(point.rstrip("/") + "/")
        if inside and len(point) > best_len:
            try:
                best, best_len = int(parts[0]), len(point)
            except ValueError:
                continue
    return best


def place(path) -> dict:
    """Where a read happened: the path as given, its realpath, ``st_dev`` and
    mount id. A path that can't be resolved keeps only what could be read."""
    out: dict = {"path": str(path)}
    try:
        real = os.path.realpath(path)
        out["realpath"] = real
        out["st_dev"] = os.stat(real).st_dev
        out["mnt_id"] = mnt_id(real)
    except OSError:
        pass
    return out


def registered(case_dir, path) -> dict | None:
    """The registry's entry for ``path``, matched exactly on its resolved path:
    ``{path, sha256}`` as registered, or None. No search, no re-hash."""
    if case_dir is None:
        return None
    try:
        real = os.path.realpath(path)
        data = json.loads((Path(case_dir) / "evidence.json").read_text())
    except (OSError, ValueError):
        return None
    for f in data.get("files", []) if isinstance(data, dict) else []:
        if isinstance(f, dict) and f.get("path") == real and f.get("sha256"):
            return {"path": str(f["path"]), "sha256": str(f["sha256"])}
    return None


def file_input(
    case_dir, path, sha256: str | None = None, produced_by=None
) -> tuple[dict, dict | None]:
    """``(input, registered entry)`` for a file a step reads: a registered
    file by the registry's hash; otherwise ``sha256`` (from the manifest of
    the step that wrote it) or a fresh hash ("" for a folder). Raises OSError
    when the file can't be read."""
    entry = place(path)
    reg = registered(case_dir, path)
    if reg is None:
        if sha256 is None:
            made = _extracted().get(entry.get("realpath", ""))
            if made is not None:  # an extracted file: its hash in the extraction's manifest
                sha256, produced_by = made[0], produced_by or made[1]
            else:
                sha256 = sha256_file(Path(path)) if Path(path).is_file() else ""
        entry["sha256"] = sha256
    if produced_by:
        entry["produced_by"] = produced_by
    return entry, reg


def output(path) -> dict:
    """A file a step wrote: ``{path, sha256, size}``."""
    p = Path(path)
    return {"path": str(p), "sha256": sha256_file(p), "size": p.stat().st_size}


def write(
    audit,
    tool: str,
    *,
    params: dict,
    summary,
    inputs: list[dict] | None = None,
    input_registered: list[dict] | None = None,
    outputs: list[dict] | None = None,
    about: str = "",
    extra: dict | None = None,
) -> str:
    """Write one step's entry under a new id; "" when it couldn't be written."""
    fields: dict = dict(extra or {})
    inputs = list(inputs or [])
    regs = list(input_registered or [])
    if inputs:
        fields["inputs"] = inputs
    if regs:
        fields["input_registered"] = regs
    if outputs:
        fields["outputs"] = outputs
    if about:
        fields["about"] = about
    by_path = {r["path"]: r["sha256"] for r in regs}
    files = [i["path"] for i in inputs]
    shas = [i.get("sha256") or by_path.get(os.path.realpath(i["path"]), "") for i in inputs]
    if not regs and not any("sha256" in i for i in inputs):
        shas = []  # nothing was hashed (a read that failed): no hash, not an empty one
    aid = audit._next_audit_id()
    logged = audit.log(
        tool=tool,
        audit_id=aid,
        params=params,
        result_summary=summary,
        input_files=files or None,
        input_sha256s=shas if files else None,
        source_evidence=files[0] if files else "",
        extra=fields,
    )
    return "" if logged is None else aid


class NoEntry(RuntimeError):
    """A step's entry couldn't be written, so what it reads isn't indexed."""


class Unreadable(NoEntry):
    """The file a step reads can't be read; its failure is recorded."""


class Refused(RuntimeError):
    """An ingest's input doesn't trace FULL to registered evidence: nothing
    of it is read or sent."""

    def __init__(self, path: str, why: str, fix: str):
        super().__init__(why)
        self.path, self.why, self.fix = path, why, fix


NOT_INDEXED = "not indexed"


def not_indexed(notes: list[str] | None, path, err: NoEntry) -> None:
    """A file a parser couldn't index, as it couldn't be read or its step
    couldn't be written: named with the reason in the ingest status (the
    parser's ``notes``) and on the console, never counted as an ordinary skip."""
    import sys

    why = f"couldn't be read ({err})" if isinstance(err, Unreadable) else str(err)
    note = f"{NOT_INDEXED}: {path}: {why}"
    if notes is not None:
        notes.append(note)
    print(f"  {note}", file=sys.stderr)


def read_step(
    audit,
    tool: str,
    path,
    *,
    case_dir,
    params: dict,
    sha256: str | None = None,
    produced_by=None,
    outputs=None,
    extra: dict | None = None,
) -> tuple[str, str]:
    """Write the step that reads ``path``, before any of its records: the
    file, its place and hash (or the registry's), ``params`` (host, index,
    run) and any ``outputs`` it wrote. Returns ``(audit id, the file's
    SHA-256)``. A file that can't be read gets a failure entry and raises
    Unreadable; an entry that can't be written raises NoEntry. Either way the
    file is not indexed."""
    params = {**params, "file": str(path)}
    try:
        entry, reg = file_input(case_dir, path, sha256, produced_by)
    except OSError as e:
        write(audit, tool, params=params, summary=f"FAILED: {e}", inputs=[place(path)])
        raise Unreadable(str(e)) from e
    aid = write(
        audit,
        tool,
        params=params,
        summary="recorded before its records were indexed",
        inputs=[entry],
        input_registered=[reg] if reg else None,
        outputs=[output(o) for o in outputs or ()],
        extra=extra,
    )
    if not aid:
        raise NoEntry(NO_ENTRY)
    return aid, (reg["sha256"] if reg else entry.get("sha256", ""))


def later(
    audit,
    about: str,
    tool: str,
    summary,
    params: dict | None = None,
    extra: dict | None = None,
    inputs: list[dict] | None = None,
) -> str:
    """A later fact about step ``about``, as an entry of its own (with the
    inputs the step turned out to read, when only its tool knew them)."""
    return write(
        audit, tool, params=params or {}, summary=summary, about=about, extra=extra, inputs=inputs
    )


# The run's writer, case and params, for steps written deep inside a parser
# (a tool's CSV, a Plaso fallback's JSONL): the site that owns the writer opens
# it; the parser names what it reads.
_tls = threading.local()


@contextlib.contextmanager
def recording(audit, case_dir, tool: str, params: dict):
    """Steps written inside the block go to ``audit`` as ``tool``."""
    prev = getattr(_tls, "rec", None)
    _tls.rec = (audit, case_dir, tool, params)
    try:
        yield
    finally:
        _tls.rec = prev


def step_entry(
    read, *, sha256: str | None = None, produced_by=None, outputs=None, extra=None
) -> str:
    """Write the step that reads ``read`` (its records follow) under the open
    recording; ``outputs`` are files it wrote. Raises as read_step, and NoEntry
    when no recording is open."""
    rec = getattr(_tls, "rec", None)
    if rec is None:
        raise NoEntry(f"{read}: no ingest run is recording its steps")
    audit, case_dir, tool, params = rec
    aid, _sha = read_step(
        audit, tool, read, case_dir=case_dir, params=params, sha256=sha256,
        produced_by=produced_by, outputs=outputs, extra=extra,
    )  # fmt: skip
    return aid


@contextlib.contextmanager
def step(read, **kw):
    """Write ``read``'s step, then index the block's records under it."""
    from opensearch_mcp import write_context as wc

    aid = step_entry(read, **kw)
    with wc.op(aid):
        yield aid


def current_recording():
    """``(audit, case_dir, tool, params)`` of the open recording, or None."""
    return getattr(_tls, "rec", None)


def staging_step(copied: list[tuple], tool: str, wintools_audit_id: str = "") -> str:
    """Record a staging copy (for a Windows tool to read over the share) as a
    step: each original read (the registry's when registered, otherwise
    hashed with its place) and each copy written, hashed; and the wintools
    call's own audit id when it ran first. Raises NoEntry as step_entry."""
    rec = getattr(_tls, "rec", None)
    if rec is None:
        raise NoEntry(f"staging for {tool}: no ingest run is recording its steps")
    audit, case_dir, _tool, params = rec
    inputs, regs, outputs = [], [], []
    for original, copy in copied:
        entry, reg = file_input(case_dir, original)
        inputs.append(entry)
        if reg:
            regs.append(reg)
        outputs.append(output(copy))
    aid = write(
        audit,
        "stage_for_wintools",
        params={**params, "tool": tool},
        summary=f"{len(outputs)} file(s) staged for {tool}",
        inputs=inputs,
        input_registered=regs or None,
        outputs=outputs,
        extra={"wintools_audit_id": wintools_audit_id} if wintools_audit_id else None,
    )
    if not aid:
        raise NoEntry(f"staging for {tool}: {NO_ENTRY}")
    return aid


def file_marker(path, **kw) -> dict:
    """For a parser that batches several files' records: write ``path``'s step
    (under the open recording) and return the marker its records carry, so each
    is stamped with its own file's step. ``{}`` when no recording is open (the
    caller's open step applies). Raises NoEntry when the entry couldn't be
    written: the file is then not indexed."""
    from opensearch_mcp.write_context import STEP_KEY

    if getattr(_tls, "rec", None) is None:
        return {}
    return {STEP_KEY: step_entry(path, **kw)}


def _extracted() -> dict:
    """``{realpath: (sha256, extraction step)}`` of the files this thread's
    run extracted."""
    made = getattr(_tls, "extracted", None)
    if made is None:
        made = _tls.extracted = {}
    return made


def reset_extracted() -> None:
    """Forget the run's extracted files (the run is over)."""
    _tls.extracted = {}


def extraction_step(audit, case_dir, archive, dest, command: list[str], params=None) -> str:
    """Record an archive's extraction, after it and before any member is used:
    the archive (by the registry when registered, never hashed again), the
    command (it never carries the password: 7z reads that on stdin) and an
    output manifest of every regular file extracted, hashed. A later step that
    reads one of them takes its hash from the manifest. Raises NoEntry when
    the entry couldn't be written."""
    entry, reg = file_input(case_dir, archive)
    outs = [output(p) for p in sorted(Path(dest).rglob("*")) if p.is_file() and not p.is_symlink()]
    aid = write(
        audit,
        "extract_archive",
        params={"archive": str(archive), "dest": str(dest), "command": [str(c) for c in command],
                **(params or {})},
        summary=f"{len(outs)} file(s) extracted",
        inputs=[entry],
        input_registered=[reg] if reg else None,
        outputs=outs,
    )  # fmt: skip
    if not aid:
        raise NoEntry(NO_ENTRY)
    made = _extracted()
    for o in outs:
        made[os.path.realpath(o["path"])] = (o["sha256"], aid)
    return aid


def recorded_hash(case_dir, path, *, case=None, done=None) -> str:
    """The hash of a large file read whole and never hashed here (an image, a
    memory dump), as recorded when an earlier operation wrote it: what its
    completed background job recorded while the file is unchanged; else
    `pending:<job>` of the newest operation that recorded it as an output whose
    job hasn't closed, while the file is still that output (its inode, size
    and mtime as recorded: a file replaced at the path never takes it); the
    resolver takes it through that job. Else "". A gate passes the case and
    `done` (`completed_hashes` of the files it walks) it read once for all."""
    if case_dir is None:
        return ""
    from sift_common import file_identity as fi
    from sift_common import provenance as pv

    if done is not None:
        sha = done.get(str(path), {}).get("sha256")
    else:
        sha = fi.completed_hash(case_dir, path)
    if sha:
        return sha
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError:
        return ""
    now = (st.st_ino, st.st_size, st.st_mtime_ns)
    if case is None:
        case = pv.load_case(case_dir)
    # every job with a completion row is closed: only an open one is pending
    closed = {str(e.get("job_id")) for items in case.by_id.values() for e, _ in items
              if e.get("tool") in ("hash_complete", "hash_failed")}  # fmt: skip
    found = [(pv._when(case, e), o["sha256"])
             for items in case.by_id.values() for e, _ in items
             for o in e.get("outputs") or [] if isinstance(o, dict)
             and str(o.get("sha256") or "").startswith("pending:")
             and o["sha256"][len("pending:"):] not in closed
             and os.path.realpath(str(pv._where(case, o))) == real
             and (o.get("st_ino"), o.get("size"), o.get("mtime_ns")) == now]  # fmt: skip
    return max(found)[1] if found else ""


def large_input(case_dir, path) -> dict:
    """A large input read whole: its place, with its recorded hash if any."""
    entry = place(path)
    if sha := recorded_hash(case_dir, path):
        entry["sha256"] = sha
    return entry


def image_input(case_dir, path) -> tuple[dict, dict | None]:
    """An image a tool reads whole: by the registry, or by the manifest of the
    extraction that wrote it, or by the hash recorded when an earlier
    operation wrote it (`recorded_hash`), so its chain links to that
    operation; otherwise its place only (an image is large and is not hashed
    here)."""
    entry = place(path)
    reg = registered(case_dir, path)
    if reg is None:
        made = _extracted().get(entry.get("realpath", ""))
        if made is not None:
            entry["sha256"], entry["produced_by"] = made
        elif sha := recorded_hash(case_dir, path):
            entry["sha256"] = sha
    return entry, reg


def set_run(audit, case_dir, roots: list[dict] | None = None) -> None:
    """The run open on this thread: its writer, case and roots (the registered
    evidence it was given, ``{path, sha256}``); None, None closes it."""
    _tls.run = (audit, case_dir) if audit is not None else None
    _tls.roots = list(roots or []) if audit is not None else []


def gate(case_dir, path) -> tuple[list[dict], dict]:
    """``(roots, registered folder or {})``: the registered evidence an
    ingest's input traces to, before anything of it is read. A registered
    folder, or anything in one, by its manifest's hash; a file that traces
    FULL, or a pending hash on a recorded output that is still that output
    (inode, size, mtime as recorded) whose producing operation traces FULL;
    any other folder, every file in it. Anything else raises Refused with the
    trace's fix: DECLARED, AMBIGUOUS, BROKEN."""
    from sift_common import provenance as pv

    real = os.path.realpath(path)
    if case_dir is None:
        raise Refused(real, "no case to trace it in", "activate the case it is registered in")
    case = pv.load_case(case_dir)
    folder = next((r for r in case.roots if r.get("kind") == "folder" and (
        real == r["path"] or real.startswith(r["path"] + os.sep))), None)  # fmt: skip
    if folder is not None:  # its members are taken as they are
        return [{"path": folder["path"], "sha256": folder.get("manifest_sha256", "")}], folder
    if not os.path.isdir(real):
        return _gate_file(pv, case, case_dir, real), {}
    from sift_common import file_identity as fi

    files = []
    for top, dirs, names in os.walk(real):
        dirs.sort()
        for n in sorted(names):
            f = os.path.join(top, n)
            if os.path.isfile(f) and not os.path.islink(f):
                files.append(f)
    done: list = []  # the hash log, read once for all the files, when first needed

    def completed() -> dict:
        if not done:
            done.append(fi.completed_hashes(case_dir, files))
        return done[0]

    roots: dict = {}
    for f in files:
        roots.update((r["path"], r) for r in _gate_file(pv, case, case_dir, f, completed))
    return list(roots.values()), {}


def _gate_file(pv, case, case_dir, real: str, completed=None) -> list[dict]:
    p = place(real)
    at = {"realpath": real, "st_dev": p.get("st_dev"), "mnt_id": p.get("mnt_id")}
    t = pv.trace_file(case, real, None, **at)  # registered, or read through a mount
    if t.grade == "FULL":
        return [{"path": r["path"], "sha256": r.get("sha256", "")} for r in t.roots]
    # the trace's own index (cached under this name): (entry, line, sha) each
    outputs = pv._index(case, "outputs", lambda e, line: [
        (os.path.realpath(o), (e, line, h)) for o, h in pv._outputs(case, e)])  # fmt: skip
    if real not in outputs:  # no recorded origin can hold it: refused unhashed
        raise Refused(real, t.reason, (t.break_ or {}).get("fix", ""))
    done = completed() if completed is not None else None
    sha = recorded_hash(case_dir, real, case=case, done=done) or sha256_file(Path(real))
    t = pv.trace_file(case, real, sha, **at)
    if t.grade != "FULL" and sha.startswith("pending:") and (
            (t.break_ or {}).get("kind") == "hash-pending"):  # fmt: skip
        made = [e for e, _, h in outputs[real] if h == sha]  # its producing operation
        t = pv.trace_op(case, made[-1]["audit_id"]) if made else t
    if t.grade == "FULL":
        return [{"path": r["path"], "sha256": r.get("sha256", "")} for r in t.roots]
    raise Refused(real, t.reason, (t.break_ or {}).get("fix", ""))


def run_roots() -> list[dict]:
    """The roots of the run open on this thread: what its records come from."""
    return list(getattr(_tls, "roots", None) or [])


def current_run():
    """``(audit, case_dir)`` of the run open on this thread, or None."""
    return getattr(_tls, "run", None)


def mount_point(target, offset=None, store: str = "") -> dict:
    """A mount point as the mount and umount records name it: never hashed."""
    real = os.path.realpath(target)
    point: dict = {"target": str(target), "realpath": real}
    try:
        point["st_dev"] = os.stat(real).st_dev
    except OSError:
        point["st_dev"] = None
    point["mnt_id"] = mnt_id(real)
    point["offset"] = offset
    if store:
        point["store"] = store
    return point


def mount_step(image, points: list[dict], tool: str = "mount_image") -> str:
    """Record a mount of ``image`` under the open run: ``mount: {image,
    points}``, the image as an input (by the registry when registered).
    "" when no run is open or it couldn't be written."""
    run = current_run()
    if run is None or not points:
        return ""
    audit, case_dir = run
    entry, reg = image_input(case_dir, image)
    return write(
        audit,
        tool,
        params={"image": str(image)},
        summary=f"{len(points)} mount point(s)",
        inputs=[entry],
        input_registered=[reg] if reg else None,
        extra={"mount": {"image": reg["path"] if reg else str(image), "points": points}},
    )


def umount_entry(audit, realpath: str, mount_id) -> str:
    """Record an unmount, read before it ran: ``umount: {realpath, mnt_id}``.
    Readers pair it with the mount point whose realpath and mnt_id match."""
    return write(
        audit,
        "umount",
        params={"realpath": realpath},
        summary="unmounted",
        extra={"umount": {"realpath": realpath, "mnt_id": mount_id}},
    )


def reference_step(audit, tool: str, source: str, source_version: str, params: dict) -> str:
    """An enrichment run's step, written before its first write: the source it
    consults and that source's version (or database version). Its id is what
    the run stamps on every field group it writes. Raises NoEntry when it
    couldn't be written."""
    aid = write(
        audit,
        tool,
        params=params,
        summary="recorded before its first write",
        extra={"reference": {"source": source, "source_version": source_version}},
    )
    if not aid:
        raise NoEntry(NO_ENTRY)
    return aid


# An assignment to a triage field (not a comparison, not the op id itself)
_SETS_TRIAGE = re.compile(r"ctx\._source\['triage\.(?!op_id')\w+'\]\s*=(?!=)")
_STAMP = "ctx._source['triage.op_id'] = params.op_id; "


class StampingClient:
    """An OpenSearch client whose update_by_query scripts stamp `triage.op_id`,
    the enrichment step, wherever they set a `triage.*` field: just before
    each such assignment, so a record the script leaves alone isn't stamped."""

    def __init__(self, client, op_id: str):
        self._client, self.op_id = client, op_id

    def __getattr__(self, name):
        return getattr(self._client, name)

    def update_by_query(self, *args, **kw):
        body = kw.get("body")
        script = body.get("script") if isinstance(body, dict) else None
        source = str(script.get("source", "")) if isinstance(script, dict) else ""
        if _SETS_TRIAGE.search(source):
            params = {**(script.get("params") or {}), "op_id": self.op_id}
            stamped = _SETS_TRIAGE.sub(lambda m: _STAMP + m.group(0), source)
            script = {**script, "params": params, "source": stamped}
            kw["body"] = {**body, "script": script}
        return self._client.update_by_query(*args, **kw)


def case_writer(audit, case_dir):
    """A writer for `case_dir`'s audit (whichever case is active), under
    `audit`'s name; `audit` itself when the case has no folder."""
    if case_dir is None:
        return audit
    from sift_common.audit import AuditWriter

    name = getattr(audit, "mcp_name", None) or "opensearch-mcp"
    return AuditWriter(mcp_name=name, case_dir_resolver=lambda: case_dir)
