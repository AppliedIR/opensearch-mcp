"""Where an ingest run writes, and as which machine.

An ingest worker opens one ``WriteContext`` per evidence unit (a host
folder, a disk-image volume, a memory image, a file or folder argument).
``flush_bulk`` applies the open context to every document it sends: the
machine key and canonical name of the document's own host name, the unit,
and an id that carries the machine key, so two machines that share a host
name, a file path and record numbers never overwrite each other, and a
re-collection of one machine replaces its own documents.

Index names carry no host: every write goes to ``case-<c12>-<type>-0``.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sift_common import host_identity

from opensearch_mcp.bulk import ShardCapacityExhausted

_tls = threading.local()


class NoWriteContext(RuntimeError):
    """A write to a case index was attempted outside an ingest run's context."""


def case_identity(case_dir: str | os.PathLike) -> tuple[str, int]:
    """``(c12, naming_version)`` of a case, from its CASE.yaml: ``c12`` is
    the first 12 hex digits of ``case_uuid``, and "" when it has none yet
    (nothing has been written under an identity). Reads only: a write gets
    its identity from ``host_identity.ensure_case_uuid``.
    """
    path = Path(case_dir) / "CASE.yaml"
    try:
        meta = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        raise FileNotFoundError(f"no CASE.yaml in {case_dir}") from None
    if not isinstance(meta, dict):
        meta = {}
    case_uuid = str(meta.get("case_uuid") or "").replace("-", "").lower()
    if len(case_uuid) == 32 and all(c in "0123456789abcdef" for c in case_uuid):
        return case_uuid[:12], int(meta.get("naming_version") or 1)
    return "", int(meta.get("naming_version") or 1)


@dataclass
class WriteContext:
    """One evidence unit's writes in one case."""

    case_dir: Path
    c12: str
    unit: str
    unit_raw: str
    origin: str = host_identity.ARTIFACT
    run_id: str = ""
    store: str = ""  # a shadow copy's id (vss1, p2-vss1); "" for live or no --vss
    names_origin: str = host_identity.ARTIFACT  # of every name its records give
    _resolved: dict = field(default_factory=dict)

    def resolve(self, raw: str | None) -> tuple[str, str, str]:
        """``(raw, machine key, canonical)`` for a document's host name; the
        unit's own name when the document has none."""
        name = raw if isinstance(raw, str) and raw.strip() else self.unit_raw
        hit = self._resolved.get(name)
        if hit is None:
            # the unit's own name keeps how it was given; every other name is
            # what the run's input is: the AI's when the AI wrote or registered it
            origin = self.origin if name == self.unit_raw else self.names_origin
            key, canonical = host_identity.get_or_mint(
                self.case_dir, self.unit, name, origin=origin
            )
            hit = self._resolved[name] = (key, canonical)
        return name, hit[0], hit[1]


def current() -> WriteContext | None:
    """The write context open on this thread, or None."""
    return getattr(_tls, "ctx", None)


def set_current(ctx: WriteContext | None) -> None:
    """Open ``ctx`` (None closes) for the writes that follow on this thread."""
    _tls.ctx = ctx


@contextlib.contextmanager
def restoring():
    """Put back, on leaving the block, the context open on entering it, and
    release what the block held (the case lock a run takes after its gate)."""
    prev = current()
    held = getattr(_tls, "held", None)
    _tls.held = contextlib.ExitStack()
    try:
        yield
    finally:
        _tls.ctx = prev
        try:
            _tls.held.close()
        finally:
            _tls.held = held


_process_held = contextlib.ExitStack()  # a worker's own run: released as it exits


def hold(cm) -> None:
    """Enter ``cm`` until the enclosing ``restoring()`` block ends (the
    process, outside one)."""
    stack = getattr(_tls, "held", None)
    (stack if stack is not None else _process_held).enter_context(cm)


def current_op() -> str:
    """The step whose records are being written on this thread ("" for none):
    a parsed file's or a plugin run's audit id."""
    return getattr(_tls, "op", "")


@contextlib.contextmanager
def op(audit_id: str):
    """Write the records inside the block under step ``audit_id``."""
    prev = current_op()
    _tls.op = audit_id
    try:
        yield audit_id
    finally:
        _tls.op = prev


@contextlib.contextmanager
def writing(ctx: WriteContext):
    """Open ``ctx`` for the writes inside the block."""
    prev = current()
    _tls.ctx = ctx
    try:
        yield ctx
    finally:
        _tls.ctx = prev


def open_unit(
    case_dir: str | os.PathLike,
    locator: str,
    raw: str,
    *,
    source: str,
    origin: str = host_identity.FOLDER,
    run_id: str = "",
    input_path=None,
) -> WriteContext:
    """Record an evidence unit and its own host name, and return its context.
    `input_path` is what the run reads: the names its records give count as
    the AI's when the AI wrote or registered it."""
    from opensearch_mcp.names_scan import file_origin

    root = Path(case_dir)
    host_identity.ensure_host_files(root)
    c12, _ = host_identity.ensure_case_uuid(root)  # the write's identity, minted if new
    unit = host_identity.unit_key(locator)
    records = [{"kind": "unit", "unit": unit, "locator": locator, "source": source}]
    if raw:  # a unit given no name gets its machine from the examiner, at the gate
        records.append(
            {"kind": "name", "unit": unit, "raw": raw, "evidence": source, "origin": origin}
        )
    host_identity.append_observations(root, records)
    for key in [k for k in REMOVED if k[:2] == (c12, raw)]:
        del REMOVED[key]  # a run reports its own removals, not an earlier run's
    return WriteContext(
        case_dir=root, c12=c12, unit=unit, unit_raw=raw, origin=origin, run_id=run_id,
        names_origin=file_origin(root, input_path) if input_path is not None
        else host_identity.ARTIFACT,
    )  # fmt: skip


def case_dir_for(case_id: str) -> Path | None:
    """The directory of the case named ``case_id``: the active case (or
    ``VHIR_CASE_DIR``) when it has that name, else ``VHIR_CASES_DIR/<id>``
    (default ``~/cases``); None when there is none."""
    if not case_id or Path(case_id).name != case_id:
        return None
    from sift_common import resolve_case_dir

    active = resolve_case_dir()  # VHIR_CASE_DIR, else the active case
    if active and Path(active).name == case_id:
        return Path(active)
    root = Path(os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases")))
    case_dir = root / case_id
    return case_dir if case_dir.is_dir() else None


def host_context(case_dir, case_id: str, host, run_id: str = "", input_path=None) -> WriteContext:
    """The write context of a discovered host's evidence unit, opened once."""
    ctx = getattr(host, "write_ctx", None)
    if ctx is not None:
        return ctx
    root = Path(case_dir) if case_dir else case_dir_for(case_id)
    if root is None or not (root / "CASE.yaml").is_file():
        raise NoWriteContext(
            f"no case directory for {case_id!r}: records can't be given their machine"
        )
    locator = getattr(host, "unit_locator", "") or host_identity.unit_locator(
        host.volume_root, root
    )
    ctx = open_unit(
        root,
        locator,
        host.hostname,
        source="evidence folder",
        origin=getattr(host, "name_origin", "") or host_identity.FOLDER,
        run_id=run_id,
        input_path=input_path if input_path is not None else host.volume_root,
    )
    vss_id = getattr(host, "vss_id", "") or ""
    ctx.store = "" if vss_id == "live" else vss_id
    host.write_ctx = ctx
    return ctx


def index_name(artifact_type: str) -> str:
    """The index the open context writes ``artifact_type`` records to."""
    from opensearch_mcp.paths import build_index_name

    ctx = current()
    if ctx is None:
        raise NoWriteContext("no ingest run is open: refusing to name a case index")
    return build_index_name(ctx.c12, artifact_type)


def doc_id(machine_key: str, rid: str) -> str:
    """A stored id: the machine key and the parser's own record id."""
    return hashlib.sha256(f"{machine_key}:{rid}".encode()).hexdigest()[:20]


_V2_INDEX = re.compile(r"^case-[0-9a-f]{12}-.+-0$")

# Types whose index grows with the number of machines: created with four
# primary shards.
HOST_SCALED_TYPES = frozenset({"evtx", "hayabusa", "mft", "usn", "timeline", "plaso"})
HOST_SCALED_SHARDS = 4
# Lucene holds about 2.147e9 documents per shard, deleted ones included.
SHARD_DOC_LIMIT = 1_500_000_000

_prepared: set[str] = set()
_imported: set[Path] = set()  # cases whose pre-0.7 hosts this process has seeded


class ShardHeadroom(ShardCapacityExhausted):
    """A shard of the target index is near Lucene's document limit."""


def artifact_type_of(index: str) -> str:
    """`<type>` of `case-<c12>-<type>-0`."""
    return index.split("-", 2)[2].rsplit("-", 1)[0] if index.count("-") >= 3 else ""


def shard_headroom(client, index: str, adding: int = 0) -> str:
    """Why `index` can't take `adding` more documents, or ""."""
    try:
        stats = client.indices.stats(index=index, metric="docs", level="shards")
    except Exception:
        return ""
    for idx, entry in (stats.get("indices") or {}).items():
        for shard, copies in (entry.get("shards") or {}).items():
            for copy in copies:
                if not (copy.get("routing") or {}).get("primary", True):
                    continue
                docs = copy.get("docs") or {}
                used = int(docs.get("count", 0)) + int(docs.get("deleted", 0))
                if used + adding > SHARD_DOC_LIMIT:
                    return (
                        f"{idx} shard {shard} holds {used:,} documents (live and deleted), "
                        f"past {SHARD_DOC_LIMIT:,}: split the index with _split "
                        "(more primary shards) before adding more"
                    )
    return ""


def prepare_index(client, index: str) -> None:
    """Before this process's first write to a case index: create it (four
    primaries for host-scaled types) and refuse when a shard has no headroom."""
    if index in _prepared or not _V2_INDEX.match(index):
        return
    try:
        exists = client.indices.exists(index=index)
    except Exception:
        exists = None  # unanswered: the bulk request creates it, and says why if it can't
    if exists is False:
        body = {}
        if artifact_type_of(index) in HOST_SCALED_TYPES:
            body = {"settings": {"index": {"number_of_shards": HOST_SCALED_SHARDS}}}
        try:
            client.indices.create(index=index, body=body)
        except Exception as e:
            if "resource_already_exists" not in str(e):
                raise
    reason = shard_headroom(client, index)
    if reason:
        raise ShardHeadroom(reason)
    _prepared.add(index)


SECOND_COPY_NOTE = (
    "this host already has pre-0.7 data in this case; this ingest adds a second copy"
)
# (case c12, host name as ingested, artifact type) -> the note, for this process's runs
SECOND_COPY: dict[tuple[str, str, str], str] = {}
# Machine fields the evidence carried and the stamp removed, per (case, unit name, type)
REMOVED: dict[tuple[str, str, str], int] = {}


def _v1_names(ctx: WriteContext) -> tuple[str, list[str]]:
    """(the case id pre-0.7 names were built from, the unit's names as a
    pre-0.7 index would carry them: the raw name and its v1 canonical)."""
    meta = {}
    try:
        meta = yaml.safe_load((ctx.case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        pass
    legacy_id = str(meta.get("case_id") or ctx.case_dir.name) if isinstance(meta, dict) else ""
    names = [ctx.unit_raw]
    path = ctx.case_dir / "host-dictionary.yaml"
    if path.is_file():
        try:
            from opensearch_mcp.host_dictionary import HostDictionary

            canonical = HostDictionary.load(path).resolve(ctx.unit_raw)
            if canonical:
                names.append(canonical)
        except Exception:
            pass
    return legacy_id, names


def note_second_copy(client, ctx: WriteContext, index: str) -> str:
    """In a case from before 0.7, when the unit's host already has data of
    this type in a pre-0.7 per-host index, record and return the notice."""
    from opensearch_mcp.paths import legacy_index_name

    atype = artifact_type_of(index)
    key = (ctx.c12, ctx.unit_raw, atype)
    if key in SECOND_COPY:
        return SECOND_COPY[key]
    note = ""
    if case_identity(ctx.case_dir)[1] == 1:
        legacy_id, names = _v1_names(ctx)
        for name in dict.fromkeys(names):
            try:
                if client.indices.exists(index=legacy_index_name(legacy_id, atype, name)):
                    note = SECOND_COPY_NOTE
                    break
            except Exception:
                continue
    SECOND_COPY[key] = note
    return note


def second_copy_types(hostname: str = "", c12: str = "") -> list[str]:
    """Artifact types that got the notice in this process: for `hostname`, in
    case `c12` (the open context's when not given)."""
    c12 = c12 or (current().c12 if current() is not None else "")
    return sorted(
        {
            t
            for (c, h, t), note in SECOND_COPY.items()
            if note and (not c12 or c == c12) and (not hostname or h == hostname)
        }
    )


def second_copy_note(hostname: str = "", artifact_type: str = "", c12: str = "") -> str:
    """The notice for `hostname`'s `artifact_type`, or for any it got."""
    types = second_copy_types(hostname, c12)
    if artifact_type:
        return SECOND_COPY_NOTE if artifact_type in types else ""
    return f"{SECOND_COPY_NOTE} ({', '.join(types)})" if types else ""


def removed_note(hostname: str = "", artifact_type: str = "", c12: str = "") -> str:
    """How many reserved identity fields the evidence of `hostname` (of
    `artifact_type`) carried and the stamp removed, as a status note."""
    c12 = c12 or (current().c12 if current() is not None else "")
    n = sum(
        v
        for (c, h, t), v in REMOVED.items()
        if (not c12 or c == c12)
        and (not hostname or h == hostname)
        and (not artifact_type or t == artifact_type)
    )
    if not n:
        return ""
    return f"{n} reserved identity field{'' if n == 1 else 's'} removed from evidence"


def stamp_or_refuse(actions: list[dict], client=None) -> None:
    """Stamp ``actions`` with the open context; refuse a write to a case
    index when no context is open, so no record is stored without its machine."""
    # a parser that batches several files' records names each record's step;
    # the marker is never sent
    steps = [str(a.pop(STEP_KEY, "") or "") for a in actions]
    ctx = current()
    if ctx is not None:
        if client is not None and ctx.case_dir not in _imported:
            from opensearch_mcp.case_scope import ensure_v1_imported

            ensure_v1_imported(client, ctx.case_dir)  # before any name binds
            _imported.add(ctx.case_dir)
        stamp(ctx, actions, steps)
        if client is not None:
            for index in {str(a.get("_index", "")) for a in actions}:
                if index.startswith(f"case-{ctx.c12}-"):
                    prepare_index(client, index)
                    note_second_copy(client, ctx, index)
        return
    for action in actions:
        if _V2_INDEX.match(str(action.get("_index", ""))):
            raise NoWriteContext(f"refusing to write to {action['_index']}: no ingest run is open")


# An action's own step, when its parser batches several files' records.
STEP_KEY = "_vhir_op"


def stamp(ctx: WriteContext, actions: list[dict], steps: list[str] | None = None) -> None:
    """Set the machine, unit and id fields of every action into ``ctx``'s case,
    and the step of a record whose parser batches several files (``steps``)."""
    prefix = f"case-{ctx.c12}-"
    for n, action in enumerate(actions):
        if not str(action.get("_index", "")).startswith(prefix):
            continue
        src = action.setdefault("_source", {})
        step = steps[n] if steps and n < len(steps) else ""
        if step:  # the step that read the record's file
            src["vhir.ingest_audit_id"] = step
        rid = action.get("_id")
        resent = rid is not None and _stamped_here(action, src)
        if resent:
            rid = src["vhir.rid"]  # a batch sent again: its parser id, not the stored one
        removed = _drop_owned(src, resent)  # evidence never sets a record's machine
        if removed:
            key = (ctx.c12, ctx.unit_raw, artifact_type_of(action["_index"]))
            REMOVED[key] = REMOVED.get(key, 0) + removed
        raw, key, canonical = ctx.resolve(src.get("host.name"))
        src["host.name"] = raw
        src["host.id"] = canonical
        src["vhir.host_key"] = key
        src["vhir.unit"] = ctx.unit
        if rid is not None:
            src["vhir.rid"] = str(rid)
            action["_id"] = doc_id(key, str(rid))
        if ctx.store and action.get("_op_type", "index") == "index":
            # a shadow copy never replaces a record already in the case: the
            # live volume's tag wins, and the first copy to hold it keeps its own
            action["_op_type"] = "create"


# What the stamp owns, dotted and nested: evidence that carries them is restamped.
_OWNED = ("host.id", "vhir.host_key", "vhir.unit", "vhir.rid", "vhir.prev_ids")


def _stamped_here(action: dict, src: dict) -> bool:
    """The action already went through stamp: its `_id` is the hash of the
    key and parser id it carries. Evidence can't produce that: the key is a
    random value it never sees."""
    key, rid = src.get("vhir.host_key"), src.get("vhir.rid")
    return bool(key and rid) and action.get("_id") == doc_id(str(key), str(rid))


# Field names the stamp owns, at any depth of the subtree they belong to.
_RESERVED = {"vhir": {"host_key", "unit", "rid", "prev_ids"}, "host": {"id"}}


def _drop_owned(src: dict, resent: bool = False) -> int:
    """Remove the stamp's own fields wherever evidence put them: dotted, or
    at any depth of a `vhir` or `host` subtree (objects and lists of them,
    which OpenSearch indexes as the same fields). Returns how many came from
    the evidence. A parser's own `host.id`, and the stamp's own fields on a
    batch sent again, aren't counted: the stamp always replaces those."""
    count = 0
    for name in _OWNED:
        if name in src:
            del src[name]
            count += 0 if resent or name == "host.id" else 1
    for key in list(src):
        top, _, rest = key.partition(".")
        names = _RESERVED.get(top)
        if names is None:
            continue
        if rest and rest.rpartition(".")[2] in names:  # dotted, deeper than _OWNED
            del src[key]
            count += 1
            continue
        removed = _strip(src[key], names)
        if removed and src[key] in ({}, []):
            del src[key]
        count += removed
    return count


def _strip(node, names: set[str]) -> int:
    """Remove `names` at any depth of `node`; drop what that empties."""
    count = 0
    if isinstance(node, dict):
        for key in list(node):
            if key.rpartition(".")[2] in names:
                del node[key]
                count += 1
                continue
            removed = _strip(node[key], names)
            if removed and node[key] in ({}, []):
                del node[key]
            count += removed
    elif isinstance(node, list):
        kept = []
        for item in node:
            removed = _strip(item, names)
            count += removed
            if not (removed and item in ({}, [])):
                kept.append(item)
        node[:] = kept
    return count
