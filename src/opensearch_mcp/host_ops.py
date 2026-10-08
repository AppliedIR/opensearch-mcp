"""Rename, merge and split a case's machines (the examiner's host operations).

Every operation relabels: it sets ``host.id`` on the docs of the machine keys
it moves and never re-keys, creates or deletes a doc, so a doc's id keeps its
original machine key and a merge keeps both copies of a record two machines
both held. Pre-0.7 docs, which carry no machine key, are selected by their
index and ``host.name``.

One operation runs at a time, with the case lock held exclusively, so no
ingest or enrichment writes into the case meanwhile. Its order:

  every check (field forms, shard headroom) → the journal entry
  (``running``, with the doc counts per key) → the relabel → the verify
  → the decision line → ``done``

and on any failure the entry is ``incomplete`` with its reason and counts. The
decision line is appended only after the docs carry the new names. While an
operation is incomplete, only resuming it is accepted.

No MCP tool starts an operation: the portal does, through ``run`` or
``python -m opensearch_mcp.host_ops``.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from sift_common import host_identity as hi

KINDS = ("rename", "merge", "split")
V1_UNIT_PREFIX = "pre-0.7 index "
# A doc's host.id where it stands: a flat key (every v2 doc) or an object.
_SET_HOST_ID = (
    "if (ctx._source.containsKey('host.id') || !(ctx._source.get('host') instanceof Map))"
    " { ctx._source['host.id'] = params.c } else { ctx._source['host']['id'] = params.c }"
)
_KEYWORD_FIELDS = ("vhir.host_key", "vhir.unit", "host.name", "host.id")
_POLL_SECONDS = 0.5


class HostOpRefused(Exception):
    """An operation that may not start (nothing was written)."""


# --------------------------------------------------------------------------
# The plan: what each kind moves, checked against the fold


def _machine(state: hi.HostState, key) -> hi.Machine:
    m = state.machine_of_key(str(key or ""))
    if m is None:
        raise HostOpRefused(f"no machine {key!r} in this case")
    return m


def _new_canonical(state: hi.HostState, canonical, own: set[str]) -> str:
    name = str(canonical or "").strip()
    if not name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise HostOpRefused("a host name must be given, without control characters")
    owner = state.canonical_owner(name)
    if owner is not None and owner.id not in own:
        raise HostOpRefused(
            f"host name {name!r} is already used by another machine ({owner.canonical}); "
            "merge the two machines instead"
        )
    return name


def plan(state: hi.HostState, op: dict) -> dict:
    """The decision args, the machine keys to relabel and the name they get,
    and the pre-0.7 (index, host.name) pairs that go with them. Raises
    HostOpRefused when the operation doesn't fit the case as it is."""
    kind = op.get("kind")
    if kind not in KINDS:
        raise HostOpRefused(f"unknown host operation {kind!r}")
    if kind == "rename":
        m = _machine(state, op.get("machine"))
        canonical = _new_canonical(state, op.get("canonical"), {m.id})
        if canonical == m.canonical:
            raise HostOpRefused(f"the machine is already named {canonical!r}")
        args = {"machine": m.id, "canonical": canonical}
        keys, pairs = list(m.keys), list(m.pairs)
    elif kind == "merge":
        into = _machine(state, op.get("into"))
        others = [_machine(state, k) for k in op.get("from") or ()]
        if not others or any(o.id == into.id for o in others):
            raise HostOpRefused("a merge needs one or more other machines to merge in")
        canonical = into.canonical
        args = {"into": into.id, "from": sorted({o.id for o in others})}
        keys = sorted({k for o in others for k in o.keys})
        pairs = [p for o in others for p in o.pairs]
    else:
        m = _machine(state, op.get("machine"))
        keys = sorted({str(k) for k in op.get("keys") or ()})
        if not keys or not set(keys) < set(m.keys):
            raise HostOpRefused(
                "a split moves some of the machine's keys, never none and never all"
            )
        canonical = _new_canonical(state, op.get("canonical"), set())
        args = {"machine": m.id, "keys": keys, "canonical": canonical}
        pairs = [p for p in m.pairs if state.bindings.get(p) in keys]
    v1 = sorted(
        (str(state.units.get(u, {}).get("locator", ""))[len(V1_UNIT_PREFIX) :], raw)
        for u, raw in pairs
        if str(state.units.get(u, {}).get("locator", "")).startswith(V1_UNIT_PREFIX)
    )
    return {"kind": kind, "args": args, "keys": keys, "canonical": canonical, "v1": v1}


# --------------------------------------------------------------------------
# The indices: field forms first


def _kind(props: dict, dotted: str) -> tuple[str | None, bool]:
    """(mapping type of `dotted`, whether it has a keyword sub-field)."""
    node = props.get(dotted)
    if not isinstance(node, dict):
        node, here = None, props
        for part in dotted.split("."):
            node = (here or {}).get(part)
            if not isinstance(node, dict):
                return None, False
            here = node.get("properties")
    return node.get("type"), "keyword" in (node.get("fields") or {})


def _form(props: dict, dotted: str) -> str | None:
    kind, sub = _kind(props, dotted)
    if kind == "keyword":
        return dotted
    if kind == "text" and sub:
        return f"{dotted}.keyword"
    return None


def check_indices(client, c12: str, v1_indices: list[str]) -> dict:
    """{index: {field: form}} for the case's own indices and the pre-0.7
    ones in the plan. Raises HostOpRefused on an own index that doesn't map
    the identity fields as keyword, or a pre-0.7 index with no usable
    host.name or host.id form."""
    forms: dict[str, dict] = {}
    try:
        own = client.indices.get_mapping(index=f"case-{c12}-*", allow_no_indices=True)
    except Exception as e:
        raise HostOpRefused(f"the case's indices can't be read: {e}") from e
    for index, body in sorted((own or {}).items()):
        props = (body.get("mappings") or {}).get("properties") or {}
        bad = [f for f in _KEYWORD_FIELDS if _kind(props, f)[0] not in (None, "keyword")]
        bad += [f for f in _KEYWORD_FIELDS[:3] if _kind(props, f)[0] is None]
        if bad:
            raise HostOpRefused(
                f"index {index} doesn't map {', '.join(sorted(set(bad)))} as keyword; "
                "nothing was changed. Delete and re-ingest that index"
            )
        forms[index] = {f: f for f in _KEYWORD_FIELDS}
    for index in sorted(set(v1_indices)):
        try:
            body = client.indices.get_mapping(index=index)[index]
        except Exception as e:
            raise HostOpRefused(f"pre-0.7 index {index} can't be read: {e}") from e
        props = (body.get("mappings") or {}).get("properties") or {}
        name_f, id_f = _form(props, "host.name"), _form(props, "host.id")
        if not name_f or not id_f:
            raise HostOpRefused(
                f"pre-0.7 index {index} has no keyword host.name or host.id to select by; "
                "nothing was changed"
            )
        forms[index] = {"host.name": name_f, "host.id": id_f}
    return forms


def check_headroom(client, c12: str, p: dict, forms: dict) -> None:
    """Raises HostOpRefused when an index's shard couldn't take the operation's
    updates (each leaves a deleted copy behind until a merge) under Lucene's
    document limit."""
    from opensearch_mcp.write_context import shard_headroom

    for index in sorted(forms):
        if index in {i for i, _ in p["v1"]}:
            n = sum(_count(client, index, _v1_query(forms[index], name))
                    for i, name in p["v1"] if i == index)  # fmt: skip
        else:
            n = _count(client, index, _own_query(p["keys"]))
        why = shard_headroom(client, index, n) if n else ""
        if why:
            raise HostOpRefused(f"{why}; nothing was changed")


# --------------------------------------------------------------------------
# Selections, counts, the relabel and the verify


def _own_query(keys: list[str], canonical: str | None = None) -> dict:
    q: dict = {"bool": {"filter": [{"terms": {"vhir.host_key": keys}}]}}
    if canonical is not None:
        q["bool"]["must_not"] = [{"term": {"host.id": canonical}}]
    return q


def _v1_query(forms: dict, name: str, canonical: str | None = None) -> dict:
    q: dict = {"bool": {"filter": [{"term": {forms["host.name"]: name}}]}}
    if canonical is not None:
        q["bool"]["must_not"] = [{"term": {forms["host.id"]: canonical}}]
    return q


def _count(client, index: str, query: dict) -> int:
    resp = client.count(
        index=index, body={"query": query}, allow_no_indices=True, ignore_unavailable=True
    )
    failed = int((resp.get("_shards") or {}).get("failed") or 0)
    if failed:  # a count without them isn't the count
        raise HostOpRefused(f"{index}: {failed} shard(s) failed to answer a count; try again")
    return int(resp.get("count", 0))


def counts(client, c12: str, p: dict, forms: dict) -> dict:
    """Docs per machine key, and per pre-0.7 (index, host.name)."""
    per_key = {}
    for k in p["keys"]:
        per_key[k] = _count(client, f"case-{c12}-*", _own_query([k]))
    per_v1 = {
        f"{index}|{name}": _count(client, index, _v1_query(forms[index], name))
        for index, name in p["v1"]
    }
    return {"keys": per_key, "v1": per_v1}


def _update(client, index: str, query: dict, canonical: str) -> dict:
    """One update_by_query (conflicts abort, run as a task, polled)."""
    resp = client.update_by_query(
        index=index,
        body={"query": query, "script": {"source": _SET_HOST_ID, "params": {"c": canonical}}},
        conflicts="abort",
        refresh=True,
        wait_for_completion=False,
        allow_no_indices=True,
        ignore_unavailable=True,
    )
    task = resp.get("task")
    if not task:
        return resp
    while True:
        status = client.tasks.get(task_id=task)
        if status.get("completed"):
            if status.get("error"):
                raise RuntimeError(f"task {task}: {status['error']}")
            return status.get("response") or {}
        time.sleep(_POLL_SECONDS)


def relabel(client, c12: str, p: dict, forms: dict) -> int:
    """Set host.id on every doc of the plan. Returns the docs updated."""
    updated = 0
    selections = [(f"case-{c12}-*", _own_query(p["keys"], p["canonical"]))]
    selections += [
        (index, _v1_query(forms[index], name, p["canonical"])) for index, name in p["v1"]
    ]
    for index, query in selections:
        result = _update(client, index, query, p["canonical"])
        failures = result.get("failures") or []
        if failures or result.get("version_conflicts"):
            raise RuntimeError(
                f"{index}: {len(failures)} failure(s), {result.get('version_conflicts', 0)} "
                f"version conflict(s): {json.dumps(failures[:3])[:300]}"
            )
        updated += int(result.get("updated", 0))
    return updated


def verify(client, c12: str, p: dict, forms: dict, before: dict) -> str:
    """Why the docs don't all carry the new name with every count unchanged,
    or ""."""
    stale = _count(client, f"case-{c12}-*", _own_query(p["keys"], p["canonical"]))
    stale += sum(
        _count(client, index, _v1_query(forms[index], name, p["canonical"]))
        for index, name in p["v1"]
    )
    if stale:
        return f"{stale} doc(s) still without the name {p['canonical']!r}"
    after = counts(client, c12, p, forms)
    if after != before:
        return f"doc counts changed during the operation: before {before}, after {after}"
    return ""


# --------------------------------------------------------------------------
# What else writes into the case


def unfinished_note(op: dict) -> str:
    """What to say of an unfinished operation (``hi.unfinished_op``)."""
    what = op.get("kind") or "host operation"
    if op.get("canonical"):
        what += f" to {op['canonical']!r}"
    return (
        f"host operation {op.get('id', '?')} ({what}) is {op.get('state', 'unfinished')}: "
        "the examiner resumes it in the Hosts tab"
    )


@contextlib.contextmanager
def case_writes(case_dir):
    """Hold the case lock shared for writes into the case's docs that aren't
    an ingest (enrichment): never while a host operation runs or is left
    unfinished. Raises HostOpRefused."""
    root = Path(case_dir)
    held = contextlib.ExitStack()
    try:
        held.enter_context(hi.case_lock(root, shared=True))
    except hi.CaseLockBusy:
        raise HostOpRefused(
            "the examiner's host operation is running; try again when it's done"
        ) from None
    with held:
        op = hi.unfinished_op(root)
        if op:
            raise HostOpRefused(unfinished_note(op))
        yield


# --------------------------------------------------------------------------
# One operation


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _busy_reason(case_dir: Path) -> str:
    from opensearch_mcp.ingest_status import read_active_ingests

    try:
        runs = [
            r
            for r in read_active_ingests()
            if r.get("case_id") == case_dir.name and r.get("status") in ("running", "starting")
        ]
    except Exception:
        runs = []
    if not runs:
        return "a process holds the case lock"
    named = ", ".join(f"{r.get('run_id') or r.get('pid')} ({r.get('status')})" for r in runs)
    return f"runs are writing into the case: {named}"


def run(case_dir, op: dict | None, examiner: str, resume: str | None = None, client=None) -> dict:
    """Run a host operation, or resume an incomplete one. Returns its
    journal entry ({"id", "state", ...}). Raises HostOpRefused when it may
    not start."""
    root = Path(case_dir)
    if not examiner:
        raise HostOpRefused("a host operation needs the examiner who asks for it")
    from opensearch_mcp.write_context import case_identity

    held = contextlib.ExitStack()
    try:
        held.enter_context(hi.case_lock(root, shared=False))
    except hi.CaseLockBusy:
        raise HostOpRefused(_busy_reason(root)) from None
    with held:
        return _run_locked(root, op, examiner, resume, client, case_identity(root)[0])


def _entry(root: Path, op_id: str, **fields) -> dict:
    return {"id": op_id, **hi.record_op(root, op_id, fields)}


def _run_locked(root: Path, op, examiner, resume, client, c12) -> dict:
    pending = hi.unfinished_op(root)
    if resume is not None:
        if pending is None or pending["id"] != resume:
            raise HostOpRefused(f"there's no incomplete host operation {resume!r}")
        op_id, op = resume, pending["op"]
        if hi.decided_op(root, op_id):  # it finished; the worker stopped before saying so
            return _entry(root, op_id, state="done", finished=_now())
    elif pending is not None:
        raise HostOpRefused(
            f"host operation {pending['id']} is {pending.get('state')}: resume it first"
        )
    else:
        op_id = f"op-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{secrets.token_hex(3)}"
    if client is None:
        from opensearch_mcp.client import get_client

        client = get_client()
    state = hi.load(root)
    p = plan(state, op)
    forms = check_indices(client, c12, [index for index, _ in p["v1"]])
    check_headroom(client, c12, p, forms)
    if resume is None:  # the baseline: what the cluster holds now, every write visible
        client.indices.refresh(
            index=",".join([f"case-{c12}-*", *sorted({i for i, _ in p["v1"]})]),
            allow_no_indices=True, ignore_unavailable=True,
        )  # fmt: skip
    before = pending.get("before") if resume is not None else counts(client, c12, p, forms)
    hi.record_op(root, op_id, {
        "op": op, "kind": p["kind"], "args": p["args"], "keys": p["keys"],
        "canonical": p["canonical"], "v1": [list(x) for x in p["v1"]], "before": before,
        "examiner": examiner, "state": "running", "reason": "",
        **({} if resume is not None else {"started": _now()}),
    })  # fmt: skip
    try:
        updated = relabel(client, c12, p, forms)
        why = verify(client, c12, p, forms, before)
        if why:
            return _entry(root, op_id, state="incomplete", reason=why)
        hi.append_decision(
            root,
            {"action": p["kind"], "examiner": examiner, "origin": "portal", "op": op_id,
             "args": p["args"]},
            state.obs_offset,
            door="R",
        )  # fmt: skip
    except Exception as e:
        return _entry(root, op_id, state="incomplete", reason=str(e)[:500])
    return _entry(root, op_id, state="done", relabelled=updated, finished=_now())


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m opensearch_mcp.host_ops")
    ap.add_argument("--case-dir", required=True)
    ap.add_argument("--examiner", required=True)
    which = ap.add_mutually_exclusive_group(required=True)
    which.add_argument("--op", help="the operation, as JSON")
    which.add_argument("--resume", help="the id of an incomplete operation")
    args = ap.parse_args(argv)
    try:
        op = json.loads(args.op) if args.op else None
        if op is not None and not isinstance(op, dict):
            raise HostOpRefused("--op must be a JSON object")
        result = run(args.case_dir, op, args.examiner, resume=args.resume)
    except (HostOpRefused, hi.HostLogError, ValueError) as e:
        print(json.dumps({"state": "refused", "reason": str(e)}))
        return 2
    print(json.dumps(result))
    return 0 if result.get("state") == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
