"""Which indices belong to a case.

Every case-scoped read, enrichment write and index check takes its index
expression from here. A case's indices are named from its identity in
CASE.yaml (``case-<c12>-…``), never from its folder name, so a renamed case
folder keeps its data and two cases never read each other's.

A case from before 0.7 also has per-host indices named from its case id
(``case-<case id>-<type>-<host>``). They're read through an expression
computed on every call, never stored: ``case-<id>-*`` less ``-case-<t>-*``
for each case beside this one whose id ``t`` begins ``<id>-`` (those names
are the other case's). A case marked ``legacy_alias: none`` (restored beside
its original, or given a new identity) reads none.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from opensearch_mcp.paths import sanitize_index_component


class CaseScopeError(ValueError):
    """No case to read, or an index expression outside the case."""


@dataclass(frozen=True)
class CaseScope:
    case_id: str
    case_dir: Path
    c12: str
    naming_version: int
    legacy_id: str = ""  # CASE.yaml case_id: what pre-0.7 index names were built from

    @property
    def prefix(self) -> str:
        return f"case-{self.c12}-"

    @property
    def legacy_prefix(self) -> str:
        """`case-<id>-` of this case's pre-0.7 index names."""
        return f"case-{sanitize_index_component(self.legacy_id or self.case_id)}-"


def _active_case_id() -> str:
    from opensearch_mcp.paths import vhir_dir

    path = vhir_dir() / "active_case"
    try:
        raw = path.read_text().strip()
    except OSError:
        return ""
    return Path(raw).name if raw else ""


def scope_of(case_id: str = "") -> CaseScope:
    """The scope of `case_id`, or of the active case. Raises CaseScopeError
    when there's no case, or it has no directory."""
    from opensearch_mcp.write_context import case_dir_for, case_identity

    cid = case_id or _active_case_id()
    if not cid:
        raise CaseScopeError(
            "No active case: activate a case (vhir case activate) or pass case_id."
        )
    case_dir = case_dir_for(cid)
    if case_dir is None or not (case_dir / "CASE.yaml").is_file():
        raise CaseScopeError(f"No case directory with a CASE.yaml for case {cid!r}.")
    c12, version = case_identity(case_dir)
    legacy_id = str(_case_yaml(case_dir).get("case_id") or cid)
    return CaseScope(
        case_id=cid, case_dir=case_dir, c12=c12, naming_version=version, legacy_id=legacy_id
    )


def legacy_expression(scope: CaseScope, artifact_type: str = "", client=None) -> str:
    """The case's pre-0.7 indices (of one type), as an expression: "" when it
    has none to read.

    With a client, the indices are listed in this call, and a longer case id
    is excluded only when it has pre-0.7 indices: an exclusion that matches
    nothing fails a request made with allow_no_indices=False. When they
    can't be listed, every longer case id is excluded.
    """
    if scope.naming_version != 1 or not scope.legacy_id:
        return ""
    if _case_yaml(scope.case_dir).get("legacy_alias") == "none":
        return ""
    token = f"{sanitize_index_component(artifact_type)}-" if artifact_type else ""
    include = f"{scope.legacy_prefix}{token}*"
    longer = sorted(_longer_prefixes(scope))
    names = _index_names(client, include) if client is not None else None
    if names is not None:
        longer = [p for p in longer if any(n.startswith(p) for n in names)]
    return ",".join([include, *(f"-{p}*" for p in longer)])


def _index_names(client, pattern: str) -> list[str] | None:
    """Open indices matching `pattern`; None when they can't be listed."""
    try:
        return list(client.indices.get(index=pattern, expand_wildcards="open"))
    except Exception:
        return None


def case_read_scope(case_id: str = "", client=None, artifact_type: str = "") -> str:
    """The index expression of a case (or of one artifact type in it):
    `case-<c12>-*`, plus its pre-0.7 indices for a case from before 0.7."""
    scope = scope_of(case_id)
    token = f"{sanitize_index_component(artifact_type)}-" if artifact_type else ""
    new = f"{scope.prefix}{token}*" if scope.c12 else ""
    old = legacy_expression(scope, artifact_type, client)
    # A wildcard that matches nothing fails a request made with
    # allow_no_indices=False: name each part only when it matches something,
    # and the case's own when neither does.
    if client is not None:
        new_ok = bool(new) and _any_index(client, new)
        old_ok = bool(old) and _any_index(client, old)
        if new_ok or old_ok:
            new, old = (new if new_ok else ""), (old if old_ok else "")
    parts = [p for p in (new, old) if p]
    if not parts:  # no identity yet (nothing written) and nothing from before 0.7 to read
        raise CaseScopeError(f"Case {scope.case_id!r} has nothing indexed yet.")
    return ",".join(parts)


def _any_index(client, pattern: str) -> bool:
    """Whether `pattern` matches an open index (exists() answers true for a
    wildcard that matches none)."""
    try:
        found = client.indices.get(index=pattern, expand_wildcards="open")
    except Exception:
        return True
    return bool(found) if isinstance(found, dict) else True


def confine(expression: str, case_id: str = "", client=None) -> str:
    """`expression` when every segment is in the case: it starts with
    `case-<c12>-`, or is a pre-0.7 name of this case that can't reach another
    case's indices, or only excludes (`-…`). Raises CaseScopeError otherwise.
    An empty expression is the whole case."""
    if not expression or not expression.strip():
        return case_read_scope(case_id, client)
    scope = scope_of(case_id)
    for segment in expression.split(","):
        seg = segment.strip()
        if not seg or seg.startswith("-"):
            continue
        if scope.c12 and seg.startswith(scope.prefix):
            continue
        if _legacy_segment_is_own(seg, scope):
            continue
        own = scope.prefix if scope.c12 else scope.legacy_prefix
        raise CaseScopeError(
            f"Index segment {seg!r} is outside case {scope.case_id!r}: its indices start "
            f"with {own!r}. Omit index to read the whole case."
        )
    return expression


def _longer_prefixes(scope: CaseScope) -> set[str]:
    """`case-<id>-` of the local cases whose id begins with this case's id
    and a dash: their pre-0.7 names begin with this case's prefix."""
    own = scope.legacy_prefix
    return {
        f"case-{c}-"
        for c in _local_case_ids(scope.case_dir)
        if f"case-{c}-" != own and f"case-{c}-".startswith(own)
    }


def _legacy_segment_is_own(segment: str, scope: CaseScope) -> bool:
    """A pre-0.7 name or pattern of a pre-0.7 case that can't reach another
    case's indices: it starts `case-<id>-`, and its literal part (up to a
    wildcard) is incompatible with every longer local case id's prefix."""
    if not legacy_expression(scope) or not segment.startswith(scope.legacy_prefix):
        return False
    literal = re.split(r"[*?]", segment, maxsplit=1)[0]
    return not any(literal.startswith(p) or p.startswith(literal) for p in _longer_prefixes(scope))


def artifact_type(index: str, scope: CaseScope) -> str:
    """The artifact type of one of the case's indices: the remainder after
    `case-<c12>-` with `-0` removed; for a pre-0.7 index, the type token
    after `case-<id>-` (its host tail dropped)."""
    if index.startswith(scope.prefix):
        rest = index[len(scope.prefix) :]
        return rest[:-2] if rest.endswith("-0") else rest
    if index.startswith(scope.legacy_prefix):
        rest = index[len(scope.legacy_prefix) :]
        return rest.rsplit("-", 1)[0] if "-" in rest else rest
    return index


# --------------------------------------------------------------------------
# Cases beside this one


def _case_yaml(case_dir: Path) -> dict:
    try:
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return meta if isinstance(meta, dict) else {}


def _local_case_ids(case_dir: Path) -> set[str]:
    """Sanitized ids of the cases beside this one: each one's CASE.yaml
    `case_id` (what its pre-0.7 names were built from) and its folder name."""
    ids: set[str] = set()
    try:
        dirs = [d for d in case_dir.parent.iterdir() if d.is_dir() and (d / "CASE.yaml").is_file()]
    except OSError:
        return ids
    for d in dirs:
        ids.add(sanitize_index_component(d.name))
        cid = _case_yaml(d).get("case_id")
        if cid:
            ids.add(sanitize_index_component(str(cid)))
    return ids


def unattributed_indices(client, scope: CaseScope) -> list[str]:
    """Case indices no case on this machine can claim: neither a case's
    identity prefix nor the pre-0.7 prefix of a case directory beside this
    one. They're read by no case."""
    from opensearch_mcp.write_context import case_identity

    try:
        names = sorted(client.indices.get(index="case-*", expand_wildcards="open"))
    except Exception:
        return []
    prefixes = set()
    for d in scope.case_dir.parent.iterdir():
        if not (d / "CASE.yaml").is_file():
            continue
        try:
            c12, _ = case_identity(d)
        except FileNotFoundError:
            continue
        prefixes.add(f"case-{c12}-")
        meta = _case_yaml(d)
        prefixes.add(f"case-{sanitize_index_component(str(meta.get('case_id') or d.name))}-")
    return [n for n in names if not any(n.startswith(p) for p in prefixes)]


# --------------------------------------------------------------------------
# A pre-0.7 case's hosts, once


def _field_form(props: dict, field: str) -> str | None:
    """`field` when the index maps it as keyword, `field.keyword` when it's
    text with a keyword sub-field, else None."""
    from opensearch_mcp.host_dictionary import detect_host_id_mapping_type

    if field == "host.id":
        kind = detect_host_id_mapping_type(props)
    else:
        node = props.get(field) or (props.get("host") or {}).get("properties", {}).get(
            field.split(".", 1)[1]
        )
        kind = node.get("type") if isinstance(node, dict) else None
        if kind == "text" and "keyword" in (node.get("fields") or {}):
            return f"{field}.keyword"
    if kind == "keyword":
        return field
    if kind == "text":
        return f"{field}.keyword"
    return None


def _v1_pairs(client, index: str) -> list[tuple[str, str, str]]:
    """(index, host.name, host.id) for every pair in one pre-0.7 index, read
    with that index's own field forms."""
    props = client.indices.get_mapping(index=index)[index]["mappings"].get("properties", {})
    name_f, id_f = _field_form(props, "host.name"), _field_form(props, "host.id")
    if not name_f:
        return []
    sources = [{"name": {"terms": {"field": name_f}}}]
    if id_f:
        sources.append({"id": {"terms": {"field": id_f, "missing_bucket": True}}})
    pairs, after = [], None
    while True:
        comp = {"size": 1000, "sources": sources}
        if after:
            comp["after"] = after
        resp = client.search(index=index, body={"size": 0, "aggs": {"p": {"composite": comp}}})
        agg = resp.get("aggregations", {}).get("p", {})
        for b in agg.get("buckets", []):
            pairs.append((index, b["key"]["name"], b["key"].get("id") or b["key"]["name"]))
        after = agg.get("after_key")
        if not after or not agg.get("buckets"):
            return pairs


def ensure_v1_imported(client, case_dir) -> bool:
    """For a case from before 0.7, seed its host logs once from its v1 host
    dictionary and the host names its pre-0.7 indices hold, so a new ingest
    of one of its hosts joins that host's machine and keeps its host.id.
    Returns True when it imported now. A failed read raises, and nothing is
    recorded: the import runs again next time rather than on partial pairs."""
    from sift_common import host_identity

    from opensearch_mcp.write_context import case_identity

    case_dir = Path(case_dir)
    if host_identity.load(case_dir).v1_imported:
        return False
    c12, version = case_identity(case_dir)
    if version != 1:
        return False
    meta = _case_yaml(case_dir)
    scope = CaseScope(
        case_id=case_dir.name,
        case_dir=case_dir,
        c12=c12,
        naming_version=version,
        legacy_id=str(meta.get("case_id") or case_dir.name),
    )
    old = legacy_expression(scope)
    members = sorted(client.indices.get(index=old, expand_wildcards="open")) if old else []
    hosts = {}
    path = case_dir / "host-dictionary.yaml"
    if path.is_file():
        try:
            hosts = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("hosts") or {}
        except (OSError, yaml.YAMLError):
            hosts = {}
    pairs = [p for index in members for p in _v1_pairs(client, index)]
    return host_identity.import_v1(case_dir, hosts, pairs)
