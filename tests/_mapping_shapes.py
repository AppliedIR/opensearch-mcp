"""get_mapping and cat.indices as OpenSearch 3.5.0 answers them, for a test
cluster given as {index: {dotted field name: type, or a mapping}}.

get_mapping with filter_path `*.mappings.properties.<top>` lists only the
indices that map <top>, a red one too; cat.indices lists every index the
expression names. A name under a leaf is that leaf's multi-field
(Path.keyword under a text Path).
"""

from __future__ import annotations

from fnmatch import fnmatch
from unittest.mock import MagicMock


def properties(fields: dict) -> dict:
    """{dotted name: type or mapping} as a mapping's properties."""
    props: dict = {}
    for name in sorted(fields, key=lambda n: n.count(".")):
        spec = fields[name]
        *parents, leaf = name.split(".")
        here = props
        for part in parents:
            node = here.setdefault(part, {})
            here = node.setdefault("fields" if "type" in node else "properties", {})
        here[leaf] = {"type": spec} if isinstance(spec, str) else dict(spec)
    return props


def named(mapped: dict, index: str) -> list[str]:
    """The indices of `mapped` that `index`, a comma list of names or patterns, names."""
    parts = index.split(",")
    return sorted(n for n in mapped if any(fnmatch(n, p) for p in parts))


def get_mapping(mapped: dict):
    """Answers a filter_path to one top-level field, or none; another filter
    (the dynamic templates) finds nothing here."""

    def answer(index, filter_path=None, **kw):
        out = {}
        top = (filter_path or "").partition(".mappings.properties.")[2]
        if filter_path and not top:
            return out
        for name in named(mapped, index):
            props = properties(mapped[name])
            if filter_path is None:
                out[name] = {"mappings": {"properties": props}}
            elif top in props:
                out[name] = {"mappings": {"properties": {top: props[top]}}}
        return out

    return answer


def cat_indices(mapped: dict):
    return lambda index="*", **kw: [{"index": n} for n in named(mapped, index)]


def serve(client, mapped: dict, cat: bool = True) -> None:
    """Point a MagicMock client's get_mapping (and cat.indices, unless the test
    sets its own rows) at `mapped`."""
    client.indices.get_mapping = MagicMock(side_effect=get_mapping(mapped))
    if cat:
        client.cat.indices = MagicMock(side_effect=cat_indices(mapped))
