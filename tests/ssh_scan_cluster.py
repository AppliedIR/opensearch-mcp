"""An in-memory cluster for the ssh scan-route tests (from the G2 spec's probes).

Honours: bulk create (409 when the id is held) and index; raise_on_error is the
helpers' job (they read our `errors`/`items`); count/search with bool
(filter/must/must_not), term, terms, exists, match_all. An unknown clause
raises. A missing index raises NotFoundError on count/search.
"""

from __future__ import annotations

import json

from opensearchpy.exceptions import NotFoundError


class _Indices:
    def __init__(self, store):
        self.s = store

    def exists(self, index, **kw):
        return index in self.s.docs

    def create(self, index, body=None, **kw):
        self.s.docs.setdefault(index, {})
        return {"acknowledged": True}

    def stats(self, **kw):
        return {"indices": {}}

    def get_settings(self, index, **kw):
        if index not in self.s.docs:
            raise NotFoundError(404, "index_not_found_exception", {})
        return {index: {"settings": {}, "defaults": {"index.mapping.depth.limit": "20"}}}

    def simulate_index_template(self, name, **kw):
        return {"template": {"settings": {}}}

    def refresh(self, index=None, **kw):
        return {}

    def get(self, index=None, **kw):
        names = [n for n in self.s.docs if _idx_match(n, index)]
        if not names and index and "*" not in str(index):
            raise NotFoundError(404, "index_not_found_exception", {"index": index})
        return {n: {"aliases": {}, "mappings": {}, "settings": {}} for n in names}

    def get_alias(self, index=None, name=None, **kw):
        return {}


def _get(src, field):
    if field in src:
        return src[field]
    node = src
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _match(src, q):
    if not q or "match_all" in q:
        return True
    ((kind, arg),) = q.items()
    if kind == "bool":
        ok = all(_match(src, c) for c in _list(arg.get("filter")) + _list(arg.get("must")))
        return ok and not any(_match(src, c) for c in _list(arg.get("must_not")))
    if kind == "term":
        ((f, v),) = arg.items()
        v = v["value"] if isinstance(v, dict) else v
        got = _get(src, f)
        return got == v or (isinstance(got, list) and v in got)
    if kind == "terms":
        ((f, vs),) = arg.items()
        return _get(src, f) in vs
    if kind == "exists":
        return _get(src, arg["field"]) is not None
    raise ValueError(f"fake: unknown clause {kind}")


def _list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


class FakeOS:
    def __init__(self):
        from types import SimpleNamespace

        from opensearchpy.serializer import JSONSerializer

        self.docs: dict[str, dict[str, dict]] = {}
        self.indices = _Indices(self)
        self.transport = SimpleNamespace(serializer=JSONSerializer())

    # --- writes -------------------------------------------------------
    def bulk(self, body=None, *a, **kw):
        if body is None and a:
            body = a[0]
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
        lines = body.splitlines() if isinstance(body, str) else list(body)
        lines = [json.loads(x) if isinstance(x, (str, bytes)) else x for x in lines if x]
        items, errors = [], False
        i = 0
        while i < len(lines):
            ((op, meta),) = lines[i].items()
            src = lines[i + 1] if op != "delete" else None
            i += 2 if op != "delete" else 1
            idx, did = meta["_index"], meta.get("_id")
            store = self.docs.setdefault(idx, {})
            if op == "create" and did in store:
                errors = True
                items.append(
                    {
                        op: {
                            "_index": idx,
                            "_id": did,
                            "status": 409,
                            "error": {"type": "version_conflict_engine_exception"},
                        }
                    }
                )
                continue
            store[did] = src
            items.append({op: {"_index": idx, "_id": did, "status": 201, "result": "created"}})
        return {"took": 1, "errors": errors, "items": items}

    def mget(self, body=None, **kw):
        out = []
        for d in body["docs"]:
            src = self.docs.get(d["_index"], {}).get(d["_id"])
            out.append(
                {
                    "_index": d["_index"],
                    "_id": d["_id"],
                    "found": src is not None,
                    "_source": src or {},
                }
            )
        return {"docs": out}

    # --- reads --------------------------------------------------------
    def _hits(self, index, body):
        names = [n for n in self.docs if _idx_match(n, index)]
        if not names:
            raise NotFoundError(404, "index_not_found_exception", {"index": index})
        q = (body or {}).get("query")
        return [(n, i, s) for n in names for i, s in self.docs[n].items() if _match(s, q)]

    def count(self, index=None, body=None, **kw):
        return {"count": len(self._hits(index, body))}

    def search(self, index=None, body=None, **kw):
        hits = self._hits(index, body)
        size = (body or {}).get("size", 10)
        return {
            "hits": {
                "total": {"value": len(hits)},
                "hits": [{"_index": n, "_id": i, "_source": s} for n, i, s in hits[:size]],
            }
        }

    # --- helpers for probes ------------------------------------------
    def all(self, prefix=""):
        return [
            (n, i, s)
            for n, d in sorted(self.docs.items())
            if n.startswith(prefix)
            for i, s in sorted(d.items())
        ]


def _idx_match(name, pattern):
    if pattern is None:
        return True
    for p in str(pattern).split(","):
        if p.endswith("*") and name.startswith(p[:-1]):
            return True
        if name == p:
            return True
    return False
