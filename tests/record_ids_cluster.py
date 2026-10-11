"""An in-memory cluster for the record-id tests: what the ingest paths call.

- helpers.bulk(client, actions, ...): `create` on an existing (index, id) is a
  409 error item, `index` overwrites; returns (successes, errors).
- client.mget, indices.exists/create/stats.
- client.count(index=, body={"query": ...}): bool (filter/must/must_not),
  term, terms, exists and match_all. Any other clause raises, so a change
  can't pass on a query this doesn't understand. A missing index raises
  NotFoundError, as the cluster does. Fields match as keyword (exact).
"""

from __future__ import annotations

import uuid
from pathlib import Path

from opensearchpy.exceptions import NotFoundError


def _get(src, field):
    if field in src:
        return src[field]
    node = src
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _vals(v):
    return v if isinstance(v, list) else [v]


def _match(src, q):
    if not q:
        return True
    ((kind, arg),) = q.items()
    if kind == "match_all":
        return True
    if kind == "bool":
        unknown = set(arg) - {"filter", "must", "must_not"}
        if unknown:
            raise ValueError(f"fake count: unsupported bool keys {unknown}")
        pos = _vals(arg.get("filter", [])) + _vals(arg.get("must", []))
        neg = _vals(arg.get("must_not", []))
        return all(_match(src, c) for c in pos) and not any(_match(src, c) for c in neg)
    if kind == "term":
        ((field, val),) = arg.items()
        if isinstance(val, dict):
            val = val["value"]
        return val in _vals(_get(src, field))
    if kind == "terms":
        ((field, vals),) = arg.items()
        return any(v in vals for v in _vals(_get(src, field)))
    if kind == "exists":
        v = _get(src, arg["field"])
        return v is not None and v != []
    raise ValueError(f"fake count: unsupported clause {kind}")


class Cluster:
    def __init__(self):
        self.store: dict[tuple[str, str], dict] = {}
        self.created: set[str] = set()
        cluster = self

        class Indices:
            def exists(self, index=None, **kw):
                return index in cluster.created or any(i == index for i, _ in cluster.store)

            def create(self, index=None, body=None, **kw):
                cluster.created.add(index)
                return {"acknowledged": True}

            def stats(self, index=None, **kw):
                return {"indices": {}}

            def get_settings(self, **kw):
                raise RuntimeError("no cluster")

        class Client:
            indices = Indices()

            def mget(self, body=None, **kw):
                out = []
                for d in body["docs"]:
                    key = (d["_index"], d["_id"])
                    src = cluster.store.get(key)
                    out.append({"_index": key[0], "_id": key[1], "found": src is not None,
                                **({"_source": src} if src is not None else {})})  # fmt: skip
                return {"docs": out}

            def count(self, index=None, body=None, **kw):
                if not self.indices.exists(index=index):
                    raise NotFoundError(404, "index_not_found_exception", {"index": index})
                q = (body or {}).get("query", {"match_all": {}})
                n = sum(1 for (i, _), s in cluster.store.items() if i == index and _match(s, q))
                return {"count": n}

        self.client = Client

    def bulk(self, client, actions, max_retries=None, raise_on_error=True,
             request_timeout=None, **kw):  # fmt: skip
        ok, errors = 0, []
        for a in list(actions):
            key = (a["_index"], a["_id"])
            if a.get("_op_type", "index") == "create" and key in self.store:
                conflict = {"type": "version_conflict_engine_exception",
                            "reason": "document already exists"}  # fmt: skip
                errors.append({"create": {"_index": a["_index"], "_id": a["_id"], "status": 409,
                                          "error": conflict}})  # fmt: skip
                continue
            self.store[key] = dict(a["_source"])
            self.created.add(a["_index"])
            ok += 1
        if raise_on_error and errors:
            raise RuntimeError(f"BulkIndexError: {len(errors)} errors")
        return ok, errors

    def docs(self, index: str) -> list[tuple[str, dict]]:
        """[(_id, _source)] stored in `index`, sorted by _id."""
        return sorted(((k[1], v) for k, v in self.store.items() if k[0] == index),
                      key=lambda t: t[0])  # fmt: skip


def make_case(cases_dir: Path, name: str) -> Path:
    """A case with an identity, as the record-id spec's probes made them."""
    case = cases_dir / name
    case.mkdir(parents=True, exist_ok=True)
    if not (case / "CASE.yaml").exists():
        (case / "CASE.yaml").write_text(
            f"case_id: {name}\ncase_uuid: {uuid.UUID(int=0xABC0 + len(name))}\nnaming_version: 2\n"
        )
    return case
