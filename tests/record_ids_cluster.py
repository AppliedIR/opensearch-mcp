"""An in-memory cluster for the record-id tests: what the ingest paths call.

- helpers.bulk(client, actions, ...): `create` on an existing (index, id) is a
  409 error item, `index` overwrites; returns (successes, errors).
- client.mget: each id found (with its `_version`) or not; an index that
  doesn't exist answers each of its ids with an index_not_found_exception
  item, as the cluster does. `mget_error` makes the request raise, and
  `mget_item_error` answers every id with that error item, `mget_short`
  leaves out the last answer.
- indices.exists/create/stats.
"""

from __future__ import annotations

import uuid
from pathlib import Path

NO_INDEX = {"type": "index_not_found_exception", "reason": "no such index"}


class Cluster:
    def __init__(self):
        self.store: dict[tuple[str, str], dict] = {}
        self.created: set[str] = set()
        self.reject = False  # every write refused (a mapping conflict, a block)
        self.timeout_once = False  # the next write is stored, then answered by a timeout
        self.versions: dict[tuple[str, str], int] = {}  # each stored doc's _version
        self.asked: list[tuple[str, str]] = []  # every (index, id) an mget asked for
        self.mget_error: Exception | None = None
        self.mget_item_error: dict | None = None
        self.mget_short = False  # one answer fewer than the ids asked
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

            def refresh(self, index=None, **kw):
                return {}

        class Client:
            indices = Indices()

            def mget(self, body=None, **kw):
                cluster.asked += [(d["_index"], d["_id"]) for d in body["docs"]]
                if cluster.mget_error is not None:
                    raise cluster.mget_error
                out = []
                for d in body["docs"]:
                    key = (d["_index"], d["_id"])
                    src = cluster.store.get(key)
                    if cluster.mget_item_error is not None or not self.indices.exists(
                        index=key[0]
                    ):
                        error = cluster.mget_item_error or NO_INDEX
                        out.append({"_index": key[0], "_id": key[1], "error": error})
                        continue
                    out.append({"_index": key[0], "_id": key[1], "found": src is not None,
                                **({"_source": src, "_version": cluster.versions[key]}
                                   if src is not None else {})})  # fmt: skip
                return {"docs": out[:-1] if cluster.mget_short else out}

        self.client = Client

    def bulk(self, client, actions, max_retries=None, raise_on_error=True,
             request_timeout=None, **kw):  # fmt: skip
        ok, errors = 0, []
        actions = list(actions)
        if self.timeout_once:  # stored, but the answer never came back
            self.timeout_once = False
            for a in actions:
                if (a["_index"], a["_id"]) not in self.store:
                    self.store[(a["_index"], a["_id"])] = dict(a["_source"])
                    self.versions[(a["_index"], a["_id"])] = 1
            from opensearchpy.exceptions import ConnectionTimeout

            raise ConnectionTimeout("TIMEOUT", "read timed out", None)
        for a in actions:
            key = (a["_index"], a["_id"])
            if self.reject:
                refused = {"type": "mapper_parsing_exception", "reason": "rejected"}
                item = {"_index": a["_index"], "_id": a["_id"], "status": 400, "error": refused}
                errors.append({a.get("_op_type", "index"): item})
                continue
            if a.get("_op_type", "index") == "create" and key in self.store:
                conflict = {"type": "version_conflict_engine_exception",
                            "reason": "document already exists"}  # fmt: skip
                errors.append({"create": {"_index": a["_index"], "_id": a["_id"], "status": 409,
                                          "error": conflict}})  # fmt: skip
                continue
            self.store[key] = dict(a["_source"])
            self.versions[key] = self.versions.get(key, 0) + 1
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
