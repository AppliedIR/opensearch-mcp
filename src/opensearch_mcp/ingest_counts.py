"""What the index kept of one ingest run, counted after it.

The bulk counts are of documents sent: two rows that key to the same
document count twice and are stored once, and a value the mapping can't
parse (an `@timestamp`, say) is dropped from the document with no error.
"""

from __future__ import annotations

import sys

# A terms aggregation on _ignored errors or comes back empty; the field
# names are in the hits' metadata, so a few hits name them.
_SAMPLE = 20


def stored_counts(client, index: str, audit_id: str) -> dict:
    """{"stored": documents carrying this run's audit id, "ignored": {field:
    documents where the mapping ignored that field}}, or {} if the cluster
    couldn't be asked: counting never fails the ingest."""
    run = {"term": {"vhir.ingest_audit_id": audit_id}}
    with_ignored = {"bool": {"filter": [run, {"exists": {"field": "_ignored"}}]}}
    try:
        client.indices.refresh(index=index)
        stored = client.count(index=index, body={"query": run})["count"]
        ignored: dict[str, int] = {}
        if client.count(index=index, body={"query": with_ignored})["count"]:
            body = {"query": with_ignored, "size": _SAMPLE, "_source": False}
            hits = client.search(index=index, body=body)["hits"]["hits"]
            for name in sorted({f for h in hits for f in h.get("_ignored", [])}):
                field = {"bool": {"filter": [run, {"term": {"_ignored": name}}]}}
                ignored[name] = client.count(index=index, body={"query": field})["count"]
        if not all(isinstance(n, int) for n in (stored, *ignored.values())):
            raise TypeError(f"counts that aren't numbers: {stored!r}, {ignored!r}")
        return {"stored": stored, "ignored": ignored}
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: could not count what {index} stored: {e}", file=sys.stderr)
        return {}


def describe(artifact: dict) -> str:
    """ ", 682 stored; ignored: @timestamp ×1" for a status line, or ""."""
    if "stored" not in artifact:
        return ""
    text = f", {artifact['stored']:,} stored"
    ignored = artifact.get("ignored") or {}
    if ignored:
        text += "; ignored: " + ", ".join(f"{f} ×{n:,}" for f, n in ignored.items())
    return text
