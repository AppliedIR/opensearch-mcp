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
        ignored_docs = client.count(index=index, body={"query": with_ignored})["count"]
        if ignored_docs:
            body = {"query": with_ignored, "size": _SAMPLE, "_source": False}
            hits = client.search(index=index, body=body)["hits"]["hits"]
            for name in sorted({f for h in hits for f in h.get("_ignored", [])}):
                field = {"bool": {"filter": [run, {"term": {"_ignored": name}}]}}
                ignored[name] = client.count(index=index, body={"query": field})["count"]
        if not all(isinstance(n, int) for n in (stored, ignored_docs, *ignored.values())):
            raise TypeError(f"counts that aren't numbers: {stored!r}, {ignored!r}")
        return {"stored": stored, "ignored_docs": ignored_docs, "ignored": ignored}
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: could not count what {index} stored: {e}", file=sys.stderr)
        return {}


# _ignored records malformed values; a keyword over ignore_above isn't in it.
NOTE = "Unparsed-field counts don't include values over ignore_above."


def describe(artifact: dict) -> str:
    """For a status line, e.g. ", 31 stored; 31 docs with unparsed fields
    (e.g. @timestamp ×30)", or "". The field names come from a sample, so
    they're examples; the document total is exact."""
    if "stored" not in artifact:
        return ""
    text = f", {artifact['stored']:,} stored"
    if artifact.get("ignored_docs"):
        n = artifact["ignored_docs"]
        text += f"; {n:,} doc{'' if n == 1 else 's'} with unparsed fields"
        ignored = artifact.get("ignored") or {}
        if ignored:
            text += " (e.g. " + ", ".join(f"{f} ×{n:,}" for f, n in ignored.items()) + ")"
    return text
