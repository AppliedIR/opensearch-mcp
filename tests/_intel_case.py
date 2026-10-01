"""A throwaway case for enrichment tests, laid out the way ingest lays one out.

Indices are named `case-<id>-<kind>-<name>` so `enrich_case(client, <id>)`
finds them. json, delimited and prefetch indices get the shipped templates under
this run's own names, at a priority above the live ones; an
evtx-shaped index uses the fields the evtx template maps (`winlog.event_data.*`
keyword, `source.ip` ip) under a kind no live template matches, so the live
evtx ingest pipeline never runs on test documents.
"""

from __future__ import annotations

import contextlib
import copy
import json
import uuid
from pathlib import Path

_MAPPINGS_DIR = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"

EVTX_MAPPING = {
    "properties": {
        "source": {"properties": {"ip": {"type": "ip"}}},
        "winlog": {
            "properties": {
                "event_data": {
                    "properties": {
                        name: {"type": "keyword"}
                        for name in (
                            "Hashes",
                            "QueryName",
                            "IpAddress",
                            "SourceIp",
                            "DestinationIp",
                        )
                    }
                }
            }
        },
    }
}


_TEMPLATES = (
    ("json", "json_template.json"),
    ("delim", "delimited_template.json"),
    ("prefetch", "prefetch_template.json"),  # its undeclared fields map as text
)


@contextlib.contextmanager
def intel_case(client, docs: dict[str, list[dict]], prefix: str = "pytest-intel"):
    """`docs` maps `<kind>-<name>` to its records; kind is json, delim,
    prefetch or winevt.

    Yields the case id. Everything is removed afterwards, even if setup fails.
    """
    case_id = f"{prefix}-{uuid.uuid4().hex[:8]}"
    base = f"case-{case_id}"
    try:
        component = json.loads((_MAPPINGS_DIR / "json_type_stability.json").read_text())
        client.cluster.put_component_template(name=f"{base}-comp", body=component)
        for kind, filename in _TEMPLATES:
            body = copy.deepcopy(json.loads((_MAPPINGS_DIR / filename).read_text()))
            body["template"].pop("aliases", None)
            body["index_patterns"] = [f"{base}-{kind}-*"]
            if kind != "prefetch":
                body["composed_of"] = [f"{base}-comp"]
            body["priority"] = 900
            client.indices.put_index_template(name=f"{base}-{kind}", body=body)
        for name, records in docs.items():
            index = f"{base}-{name}"
            if name.startswith("winevt-"):
                client.indices.create(index=index, body={"mappings": EVTX_MAPPING})
            for i, record in enumerate(records):
                client.index(index=index, id=str(i), body=record)
        client.indices.refresh(index=f"{base}-*")
        yield case_id
    finally:
        client.indices.delete(index=f"{base}-*", ignore=[404])
        for kind, _ in _TEMPLATES:
            client.indices.delete_index_template(name=f"{base}-{kind}", ignore=[404])
        client.cluster.delete_component_template(name=f"{base}-comp", ignore=[404])
