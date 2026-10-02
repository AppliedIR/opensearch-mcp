"""The tree's index templates, component template and pipeline, under a run tag.

The real installer writes the live names, and deletes a legacy one, so a test
that ran it changed the templates every examiner case on the cluster uses.
Here every name gets the run tag, `case-*` patterns become `case-{tag}-*`,
`composed_of` and `default_pipeline` follow the renames, aliases are dropped
so test indices don't join the live ones, and each priority moves up by a
fixed offset: the copies outrank the live templates on test indices while
keeping their own order, which matters where two patterns overlap (csv and
srum both match `-srum-`). Only what was created here is removed.
"""

from __future__ import annotations

import copy

from opensearch_mcp import mappings

PRIORITY_OFFSET = 1000


def install(client, tag: str) -> dict[str, list[str]]:
    """Install the tree's templates for `case-{tag}-*` indices. Returns what
    was created, for `remove`."""
    created: dict[str, list[str]] = {"components": [], "pipelines": [], "templates": []}
    renamed = {}
    for name, filename in mappings._COMPONENT_TEMPLATES_REGISTRY:
        renamed[name] = f"{tag}-{name}"
        body = mappings._load_json(mappings._MAPPINGS_DIR / filename)
        client.cluster.put_component_template(name=renamed[name], body=body)
        created["components"].append(renamed[name])

    pipeline = f"{tag}-{mappings._PIPELINE_ID}"
    client.ingest.put_pipeline(id=pipeline, body=mappings._load_json(mappings._PIPELINE_FILE))
    created["pipelines"].append(pipeline)

    registry = [*mappings._TEMPLATES_REGISTRY]
    registry.append((mappings._TEMPLATE_NAME, mappings._EVTX_TEMPLATE_FILE.name))
    for name, filename in registry:
        body = copy.deepcopy(mappings._load_json(mappings._MAPPINGS_DIR / filename))
        body["index_patterns"] = [
            f"case-{tag}-{p.removeprefix('case-')}" for p in body["index_patterns"]
        ]
        body["priority"] = body.get("priority", 0) + PRIORITY_OFFSET
        if "composed_of" in body:
            body["composed_of"] = [renamed[c] for c in body["composed_of"]]
        template = body.setdefault("template", {})
        template.pop("aliases", None)
        settings = template.get("settings", {})
        for scope, key in (
            (settings, "index.default_pipeline"),
            (settings.get("index", {}), "default_pipeline"),
        ):
            if scope.get(key) == mappings._PIPELINE_ID:
                scope[key] = pipeline
        client.indices.put_index_template(name=f"{tag}-{name}", body=body)
        created["templates"].append(f"{tag}-{name}")
    return created


def remove(client, created: dict[str, list[str]]) -> None:
    for name in created["templates"]:
        client.indices.delete_index_template(name=name, ignore=[404])
    for name in created["components"]:
        client.cluster.delete_component_template(name=name, ignore=[404])
    for name in created["pipelines"]:
        client.ingest.delete_pipeline(id=name, ignore=[404])
