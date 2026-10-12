"""Index template + ingest pipeline install helpers.

Currently focused on the winlog Data normalization pipeline (Fix G).
Exposed from here rather than from server.py so the installer is
importable without pulling the MCP server module (useful for CLI
paths and tests).
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MAPPINGS_DIR = Path(__file__).resolve().parent
_PIPELINE_FILE = _MAPPINGS_DIR / "winlog_data_normalize_v1.json"
_EVTX_TEMPLATE_FILE = _MAPPINGS_DIR / "evtx_ecs_template.json"

# Component templates composed into composable templates via `composed_of`.
# Must be PUT before any composable template that references them —
# OpenSearch rejects composable PUT if referenced components don't yet
# exist. See install_component_templates() below.
_COMPONENT_TEMPLATES_REGISTRY: list[tuple[str, str]] = [
    ("vhir-json-type-stability", "json_type_stability.json"),
]

_PIPELINE_ID = "winlog_data_normalize_v1"
# Canonical evtx template name. scripts/setup-opensearch.sh uses the
# same name. Earlier versions installed under "vhir-evtx"; that legacy
# name is DELETEd in ensure_winlog_pipeline so upgraded clusters don't
# retain two templates matching case-*-evtx-* at identical priority
# (undefined-winner bug).
_TEMPLATE_NAME = "vhir-evtx-ecs"
_LEGACY_TEMPLATE_NAME = "vhir-evtx"
_TEMPLATE_PATTERN = "case-*-evtx-*"
_TEMPLATE_PRIORITY = 100

# Non-evtx templates. evtx is handled by ensure_winlog_pipeline because
# it requires the winlog pipeline to be PUT first + collision-checked +
# validate-before-PUT against the pipeline script. The templates below
# are plain mapping installs with no such dependency.
#
# Names match scripts/setup-opensearch.sh — keep in sync. setup-opensearch.sh
# runs once at deployment time; without install_all_templates() running on
# every MCP startup/ingest, edits to these JSON files on disk never reach
# upgraded deployments (confirmed by Test agent 2026-04-21: delimited/json/
# vol3 template edits were dead code without this installer).
_TEMPLATES_REGISTRY: list[tuple[str, str]] = [
    ("vhir-csv", "csv_template.json"),
    ("vhir-prefetch", "prefetch_template.json"),
    ("vhir-plaso", "plaso_template.json"),
    ("vhir-srum", "srum_template.json"),
    ("vhir-transcripts", "transcripts_template.json"),
    ("vhir-w3c", "w3c_template.json"),
    ("vhir-defender", "defender_template.json"),
    ("vhir-tasks", "tasks_template.json"),
    ("vhir-wer", "wer_template.json"),
    ("vhir-ssh", "ssh_template.json"),
    ("vhir-vol3", "vol3_template.json"),
    ("vhir-json", "json_template.json"),
    ("vhir-delimited", "delimited_template.json"),
    ("vhir-accesslog", "accesslog_template.json"),
    ("vhir-hayabusa", "hayabusa_template.json"),
]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


# Every case index records which machine and evidence unit each document
# belongs to. Added to every template, so no index can map them otherwise.
HOST_KEY_FIELDS: dict[str, dict] = {
    "vhir.host_key": {"type": "keyword"},
    "vhir.unit": {"type": "keyword"},
    "vhir.prev_ids": {"type": "keyword"},
    "vhir.rid": {"type": "keyword", "index": False},
    # the registered evidence a record's run was given, and the record's hash
    "vhir.original.path": {"type": "keyword"},
    "vhir.original.sha256": {"type": "keyword"},
    "vhir.content_hash": {"type": "keyword"},
}


def with_host_key_fields(body: dict) -> dict:
    """`body` (an index template) with the machine and unit fields mapped."""
    props = body.setdefault("template", {}).setdefault("mappings", {}).setdefault("properties", {})
    props.update(HOST_KEY_FIELDS)
    return body


def template_type_tokens() -> frozenset[str]:
    """The artifact type of every shipped template pattern (`case-*-<type>-*`)."""
    tokens = set()
    for path in [_EVTX_TEMPLATE_FILE] + [_MAPPINGS_DIR / f for _, f in _TEMPLATES_REGISTRY]:
        for pattern in _load_json(path).get("index_patterns", []):
            parts = pattern.split("-")
            if len(parts) == 4 and parts[0] == "case" and parts[1] == "*" and parts[3] == "*":
                tokens.add(parts[2])
    return frozenset(tokens)


def stale_date_fields(client, index: str, why: list | None = None) -> list[str] | None:
    """The csv template's date fields (the EZ tools' date columns) that `index`
    maps as dates without the template's format: an index made before 0.6.5,
    whose EZ dates go unparsed until it is rebuilt from the template. None when
    the mapping can't be read, and why in `why` when given."""
    props = _load_json(_MAPPINGS_DIR / "csv_template.json")["template"]["mappings"]["properties"]
    want = {
        f: p["format"] for f, p in props.items() if p.get("type") == "date" and p.get("format")
    }
    try:
        got = client.indices.get_mapping(index=index)[index]["mappings"].get("properties", {})
    except Exception as e:
        if why is not None:
            why.append(str(e) or type(e).__name__)
        return None
    return sorted(
        f for f, fmt in want.items()
        if (got.get(f) or {}).get("type") == "date" and got[f].get("format") != fmt
    )  # fmt: skip


def install_component_templates(client) -> dict[str, Any]:
    """Idempotent install of shared component templates.

    Component templates (vhir-json-type-stability today) are composed
    into composable index templates via `composed_of`. They must exist
    on the cluster BEFORE any composable template PUT that references
    them — OpenSearch rejects the composable otherwise. This function
    runs first from install_all_templates().

    Returns same shape as install_all_templates.
    """
    results: dict[str, Any] = {"installed": [], "failed": [], "skipped": []}
    for comp_name, filename in _COMPONENT_TEMPLATES_REGISTRY:
        path = _MAPPINGS_DIR / filename
        if not path.exists():
            results["skipped"].append(comp_name)
            continue
        try:
            body = _load_json(path)
            client.cluster.put_component_template(name=comp_name, body=body)
            results["installed"].append(comp_name)
        except Exception as e:
            logger.warning("install_component_templates: %s failed: %s", comp_name, e)
            results["failed"].append({"template": comp_name, "error": str(e)})
    return results


# The stamp's own fields: what an index made before they were mapped lacks
STAMP_FIELDS = ("vhir.original.path", "vhir.original.sha256", "vhir.content_hash")


def put_stamp_fields(client, audit=None) -> dict[str, Any]:
    """Map the stamp's fields `keyword` on every open case index, one
    put_mapping each (one index's conflict doesn't stop the others), recorded
    as one step when `audit` is given."""
    results: dict[str, Any] = {"patched": [], "failed": []}
    props = {f: HOST_KEY_FIELDS[f] for f in STAMP_FIELDS}
    try:
        rows = client.cat.indices(index="case-*", h="index", format="json",
                                  expand_wildcards="open")  # fmt: skip
    except Exception as e:
        results["failed"].append({"index": "case-*", "error": str(e)})
        rows = []
    names = [r.get("index") for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    for index in sorted(n for n in names if n):
        try:
            client.indices.put_mapping(index=index, body={"properties": props})
            results["patched"].append(index)
        except Exception as e:
            logger.warning("put_stamp_fields: %s failed: %s", index, e)
            results["failed"].append({"index": index, "error": str(e)})
    if audit is not None and (results["patched"] or results["failed"]):
        from opensearch_mcp import ops

        ops.write(
            audit,
            "put_stamp_fields",
            params={"fields": list(STAMP_FIELDS), "indices": results["patched"]},
            summary=f"{len(results['patched'])} case index(es) given the stamp's fields"
            + (f", {len(results['failed'])} failed" if results["failed"] else ""),
            extra={"failed": results["failed"]} if results["failed"] else None,
        )
    return results


def install_all_templates(client, audit=None) -> dict[str, Any]:
    """Idempotent install of all non-evtx case-* index templates.

    Installs component templates FIRST (they're referenced by composable
    templates via composed_of), then each composable template in
    _TEMPLATES_REGISTRY. Per-template failures are collected and
    returned; a single failure does NOT abort the remaining installs —
    a typo in one template file should not strand the others.

    Called from the same sites as ensure_winlog_pipeline (server
    first-connection, ingest pre-flight, idx_install_pipelines tool).
    Without this, edits to csv/prefetch/srum/transcripts/w3c/defender/
    tasks/wer/ssh/vol3/json/delimited/accesslog/hayabusa templates on
    disk never reach the cluster after initial setup-opensearch.sh run.

    Returns:
        {
          "installed": [template_name, ...],
          "failed":    [{"template": name, "error": str}, ...],
          "skipped":   [template_name, ...],    # file missing on disk
          "components": {component-install sub-result dict},
          "patched_indices": {patch_flattened_indices sub-result dict},
        }
    """
    comp_results = install_component_templates(client)
    results: dict[str, Any] = {
        "installed": [],
        "failed": [],
        "skipped": [],
        "components": comp_results,
    }
    loaded: list[Any] = []
    for tpl_name, filename in _TEMPLATES_REGISTRY:
        path = _MAPPINGS_DIR / filename
        if not path.exists():
            results["skipped"].append(tpl_name)
            continue
        try:
            body = with_host_key_fields(_load_json(path))
            loaded.append(body)
            client.indices.put_index_template(name=tpl_name, body=body)
            results["installed"].append(tpl_name)
        except Exception as e:
            logger.warning("install_all_templates: %s failed: %s", tpl_name, e)
            results["failed"].append({"template": tpl_name, "error": str(e)})
    try:
        patterns = _composing_index_patterns(loaded)
        results["patched_indices"] = patch_flattened_indices(client, patterns)
    except Exception as e:  # never cost the install its per-template results
        logger.warning("install_all_templates: patching existing indices failed: %s", e)
        results["patched_indices"] = {"patched": [], "failed": [{"index": "*", "error": str(e)}]}
    results["stamp_fields"] = put_stamp_fields(client, audit)  # indices made before them
    return results


def _composing_index_patterns(bodies: list[Any]) -> list[str]:
    """Index patterns of the loaded templates that compose a registered
    component. Takes the bodies the install loop already read, so a file that
    does not parse is reported once, as that template's failure."""
    components = {name for name, _ in _COMPONENT_TEMPLATES_REGISTRY}
    return [
        pattern
        for body in bodies
        if isinstance(body, dict) and components & set(body.get("composed_of", []))
        for pattern in body.get("index_patterns", [])
    ]


def patch_flattened_indices(client, index_patterns: list[str]) -> dict[str, Any]:
    """Replace `dynamic_templates` on existing open indices still carrying a
    `flattened` rule, with the component's current list.

    `flattened` is not an OpenSearch type, so those rules rejected every
    record holding an object or a dotted key. Dynamic templates live in the
    index's own mapping, so installing a fixed component template leaves
    existing indices unchanged; one `put_mapping` per index replaces the list
    on the open index without closing it. Index-level settings are static
    and stay as they were.
    """
    results: dict[str, Any] = {"patched": [], "failed": []}
    if not index_patterns:
        return results
    try:
        component = _load_json(_MAPPINGS_DIR / "json_type_stability.json")
        replacement = component["template"]["mappings"]["dynamic_templates"]
    except Exception as e:
        logger.warning("patch_flattened_indices: component unreadable: %s", e)
        results["failed"].append({"index": ",".join(index_patterns), "error": str(e)})
        return results
    try:
        current = client.indices.get_mapping(
            index=",".join(index_patterns),
            expand_wildcards="open",
            allow_no_indices=True,
            ignore_unavailable=True,
            filter_path="*.mappings.dynamic_templates",
        )
    except Exception as e:
        logger.warning("patch_flattened_indices: reading mappings failed: %s", e)
        results["failed"].append({"index": ",".join(index_patterns), "error": str(e)})
        return results
    if not isinstance(current, dict):
        return results
    for index, body in current.items():
        rules = body.get("mappings", {}).get("dynamic_templates", [])
        if not any(
            rule.get("mapping", {}).get("type") == "flattened"
            for entry in rules
            for rule in entry.values()
        ):
            continue
        try:
            client.indices.put_mapping(index=index, body={"dynamic_templates": replacement})
            results["patched"].append(index)
        except Exception as e:
            logger.warning("patch_flattened_indices: %s failed: %s", index, e)
            results["failed"].append({"index": index, "error": str(e)})
    return results


_EVENT_DATA = "winlog.event_data"
_EVTX_RULE = "winlog_event_data_strings"


def _evtx_limits() -> tuple[dict[str, int], int, dict]:
    """The evtx template's event-data keyword limits: each explicit
    property's ({dotted path: limit}), the dynamic rule's, and the rule's
    entry as the template gives it."""
    m = _load_json(_EVTX_TEMPLATE_FILE)["template"]["mappings"]
    explicit = {
        path: body["ignore_above"]
        for path, body in m.get("properties", {}).items()
        if path.startswith(_EVENT_DATA + ".")
        and body.get("type") == "keyword"
        and "ignore_above" in body
    }
    entry = next(e for e in m["dynamic_templates"] if _EVTX_RULE in e)
    return explicit, entry[_EVTX_RULE]["mapping"]["ignore_above"], entry


def _event_data(mapping: dict) -> dict:
    """The `winlog.event_data` properties of an index's mapping."""
    for key in ("winlog", "event_data"):
        mapping = mapping.get("properties", {}).get(key, {})
        if not isinstance(mapping, dict):
            return {}
    props = mapping.get("properties", {})
    return props if isinstance(props, dict) else {}


def _low_event_data(
    props: dict, prefix: str, explicit: dict[str, int], rule: int
) -> tuple[dict[str, int], dict]:
    """The keyword fields under `prefix` whose `ignore_above` is below the
    template's limit for their path (its explicit property, else the rule):
    ({dotted path: current limit}, the put_mapping properties raising them).
    A field without a limit, or of another type, is left as it is."""
    low: dict[str, int] = {}
    body: dict[str, Any] = {}
    for name, m in props.items():
        if not isinstance(m, dict):
            continue
        path = f"{prefix}.{name}"
        limit = m.get("ignore_above")
        want = explicit.get(path, rule)
        if m.get("type") == "keyword" and isinstance(limit, int) and limit < want:
            low[path] = limit
            body[name] = {**m, "ignore_above": want}
        if isinstance(m.get("properties"), dict):
            sub_low, sub_body = _low_event_data(m["properties"], path, explicit, rule)
            low.update(sub_low)
            if sub_body:
                body[name] = {"properties": sub_body}
    return low, body


def _low_rule(rules: list, rule: int) -> int | None:
    """The index's own event-data rule's limit, when below the template's."""
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        limit = (entry.get(_EVTX_RULE) or {}).get("mapping", {}).get("ignore_above")
        if isinstance(limit, int) and limit < rule:
            return limit
    return None


def patch_evtx_indices(client, audit=None) -> dict[str, Any]:
    """Raise the event-data limits on every open evtx index to the template's.

    A template applies only when an index is made, and a dynamic rule maps
    only fields not mapped yet: so each index's full mapping is read, and one
    `put_mapping` replaces its event-data rule and raises each keyword field
    below the template's limit for its path. A limit is never lowered, and an
    index already at the template's limits is sent nothing. Records already
    stored keep the limit they were indexed with."""
    results: dict[str, Any] = {"patched": {}, "unchanged": [], "failed": []}
    explicit, rule, entry = _evtx_limits()
    try:
        current = client.indices.get_mapping(
            index=_TEMPLATE_PATTERN,
            expand_wildcards="open",
            allow_no_indices=True,
            ignore_unavailable=True,
        )
    except Exception as e:
        logger.warning("patch_evtx_indices: reading mappings failed: %s", e)
        results["failed"].append({"index": _TEMPLATE_PATTERN, "error": str(e)})
        return results
    if not isinstance(current, dict):
        return results
    for index, body in sorted(current.items()):
        mapping = body.get("mappings", {}) if isinstance(body, dict) else {}
        low, props = _low_event_data(_event_data(mapping), _EVENT_DATA, explicit, rule)
        rules = mapping.get("dynamic_templates") or []
        raised = rules
        if _low_rule(rules, rule) is not None:
            raised = [entry if _EVTX_RULE in e else e for e in rules]
        if not props and raised == rules:
            results["unchanged"].append(index)
            continue
        put: dict[str, Any] = {}
        if raised != rules:
            put["dynamic_templates"] = raised
        if props:
            put["properties"] = {"winlog": {"properties": {"event_data": {"properties": props}}}}
        try:
            client.indices.put_mapping(index=index, body=put)
            results["patched"][index] = sorted(low) + ([_EVTX_RULE] if raised != rules else [])
        except Exception as e:  # one index's refusal doesn't stop the others
            logger.warning("patch_evtx_indices: %s failed: %s", index, e)
            results["failed"].append({"index": index, "error": str(e)})
    if audit is not None and (results["patched"] or results["failed"]):
        from opensearch_mcp import ops

        ops.write(
            audit,
            "patch_evtx_indices",
            params={"indices": results["patched"]},
            summary=f"{len(results['patched'])} evtx index(es) given the template's "
            "event-data limits"
            + (f", {len(results['failed'])} failed" if results["failed"] else ""),
            extra={"failed": results["failed"]} if results["failed"] else None,
        )
    return results


class _Unreadable(Exception):
    """A mapping whose event-data limits can't be read from its shape."""


def _dict(value, what: str) -> dict:
    if not isinstance(value, dict):
        raise _Unreadable(f"{what} isn't an object")
    return value


def _read_low(props: dict, prefix: str, explicit: dict[str, int], rule: int, low: dict) -> None:
    """Every field mapping under `prefix`, read strictly: each is an object,
    a keyword's limit (if any) is an integer, and nested properties are an
    object. The keyword fields below the template's limit go in `low`."""
    for name, m in props.items():
        path = f"{prefix}.{name}"
        m = _dict(m, path)
        if m.get("type") == "keyword" and "ignore_above" in m:
            limit = m["ignore_above"]
            if not isinstance(limit, int) or isinstance(limit, bool):
                raise _Unreadable(f"{path}'s ignore_above isn't an integer")
            if limit < explicit.get(path, rule):
                low[path] = limit
        if "properties" in m:
            _read_low(_dict(m["properties"], f"{path}'s properties"), path, explicit, rule, low)


def evtx_limit_note(client, index: str) -> str:
    """What an evtx ingest into `index` says about its event-data limits.

    "" only when the index isn't made yet (404: the template applies), or on
    a positive read: the mapping is an object, every event-data field mapping
    in it is one, and every keyword limit and the rule's are integers at
    least the template's. Limits below the template's name their fields and
    the lowest limit. Anything else, including any error while reading, says
    the limits couldn't be checked: they are unknown, not fine. Nothing is
    raised into the ingest."""
    from opensearchpy.exceptions import NotFoundError

    try:
        try:
            got = client.indices.get_mapping(index=index)
        except NotFoundError:
            return ""
        explicit, rule, _ = _evtx_limits()
        body = _dict(got, "the mapping reply").get(index)
        mapping = _dict(_dict(body, f"the reply for {index}").get("mappings"), "its mappings")
        rules = mapping.get("dynamic_templates")
        if not isinstance(rules, list):
            raise _Unreadable(f"its mapping has no readable {_EVTX_RULE} rule")
        limits_of_rule = [
            _dict(_dict(e[_EVTX_RULE], _EVTX_RULE).get("mapping"), f"{_EVTX_RULE}'s mapping").get(
                "ignore_above"
            )
            for e in rules
            if isinstance(e, dict) and _EVTX_RULE in e
        ]
        if not limits_of_rule or not all(
            isinstance(n, int) and not isinstance(n, bool) for n in limits_of_rule
        ):
            raise _Unreadable(f"its mapping has no readable {_EVTX_RULE} rule")
        node = _dict(mapping.get("properties"), "its properties")
        for key in ("winlog", "event_data"):
            if key not in node:
                node = {}
                break
            node = _dict(_dict(node[key], key).get("properties", {}), f"{key}'s properties")
        low: dict[str, int] = {}
        _read_low(node, _EVENT_DATA, explicit, rule, low)
    except Exception as e:  # an unreadable shape or any error: the ingest goes on, and says so
        return f"couldn't check {index}'s event-data limits: {e}"
    names = sorted(path[len(_EVENT_DATA) + 1 :] for path in low)
    limits = list(low.values())
    if (rule_limit := min(limits_of_rule)) < rule:
        names.append("new fields")
        limits.append(rule_limit)
    if not names:
        return ""
    shown = ", ".join(names[:10]) + (", …" if len(names) > 10 else "")
    return (
        f"{index}: winlog.event_data values longer than {min(limits):,} characters in "
        f"{shown} are stored but not indexed, so a search on those fields doesn't find "
        "them (the index's mapping predates 0.6.5 and wasn't updated)"
    )


def ensure_winlog_pipeline(client, audit=None) -> dict[str, Any]:
    """Install winlog_data_normalize_v1 pipeline + update evtx template.

    Order (IMPORTANT — Rev 6 correctness correction):
      1. Collision check against any operator template at higher
         priority on matching pattern.
      2. Simulate pipeline inline against 5 input shapes BEFORE PUT:
         nested+object, nested+string, nested+list, flat-dotted+object,
         flat-dotted+string. Flat-dotted shapes are what parse_evtx.py
         actually emits — G8 slipped past earlier rounds because only
         nested shapes were tested. Existing pipeline (if any) stays
         in place on validation failure.
      3. PUT pipeline only after validation passes.
      4. PUT template (which binds default_pipeline to the now-valid
         pipeline).
      5. Warn operator about legacy indices predating the pipeline
         (non-fatal — just surfaces the re-ingest edge case).

    Returns {status, ...details}. status == "ok" on success;
    status == "error" with actionable message otherwise.
    """
    # Non-evtx templates have zero dependency on the winlog pipeline
    # or evtx template. Install them first so they deploy even when
    # the evtx path below refuses (priority collision, default_pipeline
    # conflict, simulate-validation failure) or the whole function
    # raises. This matches CR's 2026-04-21 recommendation.
    try:
        other_templates_result = install_all_templates(client, audit)
    except Exception as _ot_e:
        logger.warning("install_all_templates unexpected failure: %s", _ot_e)
        other_templates_result = {
            "installed": [],
            "failed": [{"template": "*", "error": str(_ot_e)}],
            "skipped": [],
        }

    try:
        # 1. Collision check — does anyone outrank us on the pattern?
        try:
            sim = client.indices.simulate_index_template(
                name=f"{_TEMPLATE_PATTERN.replace('*', 'PROBE')}"
            )
        except Exception:
            sim = {}
        existing_priority = (sim.get("template", {}) or {}).get("priority", 0) or 0
        if existing_priority > _TEMPLATE_PRIORITY:
            return {
                "status": "error",
                "error": (
                    f"Existing index template with priority "
                    f"{existing_priority} preempts ours "
                    f"({_TEMPLATE_PRIORITY}) for pattern "
                    f"{_TEMPLATE_PATTERN}. Resolve before install."
                ),
                "other_templates": other_templates_result,
            }
        existing_dp = (
            (sim.get("template", {}) or {})
            .get("settings", {})
            .get("index", {})
            .get("default_pipeline")
        )
        if existing_dp and existing_dp != _PIPELINE_ID:
            return {
                "status": "error",
                "error": (
                    f"Existing default_pipeline '{existing_dp}' already "
                    f"bound to {_TEMPLATE_PATTERN}. Manual resolution "
                    f"required before installing {_PIPELINE_ID}."
                ),
                "other_templates": other_templates_result,
            }

        # 2. Simulate-pipeline validation BEFORE PUT — inline body form.
        # Test both document shapes: nested (ctx.winlog.event_data) and
        # flat-dotted-key (ctx['winlog.event_data']). parse_evtx.py
        # emits the flat form; missing that case in validation is how
        # G8 slipped past earlier rounds — the pipeline ran but early-
        # returned on real docs.
        pipeline_body = _load_json(_PIPELINE_FILE)
        validation_docs = [
            # Shape 0: nested, object Data
            {
                "_index": "case-probe-evtx-validate",
                "_source": {"winlog": {"event_data": {"Data": {"TargetUserName": "alice"}}}},
            },
            # Shape 1: nested, string Data
            {
                "_index": "case-probe-evtx-validate",
                "_source": {"winlog": {"event_data": {"Data": "raw string value"}}},
            },
            # Shape 2: nested, list Data
            {
                "_index": "case-probe-evtx-validate",
                "_source": {"winlog": {"event_data": {"Data": ["val1", "val2"]}}},
            },
            # Shape 3: flat-dotted key, object Data (parse_evtx shape)
            {
                "_index": "case-probe-evtx-validate",
                "_source": {"winlog.event_data": {"Data": {"LogonType": "3"}}},
            },
            # Shape 4: flat-dotted key, string Data
            {
                "_index": "case-probe-evtx-validate",
                "_source": {"winlog.event_data": {"Data": "flat raw"}},
            },
        ]
        sim_result = client.ingest.simulate(
            body={"pipeline": pipeline_body, "docs": validation_docs}
        )
        for i, doc_result in enumerate(sim_result.get("docs", [])):
            source = doc_result.get("doc", {}).get("_source", {})
            # Fall back between nested and flat-dotted lookup to
            # mirror the script's own navigation.
            out = source.get("winlog", {}).get("event_data") or source.get("winlog.event_data", {})
            if "Data_raw" not in out:
                return {
                    "status": "error",
                    "error": (
                        f"Simulate validation failed on input shape {i}: "
                        f"Data_raw missing post-pipeline. Existing "
                        f"pipeline (if any) left in place."
                    ),
                    "other_templates": other_templates_result,
                }
            # Object-shape inputs (shapes 0, 3) must retain Data.
            # Non-object inputs (shapes 1, 2, 4) must NOT retain Data.
            obj_shapes = {0, 3}
            if i in obj_shapes and "Data" not in out:
                return {
                    "status": "error",
                    "error": f"Shape {i} (object): expected Data to survive",
                    "other_templates": other_templates_result,
                }
            if i not in obj_shapes and "Data" in out:
                return {
                    "status": "error",
                    "error": (
                        f"Shape {i} (non-object): expected Data to be stripped but it remains"
                    ),
                    "other_templates": other_templates_result,
                }

        # 3. PUT pipeline (only after validation).
        client.ingest.put_pipeline(id=_PIPELINE_ID, body=pipeline_body)

        # 4. PUT index template (binds default_pipeline).
        # Non-evtx templates are already installed at the top of the
        # function so they land even if steps 1-3 refuse.
        # Legacy cleanup: prior versions installed under _LEGACY_TEMPLATE_NAME.
        # Delete that first (ignore 404) so upgraded clusters don't retain
        # two templates matching the same pattern at the same priority.
        try:
            client.indices.delete_index_template(name=_LEGACY_TEMPLATE_NAME, ignore=[404])
        except Exception as _legacy_e:
            logger.debug("legacy evtx template delete non-fatal: %s", _legacy_e)
        template_body = with_host_key_fields(_load_json(_EVTX_TEMPLATE_FILE))
        client.indices.put_index_template(name=_TEMPLATE_NAME, body=template_body)
        # Existing evtx indices get the template's event-data limits too
        evtx_indices = patch_evtx_indices(client, audit)

        # 5. Legacy re-ingest guard (non-fatal).
        legacy_count = 0
        try:
            mappings = client.indices.get_mapping(index=_TEMPLATE_PATTERN)
            for idx, m in (mappings or {}).items():
                props = (
                    m.get("mappings", {})
                    .get("properties", {})
                    .get("winlog", {})
                    .get("properties", {})
                    .get("event_data", {})
                    .get("properties", {})
                )
                if "Data_raw" not in props:
                    legacy_count += 1
            if legacy_count:
                print(
                    f"NOTE: {legacy_count} legacy evtx indices predate "
                    f"pipeline {_PIPELINE_ID}. Re-ingest of their source "
                    f"evidence will require --recreate-index if shape "
                    f"conflicts arise.",
                    file=sys.stderr,
                )
        except Exception:
            pass  # legacy guard is informational only

        # Evtx path succeeded. Downgrade status to "partial" if any
        # non-evtx template failed — otherwise an "ok" response masks
        # 13-of-14 broken templates behind a green light.
        success_status = "ok"
        patched = other_templates_result.get("patched_indices") or {}
        if other_templates_result.get("failed") or patched.get("failed") or evtx_indices["failed"]:
            success_status = "partial"
        return {
            "status": success_status,
            "pipeline": _PIPELINE_ID,
            "template": _TEMPLATE_NAME,
            "legacy_indices_without_data_raw": legacy_count,
            "evtx_patched": evtx_indices["patched"],
            "evtx_unchanged": evtx_indices["unchanged"],
            "evtx_failed": evtx_indices["failed"],
            "other_templates": other_templates_result,
        }

    except Exception as e:
        logger.exception("ensure_winlog_pipeline failed")
        return {
            "status": "error",
            "error": str(e),
            "other_templates": other_templates_result,
        }
