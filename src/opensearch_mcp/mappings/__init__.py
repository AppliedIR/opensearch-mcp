"""Index template + ingest pipeline install helpers.

Currently focused on the winlog Data normalization pipeline (Fix G).
Exposed from here rather than from server.py so the installer is
importable without pulling the MCP server module (useful for CLI
paths and tests).
"""

from __future__ import annotations

import fnmatch
import json
import logging
import sys
import threading
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
# What each template governs, as its file says (a test keeps them equal), so
# the template an index gets is decided without reading every file: one whose
# file is missing or doesn't parse refuses its own indices and no others.
_TEMPLATE_PATTERNS: dict[str, tuple[int, tuple[str, ...]]] = {
    "vhir-csv": (
        10,
        (
            "case-*-amcache-*",
            "case-*-shimcache-*",
            "case-*-mft-*",
            "case-*-usn-*",
            "case-*-registry-*",
            "case-*-shellbags-*",
            "case-*-jumplists-*",
            "case-*-lnk-*",
            "case-*-recyclebin-*",
            "case-*-timeline-*",
            "case-*-srum-*",
        ),
    ),
    "vhir-prefetch": (20, ("case-*-prefetch-*",)),
    "vhir-plaso": (29, ("case-*-plaso-*",)),
    "vhir-srum": (21, ("case-*-srum-*",)),
    "vhir-transcripts": (22, ("case-*-transcripts-*",)),
    "vhir-w3c": (
        23,
        (
            "case-*-iis-*",
            "case-*-httperr-*",
            "case-*-firewall-*",
        ),
    ),
    "vhir-defender": (24, ("case-*-defender-*",)),
    "vhir-tasks": (25, ("case-*-tasks-*",)),
    "vhir-wer": (26, ("case-*-wer-*",)),
    "vhir-ssh": (27, ("case-*-ssh-*",)),
    "vhir-vol3": (15, ("case-*-vol-*",)),
    "vhir-json": (12, ("case-*-json-*",)),
    "vhir-delimited": (
        11,
        (
            "case-*-delim-*",
            "case-*-zeek-*",
            "case-*-bodyfile-*",
        ),
    ),
    "vhir-accesslog": (28, ("case-*-accesslog-*",)),
    "vhir-hayabusa": (18, ("case-*-hayabusa-*",)),
}


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


_INSTALLED_LOCK = threading.Lock()
_INSTALLED: dict | None = None  # this process's ensure_winlog_pipeline result


def ensure_installed_once(client, audit=None) -> dict:
    """ensure_winlog_pipeline, once per process (whatever the cluster already
    holds: an older release's templates are replaced), from the process's
    first write. What wasn't installed is printed once."""
    global _INSTALLED
    with _INSTALLED_LOCK:
        if _INSTALLED is None:
            try:
                _INSTALLED = ensure_winlog_pipeline(client, audit)
            except Exception as e:
                _INSTALLED = {"status": "error", "error": str(e)}
            other = _INSTALLED.get("other_templates") or {}
            failed = (other.get("components") or {}).get("failed", []) + other.get("failed", [])
            bad = [f"{f.get('template')}: {f.get('error')}" for f in failed]
            if _INSTALLED.get("status") not in ("ok", "partial"):
                bad.append(f"{_TEMPLATE_NAME}: {_INSTALLED.get('error')}")
            if bad:
                print("WARNING: index templates not installed: " + "; ".join(bad),
                      file=sys.stderr)  # fmt: skip
        return _INSTALLED


def template_for(index: str) -> str | None:
    """The shipped non-evtx template OpenSearch would apply to `index`: of
    those whose patterns match, the one of highest priority. None for evtx
    (ensure_winlog_pipeline's) and for an index none matches."""
    best: tuple[int, str] | None = None
    for name, (priority, patterns) in _TEMPLATE_PATTERNS.items():
        if any(fnmatch.fnmatchcase(index, p) for p in patterns):
            if best is None or priority > best[0]:
                best = (priority, name)
    return best[1] if best else None


def not_installed(result: dict, template: str) -> str:
    """Why non-evtx `template` isn't on the cluster after the install
    `result`, or "" when it is."""
    other = result.get("other_templates") or {}
    if template in other.get("skipped", []):
        return f"its file {dict(_TEMPLATES_REGISTRY).get(template)} is missing"
    for f in other.get("failed", []):
        if f.get("template") in (template, "*"):
            return str(f.get("error") or "failed")
    if template not in other.get("installed", []):
        return str(result.get("error") or "not installed")
    return ""


def install_all_templates(client, audit=None) -> dict[str, Any]:
    """Idempotent install of all non-evtx case-* index templates.

    Installs component templates FIRST (they're referenced by composable
    templates via composed_of), then each composable template in
    _TEMPLATES_REGISTRY. Per-template failures are collected and
    returned; a single failure does NOT abort the remaining installs —
    a typo in one template file should not strand the others.

    Called from ensure_winlog_pipeline, so from the same sites: the server's
    first connection, idx_install_pipelines, and every ingest process's first
    write (ensure_installed_once, from write_context.prepare_index).
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
        except ValueError as e:  # the file doesn't parse
            logger.warning("install_all_templates: %s doesn't parse: %s", filename, e)
            results["failed"].append(
                {"template": tpl_name, "error": f"{filename} doesn't parse: {e}"}
            )
            continue
        try:
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
        if other_templates_result.get("failed") or patched.get("failed"):
            success_status = "partial"
        return {
            "status": success_status,
            "pipeline": _PIPELINE_ID,
            "template": _TEMPLATE_NAME,
            "legacy_indices_without_data_raw": legacy_count,
            "other_templates": other_templates_result,
        }

    except Exception as e:
        logger.exception("ensure_winlog_pipeline failed")
        return {
            "status": "error",
            "error": str(e),
            "other_templates": other_templates_result,
        }
