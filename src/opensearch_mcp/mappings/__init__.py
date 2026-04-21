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


def install_all_templates(client) -> dict[str, Any]:
    """Idempotent install of all non-evtx case-* index templates.

    Each template in _TEMPLATES_REGISTRY is PUT by name. Per-template
    failures are collected and returned; a single failure does NOT
    abort the remaining installs — a typo in one template file should
    not strand the other 13.

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
        }
    """
    results: dict[str, Any] = {"installed": [], "failed": [], "skipped": []}
    for tpl_name, filename in _TEMPLATES_REGISTRY:
        path = _MAPPINGS_DIR / filename
        if not path.exists():
            results["skipped"].append(tpl_name)
            continue
        try:
            body = _load_json(path)
            client.indices.put_index_template(name=tpl_name, body=body)
            results["installed"].append(tpl_name)
        except Exception as e:
            logger.warning("install_all_templates: %s failed: %s", tpl_name, e)
            results["failed"].append({"template": tpl_name, "error": str(e)})
    return results


def ensure_winlog_pipeline(client) -> dict[str, Any]:
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
        other_templates_result = install_all_templates(client)
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
        template_body = _load_json(_EVTX_TEMPLATE_FILE)
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
        if other_templates_result.get("failed"):
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
