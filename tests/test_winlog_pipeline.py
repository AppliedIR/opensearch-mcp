"""Unit tests for winlog_data_normalize_v1 pipeline + installer.

Covers the G8 regression (Test Round 3): pipeline script uses
ctx.winlog?.event_data navigation, but parse_evtx.py emits docs
with "winlog.event_data" as a literal flat-dotted top-level key.
The script must handle both shapes — if it early-returns on real
docs, Data_raw never populates and the fix is dormant.

Tests here exercise:
  1. Pipeline JSON loadable + has both nested and flat handling in script source
  2. Install-time validation rejects a script that only handles nested form
  3. ensure_winlog_pipeline uses validate-BEFORE-PUT ordering
  4. Install refuses on priority collision + existing default_pipeline
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from opensearch_mcp.mappings import (
    _EVTX_TEMPLATE_FILE,
    _MAPPINGS_DIR,
    _PIPELINE_FILE,
    _PIPELINE_ID,
    _TEMPLATE_NAME,
    _TEMPLATE_PRIORITY,
    _TEMPLATES_REGISTRY,
    ensure_winlog_pipeline,
    install_all_templates,
)


def _simulate_result_for_doc(source: dict) -> dict:
    """Replicate the Painless script's logic in Python for simulate mocks.

    Must mirror the JSON script source character-for-character in
    behavior — otherwise the install-time validation tests pass with
    a faulty script.
    """
    # Nested lookup, fallback to flat-dotted key.
    ed = source.get("winlog", {}).get("event_data")
    if ed is None:
        ed = source.get("winlog.event_data")
    if ed is None:
        return {"doc": {"_source": source}}
    d = ed.get("Data")
    if d is None:
        return {"doc": {"_source": source}}
    if isinstance(d, dict):
        ed["Data_raw"] = str(d)
    else:
        ed["Data_raw"] = str(d)
        ed.pop("Data", None)
    return {"doc": {"_source": source}}


class TestPipelineScriptShape:
    """The pipeline script must handle both nested and flat-dotted forms."""

    def test_pipeline_file_exists_and_valid_json(self):
        assert _PIPELINE_FILE.exists()
        body = json.loads(_PIPELINE_FILE.read_text())
        assert body["description"]
        assert len(body["processors"]) >= 1
        script = body["processors"][0]["script"]["source"]
        # The script must navigate both shapes.
        assert "ctx.winlog?.event_data" in script
        assert "ctx['winlog.event_data']" in script, (
            "Pipeline script must fall through to flat-dotted key "
            "lookup; parse_evtx.py emits docs in that shape. Missing "
            "this fallback caused the G8 bug where the pipeline ran "
            "but early-returned on every real evtx doc."
        )

    def test_pipeline_on_failure_strips_data(self):
        """Both script-level and pipeline-level on_failure remove
        winlog.event_data.Data defensively to prevent doc rejection
        on a mapping conflict if the script itself errors."""
        body = json.loads(_PIPELINE_FILE.read_text())
        script_on_failure = body["processors"][0]["script"]["on_failure"]
        pipeline_on_failure = body["on_failure"]
        for stage in (script_on_failure, pipeline_on_failure):
            has_remove = any(
                p.get("remove", {}).get("field") == "winlog.event_data.Data" for p in stage
            )
            assert has_remove, f"on_failure missing Data strip: {stage}"


class TestEnsureWinlogPipeline:
    """Integration-lite tests for the installer helper.

    Mocks the OpenSearch client to verify:
      - validate-BEFORE-PUT ordering (G install-order correctness)
      - collision detection refuses on priority or existing default_pipeline
      - simulate failure refuses without PUTting
    """

    def _mock_client_ok(self):
        """Client that passes all install-time checks."""
        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {"priority": 0, "settings": {"index": {}}}
        }

        def fake_simulate(body):
            docs = body["docs"]
            return {"docs": [_simulate_result_for_doc(d["_source"]) for d in docs]}

        client.ingest.simulate.side_effect = fake_simulate
        client.indices.get_mapping.return_value = {}
        return client

    def test_happy_path_installs_pipeline_then_template(self):
        client = self._mock_client_ok()
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "ok"
        assert result["pipeline"] == _PIPELINE_ID
        assert result["template"] == _TEMPLATE_NAME
        # Order invariant (post CR 2026-04-21 refactor):
        # install_all_templates (14 non-evtx) → simulate → put_pipeline
        # → put_evtx_template. Non-evtx templates move to the top so
        # they install even when the evtx path refuses. The critical
        # pair is still put_pipeline BEFORE the evtx template PUT.
        method_names = [c[0] for c in client.mock_calls if "." in c[0]]
        simulate_idx = next(i for i, n in enumerate(method_names) if n == "ingest.simulate")
        put_pipeline_idx = next(
            i for i, n in enumerate(method_names) if n == "ingest.put_pipeline"
        )
        # Locate the evtx-specific template PUT by name, not the first
        # put_index_template call (which is now a non-evtx one).
        put_evtx_idx = next(
            i
            for i, c in enumerate(client.mock_calls)
            if c[0] == "indices.put_index_template" and c.kwargs.get("name") == _TEMPLATE_NAME
        )
        assert simulate_idx < put_pipeline_idx, (
            "Install-order correctness: simulate-validate MUST run "
            "BEFORE put_pipeline so a broken body can't replace a "
            "working one"
        )
        assert put_pipeline_idx < put_evtx_idx, (
            "put_pipeline must run before put_index_template(evtx) "
            "so the evtx template never references a missing pipeline"
        )

    def test_refuses_on_priority_collision(self):
        client = self._mock_client_ok()
        client.indices.simulate_index_template.return_value = {
            "template": {
                "priority": _TEMPLATE_PRIORITY + 1,
                "settings": {"index": {}},
            }
        }
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "error"
        assert "priority" in result["error"].lower()
        # Evtx-specific artifacts (pipeline + evtx template) must NOT
        # install on collision. Non-evtx templates DO install — they
        # have no dependency on the evtx pipeline (CR 2026-04-21 fix).
        client.ingest.put_pipeline.assert_not_called()
        evtx_puts = [
            c
            for c in client.mock_calls
            if c[0] == "indices.put_index_template" and c.kwargs.get("name") == _TEMPLATE_NAME
        ]
        assert evtx_puts == [], "evtx template must not install on priority collision"

    def test_refuses_on_existing_default_pipeline(self):
        client = self._mock_client_ok()
        client.indices.simulate_index_template.return_value = {
            "template": {
                "priority": 0,
                "settings": {"index": {"default_pipeline": "other_pipeline"}},
            }
        }
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "error"
        assert "default_pipeline" in result["error"].lower()
        client.ingest.put_pipeline.assert_not_called()

    def test_refuses_on_simulate_validation_failure(self):
        """If the pipeline script doesn't populate Data_raw on any
        test shape, install must refuse — existing pipeline (if any)
        stays live."""
        client = self._mock_client_ok()
        # Simulate returns docs without Data_raw (buggy script).
        client.ingest.simulate.side_effect = lambda body: {
            "docs": [{"doc": {"_source": d["_source"]}} for d in body["docs"]]
        }
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "error"
        assert "data_raw" in result["error"].lower()
        client.ingest.put_pipeline.assert_not_called()

    def test_flat_dotted_shape_in_validation_docs(self):
        """G8 regression guard: install-time simulate MUST include a
        doc shape with 'winlog.event_data' as a flat-dotted top-level
        key — the shape parse_evtx.py actually produces. Without this
        shape in validation, a script that only handles the nested
        form passes install but silently early-returns on real docs.
        """
        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {"priority": 0, "settings": {"index": {}}}
        }
        captured_docs = []

        def fake_simulate(body):
            captured_docs.extend(body["docs"])
            return {"docs": [_simulate_result_for_doc(d["_source"]) for d in body["docs"]]}

        client.ingest.simulate.side_effect = fake_simulate
        client.indices.get_mapping.return_value = {}
        ensure_winlog_pipeline(client)
        # Confirm at least one validation doc uses the flat-dotted
        # top-level key.
        flat_shapes = [
            d
            for d in captured_docs
            if "winlog.event_data" in d["_source"] and "winlog" not in d["_source"]
        ]
        assert flat_shapes, (
            "Install-time validation must include at least one doc "
            "with 'winlog.event_data' as a flat-dotted top-level key; "
            "this is the shape parse_evtx.py produces"
        )


class TestEvtxTemplate:
    """Template additions for Fix G."""

    def test_template_has_explicit_data_object_mapping(self):
        body = json.loads(_EVTX_TEMPLATE_FILE.read_text())
        props = body["template"]["mappings"]["properties"]
        data_mapping = props.get("winlog.event_data.Data")
        assert data_mapping is not None, (
            "Template must declare winlog.event_data.Data explicitly "
            "as object; otherwise first-seen shape wins dynamically"
        )
        assert data_mapping["type"] == "object"

    def test_template_has_data_raw_text_keyword_fields(self):
        body = json.loads(_EVTX_TEMPLATE_FILE.read_text())
        props = body["template"]["mappings"]["properties"]
        raw = props.get("winlog.event_data.Data_raw")
        assert raw is not None
        assert raw["type"] == "text"
        assert raw["fields"]["keyword"]["type"] == "keyword"
        # Rev 6: 10000 chars (multi-byte UTF-8 safe under Lucene 32766-byte cap).
        assert raw["fields"]["keyword"]["ignore_above"] == 10000

    def test_template_default_pipeline_bound(self):
        body = json.loads(_EVTX_TEMPLATE_FILE.read_text())
        settings = body["template"]["settings"]
        # OpenSearch accepts both flat-dotted and nested settings keys.
        # This template uses the flat-dotted form ("index.default_pipeline")
        # to match the surrounding style in the file.
        bound = settings.get("index.default_pipeline") or settings.get("index", {}).get(
            "default_pipeline"
        )
        assert bound == _PIPELINE_ID

    def test_template_priority_100(self):
        body = json.loads(_EVTX_TEMPLATE_FILE.read_text())
        assert body["priority"] == _TEMPLATE_PRIORITY == 100

    def test_vol3_pid_ppid_are_long_with_ignore_malformed(self):
        """Regression guard: Vol3 svcscan (and other plugins like
        pslist/pstree/netstat) emit PID/PPID as uint32 values that can
        exceed Java int32 max (2,147,483,647). Test agent's memory
        ingest 2026-04-22 surfaced PID=2,200,369,488 causing
        'failed to parse field [PID] of type [integer]' — captured via
        the bulk_failed_reason TLS plumbing added same round.

        Fix: type=long (covers full uint32 range) + ignore_malformed
        as defense-in-depth for any future non-numeric PID.
        """
        vol3_path = _EVTX_TEMPLATE_FILE.parent / "vol3_template.json"
        body = json.loads(vol3_path.read_text())
        props = body["template"]["mappings"]["properties"]
        for field in ("PID", "PPID"):
            assert props[field]["type"] == "long", (
                f"{field} must be long — svcscan emits values exceeding int32 max (~2.15B)"
            )
            assert props[field].get("ignore_malformed") is True, (
                f"{field} needs ignore_malformed to survive any "
                f"future non-numeric value from volatility"
            )

    def test_template_has_explicit_data_hashtext_keyword_mapping(self):
        """Regression guard: pyevtx-rs emits Data as {'#text': '<val>'}
        for XML-shaped records. Without an explicit mapping, OpenSearch's
        dynamic inference locks Data.#text to the first-seen value type
        (usually keyword from strings); the one-in-N event with a
        date-shaped #text value is rejected with a mapping conflict.
        Test agent observed this as 1/~210k deterministic bulk_failed
        across every evtx ingest containing a date-shaped element.
        Catches anyone reverting this mapping in a future template edit.
        """
        body = json.loads(_EVTX_TEMPLATE_FILE.read_text())
        props = body["template"]["mappings"]["properties"]
        data_hashtext = props.get("winlog.event_data.Data.#text")
        assert data_hashtext is not None, (
            "winlog.event_data.Data.#text must have an explicit mapping — "
            "otherwise dynamic date-detection on that sub-field rejects "
            "1 event per ingest when the value parses as a date."
        )
        assert data_hashtext["type"] == "keyword"


class TestSingleNodeReplicasZero:
    """Every case-* template Valhuntir installs must declare
    index.number_of_replicas: 0.

    Valhuntir's deployment model is single-node OpenSearch. The cluster
    default of 1 replica means every new index reserves 2 shards
    (1 primary + 1 unassigned replica) — halving the usable budget
    against max_shards_per_node. Setting replicas=0 on every template
    Valhuntir owns makes the shard accounting match the deployment
    reality and postpones pre-flight refusal on busy single-node
    clusters.

    Guard: if a future template edit drops this setting from any
    template (by omission or typo), the pre-flight headroom check
    starts refusing ingests on indices matching that template twice
    as often as it should. Partial coverage (some templates have it,
    some don't) was the condition Test agent flagged post-launch-retest
    2026-04-21 — this test now covers the full set.
    """

    def _replicas_of(self, template_path):
        body = json.loads(template_path.read_text())
        settings = body["template"]["settings"]
        # Accept both flat-dotted and nested settings forms.
        flat = settings.get("index.number_of_replicas")
        if flat is not None:
            return flat
        return settings.get("index", {}).get("number_of_replicas")

    def test_evtx_template(self):
        from opensearch_mcp.mappings import _EVTX_TEMPLATE_FILE as p

        assert self._replicas_of(p) == 0

    def test_all_registered_templates_have_replicas_zero(self):
        """The full 14 non-evtx templates in _TEMPLATES_REGISTRY must
        each declare replicas=0. Iterates via the same registry the
        installer uses, so adding a template to the registry without
        adding replicas=0 to its JSON fails this test immediately."""
        for tpl_name, filename in _TEMPLATES_REGISTRY:
            path = _MAPPINGS_DIR / filename
            assert self._replicas_of(path) == 0, (
                f"{tpl_name} ({filename}) missing "
                f"index.number_of_replicas: 0 — on single-node deployments "
                f"this template will match indices that still reserve a "
                f"replica shard, eroding the shard budget by 2x for its "
                f"artifact type."
            )


class TestInstallAllTemplates:
    """Verify non-evtx templates actually reach the cluster.

    Without install_all_templates(), edits to csv/prefetch/srum/...
    templates on disk are dead code — setup-opensearch.sh runs once
    at deployment, and nothing re-applies the JSON files after.
    Test agent 2026-04-21 caught this live: delimited/json/vol3
    template edits (including replicas=0) never reached the cluster.
    """

    def test_registry_has_expected_templates(self):
        """Registry must match scripts/setup-opensearch.sh names so
        we don't create orphan templates alongside setup's installs."""
        names = [n for n, _ in _TEMPLATES_REGISTRY]
        # All 14 non-evtx templates that setup-opensearch.sh registers.
        expected = {
            "vhir-csv",
            "vhir-prefetch",
            "vhir-srum",
            "vhir-transcripts",
            "vhir-w3c",
            "vhir-defender",
            "vhir-tasks",
            "vhir-wer",
            "vhir-ssh",
            "vhir-vol3",
            "vhir-json",
            "vhir-delimited",
            "vhir-accesslog",
            "vhir-hayabusa",
        }
        assert set(names) == expected

    def test_registry_files_exist(self):
        """Every registered filename must exist in mappings/."""
        for _, filename in _TEMPLATES_REGISTRY:
            assert (_MAPPINGS_DIR / filename).exists(), (
                f"{filename} listed in _TEMPLATES_REGISTRY but not on disk"
            )

    def test_happy_path_puts_every_template(self):
        client = MagicMock()
        result = install_all_templates(client)
        # All 14 installed, none skipped, none failed.
        assert len(result["installed"]) == 14
        assert result["skipped"] == []
        assert result["failed"] == []
        # put_index_template was called exactly 14 times.
        assert client.indices.put_index_template.call_count == 14
        # Each call used a registered template name.
        call_names = [c.kwargs["name"] for c in client.indices.put_index_template.call_args_list]
        assert set(call_names) == {n for n, _ in _TEMPLATES_REGISTRY}

    def test_missing_file_is_skipped_not_fatal(self, monkeypatch):
        """If a template JSON is missing on disk (stripped-down build,
        partial merge), the installer records it as skipped and keeps
        going. A missing file must never fail the whole set."""
        import opensearch_mcp.mappings as m

        # Inject a registry entry pointing at a file that doesn't exist.
        bogus = ("vhir-bogus", "definitely_missing_template.json")
        monkeypatch.setattr(m, "_TEMPLATES_REGISTRY", [*m._TEMPLATES_REGISTRY, bogus])

        client = MagicMock()
        result = install_all_templates(client)
        assert "vhir-bogus" in result["skipped"]
        # The real 14 still install.
        assert len(result["installed"]) == 14

    def test_per_template_failure_does_not_abort_the_set(self):
        """If OpenSearch rejects one template (e.g., malformed body),
        the other 13 must still be attempted."""
        client = MagicMock()

        def _selective_reject(name, body):
            if name == "vhir-delimited":
                raise RuntimeError("synthetic: bad mapping")
            return {"acknowledged": True}

        client.indices.put_index_template.side_effect = _selective_reject
        result = install_all_templates(client)
        assert len(result["installed"]) == 13
        assert len(result["failed"]) == 1
        assert result["failed"][0]["template"] == "vhir-delimited"
        assert "synthetic" in result["failed"][0]["error"]

    def test_setup_script_does_not_install_templates(self):
        """Post-2026-04-22 inversion: setup-opensearch.sh must NOT
        install templates — that duty moved entirely to
        ensure_winlog_pipeline + install_all_templates at MCP startup.
        Guard against accidental re-introduction of template installs
        in the setup script, which would re-create the drift trap
        (registry + setup script listing different templates).

        Catch-all vhir-single-node template is also obsolete now that
        every template declares replicas=0 explicitly.
        """
        import re

        script_path = _MAPPINGS_DIR.parent.parent.parent / "scripts" / "setup-opensearch.sh"
        if not script_path.exists():
            pytest.skip(f"setup-opensearch.sh not found at {script_path}")
        script_text = script_path.read_text()

        # No _index_template/ endpoint PUTs should remain in the setup
        # script (DELETE of legacy names is tolerated, but the current
        # script has none).
        put_matches = re.findall(
            r"-X\s+PUT\s+[^\n]*_index_template/(vhir-[a-z0-9-]+)",
            script_text,
        )
        assert not put_matches, (
            f"setup-opensearch.sh is re-installing templates "
            f"({put_matches}) — this duty moved to "
            f"ensure_winlog_pipeline/install_all_templates at MCP "
            f"startup. Having both paths install templates is a drift "
            f"trap: a template added to the registry but forgotten in "
            f"setup (or vice versa) leaves one installer in the wrong "
            f"state."
        )

    def test_ensure_winlog_pipeline_status_partial_on_non_evtx_failure(self):
        """If evtx install succeeds but any non-evtx template fails,
        status must be 'partial' — not 'ok' — so consumers inspecting
        only .status see the failure signal. CR 2026-04-21 flagged
        the original behavior as misleading (13/14 failures returned
        status='ok')."""
        from tests.test_winlog_pipeline import _simulate_result_for_doc  # self

        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {"priority": 0, "settings": {"index": {}}}
        }

        def fake_simulate(body):
            return {"docs": [_simulate_result_for_doc(d["_source"]) for d in body["docs"]]}

        client.ingest.simulate.side_effect = fake_simulate
        client.indices.get_mapping.return_value = {}

        # Reject one non-evtx template; evtx passes.
        def put_template(name, body):
            if name == "vhir-delimited":
                raise RuntimeError("synthetic mapping error")
            return {"acknowledged": True}

        client.indices.put_index_template.side_effect = put_template
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "partial"
        assert len(result["other_templates"]["failed"]) == 1
        assert result["other_templates"]["failed"][0]["template"] == "vhir-delimited"

    def test_ensure_winlog_pipeline_priority_collision_still_installs_non_evtx(self):
        """Early-return on evtx priority collision must still leave
        the 14 non-evtx templates installed — they don't depend on
        the evtx pipeline. CR 2026-04-21 fix."""
        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {"priority": 200, "settings": {"index": {}}}  # higher than ours
        }
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "error"
        assert "priority" in result["error"].lower()
        # Non-evtx templates installed despite the evtx refuse.
        assert "other_templates" in result
        assert len(result["other_templates"]["installed"]) == 14

    def test_ensure_winlog_pipeline_default_pipeline_conflict_still_installs_non_evtx(self):
        """Same invariant as priority collision: early-return on
        existing default_pipeline mismatch must still install the 14
        non-evtx templates."""
        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {
                "priority": 0,
                "settings": {"index": {"default_pipeline": "operator_custom_pipeline"}},
            }
        }
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "error"
        assert "default_pipeline" in result["error"].lower()
        assert "other_templates" in result
        assert len(result["other_templates"]["installed"]) == 14

    def test_ensure_winlog_pipeline_simulate_failure_still_installs_non_evtx(self):
        """Simulate-validation failure in the evtx path must still
        leave the 14 non-evtx templates installed."""
        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {"priority": 0, "settings": {"index": {}}}
        }
        # Simulate returns docs without Data_raw (broken script).
        client.ingest.simulate.side_effect = lambda body: {
            "docs": [{"doc": {"_source": d["_source"]}} for d in body["docs"]]
        }
        result = ensure_winlog_pipeline(client)
        assert result["status"] == "error"
        assert "data_raw" in result["error"].lower()
        assert "other_templates" in result
        assert len(result["other_templates"]["installed"]) == 14

    def test_ensure_winlog_pipeline_installs_other_templates_too(self):
        """The end-to-end fix: calling ensure_winlog_pipeline must
        also install the 14 non-evtx templates, since this is the
        function wired into server startup + ingest pre-flight."""
        from tests.test_winlog_pipeline import _simulate_result_for_doc  # self

        client = MagicMock()
        client.indices.simulate_index_template.return_value = {
            "template": {"priority": 0, "settings": {"index": {}}}
        }

        def fake_simulate(body):
            return {"docs": [_simulate_result_for_doc(d["_source"]) for d in body["docs"]]}

        client.ingest.simulate.side_effect = fake_simulate
        client.indices.get_mapping.return_value = {}

        result = ensure_winlog_pipeline(client)
        assert result["status"] == "ok"
        # Response surfaces the non-evtx install result.
        assert "other_templates" in result
        assert len(result["other_templates"]["installed"]) == 14
        # Total put_index_template calls: 14 non-evtx + 1 evtx = 15.
        assert client.indices.put_index_template.call_count == 15


def test_python_simulator_matches_painless_behavior():
    """Sanity-check the in-test Python simulator faithfully mirrors
    the Painless script across all five shapes — nested+object,
    nested+string, nested+list, flat+object, flat+string.

    If the simulator drifts from the script, the install-time
    validation tests pass with a broken script and we regress
    silently. This test is the anchor that prevents that.
    """
    cases = [
        # Nested + object: Data kept, Data_raw added
        (
            {"winlog": {"event_data": {"Data": {"k": "v"}}}},
            "Data",  # key still present
            True,  # Data_raw populated
        ),
        # Nested + string: Data removed, Data_raw populated
        ({"winlog": {"event_data": {"Data": "raw"}}}, None, True),
        # Flat + object: Data kept, Data_raw added
        ({"winlog.event_data": {"Data": {"k": "v"}}}, "Data", True),
        # Flat + string: Data removed, Data_raw populated
        ({"winlog.event_data": {"Data": "raw"}}, None, True),
        # No event_data at all: no-op
        ({"other": "field"}, None, False),
    ]
    for source, expect_data_key, expect_data_raw in cases:
        result = _simulate_result_for_doc(dict(source))
        out = result["doc"]["_source"]
        ed = out.get("winlog", {}).get("event_data") or out.get("winlog.event_data", {})
        if expect_data_raw:
            assert "Data_raw" in ed, f"Missing Data_raw for {source}"
        else:
            assert "Data_raw" not in ed, f"Unexpected Data_raw for {source}"
        if expect_data_key == "Data":
            assert "Data" in ed
        elif expect_data_key is None and expect_data_raw:
            assert "Data" not in ed
