"""Tests for vhir-json-type-stability component template.

Spec: `specs/opensearch-dynamic-template-type-stability-2026-04-24.md` Rev 2.

The 6 tests from the spec are adapted for local JSON-structure validation
(the ones that need a live OpenSearch cluster are gated to call the
install-install helper against a fake client). This file pins:

- Template JSON is well-formed, has the expected dynamic_templates shape.
- Install helper PUTs component templates BEFORE composable templates.
- `vhir-json` and `vhir-delimited` composables reference the component
  via `composed_of`.
- Catchall keyword has NO `.text` subfield (CR's `.text` drop).
- Priority + total_fields.limit match spec (10000, no per-doc priority
  clash since this is a component template).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_MAPPINGS_DIR = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"
_COMPONENT_FILE = _MAPPINGS_DIR / "json_type_stability.json"
_JSON_TEMPLATE = _MAPPINGS_DIR / "json_template.json"
_DELIMITED_TEMPLATE = _MAPPINGS_DIR / "delimited_template.json"


@pytest.fixture
def component():
    return json.loads(_COMPONENT_FILE.read_text())


@pytest.fixture
def dyn_templates(component):
    return component["template"]["mappings"]["dynamic_templates"]


# ---------------------------------------------------------------------------
# Structural contract
# ---------------------------------------------------------------------------


class TestComponentTemplateStructure:
    def test_has_template_wrapper(self, component):
        assert "template" in component
        assert "mappings" in component["template"]

    def test_dynamic_templates_ordering_and_shape(self, dyn_templates):
        """dynamic_templates is a LIST (order matters — first match wins)."""
        assert isinstance(dyn_templates, list)
        names = [next(iter(d.keys())) for d in dyn_templates]
        # Specific path_match rules must come BEFORE catchall match_mapping_type
        assert names.index("id_like_strings") < names.index("catchall_strings_keyword")
        assert names.index("labels_as_flattened") < names.index("catchall_objects_flattened")
        assert names.index("tags_as_flattened") < names.index("catchall_objects_flattened")
        assert "tags_as_flattened" in names  # CR's addition
        assert "hash_variants_flattened" in names
        assert "event_data_flattened" in names

    def test_total_fields_limit_is_10000(self, component):
        """CR-bumped 5000 → 10000."""
        settings = component["template"]["settings"]
        assert settings["index.mapping.total_fields.limit"] == 10000

    def test_ignore_malformed_true(self, component):
        settings = component["template"]["settings"]
        assert settings["index.mapping.ignore_malformed"] is True

    def test_depth_limit_20(self, component):
        assert component["template"]["settings"]["index.mapping.depth.limit"] == 20


class TestCatchallKeywordDroppedText:
    """CR optional fold — `.text` multi-field removed from catchall keyword."""

    def test_no_text_subfield_on_catchall_strings(self, dyn_templates):
        catchall = next(
            d["catchall_strings_keyword"] for d in dyn_templates if "catchall_strings_keyword" in d
        )
        mapping = catchall["mapping"]
        assert mapping["type"] == "keyword"
        # The core assertion: no .text subfield
        assert "fields" not in mapping, (
            "catchall keyword must not carry .text — storage halves, "
            "JSON sources use aggregation not grep"
        )


class TestLabelsAndTagsFlattened:
    """*.labels and *.tags both land as flattened (CR-added *.tags)."""

    def test_labels_flattened(self, dyn_templates):
        labels = next(
            d["labels_as_flattened"] for d in dyn_templates if "labels_as_flattened" in d
        )
        assert labels["path_match"] == "*.labels"
        assert labels["mapping"]["type"] == "flattened"

    def test_tags_flattened(self, dyn_templates):
        tags = next(d["tags_as_flattened"] for d in dyn_templates if "tags_as_flattened" in d)
        assert tags["path_match"] == "*.tags"
        assert tags["mapping"]["type"] == "flattened"


class TestKeywordPaths:
    """*.id, *.name, *.hostname → keyword."""

    @pytest.mark.parametrize(
        "rule_name,expected_path",
        [
            ("id_like_strings", "*.id"),
            ("name_like_strings", "*.name"),
            ("hostname_like_strings", "*.hostname"),
        ],
    )
    def test_keyword_path_match(self, dyn_templates, rule_name, expected_path):
        rule = next(d[rule_name] for d in dyn_templates if rule_name in d)
        assert rule["path_match"] == expected_path
        assert rule["match_mapping_type"] == "string"
        assert rule["mapping"]["type"] == "keyword"
        assert rule["mapping"]["ignore_above"] == 2048


# ---------------------------------------------------------------------------
# composed_of references
# ---------------------------------------------------------------------------


class TestComposedOfReferences:
    def test_json_template_composes_in_type_stability(self):
        tpl = json.loads(_JSON_TEMPLATE.read_text())
        assert "vhir-json-type-stability" in tpl.get("composed_of", [])

    def test_delimited_template_composes_in_type_stability(self):
        tpl = json.loads(_DELIMITED_TEMPLATE.read_text())
        assert "vhir-json-type-stability" in tpl.get("composed_of", [])


# ---------------------------------------------------------------------------
# Install helper (Test 6: install-on-startup round-trip)
# ---------------------------------------------------------------------------


class TestInstallComponentTemplate:
    def test_put_component_template_invoked(self):
        """install_component_templates PUTs to `_component_template/<name>`."""
        from opensearch_mcp.mappings import install_component_templates

        client = MagicMock()
        client.cluster = MagicMock()

        result = install_component_templates(client)

        assert "vhir-json-type-stability" in result["installed"]
        assert result["failed"] == []
        # The PUT call landed with the right name and a valid body.
        call = client.cluster.put_component_template.call_args
        assert call.kwargs["name"] == "vhir-json-type-stability"
        body = call.kwargs["body"]
        assert "template" in body
        assert body["template"]["settings"]["index.mapping.total_fields.limit"] == 10000

    @pytest.mark.parametrize(
        "composable_name",
        ["vhir-json", "vhir-delimited"],
        ids=["json", "delimited"],
    )
    def test_components_installed_before_composables(self, composable_name):
        """Component template PUT must happen BEFORE any composable that
        references it via composed_of. Parametrized over every composable
        that wires vhir-json-type-stability in, so adding a new one
        automatically extends the ordering guard.
        """
        from opensearch_mcp.mappings import install_all_templates

        client = MagicMock()
        client.cluster = MagicMock()
        client.indices = MagicMock()

        result = install_all_templates(client)

        assert client.cluster.put_component_template.called
        assert client.indices.put_index_template.called

        component_call_idx = None
        composable_call_idx = None
        for i, c in enumerate(client.mock_calls):
            if c[0] == "cluster.put_component_template" and component_call_idx is None:
                component_call_idx = i
            if c[0] == "indices.put_index_template":
                kwargs = c.kwargs if hasattr(c, "kwargs") else c[2]
                if kwargs.get("name") == composable_name and composable_call_idx is None:
                    composable_call_idx = i

        assert component_call_idx is not None, "component template never installed"
        assert composable_call_idx is not None, f"{composable_name} never installed"
        assert component_call_idx < composable_call_idx, (
            f"component template must install BEFORE {composable_name} "
            f"(it's composed_of the component)"
        )

        # Result surface includes the component sub-dict
        assert "components" in result
        assert "vhir-json-type-stability" in result["components"]["installed"]

    def test_install_failure_is_collected_not_raised(self):
        """A failing component install must not crash the whole batch."""
        from opensearch_mcp.mappings import install_component_templates

        client = MagicMock()
        client.cluster = MagicMock()
        client.cluster.put_component_template.side_effect = RuntimeError("cluster 503")

        result = install_component_templates(client)

        assert result["installed"] == []
        assert len(result["failed"]) == 1
        assert result["failed"][0]["template"] == "vhir-json-type-stability"
        assert "cluster 503" in result["failed"][0]["error"]


# ---------------------------------------------------------------------------
# Cluster round-trip (env-gated; auto-runs when OpenSearch is reachable).
#
# WSL2 Test's deferred harness from 2026-04-24 — the polymorphic Labels
# fixture they couldn't run in their sandbox (docker denied). Baking it
# here so it runs automatically in any env where the OpenSearch client
# resolves (SIFT workstation, docker-capable WSL2, CI, etc.).
#
# Pattern: same as tests/test_ingest_integration.py — skip when the
# cluster isn't reachable; run otherwise.
# ---------------------------------------------------------------------------


import uuid  # noqa: E402 — grouped with integration imports


@pytest.mark.integration
class TestTypeStabilityClusterRoundtrip:
    """Live-cluster verification that the component template's dynamic_templates
    actually prevent bulk-reject on type-unstable columns. Runs only when
    OpenSearch is reachable; otherwise skipped.

    This is WSL2 Test's deferred harness (Test #1 of the 2026-04-24 plan)
    — four polymorphic Labels shapes pushed against an index that composes
    the type-stability template in. With the fix, all four land; without
    it, a mapper_parsing_exception rejects doc 2 or 3.
    """

    @pytest.fixture
    def os_client(self):
        pytest.importorskip("opensearchpy")
        try:
            from opensearch_mcp.client import get_client
            from opensearch_mcp.mappings import install_all_templates

            client = get_client()
            health = client.cluster.health()
            if health.get("status") not in ("green", "yellow"):
                pytest.skip("OpenSearch cluster not healthy")
            install_all_templates(client)  # idempotent
            return client
        except FileNotFoundError:
            pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
        except Exception as e:
            pytest.skip(f"OpenSearch not available: {e}")

    @pytest.fixture
    def test_json_index(self, os_client):
        """Create a case-*-json-* index (picks up vhir-json + composed
        type-stability) and clean up after."""
        name = f"case-pytest-{uuid.uuid4().hex[:8]}-json-typestab"
        os_client.indices.create(index=name)
        yield name
        try:
            os_client.indices.delete(index=name, ignore=[404])
        except Exception:
            pass

    def test_polymorphic_labels_all_land(self, os_client, test_json_index):
        """The load-bearing contract — 4 shapes of `Labels` on the same
        field, all must land without mapper_parsing_exception.
        """
        docs = [
            {"Labels": "critical"},
            {"Labels": ["critical", "tier1"]},
            {"Labels": None},
            {"Labels": {"tier": "A", "env": "prod"}},
        ]
        for i, doc in enumerate(docs):
            resp = os_client.index(index=test_json_index, id=str(i), body=doc, refresh=True)
            assert resp["result"] in ("created", "updated"), (
                f"doc {i} with shape {type(doc['Labels']).__name__} was rejected: {resp}"
            )

        count = os_client.count(index=test_json_index)
        assert count["count"] == 4, (
            f"expected all 4 polymorphic docs indexed; got {count['count']}"
        )

    def test_labels_field_mapped_flattened(self, os_client, test_json_index):
        """Verify the mapping OpenSearch settled on is `flattened` —
        that's the mechanism that allows the polymorphic coexistence.
        """
        os_client.index(
            index=test_json_index,
            body={"Labels": {"tier": "A"}},
            refresh=True,
        )
        mapping = os_client.indices.get_mapping(index=test_json_index)
        props = mapping[test_json_index]["mappings"].get("properties", {})
        labels = props.get("Labels", {})
        assert labels.get("type") == "flattened", (
            f"Labels should be flattened via dynamic_templates; got mapping={labels}"
        )

    def test_type_unstable_logon_type(self, os_client, test_json_index):
        """Canonical repro — LogonType as string then as int on the
        same field. Pre-fix would bulk-reject doc 2.
        """
        os_client.index(index=test_json_index, id="a", body={"LogonType": "3"}, refresh=True)
        resp = os_client.index(index=test_json_index, id="b", body={"LogonType": 3}, refresh=True)
        assert resp["result"] in ("created", "updated")
        assert os_client.count(index=test_json_index)["count"] == 2
