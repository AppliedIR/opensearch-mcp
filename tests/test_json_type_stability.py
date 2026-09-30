"""Tests for the vhir-json-type-stability component template.

The component is composed into `vhir-json` and `vhir-delimited`. It keeps
objects, arrays of objects and dotted keys on OpenSearch's default object
mapping, and gives numbers and dates field-level `ignore_malformed`.

- Structure: no object templates, no index-level `ignore_malformed`, the
  string templates unchanged, install order.
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


def _rules(dyn_templates) -> dict[str, dict]:
    return {name: rule for entry in dyn_templates for name, rule in entry.items()}


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
        assert names.index("id_like_strings") < names.index("catchall_strings_keyword")
        assert names.index("name_like_strings") < names.index("catchall_strings_keyword")
        assert names.index("hostname_like_strings") < names.index("catchall_strings_keyword")

    def test_no_rule_matches_an_object(self, dyn_templates):
        """Objects keep OpenSearch's default object mapping. A rule without a
        scalar `match_mapping_type` also matches objects — including the
        intermediate object a dotted key like `source.ip` expands into — and
        the earlier ones mapped them to `flattened`, which OpenSearch does not
        have: every record with an object or a dotted key was rejected.
        """
        for name, rule in _rules(dyn_templates).items():
            assert rule.get("match_mapping_type") in {"string", "long", "double", "date"}, name

    @pytest.mark.parametrize(
        "detected,mapped",
        [("long", "long"), ("double", "float"), ("date", "date")],
    )
    def test_numbers_and_dates_ignore_malformed_per_field(self, dyn_templates, detected, mapped):
        """The type dynamic mapping would choose for that JSON value (a
        floating-point number maps `float`), plus `ignore_malformed`: a value
        of the wrong type is dropped from that field and the record is kept.
        """
        matching = [
            r for r in _rules(dyn_templates).values() if r["match_mapping_type"] == detected
        ]
        assert len(matching) == 1, detected
        assert matching[0]["mapping"] == {"type": mapped, "ignore_malformed": True}
        assert "path_match" not in matching[0] and "match" not in matching[0]

    def test_no_index_level_ignore_malformed(self, component):
        """At index level it also swallowed an object arriving at a field
        already mapped as a scalar, with `_ignored` unset."""
        assert "index.mapping.ignore_malformed" not in component["template"]["settings"]

    def test_total_fields_limit_is_10000(self, component):
        settings = component["template"]["settings"]
        assert settings["index.mapping.total_fields.limit"] == 10000

    def test_depth_limit_20(self, component):
        assert component["template"]["settings"]["index.mapping.depth.limit"] == 20


class TestCatchallKeywordDroppedText:
    """`.text` multi-field removed from catchall keyword."""

    def test_no_text_subfield_on_catchall_strings(self, dyn_templates):
        catchall = _rules(dyn_templates)["catchall_strings_keyword"]
        mapping = catchall["mapping"]
        assert mapping["type"] == "keyword"
        assert "fields" not in mapping, (
            "catchall keyword must not carry .text — storage halves, "
            "JSON sources use aggregation not grep"
        )


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
        rule = _rules(dyn_templates)[rule_name]
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
# Install helper
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
        references it via composed_of.
        """
        from opensearch_mcp.mappings import install_all_templates

        client = MagicMock()
        client.cluster = MagicMock()
        client.indices = MagicMock()

        result = install_all_templates(client)

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
        assert component_call_idx < composable_call_idx
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


# The dynamic_templates every index created from the April component carries.
