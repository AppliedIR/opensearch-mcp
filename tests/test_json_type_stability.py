"""Tests for the vhir-json-type-stability component template.

The component is composed into `vhir-json` and `vhir-delimited`. It keeps
objects, arrays of objects and dotted keys on OpenSearch's default object
mapping, and gives numbers and dates field-level `ignore_malformed`.

- Structure: no object templates, no index-level `ignore_malformed`, the
  string templates unchanged, install order.
- Every mapping file declares only types OpenSearch has — checked on the
  declared values, not the file text.
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
# Declared types are OpenSearch types
# ---------------------------------------------------------------------------

# Field types OpenSearch 3.5.0 accepts, measured by creating a mapping with
# each (`semantic` and `sparse_vector` need parameters; their handlers exist).
# `flattened` is Elasticsearch's: "No handler for type [flattened]".
OPENSEARCH_FIELD_TYPES = frozenset(
    {
        "alias", "binary", "boolean", "byte", "completion", "constant_keyword",
        "date", "date_nanos", "date_range", "double", "double_range",
        "flat_object", "float", "float_range", "geo_point", "geo_shape",
        "half_float", "integer", "integer_range", "ip", "ip_range", "join",
        "keyword", "knn_vector", "long", "long_range", "match_only_text",
        "nested", "object", "percolator", "rank_feature", "rank_features",
        "scaled_float", "search_as_you_type", "semantic", "short",
        "sparse_vector", "text", "token_count", "unsigned_long", "version",
        "wildcard", "xy_point", "xy_shape",
    }
)  # fmt: skip
# A dynamic template may leave the type to the detected one.
_DYNAMIC_PLACEHOLDER = "{dynamic_type}"


def _field_types(field: dict, path: str):
    """(path, type) for a field definition, its multi-fields and sub-fields."""
    if "type" in field:
        yield path, field["type"]
    for name, sub in field.get("fields", {}).items():
        yield from _field_types(sub, f"{path}.{name}")
    for name, sub in field.get("properties", {}).items():
        yield from _field_types(sub, f"{path}.{name}")


def _declared_types(mappings: dict):
    """Every declared type VALUE in a mappings body, with where it sits.

    Reads the structure — properties, multi-fields, dynamic templates — and
    never the text, so a note that names a type, or a field named `type`,
    is not a declaration.
    """
    for name, field in mappings.get("properties", {}).items():
        yield from _field_types(field, name)
    for entry in mappings.get("dynamic_templates", []):
        for name, rule in entry.items():
            yield from _field_types(rule.get("mapping", {}), f"dynamic_templates.{name}")


def _mapping_bodies(document):
    """Every `mappings` object in a template file."""
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "mappings" and isinstance(value, dict):
                yield value
            else:
                yield from _mapping_bodies(value)
    elif isinstance(document, list):
        for value in document:
            yield from _mapping_bodies(value)


def _unknown_types(document) -> list[tuple[str, str]]:
    return [
        (path, declared)
        for body in _mapping_bodies(document)
        for path, declared in _declared_types(body)
        if declared not in OPENSEARCH_FIELD_TYPES and declared != _DYNAMIC_PLACEHOLDER
    ]


class TestMappingTypesAreOpenSearchTypes:
    @pytest.mark.parametrize("path", sorted(_MAPPINGS_DIR.glob("*.json")), ids=lambda p: p.name)
    def test_every_mapping_file_declares_only_opensearch_types(self, path):
        assert _unknown_types(json.loads(path.read_text())) == []

    def test_the_mapping_files_are_found(self):
        """The guard reads real declarations, not an empty walk."""
        declared = [
            t
            for path in _MAPPINGS_DIR.glob("*.json")
            for body in _mapping_bodies(json.loads(path.read_text()))
            for _, t in _declared_types(body)
        ]
        assert len(declared) > 100
        assert {"keyword", "date", "long", "integer", "ip"} <= set(declared)

    @pytest.mark.parametrize(
        "document,where",
        [
            (
                {"template": {"mappings": {"dynamic_templates": [
                    {"objects": {"match_mapping_type": "object", "mapping": {"type": "flattened"}}}
                ]}}},
                "dynamic_templates.objects",
            ),
            (
                {"template": {"mappings": {"properties": {
                    "a": {"properties": {"b": {"type": "flattened"}}}
                }}}},
                "a.b",
            ),
            (
                {"template": {"mappings": {"properties": {
                    "s": {"type": "keyword", "fields": {"f": {"type": "flattened"}}}
                }}}},
                "s.f",
            ),
            ({"mappings": {"properties": {"h": {"type": "histogram"}}}}, "h"),
        ],
        ids=["dynamic-template", "nested-property", "multi-field", "other-es-only-type"],
    )  # fmt: skip
    def test_the_guard_sees_a_planted_declaration(self, document, where):
        assert [path for path, _ in _unknown_types(document)] == [where]

    def test_the_guard_reads_values_not_text(self):
        """A note that names the type, and a field NAMED `flattened` or
        `type`, declare nothing. The component's own `_meta` names it."""
        document = {
            "template": {
                "mappings": {
                    "properties": {
                        "flattened": {"type": "keyword"},
                        "type": {"type": "keyword"},
                    }
                }
            },
            "_meta": {"description": "the earlier rules used `flattened`"},
        }
        assert _unknown_types(document) == []
        assert "flattened" in _COMPONENT_FILE.read_text()


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
