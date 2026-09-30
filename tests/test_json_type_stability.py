"""Tests for the vhir-json-type-stability component template.

The component is composed into `vhir-json` and `vhir-delimited`. It keeps
objects, arrays of objects and dotted keys on OpenSearch's default object
mapping, and gives numbers and dates field-level `ignore_malformed`.

- Structure: no object templates, no index-level `ignore_malformed`, the
  string templates unchanged, install order.
- Every mapping file declares only types OpenSearch has — checked on the
  declared values, not the file text.
- Existing indices still carrying a `flattened` rule are patched in place.
- Cluster rows, through the shipped composed templates and `flush_bulk`.
"""

from __future__ import annotations

import copy
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
APRIL_DYNAMIC_TEMPLATES = [
    {"id_like_strings": {"path_match": "*.id", "match_mapping_type": "string",
                         "mapping": {"type": "keyword", "ignore_above": 2048}}},
    {"name_like_strings": {"path_match": "*.name", "match_mapping_type": "string",
                           "mapping": {"type": "keyword", "ignore_above": 2048}}},
    {"hostname_like_strings": {"path_match": "*.hostname", "match_mapping_type": "string",
                               "mapping": {"type": "keyword", "ignore_above": 2048}}},
    {"labels_as_flattened": {"path_match": "*.labels", "mapping": {"type": "flattened"}}},
    {"tags_as_flattened": {"path_match": "*.tags", "mapping": {"type": "flattened"}}},
    {"event_data_flattened": {"path_match": "EventData", "mapping": {"type": "flattened"}}},
    {"hash_variants_flattened": {"path_match": "*.hash*", "mapping": {"type": "flattened"}}},
    {"catchall_objects_flattened": {"match_mapping_type": "object",
                                    "mapping": {"type": "flattened"}}},
    {"catchall_strings_keyword": {"match_mapping_type": "string",
                                  "mapping": {"type": "keyword", "ignore_above": 2048}}},
]  # fmt: skip


def _mapping_response(dynamic_templates: dict[str, list]) -> dict:
    return {i: {"mappings": {"dynamic_templates": d}} for i, d in dynamic_templates.items()}


class TestPatchFlattenedIndices:
    """Existing indices keep the dynamic templates they were created with, so
    the fixed component does not reach them on its own."""

    def test_only_indices_carrying_flattened_are_patched_with_the_component_list(
        self, dyn_templates
    ):
        from opensearch_mcp.mappings import patch_flattened_indices

        client = MagicMock()
        client.indices.get_mapping.return_value = _mapping_response(
            {"case-a-json-old": APRIL_DYNAMIC_TEMPLATES, "case-a-json-new": dyn_templates}
        )
        result = patch_flattened_indices(client, ["case-*-json-*"])

        assert result == {"patched": ["case-a-json-old"], "failed": []}
        client.indices.put_mapping.assert_called_once_with(
            index="case-a-json-old", body={"dynamic_templates": dyn_templates}
        )

    def test_open_indices_only_and_nothing_is_closed(self):
        from opensearch_mcp.mappings import patch_flattened_indices

        client = MagicMock()
        client.indices.get_mapping.return_value = _mapping_response({"i": APRIL_DYNAMIC_TEMPLATES})
        patch_flattened_indices(client, ["case-*-json-*", "case-*-delim-*"])

        kwargs = client.indices.get_mapping.call_args.kwargs
        assert kwargs["index"] == "case-*-json-*,case-*-delim-*"
        assert kwargs["expand_wildcards"] == "open"
        assert not client.indices.close.called and not client.indices.open.called
        assert not client.indices.put_settings.called

    def test_a_failure_is_collected_and_the_rest_are_patched(self):
        from opensearch_mcp.mappings import patch_flattened_indices

        client = MagicMock()
        client.indices.get_mapping.return_value = _mapping_response(
            {"a": APRIL_DYNAMIC_TEMPLATES, "b": APRIL_DYNAMIC_TEMPLATES}
        )
        client.indices.put_mapping.side_effect = [RuntimeError("503"), {"acknowledged": True}]
        result = patch_flattened_indices(client, ["case-*"])

        assert result["patched"] == ["b"]
        assert result["failed"] == [{"index": "a", "error": "503"}]

    def test_an_unreadable_mapping_is_reported_not_raised(self):
        from opensearch_mcp.mappings import patch_flattened_indices

        client = MagicMock()
        client.indices.get_mapping.side_effect = RuntimeError("timeout")
        result = patch_flattened_indices(client, ["case-*-json-*"])

        assert result["patched"] == []
        assert "timeout" in result["failed"][0]["error"]

    def test_installing_the_templates_patches_every_composing_pattern(self):
        """The call site: installing runs the patch over every index pattern
        of a template that composes the component."""
        from opensearch_mcp.mappings import install_all_templates

        client = MagicMock()
        client.indices.get_mapping.return_value = _mapping_response(
            {"old": APRIL_DYNAMIC_TEMPLATES}
        )
        result = install_all_templates(client)

        patterns = json.loads(_JSON_TEMPLATE.read_text())["index_patterns"]
        patterns += json.loads(_DELIMITED_TEMPLATE.read_text())["index_patterns"]
        read = client.indices.get_mapping.call_args.kwargs["index"].split(",")
        assert sorted(read) == sorted(patterns)
        assert result["patched_indices"]["patched"] == ["old"]


# ---------------------------------------------------------------------------
# Cluster rows (auto-run when OpenSearch is reachable).
#
# The shipped component and the shipped vhir-json / vhir-delimited bodies are
# installed under names of their own, matching only this suite's indices, so
# a test run never replaces the live templates or touches a live index.
# Writes go through `flush_bulk`, the production path.
# ---------------------------------------------------------------------------


import uuid  # noqa: E402 — grouped with integration imports

_MD5 = "0cc175b9c0f1b6a831c399e269772661"
_SHA1 = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
_SHA256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"


@pytest.fixture(scope="module")
def os_client():
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        health = client.cluster.health()
        if health.get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
        return client
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")


@pytest.fixture(scope="module")
def templates(os_client):
    """The shipped composition under this run's own names."""
    tag = f"pytest-typestab-{uuid.uuid4().hex[:8]}"
    component = json.loads(_COMPONENT_FILE.read_text())
    os_client.cluster.put_component_template(name=f"{tag}-comp", body=component)
    for kind, path in (("json", _JSON_TEMPLATE), ("delim", _DELIMITED_TEMPLATE)):
        body = copy.deepcopy(json.loads(path.read_text()))
        body["template"].pop("aliases", None)  # never join a live alias
        body["index_patterns"] = [f"{tag}-{kind}-*"]
        body["composed_of"] = [f"{tag}-comp"]
        body["priority"] = 900
        os_client.indices.put_index_template(name=f"{tag}-{kind}", body=body)
    yield tag
    for name in os_client.indices.get(index=f"{tag}-*", expand_wildcards="all"):
        os_client.indices.delete(index=name, ignore=[404])
    for kind in ("json", "delim"):
        os_client.indices.delete_index_template(name=f"{tag}-{kind}", ignore=[404])
    os_client.cluster.delete_component_template(name=f"{tag}-comp", ignore=[404])


@pytest.mark.integration
class TestTypeStabilityClusterRoundtrip:
    @pytest.fixture(autouse=True)
    def _clean_bulk_state(self):
        from opensearch_mcp.bulk import clear_last_bulk_reason, reset_circuit_breaker

        reset_circuit_breaker()
        clear_last_bulk_reason()
        yield

    @pytest.fixture(params=["json", "delim"])
    def index(self, request, templates):
        return f"{templates}-{request.param}-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _write(client, index, docs):
        from opensearch_mcp.bulk import flush_bulk

        actions = [{"_index": index, "_id": str(i), "_source": d} for i, d in enumerate(docs)]
        result = flush_bulk(client, actions)
        client.indices.refresh(index=index)
        return result

    @staticmethod
    def _hits(client, index, field, value):
        body = {"query": {"term": {field: value}}}
        return client.search(index=index, body=body)["hits"]["total"]["value"]

    @staticmethod
    def _buckets(client, index, field):
        body = {"size": 0, "aggs": {"v": {"terms": {"field": field}}}}
        resp = client.search(index=index, body=body)
        return [b["key"] for b in resp["aggregations"]["v"]["buckets"]]

    # -- Row 1 -----------------------------------------------------------------

    def test_objects_are_indexed_searchable_and_aggregatable_under_their_names(
        self, os_client, index
    ):
        docs = [
            {"foo": {"bar": "S1"}},
            {"a": {"b": {"c": "S2"}}},
            {"list": [{"k": "S3"}, {"k": "S3b"}]},
            # The Velociraptor Windows.System.Pslist shape that failed most.
            {"Pid": 4, "Name": "System", "Hash": {"MD5": _MD5, "SHA1": _SHA1, "SHA256": _SHA256}},
        ]
        assert self._write(os_client, index, docs) == (4, 0)
        for field, value in [
            ("foo.bar", "S1"),
            ("a.b.c", "S2"),
            ("list.k", "S3"),
            ("list.k", "S3b"),
            ("Hash.MD5", _MD5),
            ("Hash.SHA1", _SHA1),
            ("Hash.SHA256", _SHA256),
        ]:
            assert self._hits(os_client, index, field, value) == 1, field
        assert self._buckets(os_client, index, "Hash.MD5") == [_MD5]
        assert self._buckets(os_client, index, "foo.bar") == ["S1"]

    # -- Row 2 -----------------------------------------------------------------

    def test_dotted_keys_are_indexed_and_searchable(self, os_client, index):
        docs = [
            {"source.ip": "8.8.8.8"},
            {"file.hash.sha256": _SHA256},
            {"EventData.TargetUserName": "S6"},
        ]
        assert self._write(os_client, index, docs) == (3, 0)
        assert self._hits(os_client, index, "source.ip", "8.8.8.8") == 1
        assert self._hits(os_client, index, "file.hash.sha256", _SHA256) == 1
        assert self._hits(os_client, index, "EventData.TargetUserName", "S6") == 1

    # -- Row 3: shape conflicts are loud, per record ---------------------------

    @pytest.mark.parametrize(
        "docs,field",
        [
            ([{"L": "x"}, {"L": {"a": "b"}}], "L"),
            ([{"L": {"a": "b"}}, {"L": "x"}], "L"),
        ],
        ids=["scalar-then-object", "object-then-scalar"],
    )
    def test_a_shape_conflict_rejects_that_record_with_its_reason(
        self, os_client, index, docs, field
    ):
        from opensearch_mcp.bulk import get_last_bulk_reason

        assert self._write(os_client, index, docs[:1]) == (1, 0)
        assert self._write(os_client, index, docs[1:]) == (0, 1)
        reason = get_last_bulk_reason()
        assert f"[{field}]" in reason and "flattened" not in reason, reason
        assert os_client.count(index=index)["count"] == 1

    def test_a_mixed_scalar_and_object_array_is_rejected_with_its_reason(self, os_client, index):
        from opensearch_mcp.bulk import get_last_bulk_reason

        assert self._write(os_client, index, [{"X": ["s", {"a": "b"}]}, {"ok": "y"}]) == (1, 1)
        reason = get_last_bulk_reason()
        assert "[X]" in reason and "flattened" not in reason, reason

    # -- Row 4: a scalar of the wrong type keeps its row -----------------------

    def test_a_number_then_a_string_keeps_the_row_and_marks_the_field(self, os_client, index):
        assert self._write(os_client, index, [{"LogonType": 3}, {"LogonType": "S11"}]) == (2, 0)
        ignored = {"query": {"term": {"_ignored": "LogonType"}}}
        assert os_client.count(index=index, body=ignored)["count"] == 1
        assert self._hits(os_client, index, "LogonType", 3) == 1

    # -- Expected loud: accepted residuals -------------------------------------

    @pytest.mark.parametrize(
        "docs,field",
        [
            ([{"B": True}, {"B": "x"}], "B"),
            ([{"B": True}, {"B": 1}], "B"),
            ([{"ok": 1}, {"threat_intel.confidence": "high"}], "threat_intel.confidence"),
            ([{"ok": 1}, {"threat_intel.enriched_at": "garbage"}], "threat_intel.enriched_at"),
            ([{"ok": 1}, {"threat_intel.checked": "maybe"}], "threat_intel.checked"),
        ],
        ids=["boolean-then-string", "boolean-then-int", "confidence", "enriched_at", "checked"],
    )
    def test_where_ignore_malformed_does_not_reach_the_record_is_rejected_loudly(
        self, os_client, index, docs, field
    ):
        """Boolean takes no `ignore_malformed`, and these declared fields set
        none; with no index-level setting a wrong value there is a counted,
        named rejection — the index-level setting dropped it silently."""
        from opensearch_mcp.bulk import get_last_bulk_reason

        assert self._write(os_client, index, docs[:1]) == (1, 0)
        assert self._write(os_client, index, docs[1:]) == (0, 1)
        assert f"[{field}]" in get_last_bulk_reason()

    # -- SPEC-902: an index created from the April component --------------------

    def test_an_old_index_accepts_objects_and_dotted_keys_after_the_patch(
        self, os_client, templates
    ):
        from opensearch_mcp.mappings import patch_flattened_indices

        index = f"{templates}-json-old-{uuid.uuid4().hex[:8]}"
        os_client.indices.create(
            index=index, body={"settings": {"index.mapping.ignore_malformed": True}}
        )
        os_client.indices.put_mapping(
            index=index, body={"dynamic_templates": APRIL_DYNAMIC_TEMPLATES}
        )
        assert self._write(os_client, index, [{"kept": "before"}]) == (1, 0)
        # Control: the old rules reject the record.
        assert self._write(os_client, index, [{"o": {"a": "x"}}]) == (0, 1)

        assert patch_flattened_indices(os_client, [index]) == {"patched": [index], "failed": []}
        assert patch_flattened_indices(os_client, [index]) == {"patched": [], "failed": []}

        docs = [{"o": {"a": "x"}}, {"source.ip": "8.8.8.8"}, {"Hash": {"MD5": _MD5}}]
        from opensearch_mcp.bulk import flush_bulk

        actions = [{"_index": index, "_id": f"n{i}", "_source": d} for i, d in enumerate(docs)]
        assert flush_bulk(os_client, actions) == (3, 0)
        os_client.indices.refresh(index=index)
        assert self._hits(os_client, index, "o.a", "x") == 1
        assert self._hits(os_client, index, "source.ip", "8.8.8.8") == 1
        assert self._buckets(os_client, index, "Hash.MD5") == [_MD5]
        assert os_client.count(index=index)["count"] == 4, "the earlier record is still there"
        state = os_client.cluster.state(index=index, metric="metadata")
        assert state["metadata"]["indices"][index]["state"] == "open"
