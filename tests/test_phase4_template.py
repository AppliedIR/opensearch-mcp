"""Tests for Phase 4 evtx_ecs_template.json — Winlogbeat compatibility + GeoIP."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_TEMPLATE_PATH = (
    Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings" / "evtx_ecs_template.json"
)


@pytest.fixture
def template():
    return json.loads(_TEMPLATE_PATH.read_text())


@pytest.fixture
def mappings(template):
    return template["template"]["mappings"]


@pytest.fixture
def properties(mappings):
    return mappings["properties"]


@pytest.fixture
def settings(template):
    return template["template"]["settings"]


# ---------------------------------------------------------------------------
# Template structure
# ---------------------------------------------------------------------------


class TestTemplateStructure:
    def test_index_pattern(self, template):
        assert template["index_patterns"] == ["case-*-evtx-*"]

    def test_has_settings(self, template):
        assert "settings" in template["template"]

    def test_has_mappings(self, template):
        assert "mappings" in template["template"]

    def test_has_dynamic_templates(self, mappings):
        assert "dynamic_templates" in mappings

    def test_has_properties(self, mappings):
        assert "properties" in mappings


# ---------------------------------------------------------------------------
# No flat_object (Phase 1 errata)
# ---------------------------------------------------------------------------


class TestNoFlatObject:
    def test_no_flat_object_type_anywhere(self, template):
        """flat_object must not appear anywhere in the template."""
        raw = json.dumps(template)
        assert "flat_object" not in raw

    def test_no_flattened_type_anywhere(self, template):
        """flattened (Elasticsearch equivalent) must not appear either."""
        raw = json.dumps(template)
        assert "flattened" not in raw

    def test_winlog_event_data_not_in_properties(self, properties):
        """winlog.event_data should NOT be explicitly typed in properties.
        It gets its sub-field types from the dynamic template."""
        assert "winlog.event_data" not in properties


# ---------------------------------------------------------------------------
# Dynamic templates (Winlogbeat-compatible keyword mapping)
# ---------------------------------------------------------------------------


class TestDynamicTemplates:
    def test_has_winlog_event_data_template(self, mappings):
        templates = mappings["dynamic_templates"]
        names = [list(t.keys())[0] for t in templates]
        assert "winlog_event_data_strings" in names

    def test_path_match(self, mappings):
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        assert dt["path_match"] == "winlog.event_data.*"

    def test_match_mapping_type_string(self, mappings):
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        assert dt["match_mapping_type"] == "string"

    def test_mapping_type_keyword(self, mappings):
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        assert dt["mapping"]["type"] == "keyword"

    def test_ignore_above_1024(self, mappings):
        """Default ignore_above for EventData keyword fields is 1024.
        Matches Winlogbeat's model. Handles long paths, registry keys."""
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        assert dt["mapping"]["ignore_above"] == 1024

    def test_not_text_type(self, mappings):
        """Dynamic template must map to keyword, NOT text.
        Default dynamic mapping creates text+keyword multi-field.
        Pure keyword is needed for Sigma rule wildcard matching."""
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        assert dt["mapping"]["type"] != "text"


# ---------------------------------------------------------------------------
# ScriptBlockText override
# ---------------------------------------------------------------------------


class TestScriptBlockTextOverride:
    def test_explicit_mapping_exists(self, properties):
        assert "winlog.event_data.ScriptBlockText" in properties

    def test_type_is_keyword(self, properties):
        sbt = properties["winlog.event_data.ScriptBlockText"]
        assert sbt["type"] == "keyword"

    def test_ignore_above_32766(self, properties):
        """ScriptBlockText can be >10KB. ignore_above must be 32766
        (Lucene keyword max) to avoid truncation that breaks Sigma matching."""
        sbt = properties["winlog.event_data.ScriptBlockText"]
        assert sbt["ignore_above"] == 32766

    def test_promoted_script_block_text_is_text(self, properties):
        """Phase 1 promoted script_block_text (top-level) must be text type
        for full-text search by examiner."""
        assert properties["script_block_text"]["type"] == "text"


# ---------------------------------------------------------------------------
# Field limit
# ---------------------------------------------------------------------------


class TestFieldLimit:
    def test_total_fields_limit(self, settings):
        assert settings["index.mapping.total_fields.limit"] == 5000

    def test_limit_is_integer(self, settings):
        assert isinstance(settings["index.mapping.total_fields.limit"], int)


# ---------------------------------------------------------------------------
# GeoIP default pipeline
# ---------------------------------------------------------------------------


class TestGeoIPPipeline:
    def test_default_pipeline_set(self, settings):
        assert settings["default_pipeline"] == "vhir-geoip"

    def test_default_pipeline_is_string(self, settings):
        assert isinstance(settings["default_pipeline"], str)


# ---------------------------------------------------------------------------
# GeoIP field mappings
# ---------------------------------------------------------------------------


class TestGeoIPFields:
    def test_country_name(self, properties):
        assert properties["source.geo.country_name"]["type"] == "keyword"

    def test_city_name(self, properties):
        assert properties["source.geo.city_name"]["type"] == "keyword"

    def test_continent_name(self, properties):
        assert properties["source.geo.continent_name"]["type"] == "keyword"

    def test_region_name(self, properties):
        assert properties["source.geo.region_name"]["type"] == "keyword"

    def test_location_geo_point(self, properties):
        """source.geo.location must be geo_point for map visualization."""
        assert properties["source.geo.location"]["type"] == "geo_point"


# ---------------------------------------------------------------------------
# Existing ECS fields preserved (regression)
# ---------------------------------------------------------------------------


class TestECSFieldsPreserved:
    """Verify Phase 1 ECS fields are unchanged by Phase 4 additions."""

    def test_event_code_integer(self, properties):
        assert properties["event.code"]["type"] == "integer"

    def test_winlog_event_id_integer(self, properties):
        assert properties["winlog.event_id"]["type"] == "integer"

    def test_timestamp_date(self, properties):
        assert properties["@timestamp"]["type"] == "date"

    def test_source_ip_type(self, properties):
        assert properties["source.ip"]["type"] == "ip"

    def test_source_ip_ignore_malformed(self, properties):
        assert properties["source.ip"]["ignore_malformed"] is True

    def test_host_name_keyword(self, properties):
        assert properties["host.name"]["type"] == "keyword"

    def test_user_name_keyword(self, properties):
        assert properties["user.name"]["type"] == "keyword"

    def test_user_effective_name_keyword(self, properties):
        assert properties["user.effective.name"]["type"] == "keyword"

    def test_winlog_channel_keyword(self, properties):
        assert properties["winlog.channel"]["type"] == "keyword"

    def test_winlog_provider_name_keyword(self, properties):
        assert properties["winlog.provider_name"]["type"] == "keyword"

    def test_winlog_logon_type_keyword(self, properties):
        assert properties["winlog.logon.type"]["type"] == "keyword"

    def test_process_name_keyword(self, properties):
        assert properties["process.name"]["type"] == "keyword"

    def test_process_command_line_text(self, properties):
        assert properties["process.command_line"]["type"] == "text"

    def test_process_command_line_keyword_subfield(self, properties):
        kw = properties["process.command_line"]["fields"]["keyword"]
        assert kw["type"] == "keyword"
        assert kw["ignore_above"] == 2048

    def test_process_parent_name_keyword(self, properties):
        assert properties["process.parent.name"]["type"] == "keyword"

    def test_file_path_keyword(self, properties):
        assert properties["file.path"]["type"] == "keyword"

    def test_provenance_fields(self, properties):
        assert properties["pipeline_version"]["type"] == "keyword"
        assert properties["vhir.source_file"]["type"] == "keyword"
        assert properties["vhir.ingest_audit_id"]["type"] == "keyword"
        assert properties["vhir.vss_id"]["type"] == "keyword"


# ---------------------------------------------------------------------------
# Security Analytics compatibility
# ---------------------------------------------------------------------------


class TestSigmaCompatibility:
    """Verify the template structure supports Sigma rule matching."""

    def test_winlog_event_id_is_integer_not_keyword(self, properties):
        """EventID must be integer for numeric comparison in Sigma rules."""
        assert properties["winlog.event_id"]["type"] == "integer"

    def test_dynamic_template_enables_wildcard_on_event_data(self, mappings):
        """With keyword type, wildcard queries like Image|endswith work.
        This is the key fix from the Phase 1 errata."""
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        # keyword type supports wildcard, prefix, and term queries
        assert dt["mapping"]["type"] == "keyword"

    def test_no_text_primary_type_for_event_data(self, mappings):
        """Default dynamic mapping would create text (primary) + keyword (sub-field).
        Sigma rules query the bare path (winlog.event_data.Image), which would hit
        the text field. Text fields tokenize values, breaking exact/wildcard matches.
        The dynamic template MUST override this to pure keyword."""
        dt = mappings["dynamic_templates"][0]["winlog_event_data_strings"]
        assert "fields" not in dt["mapping"]  # no multi-field, pure keyword
