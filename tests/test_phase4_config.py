"""Tests for Phase 4 configuration: docker-compose, setup script structure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).parent.parent
_DOCKER_COMPOSE = _REPO_ROOT / "docker" / "docker-compose.yml"
_SETUP_SCRIPT = _REPO_ROOT / "scripts" / "setup-opensearch.sh"
_TEMPLATE_PATH = _REPO_ROOT / "src" / "opensearch_mcp" / "mappings" / "evtx_ecs_template.json"


# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------


class TestDockerCompose:
    @pytest.fixture
    def compose(self):
        return yaml.safe_load(_DOCKER_COMPOSE.read_text())

    def test_heap_4gb(self, compose):
        """Security Analytics needs 4GB heap minimum."""
        env = compose["services"]["opensearch"]["environment"]
        java_opts = [e for e in env if "JAVA_OPTS" in e][0]
        assert "-Xms4g" in java_opts
        assert "-Xmx4g" in java_opts

    def test_heap_xms_equals_xmx(self, compose):
        """Xms must equal Xmx for predictable performance."""
        env = compose["services"]["opensearch"]["environment"]
        java_opts = [e for e in env if "JAVA_OPTS" in e][0]
        # Extract values
        xms = java_opts.split("-Xms")[1].split(" ")[0].split("-")[0].strip()
        xmx = java_opts.split("-Xmx")[1].split(" ")[0].strip()
        assert xms == xmx

    def test_mem_limit_exceeds_heap(self, compose):
        """Container mem_limit must exceed heap to allow JVM native memory."""
        mem = compose["services"]["opensearch"]["mem_limit"]
        # Parse mem_limit (e.g., "6g")
        if isinstance(mem, str):
            mem_gb = int(mem.rstrip("gG"))
        else:
            mem_gb = mem / (1024**3)
        assert mem_gb >= 6  # 4g heap + 2g overhead

    def test_single_node_discovery(self, compose):
        env = compose["services"]["opensearch"]["environment"]
        assert "discovery.type=single-node" in env

    def test_port_localhost_only(self, compose):
        ports = compose["services"]["opensearch"]["ports"]
        for port in ports:
            assert port.startswith("127.0.0.1:"), f"Port {port} not bound to localhost"


# ---------------------------------------------------------------------------
# Setup Script Structure
# ---------------------------------------------------------------------------


class TestSetupScript:
    @pytest.fixture
    def script(self):
        return _SETUP_SCRIPT.read_text()

    def test_geoip_datasource_created(self, script):
        assert "ip2geo/datasource/maxmind-city" in script

    def test_geoip_pipeline_created(self, script):
        assert "_ingest/pipeline/vhir-geoip" in script

    def test_geoip_pipeline_has_on_failure(self, script):
        assert "on_failure" in script

    def test_geoip_ignore_missing(self, script):
        assert "ignore_missing" in script

    def test_geoip_target_field(self, script):
        assert "source.geo" in script

    def test_geoip_applied_to_existing_indices(self, script):
        """Pipeline must be applied to existing indices, not just new ones."""
        assert "case-*-evtx-*/_settings" in script
        assert "default_pipeline" in script

    def test_sigma_rules_fetched(self, script):
        """Setup must query pre-packaged rules (two-step process)."""
        assert "pre_packaged=true" in script
        assert "category" in script and "windows" in script

    def test_detector_created(self, script):
        assert "vhir-windows" in script
        assert "_security_analytics/detectors" in script

    def test_detector_idempotent(self, script):
        """Script checks if detector already exists before creating."""
        assert "already exists" in script

    def test_detector_pre_packaged_rules_not_empty(self, script):
        """Detector must include fetched rule IDs, not empty array."""
        assert "pre_packaged_rules" in script
        assert "rule_ids" in script

    def test_no_hardcoded_password(self, script):
        """Password comes from $OS_PASSWORD variable, never hardcoded."""
        lines = script.splitlines()
        for line in lines:
            if line.strip().startswith("#"):
                continue
            # OS_PASSWORD variable is OK, but literal passwords are not
            assert "admin:admin" not in line

    def test_template_registration_before_geoip(self, script):
        """Template must be registered before GeoIP pipeline,
        because template references the pipeline as default_pipeline."""
        template_pos = script.find("index_template/vhir-evtx-ecs")
        geoip_pos = script.find("_ingest/pipeline/vhir-geoip")
        assert template_pos < geoip_pos, "Template must be registered before GeoIP pipeline"

    def test_geoip_before_detector(self, script):
        """GeoIP pipeline setup before SA detector (ordering)."""
        geoip_pos = script.find("_ingest/pipeline/vhir-geoip")
        detector_pos = script.find("_security_analytics/detectors")
        assert geoip_pos < detector_pos


# ---------------------------------------------------------------------------
# Template + Pipeline coherence
# ---------------------------------------------------------------------------


class TestTemplateCoherence:
    def test_default_pipeline_matches_created_pipeline(self):
        """Template's default_pipeline name must match the pipeline created in setup."""
        template = json.loads(_TEMPLATE_PATH.read_text())
        pipeline_name = template["template"]["settings"]["default_pipeline"]
        script = _SETUP_SCRIPT.read_text()
        assert f"pipeline/{pipeline_name}" in script

    def test_geo_fields_in_template(self):
        """All GeoIP output fields must have explicit mappings to avoid
        text+keyword default dynamic mapping."""
        template = json.loads(_TEMPLATE_PATH.read_text())
        props = template["template"]["mappings"]["properties"]
        expected_geo_fields = [
            "source.geo.country_name",
            "source.geo.city_name",
            "source.geo.continent_name",
            "source.geo.region_name",
            "source.geo.location",
        ]
        for field in expected_geo_fields:
            assert field in props, f"Missing GeoIP field mapping: {field}"
