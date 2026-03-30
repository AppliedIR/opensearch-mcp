"""Centralized OpenSearch client factory."""

from pathlib import Path

import yaml
from opensearchpy import OpenSearch

from opensearch_mcp.paths import vhir_dir


def get_client(config_path: Path | None = None) -> OpenSearch:
    """Create OpenSearch client from ~/.vhir/opensearch.yaml."""
    path = config_path or (vhir_dir() / "opensearch.yaml")
    if not path.exists():
        raise FileNotFoundError(
            f"OpenSearch config not found: {path}\n"
            "Run 'opensearch-setup' or 'vhir setup opensearch' first."
        )
    config = yaml.safe_load(path.read_text()) or {}
    host_url = config.get("host", "https://localhost:9200")
    user = config.get("user")
    password = config.get("password")
    if not user or not password:
        raise ValueError(
            f"OpenSearch config missing 'user' or 'password': {path}\n"
            "Re-run 'opensearch-setup' to regenerate."
        )
    return OpenSearch(
        hosts=[host_url],
        http_auth=(user, password),
        use_ssl=host_url.startswith("https"),
        verify_certs=config.get("verify_certs", False),
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )
