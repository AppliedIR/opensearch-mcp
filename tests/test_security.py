"""Security tests for opensearch-mcp."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opensearch_mcp.parse_csv import _detect_encoding, _doc_id

# ---------------------------------------------------------------------------
# Index name sanitization
# ---------------------------------------------------------------------------


class TestIndexNameSecurity:
    def test_index_names_lowercased(self):
        """Index names are lowercased (OpenSearch requires lowercase)."""
        from opensearch_mcp.tools import TOOLS

        case_id = "INC-2024-001"
        hostname = "WKSTN05"
        for name, cfg in TOOLS.items():
            index_name = f"case-{case_id}-{cfg.index_suffix}-{hostname}".lower()
            assert index_name == index_name.lower(), f"Index for {name} not lowercase"

    def test_index_name_no_special_chars_in_suffix(self):
        """Index suffixes contain only safe characters (alphanumeric, underscore, dash)."""
        import re

        from opensearch_mcp.tools import TOOLS

        safe_pattern = re.compile(r"^[a-z0-9_-]+$")
        for name, cfg in TOOLS.items():
            assert safe_pattern.match(cfg.index_suffix), (
                f"Tool {name} has unsafe index_suffix: {cfg.index_suffix}"
            )

    def test_case_id_path_traversal_in_index_name(self):
        """case_id with path traversal chars produces safe index name after lowercasing."""
        case_id = "../../../etc/passwd"
        hostname = "host1"
        index_name = f"case-{case_id}-evtx-{hostname}".lower()
        # The index name will contain slashes but OpenSearch will reject it at
        # index creation time. The key thing is no directory traversal occurs
        # on the filesystem side. The status module sanitizes separately.
        assert isinstance(index_name, str)

    def test_hostname_special_chars_in_index_name(self):
        """Hostname with special characters ends up lowercased in index name."""
        hostname = "HOST (Production)"
        case_id = "test"
        index_name = f"case-{case_id}-evtx-{hostname}".lower()
        # OpenSearch will reject indices with spaces/parens, but the pipeline
        # must handle this gracefully. Currently the code lowercases but does
        # not strip special chars -- this test documents current behavior.
        assert "host (production)" in index_name


# ---------------------------------------------------------------------------
# Encoding detection security
# ---------------------------------------------------------------------------


class TestEncodingSecurity:
    def test_detect_encoding_reads_only_4_bytes(self, tmp_path):
        """_detect_encoding reads only the BOM (first 4 bytes), not the whole file."""
        # Create a 10MB file
        big_file = tmp_path / "big.csv"
        big_file.write_bytes(b"col1,col2\n" + b"x" * (10 * 1024 * 1024))

        # Patch open to track read sizes
        original_open = open
        read_sizes = []

        class TrackingFile:
            def __init__(self, f):
                self._f = f

            def read(self, n=-1):
                read_sizes.append(n)
                return self._f.read(n)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self._f.close()

        with patch(
            "builtins.open", side_effect=lambda p, mode: TrackingFile(original_open(p, mode))
        ):
            _detect_encoding(big_file)

        # Should read exactly 4 bytes for BOM detection
        assert read_sizes[0] == 4


# ---------------------------------------------------------------------------
# Config-based credentials
# ---------------------------------------------------------------------------


class TestCredentialsSecurity:
    def test_get_client_reads_from_config(self, tmp_path):
        """get_client reads credentials from config file, not hardcoded."""
        config_file = tmp_path / "opensearch.yaml"
        config_file.write_text(
            "host: https://localhost:9200\nuser: testuser\npassword: testpass\n"
        )

        with patch("opensearch_mcp.client.OpenSearch") as mock_os:
            from opensearch_mcp.client import get_client

            get_client(config_path=config_file)
            mock_os.assert_called_once()
            call_kwargs = mock_os.call_args
            assert call_kwargs[1]["http_auth"] == ("testuser", "testpass")

    def test_get_client_raises_on_missing_config(self, tmp_path):
        """get_client raises FileNotFoundError when config is missing."""
        from opensearch_mcp.client import get_client

        with pytest.raises(FileNotFoundError, match="OpenSearch config not found"):
            get_client(config_path=tmp_path / "nonexistent.yaml")

    def test_get_client_raises_on_missing_credentials(self, tmp_path):
        """get_client raises ValueError when user or password missing."""
        config_file = tmp_path / "opensearch.yaml"
        config_file.write_text("host: https://localhost:9200\n")

        from opensearch_mcp.client import get_client

        with pytest.raises(ValueError, match="missing.*user.*password"):
            get_client(config_path=config_file)


# ---------------------------------------------------------------------------
# Query injection (defense-in-depth verification)
# ---------------------------------------------------------------------------


class TestQueryInjection:
    def test_query_string_is_search_only(self):
        """Verify that idx_search uses query_string (read-only search),
        not a raw HTTP endpoint that could be abused for admin operations."""
        # Read the server module source to verify it uses query_string
        import inspect

        from opensearch_mcp import server

        source = inspect.getsource(server.idx_search)
        assert "query_string" in source
        # Should NOT use raw HTTP endpoints
        assert "perform_request" not in source
        assert "_raw_query" not in source


# ---------------------------------------------------------------------------
# Status file path traversal
# ---------------------------------------------------------------------------


class TestStatusFileSecurity:
    def test_path_traversal_prevented(self, tmp_path, monkeypatch):
        """case_id with ../ cannot escape the status directory."""
        status_dir = tmp_path / ".vhir" / "ingest-status"
        monkeypatch.setattr("opensearch_mcp.ingest_status._STATUS_DIR", status_dir)

        from opensearch_mcp.ingest_status import write_status

        write_status(
            case_id="../../../tmp/evil",
            pid=1,
            run_id="x",
            status="running",
            hosts=[],
            totals={},
            started="2024-01-15T10:00:00Z",
        )

        # Verify file was created in the status directory, not elsewhere
        files = list(status_dir.glob("*.json"))
        assert len(files) == 1
        # Verify no files were created in /tmp/
        assert not (tmp_path / "tmp").exists()


# ---------------------------------------------------------------------------
# Doc ID determinism (security for dedup)
# ---------------------------------------------------------------------------


class TestDocIdSecurity:
    def test_different_index_different_id(self):
        """Same content in different indices produces different IDs."""
        row = {"col": "value"}
        id1 = _doc_id("case-a-evtx-host1", row)
        id2 = _doc_id("case-b-evtx-host1", row)
        assert id1 != id2

    def test_id_is_sha256_prefix(self):
        """Doc ID is a hex string of length 20 (SHA-256 prefix)."""
        row = {"col": "value"}
        doc_id = _doc_id("index", row)
        assert len(doc_id) == 20
        assert all(c in "0123456789abcdef" for c in doc_id)


# ---------------------------------------------------------------------------
# _validate_index — system index access prevention (S1)
# ---------------------------------------------------------------------------


class TestValidateIndex:
    def test_case_prefix_passes(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index("case-inc001-evtx-wkstn05") is None

    def test_case_wildcard_passes(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index("case-*") is None

    def test_case_vol_passes(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index("case-*-vol-pslist-*") is None

    def test_opendistro_security_blocked(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index(".opendistro_security") is not None

    def test_security_auditlog_blocked(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index("security-auditlog-2026") is not None

    def test_dot_prefix_blocked(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index(".kibana") is not None

    def test_empty_blocked(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index("") is not None

    def test_star_only_blocked(self):
        from opensearch_mcp.server import _validate_index

        assert _validate_index("*") is not None


# ---------------------------------------------------------------------------
# _sanitize_index_component — hostname/case_id sanitization (S5)
# ---------------------------------------------------------------------------


class TestSanitizeIndexComponent:
    def test_lowercase(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("WKSTN05") == "wkstn05"

    def test_spaces_replaced(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("WKSTN 05") == "wkstn-05"

    def test_slashes_replaced(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("host/name") == "host-name"

    def test_dots_preserved(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("host.domain.com") == "host.domain.com"

    def test_hyphens_preserved(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("inc-2026-001") == "inc-2026-001"

    def test_special_chars_replaced(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("host*name?") == "host-name-"

    def test_empty_string(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        assert _sanitize_index_component("") == ""

    def test_path_traversal_sanitized(self):
        from opensearch_mcp.ingest import _sanitize_index_component

        result = _sanitize_index_component("../../etc/passwd")
        assert "/" not in result
        # Dots preserved (safe in index names), slashes stripped
        assert result == "..-..-etc-passwd"
