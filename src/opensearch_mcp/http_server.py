"""HTTP transport for opensearch-mcp."""

from opensearch_mcp.server import server


def create_http_app():
    """Create ASGI app for HTTP transport."""
    server.settings.transport_security.enable_dns_rebinding_protection = True
    server.settings.transport_security.allowed_hosts = ["localhost", "127.0.0.1"]
    return server.streamable_http_app()
