"""Entry point for python -m opensearch_mcp."""

import argparse


def main():
    parser = argparse.ArgumentParser(description="OpenSearch MCP Server")
    parser.add_argument("--http", action="store_true", help="Enable HTTP server (default: stdio)")
    parser.add_argument("--port", type=int, default=4625, help="HTTP port (default: 4625)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind address (use 0.0.0.0 for remote access)",
    )
    args = parser.parse_args()

    if args.http:
        import uvicorn

        from opensearch_mcp.http_server import create_http_app

        app = create_http_app()
        uvicorn.run(app, host=args.host, port=args.port)
    else:
        from opensearch_mcp.server import main as stdio_main

        stdio_main()


if __name__ == "__main__":
    main()
