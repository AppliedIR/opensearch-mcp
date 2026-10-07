"""A by-query request with one response header per batch is sent once.

OpenSearch adds a header per scroll batch to an update_by_query response.
Past Python's default of 100, the client refused the response and
opensearch-py sent the whole request again, up to four times, so the work
was applied repeatedly and the counts were the last attempt's.
"""

from __future__ import annotations

import http.client
import http.server
import json
import subprocess
import sys
import threading

import pytest
import yaml


class _ManyHeaders(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_POST(self):
        type(self).requests += 1
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps({"updated": 150, "batches": 150}).encode()
        self.send_response(200)
        for n in range(150):  # one per batch
            self.send_header("X-Task-Usage", f"batch {n}")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def many_headers(tmp_path):
    server = http.server.HTTPServer(("127.0.0.1", 0), _ManyHeaders)
    _ManyHeaders.requests = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "opensearch.yaml"
    config.write_text(
        yaml.safe_dump(
            {"host": f"http://127.0.0.1:{server.server_port}", "user": "u", "password": "p"}
        )
    )
    yield config
    server.shutdown()


def test_a_response_with_a_header_per_batch_is_read_from_one_request(many_headers):
    from opensearch_mcp.client import get_client

    client = get_client(many_headers)
    r = client.update_by_query(index="case-0123456789ab-evtx-0", body={})
    assert r["updated"] == 150
    assert _ManyHeaders.requests == 1


@pytest.mark.parametrize(
    "entry", ["opensearch_mcp.server", "opensearch_mcp.ingest_cli", "opensearch_mcp.client"]
)
def test_every_entry_point_raises_the_header_limit(entry):
    code = f"import http.client, {entry}; print(http.client._MAXHEADERS)"
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert int(out.stdout.split()[-1]) >= 100_000
