"""Ingest workers start isolated (-I).

The server spawns `sys.executable -m opensearch_mcp.ingest_cli …` without a
cwd, so a worker started from the session's directory would import a
`json.py` or `re.py` sitting there. Every spawn list headed by the
interpreter passes -I first.
"""

import ast
from pathlib import Path

SERVER = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "server.py"


def _spawn_lists():
    for node in ast.walk(ast.parse(SERVER.read_text())):
        if isinstance(node, ast.List) and node.elts:
            head = node.elts[0]
            if isinstance(head, ast.Attribute) and head.attr == "executable":
                yield node


def test_every_worker_spawn_passes_dash_i_first():
    spawns = list(_spawn_lists())
    assert len(spawns) == 4  # scan, ingest, enrich-intel, memory
    missing = [
        n.lineno
        for n in spawns
        if not (isinstance(n.elts[1], ast.Constant) and n.elts[1].value == "-I")
    ]
    assert missing == [], f"spawns without -I at server.py lines {missing}"
