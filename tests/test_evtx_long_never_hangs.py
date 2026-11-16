"""The "hex" and "int" transforms return promptly for a value that is not a
number a long field holds: text that is no number, an empty value, and a
decimal too long for int() all give None. Each call runs in its own process
under a time limit, so a transform that hangs fails here instead of stalling
the suite. Values are synthetic."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from opensearch_mcp import normalize

SRC = str(Path(normalize.__file__).resolve().parents[1])  # the tree under test
CALL = (
    "import json, sys; sys.path.insert(0, sys.argv[1]);"
    "from opensearch_mcp.normalize import _TRANSFORMS;"
    "name, value = json.load(sys.stdin);"
    "print(json.dumps(_TRANSFORMS[name](value)))"
)
VALUES = ["zz", "x", "-", "", "9" * 4301]


@pytest.mark.parametrize("name", ["hex", "int"])
@pytest.mark.parametrize("value", VALUES, ids=["zz", "x", "dash", "empty", "decimal_4301_digits"])
def test_a_value_no_long_field_holds_returns_promptly(name, value):
    try:
        out = subprocess.run(
            [sys.executable, "-c", CALL, SRC],
            input=json.dumps([name, value]),
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the {name} transform did not return within 20 s")
    assert out.returncode == 0, out.stderr
    # "hex" reads the 4301 nines as hex digits: a number past any long field
    assert json.loads(out.stdout) is None
