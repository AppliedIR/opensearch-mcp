"""setup-opensearch.sh registers its backend without reordering gateway.yaml.

The test runs the script's own inline Python (cut from the real file, so a
change there is what's tested): setup-sift writes the owner's key first under
api_keys, and local readers take the first key as the local examiner's token.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

SCRIPT = Path(__file__).parent.parent / "scripts" / "setup-opensearch.sh"
OWNER = "vhir_gw_" + "f" * 24  # sorts after the joined key
JOINED = "vhir_gw_" + "0" * 24


def _registration_snippet() -> str:
    text = SCRIPT.read_text()
    block = text[text.index("# --- 9. Register opensearch-mcp with gateway ---") :]
    return re.search(r'"\$VENV_PYTHON" -c "(.*?)\n"', block, re.S).group(1)


def test_registering_the_backend_keeps_the_owners_key_first(tmp_path):
    gw = tmp_path / "gateway.yaml"
    config = {
        "gateway": {"host": "0.0.0.0", "port": 4508},
        "api_keys": {
            OWNER: {"examiner": "steve", "role": "lead"},
            JOINED: {"examiner": "laptop"},
        },
        "backends": {"forensic-mcp": {"type": "stdio"}},
    }
    gw.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
    code = (
        _registration_snippet()
        .replace("$GW_CONFIG", str(gw))
        .replace("$VENV_PYTHON", sys.executable)
        .replace("$VHIR_DIR", str(tmp_path))
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)
    written = yaml.safe_load(gw.read_text())
    assert "opensearch-mcp" in written["backends"]  # it did register
    assert list(written["api_keys"]) == [OWNER, JOINED]
    assert list(written) == ["gateway", "api_keys", "backends"]
