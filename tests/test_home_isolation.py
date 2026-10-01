"""The suite never touches the HOME it was started with.

Each row starts a child pytest on this file with HOME set to a scratch
directory standing in for the real one, runs one probe there, and checks what
the probe saw. The probes run only in that child.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Imported at collection, as test modules import it, so a redirect that runs
# later than collection (a fixture) is seen too late — as it would be.
from opensearch_mcp import ingest_status

_PROBE = os.environ.get("HOME_ISOLATION_PROBE")
_ROOT = Path(__file__).parent.parent


def _child(tmp_path: Path) -> tuple[Path, dict]:
    original = tmp_path / "original-home"
    (original / ".vhir").mkdir(parents=True)
    (original / ".vhir" / "opensearch.yaml").write_text("host: scratch.invalid\n")
    out = tmp_path / "probe.json"
    env = {**os.environ, "HOME": str(original), "HOME_ISOLATION_PROBE": str(out)}
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            f"{__file__}::test_probe",
        ],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert run.returncode == 0, run.stdout[-3000:]
    return original, json.loads(out.read_text())


def test_the_status_directory_is_not_under_the_original_home(tmp_path):
    original, seen = _child(tmp_path)
    assert not seen["status_dir"].startswith(str(original)), seen


def test_the_cluster_settings_are_linked_into_the_test_home(tmp_path):
    original, seen = _child(tmp_path)
    assert seen["cluster_config"] == str(original / ".vhir" / "opensearch.yaml"), seen


@pytest.mark.skipif(not _PROBE, reason="runs only in the child started above")
def test_probe():
    config = Path.home() / ".vhir" / "opensearch.yaml"
    seen = {
        "status_dir": str(ingest_status._STATUS_DIR),
        "cluster_config": str(config.resolve()) if config.exists() else "",
    }
    Path(_PROBE).write_text(json.dumps(seen))
