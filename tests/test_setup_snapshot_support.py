"""setup-opensearch.sh sets up snapshots and says so only when they are.

The container needs a read-write bind of /var/lib/vhir/snapshots at
/usr/share/opensearch/snapshots, and path.repo as a node setting; both live
in docker-compose.yml, which the script starts as project "docker". The
script's own check (cut from the real file) runs under bash with stand-in
docker and curl: anything it can't read or run counts as a problem, and a
problem ends the script with exit 3. The replies are shaped like
_nodes/settings's nested form; values are synthetic.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup-opensearch.sh"
REPO = "/usr/share/opensearch/snapshots"
FOLDER = "/var/lib/vhir/snapshots"


def test_the_compose_file_the_script_starts_has_the_bind_and_the_node_setting():
    ups = [
        ln.strip()
        for ln in SCRIPT.read_text().splitlines()
        if re.search(r"\bdocker compose\b.*\bup\b", ln) and not ln.lstrip().startswith("#")
    ]
    assert ups == ['docker compose -p docker -f "$DOCKER_DIR/docker-compose.yml" up -d']
    words = shlex.split(ups[0])
    assert words[words.index("-f") + 1] == "$DOCKER_DIR/docker-compose.yml"  # no other file
    svc = yaml.safe_load((ROOT / "docker/docker-compose.yml").read_text())["services"][
        "opensearch"
    ]
    assert f"path.repo={REPO}" in svc["environment"]
    assert f"{FOLDER}:{REPO}" in svc["volumes"]
    assert "opensearch-data:/usr/share/opensearch/data" in svc["volumes"]  # the data is kept
    assert svc["container_name"] == "vhir-opensearch"


def test_the_script_puts_no_path_repo_to_the_cluster_settings():
    assert '"path.repo"' not in SCRIPT.read_text()  # a static setting the API refuses


_STUBS = {
    # what `docker inspect --format '{{range .Mounts}}…'` prints, or a denied socket
    "docker": '#!/bin/sh\n[ "$1" = inspect ] || exit 97\n'
    '[ -n "$FAKE_DOCKER_RC" ] && { echo "permission denied" >&2; exit "$FAKE_DOCKER_RC"; }\n'
    'printf %s "$FAKE_MOUNT"\n',
    # curl -s without -f exits 0 on an error body; FAKE_CURL_RC as a timeout (28)
    "curl": '#!/bin/sh\necho "curl $*" >> "$CALLS"\n'
    '[ -n "$FAKE_CURL_RC" ] && exit "$FAKE_CURL_RC"\nprintf %s "$FAKE_NODES"\n',
}


def _nodes(*repos):
    return {"nodes": {f"n{i}": {"settings": {"path": {"repo": r}}} for i, r in enumerate(repos)}}


GOOD, RO = f"bind {FOLDER} true", f"bind {FOLDER} false"
DENIED = "docker inspect failed: permission denied"
VOL, OTHER = "volume /v/snaps/_data true", "bind /srv/other true"
M = f"the container has no read-write bind of {FOLDER} at {REPO} (docker inspect: '{{}}')"
P = f"couldn't confirm that OpenSearch's path.repo includes {REPO} (_nodes/settings: '{{}}')"
ANY = object()  # some problem, whatever its text
CASES = {  # name: (mount line, nodes reply, extra env, expected problems)
    "as-installed": ("", {}, {}, [M.format(""), P.format("{}")]),
    "target-list": (GOOD, _nodes([REPO]), {}, []),
    "target-string": (GOOD, _nodes(REPO), {}, []),
    "env-without-bind": ("", _nodes([REPO]), {}, [M.format("")]),
    "bind-without-env": (GOOD, {}, {}, [P.format("{}")]),
    "named-volume": (VOL, _nodes([REPO]), {}, [M.format(VOL)]),
    "refusal-names-path.repo": (GOOD, {"error": {"reason": "[path.repo] not dynamic"}}, {}, ANY),
    "docker-and-curl-fail": ("", "", {"FAKE_DOCKER_RC": "1", "FAKE_CURL_RC": "28"}, ANY),
    "other-repo-folder": (GOOD, _nodes(["/mnt/elsewhere"]), {}, ANY),
    "bind-from-other-folder": (OTHER, _nodes([REPO]), {}, [M.format(OTHER)]),
    "read-only-bind": (RO, _nodes([REPO]), {}, [M.format(RO)]),
    "reply-crashes-a-parser": (GOOD, {"nodes": {"n0": "garbage"}}, {}, ANY),
    "not-json": (GOOD, "<html>502 Bad Gateway</html>", {}, ANY),
    "python3-missing": (GOOD, _nodes([REPO]), {"NO_PYTHON": "1"}, ANY),
    "curl-timeout": (GOOD, "", {"FAKE_CURL_RC": "28"}, ANY),
    "docker-fails-alone": ("", _nodes([REPO]), {"FAKE_DOCKER_RC": "1"}, [M.format(DENIED)]),
    "401": (GOOD, {"error": {"type": "security_exception", "reason": "Unauthorized"}}, {}, ANY),
    "two-mounts": (f"bind {FOLDER} truevolume /x true", _nodes([REPO]), {}, ANY),
    "one-node-of-two-lacks-it": (GOOD, {"nodes": {"a": _nodes([REPO])["nodes"]["n0"],
                                                  "b": {"settings": {"path": {}}}}}, {}, ANY),
}  # fmt: skip


@pytest.mark.parametrize("name", CASES)
def test_the_snapshot_check_fails_closed(tmp_path, name):
    mount, nodes, extra, want = CASES[name]
    text = SCRIPT.read_text()
    block = text[
        text.index("# --- Check snapshot support") : text.index("# --- Raise shard limit")
    ]
    tail = text[text.index("# Snapshots are the one part") :]
    prog = tmp_path / "check.sh"
    prog.write_text(
        f'set -euo pipefail\nSCRIPT_DIR="{ROOT}/scripts"\nDOCKER_DIR="{ROOT}/docker"\n'
        f'OS_URL="https://localhost:9200"\nOS_PASSWORD="x"\nSNAPSHOTS_DIR="{FOLDER}"\n'
        + block
        + '\necho "PROBLEMS=[${SNAPSHOT_PROBLEMS-<unset>}]"\n'
        + tail
    )
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stubs = dict(_STUBS)
    if extra.get("NO_PYTHON"):
        stubs["python3"] = "#!/bin/sh\nexit 127\n"
    for name_, body in stubs.items():
        (bin_ / name_).write_text(body)
        (bin_ / name_).chmod(0o755)
    env = {
        **os.environ,
        **extra,
        "PATH": f"{bin_}:{os.environ['PATH']}",
        "CALLS": str(tmp_path / "calls.log"),
        "FAKE_MOUNT": mount,
        "FAKE_NODES": nodes if isinstance(nodes, str) else json.dumps(nodes),
    }
    r = subprocess.run(["bash", str(prog)], capture_output=True, text=True, env=env, timeout=60)
    seg = r.stdout.split("PROBLEMS=[", 1)[1].split("]\n", 1)[0]
    got = [s for s in seg.splitlines() if s]
    broken = want is ANY or bool(want)
    if want is ANY:
        assert got, r.stdout
    else:
        assert got == want
    assert ("Snapshots: OK" in r.stdout) is not broken
    assert ("Snapshots: NOT SET UP (details at the end)" in r.stdout) is broken
    assert r.returncode == (3 if broken else 0), r.stdout + r.stderr
    if broken:
        assert "ERROR: OpenSearch snapshots are not set up" in r.stdout
        assert f"  bash {ROOT}/scripts/setup-opensearch.sh" in r.stdout
    assert "_cluster/settings" not in (tmp_path / "calls.log").read_text()


@pytest.mark.parametrize(
    "exists, owner, want",
    [
        (True, "0:0", ["sudo chown 1000:1000 {d}"]),  # a folder docker made as root
        (True, "1000:1000", []),
        (False, "0:0", ["sudo mkdir -p {d}", "sudo chown 1000:1000 {d}"]),
    ],
)
def test_the_snapshot_folder_is_given_to_uid_1000_when_its_owner_differs(
    tmp_path, exists, owner, want
):
    d = tmp_path / "snapshots"
    if exists:
        d.mkdir()
    text = SCRIPT.read_text()
    block = text[text.index("# --- 2b.") : text.index("# --- 3. Start OpenSearch ---")]
    assert f'SNAPSHOTS_DIR="{FOLDER}"' in block
    prog = tmp_path / "chown.sh"
    prog.write_text(
        f'set -euo pipefail\nDOCKER_DIR="{ROOT}/docker"\n'
        + block.replace(f'SNAPSHOTS_DIR="{FOLDER}"', f'SNAPSHOTS_DIR="{d}"')
    )
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, body in {
        "sudo": '#!/bin/sh\necho "sudo $*" >> "$CALLS"\n',
        "stat": '#!/bin/sh\necho "$FAKE_OWNER"\n',
    }.items():
        (bin_ / name).write_text(body)
        (bin_ / name).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "CALLS": str(tmp_path / "calls"),
           "FAKE_OWNER": owner}  # fmt: skip
    r = subprocess.run(["bash", str(prog)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls").read_text().splitlines() if (tmp_path / "calls").exists() else []
    assert calls == [w.format(d=d) for w in want]


def test_no_override_file_is_made_or_named():
    """docker-compose.yml carries the bind and path.repo; an override file is
    a second place setup's own `-f` run never reads."""
    assert not (ROOT / "docker" / "docker-compose.override.yml").exists()
    assert "override" not in SCRIPT.read_text()


def _docker_paragraph() -> str:
    text = (ROOT / "README.md").read_text()
    (para,) = [p for p in text.split("\n\n") if p.startswith("**Docker container data:**")]
    return para


def test_the_readme_says_the_volume_survives_the_container():
    para = _docker_paragraph()
    assert "destroys" not in para
    assert "The volume survives removing or recreating the container (`docker rm -f`" in para
    assert "`docker volume rm`" in para and "another project name" in para


def test_the_readme_backs_up_every_case_not_one():
    para = _docker_paragraph()
    assert (
        "vhir backup <destination> --case <case-id> --include-opensearch`, once per case" in para
    )
    assert "`vhir backup --all` covers only the one case" in para
