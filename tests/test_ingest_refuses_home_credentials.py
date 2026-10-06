"""The ingest tools refuse the home folder itself and the hidden files and folders in it.

That's where credentials and client settings live (~/.claude.json, ~/.ssh,
~/.vhir, ~/.netrc and the like). Ingesting one indexed its secrets into the
case, where idx_search returned them. Every value here is synthetic. HOME lies
under /tmp, itself an allowed root, so the refusal has to win over it.
"""

from __future__ import annotations

import pytest

from opensearch_mcp import server as srv

REFUSAL = "is your home folder, or is in your home folder's hidden configuration area"

SECRETS = [
    ".vhir/opensearch.yaml",
    ".vhir/gateway.yaml",
    ".vhir",
    ".claude.json",
    ".claude.json.backup",
    ".claude/.credentials.json",
    ".ssh/id_ed25519",
    ".config/opencti-mcp/token",
    ".config/claude/claude_desktop_config.json",
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    ".claude.json.vhir-backup-20261006T000000Z",
]
ALLOWED = [
    "cases/X/evidence/disk.E01",
    "cases/X/evidence/rootfs/home/u/.ssh/authorized_keys",
    "cases/X/extractions/amcache.csv",
    "cases/X/.outputs/x.json",
    "Downloads/export.json",
    "evidence/host1",
    "vhir/cases/X/evidence/a.json",
]


def _tools():
    return {
        "idx_ingest": lambda p: srv.idx_ingest(path=p),
        "idx_ingest_json": lambda p: srv.idx_ingest_json(path=p, hostname="h1"),
        "idx_ingest_delimited": lambda p: srv.idx_ingest_delimited(path=p, hostname="h1"),
        "idx_ingest_accesslog": lambda p: srv.idx_ingest_accesslog(path=p, hostname="h1"),
        "idx_ingest_memory": lambda p: srv.idx_ingest_memory(path=p, hostname="h1"),
    }


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home folder under /tmp, with synthetic credential files."""
    home = tmp_path / "home"
    for rel in SECRETS + ALLOWED:
        f = home / rel
        if rel in (".vhir", "evidence/host1"):
            f.mkdir(parents=True, exist_ok=True)
            continue
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text('{"Authorization": "Bearer vhir_gw_SYNTHETIC00000000000000"}\n')
    link = home / "cases/X/evidence/link.json"
    link.symlink_to(home / ".claude.json")
    monkeypatch.setenv("HOME", str(home))
    assert str(home).startswith("/tmp/")  # under an allowed root
    return home


REFUSED = SECRETS + ["", "/", "cases/../.vhir/x", "cases/X/evidence/link.json"]


@pytest.mark.parametrize("tool", list(_tools()))
@pytest.mark.parametrize("rel", REFUSED, ids=[r or "home itself" for r in REFUSED])
def test_a_credential_path_in_home_is_refused(home, tool, rel):
    path = f"{home}/{rel}" if rel else str(home)
    resp = _tools()[tool](path)
    assert REFUSAL in resp.get("error", ""), resp
    assert resp["error"].startswith(f"Refused: {path} (resolved target: ")
    assert "Copy or move the evidence into the case's evidence/ folder" in resp["error"]


@pytest.mark.parametrize("rel", ALLOWED)
def test_evidence_elsewhere_in_home_passes_the_check(home, rel):
    assert srv._validate_path(str(home / rel)) is None


@pytest.mark.parametrize(
    "path", ["/mnt/e/x.E01", "/media/u/disk", "/cases/X/evidence", "/evidence/h1", "/tmp/x.json"]
)
def test_evidence_under_the_other_allowed_roots_passes_the_check(home, path):
    assert srv._validate_path(path) is None


@pytest.mark.parametrize("path", ["/etc/passwd", "/root/.ssh/id_rsa", "/home/other/.claude.json"])
def test_paths_outside_the_allowed_roots_are_still_refused(home, path):
    assert "not in allowed locations" in srv._validate_path(path)


def test_a_tool_still_takes_evidence_in_home(home):
    resp = srv.idx_ingest_json(path=str(home / "Downloads/export.json"), hostname="h1")
    assert REFUSAL not in resp.get("error", ""), resp
