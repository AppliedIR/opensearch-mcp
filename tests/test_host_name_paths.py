"""A host name from evidence never builds a path outside the case's
extractions/.

The name (a Velociraptor fqdn, a SYSTEM hive's ComputerName, a name read from
a CSV) is evidence, so it can hold `/`, `\\` or `..`. Where it names a folder or
file (wintools staging, SRUM's staging, Plaso's work folder), `paths.fs_name`
gives a safe name: `[A-Za-z0-9._-]` kept, anything else `_`, and when that
changed anything, `~` and a hash of the original, so two names never share
one. A staging folder that still resolves outside extractions/ (a site that
forgot the helper, or extractions/ itself a link) is refused before anything
is removed or written. Host identity, display and index names keep the
evidence's own name. wintools and the gateway are stand-ins; values are
synthetic.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sift_common.audit import AuditWriter
from test_ingest_steps import _fake_wintools, case  # noqa: F401
from test_plaso_volume import _host

from opensearch_mcp import ops, parse_csv, paths

CLIMB = "a/../../../outside/victim"


def fs_name(name: str) -> str:
    return paths.fs_name(name)  # looked up at each call: the backstop rows replace it


def _outside(case: Path) -> Path:  # noqa: F811
    """A folder beside the case that a climbing name reaches; it holds a file."""
    victim = case.parent / "outside" / "victim"
    victim.mkdir(parents=True)
    (victim / "keep.txt").write_text("examiner's file")
    return victim


def _prefetch(tmp_path: Path) -> Path:
    prefetch = tmp_path / "mnt" / "vol1" / "Prefetch"  # outside the case: staged
    prefetch.mkdir(parents=True)
    (prefetch / "CMD.EXE-1.pf").write_bytes(b"pf1")
    return prefetch


def _stage(case: Path, prefetch: Path, hostname: str, monkeypatch) -> list[str]:  # noqa: F811
    """One wintools run of PECmd over `prefetch`: the command wintools got."""
    from opensearch_mcp import wintools
    from opensearch_mcp.wintools import run_tool_and_get_csv

    _fake_wintools(case, monkeypatch, "PECmd_Output.csv")
    unc = "\\\\sift\\cases\\"  # as _to_unc_path makes it: "/" becomes "\\"
    monkeypatch.setattr(wintools, "_to_unc_path", lambda rel: unc + rel.replace("/", "\\"))
    commands = []
    run = wintools.run_windows_tool

    def seen(command, **kw):
        commands.append(command)
        return run(command, **kw)

    monkeypatch.setattr(wintools, "run_windows_tool", seen)
    with ops.recording(AuditWriter(mcp_name="opensearch-ingest-1"), case, "ingest_prefetch", {}):
        run_tool_and_get_csv("PECmd.exe", "-d", str(prefetch), hostname=hostname)
    return commands[0]


def _files(folder: Path) -> list[str]:
    return sorted(str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file())


# --- wintools staging ------------------------------------------------------------


def test_a_climbing_name_stages_under_extractions_and_two_runs_keep_the_outside(
    case,  # noqa: F811
    tmp_path,
    monkeypatch,
):
    victim, prefetch = _outside(case), _prefetch(tmp_path)
    for _ in range(2):  # the second run removes the first run's staging
        _stage(case, prefetch, CLIMB, monkeypatch)
    assert _files(victim) == ["keep.txt"]
    staged = case / "extractions" / f"Prefetch-{fs_name(CLIMB)}"
    assert _files(staged) == ["CMD.EXE-1.pf"]


def test_a_backslash_name_stays_under_extractions_on_windows_too(case, tmp_path, monkeypatch):  # noqa: F811
    """`\\` is an ordinary character here and a separator to Windows: the UNC
    path wintools gets must not climb either."""
    name = "a\\..\\..\\..\\outside\\victim"
    command = _stage(case, _prefetch(tmp_path), name, monkeypatch)
    unc = command[2]
    assert "\\..\\" not in unc and unc.endswith(f"\\extractions\\Prefetch-{fs_name(name)}"), unc
    assert "\\" not in fs_name(name)


@pytest.mark.parametrize("hostname", ["RD01", "rd01.shieldbase.com", "WKS-01_x"])
def test_a_plain_name_stages_where_it_always_did(case, tmp_path, monkeypatch, hostname):  # noqa: F811
    command = _stage(case, _prefetch(tmp_path), hostname, monkeypatch)
    assert command[2].endswith(f"\\extractions\\Prefetch-{hostname}")
    assert _files(case / "extractions" / f"Prefetch-{hostname}") == ["CMD.EXE-1.pf"]


# --- SRUM's staging ----------------------------------------------------------------


def _srum(case: Path, hostname: str, monkeypatch) -> None:  # noqa: F811
    from opensearch_mcp.parse_srum import _parse_srum_wintools

    srum = case / "evidence" / "HOST1" / "SRUDB.dat"
    srum.parent.mkdir(parents=True, exist_ok=True)
    srum.write_bytes(b"esedb")
    (srum.parent / "SRU00001.log").write_bytes(b"log")
    _fake_wintools(case, monkeypatch)
    monkeypatch.setattr(parse_csv, "ingest_csv", lambda **kw: (2, 0, 0))
    with ops.recording(AuditWriter(mcp_name="opensearch-ingest-1"), case, "ingest_srum", {}):
        _parse_srum_wintools(srum, MagicMock(), "case-x-srum-0", hostname)


@pytest.mark.parametrize("hostname", ["a/../../../../outside/victim", "..", "."])
def test_srum_stages_under_extractions_srum(case, monkeypatch, hostname):  # noqa: F811
    victim = _outside(case)
    _srum(case, hostname, monkeypatch)
    assert _files(victim) == ["keep.txt"]
    for folder in (case.parent, case, case / "extractions", case / "extractions" / "srum"):
        assert not (folder / "SRUDB.dat").exists(), folder  # only in a folder of its own
    workdir = case / "extractions" / "srum" / fs_name(hostname)
    assert workdir.parent == case / "extractions" / "srum"
    assert _files(workdir) == ["SRU00001.log", "SRUDB.dat"]


# --- Plaso's work folder -------------------------------------------------------------


def test_plaso_s_work_folder_for_a_name_with_a_slash_is_under_its_base(tmp_path, monkeypatch):
    from opensearch_mcp import ingest, parse_plaso
    from opensearch_mcp.results import HostResult

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    vr = tmp_path / "C"
    (vr / "Users").mkdir(parents=True)
    host = _host(vr, "windows")
    host.hostname = "a/../../b"
    folders = []

    def run(parsers, source, workdir, read_as_root, zone):
        folders.append(workdir)
        raise RuntimeError("stop here")

    monkeypatch.setattr(parse_plaso, "run_plaso_volume", run)
    monkeypatch.setattr(ingest, "_safe_count", lambda c, i, unit="": 0)

    class Audit:
        def _next_audit_id(self):
            return "aid-1"

        def log(self, **kw):
            return kw.get("audit_id")

    status = [{"hostname": "h", "artifacts": [{"name": "plaso", "status": "pending"}]}]
    ingest._ingest_plaso_volume(None, Audit(), "c1", host, 0, HostResult(hostname="h"), status,
                                lambda *a, **k: None, lambda: None)  # fmt: skip
    base = tmp_path / "home/.vhir/cases/c1/tmp"
    assert folders and {f.parent for f in folders} == {base}
    assert all(f.name.startswith(f"plaso-{fs_name('a/../../b')}-") for f in folders)


# --- the names ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "one, other",
    [
        ("a/b", "a_b"),
        ("x/victim", "victim"),  # not a basename
        ("a/b", None),  # None: "a/b"'s own mapping, as another host's name
        ("..", "__"),
        (".", "_"),
    ],
)
def test_two_names_never_share_a_file_system_name(one, other):
    other = fs_name(one) if other is None else other
    assert fs_name(one) != fs_name(other)


@pytest.mark.parametrize(
    "name",
    ["..", ".", "a/../b", "a\\b", "x" * 300, "é", "\udcff", "", "RD01", "rd01.shieldbase.com"],
)
def test_a_file_system_name_is_one_safe_component(name):
    got = fs_name(name)
    assert got not in (".", "..") and "/" not in got and "\\" not in got
    assert re.fullmatch(r"[A-Za-z0-9._-]{0,64}(~[0-9a-f]{12})?", got), got
    plain = re.fullmatch(r"[A-Za-z0-9._-]{0,64}", name) is not None and name not in (".", "..")
    assert (got == name) == plain


# --- the backstop -------------------------------------------------------------------


def test_a_staging_path_outside_extractions_is_refused_by_name(case, tmp_path, monkeypatch):  # noqa: F811
    """A site that forgot the helper: the check refuses before rmtree or copy."""
    victim, prefetch = _outside(case), _prefetch(tmp_path)
    monkeypatch.setattr(paths, "fs_name", lambda name: name, raising=False)
    with pytest.raises(ValueError, match="Refusing to stage into .*outside/victim"):
        _stage(case, prefetch, CLIMB, monkeypatch)
    assert _files(victim) == ["keep.txt"]


def test_srum_staging_outside_extractions_is_refused(case, monkeypatch):  # noqa: F811
    victim = _outside(case)
    monkeypatch.setattr(paths, "fs_name", lambda name: name, raising=False)
    with pytest.raises(ValueError, match="Refusing to stage into"):
        _srum(case, "a/../../../../outside/victim", monkeypatch)
    assert _files(victim) == ["keep.txt"] and not (victim / "SRUDB.dat").exists()


def test_an_extractions_folder_that_is_a_link_is_refused(case, tmp_path, monkeypatch):  # noqa: F811
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "Prefetch-HOST1").mkdir(parents=True)
    (elsewhere / "Prefetch-HOST1" / "keep.txt").write_text("not the case's")
    (case / "extractions").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ValueError, match="Refusing to stage into"):
        _stage(case, _prefetch(tmp_path), "HOST1", monkeypatch)
    assert _files(elsewhere) == ["Prefetch-HOST1/keep.txt"]
