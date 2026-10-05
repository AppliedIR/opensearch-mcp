"""EZ tools must receive each evidence path as one argument.

SIFT installs each Zimmerman tool as a /usr/local/bin wrapper that runs
``dotnet /opt/zimmermantools/<Tool>.dll ${*}``. The unquoted ``${*}`` splits
an argument on spaces and expands glob characters, so a path such as
``/cases/Evidence Drive/...`` or ``Users/John Smith`` reaches the tool as
two arguments. The tool then prints "Unrecognized command or argument" on
stderr, exits 0 and writes no CSV, and the artifact reads as zero records.

These tests build that wrapper shape with a stand-in for ``dotnet`` that
parses arguments the way the real tools do, so they run without .NET or
the Zimmerman tools installed.
"""

from __future__ import annotations

import csv
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import tools

# Stand-in for `dotnet <Tool>.dll ...` (and for a native tool binary when
# no .dll is given): same option grammar as the tools, same failure shape.
_FAKE_TOOL = r"""#!{python}
import csv, json, os, sys
args = sys.argv[1:]
if args and args[0].endswith(".dll"):
    dll = args.pop(0)
    if not os.path.isfile(dll):
        print("The application to execute does not exist: " + dll, file=sys.stderr)
        sys.exit(1)
log = os.environ.get("FAKE_EZ_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps(sys.argv) + "\n")
with_value = {{"-d", "-f", "--csv", "--csvf", "--bn", "-m"}}
flags = {{"--all", "--nl"}}
opts = {{}}
i = 0
while i < len(args):
    a = args[i]
    if a in with_value and i + 1 < len(args):
        opts[a] = args[i + 1]
        i += 2
    elif a in flags:
        i += 1
    else:
        print("Unrecognized command or argument '%s'." % a, file=sys.stderr)
        sys.exit(0)
src = opts.get("-d") or opts.get("-f")
if not src or not os.path.exists(src) or "--csv" not in opts:
    print("File '%s' not found. Exiting" % src)
    sys.exit(0)
if os.path.isdir(src):
    files = sorted(os.path.join(src, n) for n in os.listdir(src))
else:
    files = [src]
with open(os.path.join(opts["--csv"], opts.get("--csvf", "out.csv")), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["SourceFile"])
    for f in files:
        w.writerow([f])
"""

_DLL_LAYOUT = {
    "AmcacheParser": "AmcacheParser.dll",
    "AppCompatCacheParser": "AppCompatCacheParser.dll",
    "RECmd": "RECmd/RECmd.dll",
    "SBECmd": "SBECmd.dll",
    "JLECmd": "JLECmd.dll",
    "LECmd": "LECmd.dll",
    "RBCmd": "RBCmd.dll",
    "MFTECmd": "MFTECmd.dll",
    "WxTCmd": "WxTCmd.dll",
}


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _wrapper(dll: Path) -> str:
    """The wrapper text SIFT installs in /usr/local/bin."""
    return "#!/bin/bash\n\ndotnet " + str(dll) + " ${*}\n"


@pytest.fixture
def sift_layout(tmp_path, monkeypatch):
    """SIFT-shaped install: tool .dlls, `dotnet`, and the unquoted wrappers."""
    ez = tmp_path / "zimmermantools"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for rel in _DLL_LAYOUT.values():
        (ez / rel).parent.mkdir(parents=True, exist_ok=True)
        (ez / rel).write_bytes(b"")
    _write_exec(bindir / "dotnet", _FAKE_TOOL.format(python=sys.executable))
    for binary, rel in _DLL_LAYOUT.items():
        _write_exec(bindir / binary, _wrapper(ez / rel))
    monkeypatch.setenv("FAKE_EZ_LOG", str(tmp_path / "argv.jsonl"))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(tools, "_EZ_TOOLS_DIR", ez, raising=False)
    return ez


@pytest.fixture
def ingested(monkeypatch):
    """Replace indexing with a reader that records the tool's CSV rows."""
    seen: list[str] = []

    def fake_ingest_csv(csv_path, **kwargs):
        with open(csv_path, newline="") as fh:
            rows = [r["SourceFile"] for r in csv.DictReader(fh)]
        seen.extend(rows)
        return len(rows), 0, 0

    monkeypatch.setattr(tools, "ingest_csv", fake_ingest_csv)
    return seen


def _artifact(root: Path, tool_name: str, user: str = "John Smith") -> tuple[Path, list[Path]]:
    """Create the artifact a scan would hand to tool_name under root.

    Returns the path passed to the tool and the entries it should report.
    """
    vol = root / "C"
    profile = vol / "Users" / user
    recent = profile / "AppData/Roaming/Microsoft/Windows/Recent"
    single = {
        "amcache": vol / "Windows/AppCompat/Programs/Amcache.hve",
        "shimcache": vol / "Windows/System32/config/SYSTEM",
        "registry": vol / "Windows/System32/config/SYSTEM",
        "mft": vol / "$MFT",
        "usn": vol / "$Extend/$J",
        "timeline": profile / "AppData/Local/ConnectedDevicesPlatform/L.user/ActivitiesCache.db",
    }
    if tool_name in single:
        path = single[tool_name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"data")
        return path, [path]
    if tool_name == "shellbags":
        profile.mkdir(parents=True, exist_ok=True)
        (profile / "NTUSER.DAT").write_bytes(b"regf")
        return profile, [profile / "NTUSER.DAT"]
    if tool_name in ("jumplists", "lnk"):
        recent.mkdir(parents=True, exist_ok=True)
        files = [recent / "Budget Report.lnk", recent / "notes.lnk"]
        for f in files:
            f.write_bytes(b"L")
        return recent, files
    if tool_name == "recyclebin":
        sid = vol / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
        sid.mkdir(parents=True, exist_ok=True)
        (sid / "$IABC123.txt").write_bytes(b"\x02")
        return sid.parent, [sid]
    raise AssertionError(tool_name)


def _run(tool_name: str, path: Path):
    return tools.run_and_ingest(
        tool_name=tool_name,
        artifact_path=path,
        client=MagicMock(),
        case_id="c1",
        hostname="host1",
    )


_EZ_TOOLS = sorted(name for name, cfg in tools.TOOLS.items() if cfg.binary)


@pytest.mark.parametrize("tool_name", _EZ_TOOLS)
def test_every_ez_tool_reads_evidence_under_a_root_with_a_space(
    tool_name, sift_layout, ingested, tmp_path
):
    path, expected = _artifact(tmp_path / "Evidence Drive" / "host1", tool_name)
    cnt, _sk, _bf = _run(tool_name, path)
    assert cnt == len(expected)
    assert sorted(ingested) == sorted(str(p) for p in expected)


@pytest.mark.parametrize("tool_name", ["shellbags", "jumplists", "lnk"])
def test_user_profile_with_a_space_is_read(tool_name, sift_layout, ingested, tmp_path):
    path, expected = _artifact(tmp_path / "evidence" / "host1", tool_name)
    assert "John Smith" in str(path)
    cnt, _sk, _bf = _run(tool_name, path)
    assert cnt == len(expected)


def test_bracketed_profile_name_is_not_glob_expanded(sift_layout, ingested, tmp_path):
    users = tmp_path / "evidence" / "C" / "Users"
    wanted = users / "admin[1]" / "Desktop"
    other = users / "admin1" / "Desktop"
    for d, name in ((wanted, "wanted.lnk"), (other, "other.lnk")):
        d.mkdir(parents=True)
        (d / name).write_bytes(b"L")
    cnt, _sk, _bf = _run("lnk", wanted)
    assert ingested == [str(wanted / "wanted.lnk")]
    assert cnt == 1


# Anchors: a path without spaces, and installs without SIFT's layout.


def test_path_without_spaces_is_read(sift_layout, ingested, tmp_path):
    path, expected = _artifact(tmp_path / "evidence" / "host1", "lnk", user="jsmith")
    cnt, _sk, _bf = _run("lnk", path)
    assert cnt == len(expected)


def test_tool_missing_from_the_sift_layout_runs_by_name(sift_layout, ingested, tmp_path):
    # The tool on PATH belongs to another install; SIFT's directory has no LECmd.dll.
    (sift_layout / "LECmd.dll").unlink()
    elsewhere = tmp_path / "elsewhere" / "LECmd.dll"
    elsewhere.parent.mkdir()
    elsewhere.write_bytes(b"")
    _write_exec(tmp_path / "bin" / "LECmd", _wrapper(elsewhere))
    path, expected = _artifact(tmp_path / "evidence" / "host1", "lnk", user="jsmith")
    cnt, _sk, _bf = _run("lnk", path)
    assert cnt == len(expected)
    argv = json.loads((tmp_path / "argv.jsonl").read_text().splitlines()[-1])
    assert argv[1] == str(elsewhere)


def test_no_dotnet_on_path_runs_the_tool_by_name(tmp_path, monkeypatch, ingested):
    ez = tmp_path / "zimmermantools"
    ez.mkdir()
    (ez / "LECmd.dll").write_bytes(b"")
    native = tmp_path / "native"
    native.mkdir()
    _write_exec(native / "LECmd", _FAKE_TOOL.format(python=sys.executable))
    monkeypatch.setenv("PATH", str(native))
    monkeypatch.setattr(tools, "_EZ_TOOLS_DIR", ez, raising=False)
    path, expected = _artifact(tmp_path / "Evidence Drive" / "host1", "lnk")
    cnt, _sk, _bf = _run("lnk", path)
    assert cnt == len(expected)


def test_the_tool_is_launched_inside_run_tool(sift_layout, monkeypatch, tmp_path):
    # Callers and tests at the _run_tool seam see the tool's own name; the
    # .dll launcher is chosen only when the command is run.
    seen = []
    monkeypatch.setattr(tools, "_run_tool", lambda cmd, label: seen.append(cmd) or ("", ""))
    path, _expected = _artifact(tmp_path / "evidence" / "host1", "lnk", user="jsmith")
    _run("lnk", path)
    assert seen and seen[0][0] == "LECmd"
