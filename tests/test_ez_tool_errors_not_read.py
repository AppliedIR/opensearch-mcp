"""An input an EZ tool reported it could not read is named in the ingest status.

SBECmd, RECmd, AmcacheParser, AppCompatCacheParser and MFTECmd exit 0 when a
hive or file cannot be opened or parsed, and say so only in their console
output. The artifact used to read `done` with the loss nowhere in the status.
Everything here is synthetic: the tool run is a stub that prints console output
in each tool's own format.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

NULL = "Error message: Value cannot be null. (Parameter 'input')"
ABORT = (
    "Registry hive is dirty and no transaction logs were found in the same directory! "
    "LOGs should have same base name as the hive. Aborting!!"
)


def _sbecmd(profile: Path, aborted: list[str], exported: list[str], empty=()) -> str:
    out = [f"Directory to process: {profile}", "Deduplication: False"]
    for rel in aborted:
        p = f"{profile}/{rel}"
        out += [
            f"Processing {p}",
            ABORT,
            f"'{p}' is in use. Rerouting...",
            f"\tThere was an error processing {p}. {NULL}",
            "",
        ]
    for rel in exported:
        p = f"{profile}/{rel}"
        out += [
            f"Processing {p}",
            "Total ShellBags found: 5",
            f"Finished processing {p}",
            "-" * 20,
        ]
    for rel in empty:
        p = f"{profile}/{rel}"
        out += [
            f"Processing {p}",
            "\t'Software\\Microsoft\\Windows\\Shell\\BagMRU' not found in 'x'",
            "-" * 20,
        ]
    n = len(aborted) + len(exported) + len(empty)
    found = 5 * len(exported)
    return "\n".join(
        out
        + [
            "Processing complete!",
            f"Processed {n} files in 0.01 seconds!",
            f"Total ShellBags found: {found}\r",
            "",
        ]
    )


def _recmd(config: Path, ok: list[str], bad: dict[str, str]) -> str:
    out = [f"Total hives found: {len(ok) + len(bad)}"]
    for h in ok:
        out += [
            f"Processing hive {config}/{h}",
            "Two transaction logs found. Determining primary log...",
            f"Replaying log file: {config}/{h}.LOG2",
            "Found key Select and value Current!",
            "",
        ]
    for h, msg in bad.items():
        out += [f"Processing hive {config}/{h}", msg, "System.Exception: x", ""]
    out += ["Found 8 key/value pairs across 4 files", "Saving batch mode CSV file to /tmp/x.csv"]
    return "\n".join(out)


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _ingest(artifacts, console, rows, include):
    """artifacts: [(name, path)]; console(cmd) -> stdout; rows(cmd) -> CSV rows written."""

    def run_tool(cmd, label):
        n = rows(cmd)
        if n:
            out = Path(cmd[cmd.index("--csv") + 1])
            (out / "20260101000000_Output.csv").write_text("SourceFile\n" + "x\n" * n)
        return console(cmd), ""

    def ingest_csv(csv_path, **kw):
        return len(csv_path.read_text().splitlines()) - 1, 0, 0

    host = DiscoveredHost(hostname="HOST1", volume_root=Path("/evidence/HOST1/C"))
    host.artifacts = list(artifacts)
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
        patch("opensearch_mcp.tools._run_tool", side_effect=run_tool),
        patch("opensearch_mcp.tools.ingest_csv", side_effect=ingest_csv),
    ):
        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            include=include,
            status_pid=os.getpid(),
            status_run_id="run-err",
        )


def _status():
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status


def _row(status, artifact):
    (row,) = [c for c in status["checklist"] if c["artifact"] == artifact]
    return row


C = Path("/evidence/HOST1/C")
PROFILE = C / "Users/alice"
CONFIG = C / "Windows/System32/config"


def test_a_hive_shellbags_aborted_on_is_named_and_the_exported_rows_are_kept(status_dir):
    def console(cmd):
        return _sbecmd(PROFILE, ["NTUSER.DAT"], ["AppData/Local/Microsoft/Windows/UsrClass.dat"])

    _ingest([("shellbags", PROFILE)], console, lambda cmd: 5, {"shellbags"})
    status = _status()
    (w,) = status["warnings"]
    assert w.startswith(
        "HOST1: shellbags: 1 file(s) or folder(s) were not ingested, or only in part "
        f"({PROFILE}/NTUSER.DAT ("
    )
    assert "UsrClass.dat" not in w
    assert _row(status, "shellbags")["detail"].startswith("5 new")


def test_a_profile_whose_only_hives_were_aborted_on_is_named(status_dir):
    usr = "AppData/Local/Microsoft/Windows/UsrClass.dat"
    _ingest(
        [("shellbags", PROFILE)],
        lambda cmd: _sbecmd(PROFILE, [usr, "NTUSER.DAT"], []),
        lambda cmd: 0,
        {"shellbags"},
    )
    (w,) = _status()["warnings"]
    assert "HOST1: shellbags: 2 file(s)" in w
    assert f"{PROFILE}/{usr} (" in w and f"{PROFILE}/NTUSER.DAT (" in w


def test_an_amcache_hive_the_tool_could_not_parse_is_named(status_dir):
    hive = C / "Windows/AppCompat/Programs/Amcache.hve"
    msg = "There was an error: Not a valid Win32 FileTime. (Parameter 'fileTime')"
    _ingest(
        [("amcache", hive)],
        lambda cmd: f"Command line: -f {hive}\n{msg}\nSystem.Exception: x",
        lambda cmd: 0,
        {"amcache"},
    )
    status = _status()
    assert status["warnings"] == [
        "HOST1: amcache: 1 file(s) or folder(s) were not ingested, or only in part "
        f"({hive} ({msg}))"
    ]
    assert _row(status, "amcache")["detail"].startswith("0 new")


def test_a_system_hive_shimcache_could_not_read_is_named_without_quotes(status_dir):
    hive = CONFIG / "SYSTEM"
    msg = f"There was an error: Access to the path '{hive}' is denied."
    _ingest(
        [("shimcache", hive)],
        lambda cmd: f"Processing hive '{hive}'\n{msg}",
        lambda cmd: 0,
        {"shimcache"},
    )
    (w,) = _status()["warnings"]
    assert w.endswith(f"({hive} ({msg}))")


def test_each_hive_registry_could_not_read_is_named_by_its_own_path(status_dir):
    bad = {
        "SOFTWARE": "There was an error: Not a valid Win32 FileTime. (Parameter 'fileTime')",
        "SAM": "Data in byte array is not a Registry hive (bad signature)",
    }
    _ingest(
        [("registry_system", CONFIG / "SYSTEM")],
        lambda cmd: _recmd(CONFIG, ["SYSTEM", "SECURITY"], bad),
        lambda cmd: 8,
        {"registry"},
    )
    status = _status()
    (w,) = status["warnings"]
    assert "HOST1: registry: 2 file(s)" in w
    assert f"{CONFIG}/SOFTWARE ({bad['SOFTWARE']})" in w and f"{CONFIG}/SAM ({bad['SAM']})" in w
    assert f"{CONFIG}/SYSTEM (" not in w
    assert _row(status, "registry")["detail"].startswith("8 new")


def test_an_mft_the_tool_did_not_recognise_is_named(status_dir):
    mft = C / "$MFT"
    msg = f"Unknown file type! Send {mft} to the author for assistance. Exiting"
    _ingest([("mft", mft)], lambda cmd: f"File type: Unknown\n{msg}", lambda cmd: 0, {"mft"})
    (w,) = _status()["warnings"]
    assert w.endswith(f"({mft} ({msg}))")


@pytest.mark.parametrize(
    "artifact, path, console, rows",
    [
        (
            "shellbags",
            PROFILE,  # a healthy profile with no shellbags writes no CSV
            lambda: _sbecmd(
                PROFILE, [], [], ["AppData/Local/Microsoft/Windows/UsrClass.dat", "NTUSER.DAT"]
            ),
            0,
        ),
        (
            "shellbags",
            PROFILE,
            lambda: f"Directory to process: {PROFILE}\nNothing found to process",
            0,
        ),
        (
            "registry_system",
            CONFIG / "SYSTEM",
            lambda: _recmd(CONFIG, ["SYSTEM", "SOFTWARE", "SAM"], {}),
            8,
        ),
        (
            "shimcache",
            CONFIG / "SYSTEM",
            lambda: (
                f"Processing hive '{CONFIG}/SYSTEM'\n"
                "Registry hive is dirty and no transaction logs were found in the same directory. "
                "Data may be missing! Continuing anyways...\n"
                "Sequence numbers do not match! Hive is dirty and the transaction logs "
                "should be reviewed for relevant data!\n"
                "Found 847 cache entries for Windows10C_11 in ControlSet001"
            ),
            4,
        ),
    ],
    ids=[
        "shellbags-none-found",
        "shellbags-nothing-to-process",
        "registry-healthy",
        "shimcache-dirty-continued",
    ],
)
def test_healthy_tool_output_does_not_warn(status_dir, artifact, path, console, rows):
    tool = {"registry_system": "registry"}.get(artifact, artifact)
    _ingest([(artifact, path)], lambda cmd: console(), lambda cmd: rows, {tool})
    assert _status().get("warnings", []) == []


def test_jump_list_error_lines_already_covered_elsewhere_do_not_warn(tmp_path, status_dir):
    # JLECmd prints this for an empty custom jump list on a healthy profile.
    recent = tmp_path / "Users/alice/AppData/Roaming/Microsoft/Windows/Recent"
    recent.mkdir(parents=True)
    console = (
        f"Error processing {recent}/CustomDestinations/0123456789abcdef.customDestinations-ms."
        " Message: Empty custom destinations jump list\n"
        f"Error opening {recent}/AutomaticDestinations/x.automaticDestinations-ms. Message: x\n"
        "Processed 7 out of 7 files in 0.1 seconds"
    )
    _ingest([("jumplists", recent)], lambda cmd: console, lambda cmd: 25, {"jumplists"})
    assert _status().get("warnings", []) == []


def test_the_dirty_hive_cause_is_the_reason_and_does_not_carry_to_the_next_hive(status_dir):
    usr = f"{PROFILE}/AppData/Local/Microsoft/Windows/UsrClass.dat"
    console = "\n".join(
        [
            f"Processing {PROFILE}/NTUSER.DAT",
            ABORT,
            f"\tThere was an error processing {PROFILE}/NTUSER.DAT. {NULL}",
            f"Processing {usr}",
            f"\tThere was an error processing {usr}. {NULL}",
            "Total ShellBags found: 0",
        ]
    )
    _ingest([("shellbags", PROFILE)], lambda cmd: console, lambda cmd: 0, {"shellbags"})
    (w,) = _status()["warnings"]
    assert f"{PROFILE}/NTUSER.DAT ({ABORT})" in w
    assert f"{usr} (There was an error processing {usr}. {NULL})" in w
