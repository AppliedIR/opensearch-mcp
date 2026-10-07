"""Shellbags are read from a dirty NTUSER.DAT whose logs Windows named in lower case.

Windows writes NTUSER.DAT's transaction logs as ntuser.dat.LOG1/2. SBECmd looks
only for "<hive name>.LOG1/2", case-sensitively on Linux, and aborts on a dirty
hive without them. The tool run here is a stub that follows that lookup rule;
the profile is synthetic and on disk.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

ABORT = (
    "Registry hive is dirty and no transaction logs were found in the same directory! "
    "LOGs should have same base name as the hive. Aborting!!"
)
NULL = "Error message: Value cannot be null. (Parameter 'input')"
USRCLASS = "AppData/Local/Microsoft/Windows/UsrClass.dat"


def _hive(dirty: bool, bags: int) -> bytes:
    return b"regf" + struct.pack("<II", 7, 6 if dirty else 7) + b"\0" * 20 + b"BAG" * bags


def _sbecmd(cmd: list[str], calls: list[list[str]]) -> tuple[str, str]:
    """SBECmd's measured behaviour: hives by name at any depth, symlinked files skipped,
    logs only as "<hive name>.LOG1/2" in that exact case; a log holding b"BAD" fails replay."""
    calls.append(cmd)
    root = Path(cmd[cmd.index("-d") + 1])
    out = Path(cmd[cmd.index("--csv") + 1])
    csvf = cmd[cmd.index("--csvf") + 1] if "--csvf" in cmd else None
    lines = [f"Directory to process: {root}"]
    for f in sorted(root.rglob("*")):
        if (
            f.is_symlink()
            or not f.is_file()
            or f.name.lower() not in ("ntuser.dat", "usrclass.dat")
        ):
            continue
        lines.append(f"Processing {f}")
        try:
            data = f.read_bytes()
            logs = [f.parent / (f.name + s) for s in (".LOG1", ".LOG2")]
            found = [p for p in logs if p.exists()]
            if data[4:8] != data[8:12] and not found:
                lines += [ABORT, f"\tThere was an error processing {f}. {NULL}"]
                continue
            if any(b"BAD" in p.read_bytes() for p in found):
                raise OSError("bad log")
        except OSError:
            lines.append(f"\tThere was an error processing {f}. {NULL}")
            continue
        name = f"{f.stem}_{csvf}" if csvf else f"{f.stem}.csv"
        (out / name).write_text("BagPath\n" + "x\n" * data.count(b"BAG"))
        lines.append(f"Finished processing {f}")
    return "\n".join(lines + ["Processing complete!"]), ""


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _profile(tmp_path: Path, hive_name="NTUSER.DAT", logs=("ntuser.dat.LOG1",), dirty=True):
    profile = tmp_path / "evidence/HOST1/C/Users/alice"
    (profile / USRCLASS).parent.mkdir(parents=True)
    (profile / USRCLASS).write_bytes(_hive(False, 5))
    (profile / hive_name).write_bytes(_hive(dirty, 3))
    for name in logs:
        (profile / name).write_bytes(b"HvLE log")
    return profile


def _digest(root: Path) -> dict[str, str]:
    return {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _scan(profile: Path) -> tuple[dict, list[list[str]]]:
    calls: list[list[str]] = []

    def ingest_csv(csv_path, **kw):
        return len(csv_path.read_text().splitlines()) - 1, 0, 0

    host = DiscoveredHost(hostname="HOST1", volume_root=profile.parents[1])
    host.artifacts = [("shellbags", profile)]
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
        patch("opensearch_mcp.tools._run_tool", side_effect=lambda c, label: _sbecmd(c, calls)),
        patch("opensearch_mcp.tools.ingest_csv", side_effect=ingest_csv),
    ):
        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            include={"shellbags"},
            status_pid=os.getpid(),
            status_run_id="run-logcase",
        )
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    return status, calls


def _detail(status) -> str:
    (row,) = [c for c in status["checklist"] if c["artifact"] == "shellbags"]
    return row["detail"]


def test_lower_case_logs_of_a_dirty_ntuser_are_replayed_and_its_rows_indexed(tmp_path, status_dir):
    profile = _profile(tmp_path, logs=("ntuser.dat.LOG1", "ntuser.dat.LOG2"))
    before = _digest(profile)
    status, calls = _scan(profile)
    assert _detail(status).startswith("8 docs submitted")
    assert status.get("warnings", []) == []
    assert _digest(profile) == before
    assert sorted(os.listdir(profile)) == [
        "AppData",
        "NTUSER.DAT",
        "ntuser.dat.LOG1",
        "ntuser.dat.LOG2",
    ]


def test_a_collector_that_lower_cased_every_name_is_also_read(tmp_path, status_dir):
    profile = _profile(tmp_path, hive_name="ntuser.dat", logs=("ntuser.dat.log1",))
    status, _ = _scan(profile)
    assert _detail(status).startswith("8 docs submitted")
    assert status.get("warnings", []) == []


def test_logs_already_in_the_hives_case_change_nothing(tmp_path, status_dir):
    profile = _profile(tmp_path, logs=("NTUSER.DAT.LOG1",))
    status, calls = _scan(profile)
    assert len(calls) == 1
    assert _detail(status).startswith("8 docs submitted")


def test_a_clean_ntuser_is_left_to_the_one_run(tmp_path, status_dir):
    profile = _profile(tmp_path, dirty=False)
    status, calls = _scan(profile)
    assert len(calls) == 1
    assert _detail(status).startswith("8 docs submitted")


def test_a_dirty_ntuser_without_logs_stays_named(tmp_path, status_dir):
    profile = _profile(tmp_path, logs=())
    status, calls = _scan(profile)
    assert len(calls) == 1
    assert _detail(status).startswith("5 docs submitted")
    (w,) = status["warnings"]
    assert f"{profile}/NTUSER.DAT ({ABORT})" in w


def test_a_replay_that_fails_is_named_by_the_evidence_path(tmp_path, status_dir):
    profile = _profile(tmp_path)
    (profile / "ntuser.dat.LOG1").write_bytes(b"BAD log")
    status, _ = _scan(profile)
    assert _detail(status).startswith("5 docs submitted")
    (w,) = status["warnings"]
    assert "1 file(s)" in w and f"({profile}/NTUSER.DAT (" in w
    assert "vhir-shellbags-" not in w


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_unreadable_ntuser_keeps_the_other_hives_rows(tmp_path, status_dir):
    profile = _profile(tmp_path)
    (profile / "NTUSER.DAT").chmod(0)
    try:
        status, calls = _scan(profile)
    finally:
        (profile / "NTUSER.DAT").chmod(0o644)
    assert len(calls) == 1
    assert _detail(status).startswith("5 docs submitted")
    (w,) = status["warnings"]
    assert f"{profile}/NTUSER.DAT (There was an error processing " in w
