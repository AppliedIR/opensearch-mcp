"""Each user's NTUSER.DAT and UsrClass.dat are parsed by RECmd.

RECmd ran only over Windows/System32/config, so no user hive was read. Now
each profile's two hives are parsed one at a time (`-f`, the same batch file)
into the registry index. Every row records its hive as `vhir.hive`, inside
the document id: HivePath is left out of the id (it carries the temporary
path), so the same row in two users' hives used to become one document.
RECmd is replaced by a stub that writes the CSV it would; rows are synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opensearch_mcp import parse_csv, tools
from opensearch_mcp.discover import DiscoveredHost, discover_artifacts
from opensearch_mcp.parse_csv import _VOLATILE_KEYS, _doc_id

HEADER = (
    "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,"
    "ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile\n"
)
ROW = (
    '{hive},NtUser,Native messaging host,Browser,"ROOT\\Software\\Microsoft\\Edge\\'
    'NativeMessagingHosts\\com.example.host",(default),RegSz,'
    "C:\\Program Files\\Example\\host.json,,,,False,False,2026-01-02 03:04:05.0000000,\n"
)


def _profile(users: Path, name: str, hives: bool = True) -> None:
    p = users / name
    (p / "AppData/Local/Microsoft/Windows").mkdir(parents=True)
    if hives:
        (p / "NTUSER.DAT").write_bytes(b"regf")
        (p / "AppData/Local/Microsoft/Windows/UsrClass.dat").write_bytes(b"regf")


def test_each_profiles_two_hives_are_found_and_default_is_skipped(tmp_path):
    (tmp_path / "Windows/System32/config").mkdir(parents=True)
    users = tmp_path / "Users"
    for name in ("alice", "bob", "Default", "Public"):
        _profile(users, name)
    host = DiscoveredHost(hostname="w", volume_root=tmp_path)
    discover_artifacts(host)
    hives = sorted(str(p.relative_to(tmp_path)) for a, p in host.artifacts if a == "registry_user")
    assert hives == [
        "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "Users/alice/NTUSER.DAT",
        "Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "Users/bob/NTUSER.DAT",
    ]


def test_a_profile_without_hives_adds_none(tmp_path):
    (tmp_path / "Windows/System32/config").mkdir(parents=True)
    _profile(tmp_path / "Users", "carol", hives=False)
    host = DiscoveredHost(hostname="w", volume_root=tmp_path)
    discover_artifacts(host)
    assert [a for a, _ in host.artifacts if a == "registry_user"] == []


def test_recmd_reads_one_hive_with_the_batch_file(tmp_path):
    hive = tmp_path / "NTUSER.DAT"
    cmd = tools._build_command(tools.TOOLS["registry_user"], "registry_user", hive, "/tmp/out")
    assert cmd[1:] == ["-f", str(hive), "--csv", "/tmp/out", "--nl", "--bn", tools._RECMD_BATCH]


def test_excluding_registry_excludes_the_user_hives_too():
    names = {t.cli_name for t in tools.get_active_tools(exclude={"registry"})}
    assert "registry" not in names and "registry_user" not in names
    assert "registry_user" in {t.cli_name for t in tools.get_active_tools()}


@pytest.fixture
def recmd(monkeypatch):
    """RECmd writes, for each hive, the same row with that run's HivePath;
    the bulk writes are recorded."""
    sent: list[dict] = []

    def run(cmd, label):
        out = Path(cmd[cmd.index("--csv") + 1])
        hive = cmd[cmd.index("-f") + 1] if "-f" in cmd else cmd[cmd.index("-d") + 1]
        (out / "20260102030405_RECmd_Batch_Kroll_Batch_Output.csv").write_text(
            HEADER + ROW.format(hive=f"/tmp/run-{len(sent)}/{Path(hive).name}")
        )
        return "", ""

    def flush(client, actions):
        sent.extend(actions)
        return len(actions), 0

    monkeypatch.setattr(tools, "_run_tool", run)
    monkeypatch.setattr(parse_csv, "flush_bulk", flush)
    return sent


def test_the_same_row_in_two_users_hives_stays_two_documents(recmd, tmp_path):
    for user in ("alice", "bob"):
        tools.run_and_ingest(
            "registry_user",
            tmp_path / user / "NTUSER.DAT",
            client=None,
            case_id="c1",
            hostname="w",
            source_file=f"Users/{user}/NTUSER.DAT",
        )
    assert len({a["_id"] for a in recmd}) == 2
    assert [a["_source"]["vhir.hive"] for a in recmd] == [
        "Users/alice/NTUSER.DAT",
        "Users/bob/NTUSER.DAT",
    ]
    assert {a["_index"] for a in recmd} == {"case-c1-registry-w"}


def test_a_system_hive_rows_id_is_unchanged(recmd, tmp_path):
    tools.run_and_ingest(
        "registry", tmp_path / "config" / "SYSTEM", client=None, case_id="c1", hostname="w"
    )
    (action,) = recmd
    assert "vhir.hive" not in action["_source"]
    row = {k: v for k, v in action["_source"].items() if not k.startswith(("vhir.", "pipeline"))}
    row["vhir.table"] = action["_source"]["vhir.table"]
    assert action["_id"] == _doc_id("case-c1-registry-w", row, None, volatile_keys=_VOLATILE_KEYS)
