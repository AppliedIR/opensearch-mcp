"""Each registry row names the hive it came from, and the audit lists every hive.

RECmd runs once over the whole config folder, but every row was given the
first hive's path (SYSTEM), and the audit entry hashed only SYSTEM: a Run key
from SOFTWARE cited the wrong hive and the wrong hash. Each row now carries
its own hive (from RECmd's HivePath) and the audit lists every hive RECmd
says it processed, with its hash. The tool run is a stub writing RECmd-shaped
output; the hives are synthetic files on disk.
"""

from __future__ import annotations

import csv
import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest
from opensearch_mcp.parse_csv import ingest_csv

CONFIG = "Windows/System32/config"


def _volume(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "evidence" / "HOST1" / "C"
    config = root / CONFIG
    (config / "RegBack").mkdir(parents=True)
    for name in ("SYSTEM", "SOFTWARE", "SAM", "RegBack/SOFTWARE"):
        (config / name).write_bytes(f"regf {name}".encode())
    return root, config


def _recmd(config: Path, outside: Path, missing: Path):
    """RECmd's output: rows with HivePath, and a "Processing hive" line per hive."""

    def run(cmd, label):
        out = Path(cmd[cmd.index("--csv") + 1])
        rows = [
            (config / "SYSTEM", "System", "ControlSet001\\Services\\x"),
            (config / "SOFTWARE", "Software", "Microsoft\\Windows\\Run"),
            (config / "RegBack" / "SOFTWARE", "Software", "Microsoft\\RegBack"),
            ("", "Unknown", "no hive"),
            (outside, "Software", "outside the folder"),
        ]
        with (out / "Kroll_Batch.csv").open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["HivePath", "HiveType", "KeyPath", "ValueName", "ValueData"])
            for hive, kind, key in rows:
                writer.writerow([str(hive), kind, key, "v", "d"])
        lines = [f"Processing hive {p}" for p in (config / "SYSTEM", config / "SOFTWARE", missing)]
        return "\n".join(lines + ["Total hives found: 3"]), ""

    return run


def _scan(tmp_path: Path):
    root, config = _volume(tmp_path)
    outside = tmp_path / "elsewhere" / "SOFTWARE"
    missing = config / "SECURITY"  # listed by RECmd, gone before it can be hashed
    host = DiscoveredHost(hostname="HOST1", volume_root=root)
    host.artifacts = [
        ("registry_system", config / "SYSTEM"),
        ("registry_software", config / "SOFTWARE"),
    ]
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    docs: list[dict] = []

    def capture(client, actions, **kw):
        docs.extend(a["_source"] for a in actions)
        return len(actions), 0

    with (
        patch("opensearch_mcp.tools._run_tool", side_effect=_recmd(config, outside, missing)),
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=capture),
        patch("opensearch_mcp.ingest._write_ingest_manifest"),
    ):
        ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            include={"registry"},
            status_pid=os.getpid(),
            status_run_id="run-regsource",
        )
    (entry,) = [
        c.kwargs for c in audit.log.call_args_list if c.kwargs.get("tool") == "ingest_registry"
    ]
    return config, missing, docs, entry


def test_each_row_names_its_own_hive(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config, _, docs, _ = _scan(tmp_path)
    sources = {d["KeyPath"]: d["vhir.source_file"] for d in docs}
    assert sources == {
        "ControlSet001\\Services\\x": f"{CONFIG}/SYSTEM",
        "Microsoft\\Windows\\Run": f"{CONFIG}/SOFTWARE",
        "Microsoft\\RegBack": f"{CONFIG}/RegBack/SOFTWARE",
        "no hive": CONFIG,  # no usable HivePath: the folder RECmd read
        "outside the folder": CONFIG,
    }


def test_the_audit_lists_every_hive_read_with_its_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config, missing, _, entry = _scan(tmp_path)
    assert entry["input_files"] == [str(config / "SYSTEM"), str(config / "SOFTWARE"), str(missing)]
    expected = [
        hashlib.sha256((config / n).read_bytes()).hexdigest() for n in ("SYSTEM", "SOFTWARE")
    ]
    assert entry["input_sha256s"] == expected + [""]  # unhashable: listed, empty hash
    assert entry["result_summary"] == "5 indexed"  # one run over the folder, not one per hive


def test_anchor_the_csv_registry_path_keeps_the_csv_s_path(tmp_path):
    path = tmp_path / "RegistryASEPs.csv"
    path.write_text("HivePath,KeyPath,ValueName\nC:\\x\\SOFTWARE,Run,v\n")
    docs: list[dict] = []

    def capture(client, actions, **kw):
        docs.extend(a["_source"] for a in actions)
        return len(actions), 0

    with patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=capture):
        ingest_csv(
            path, client=None, index_name="i", hostname="h", source_file="RegistryASEPs.csv"
        )
    assert [d["vhir.source_file"] for d in docs] == ["RegistryASEPs.csv"]
