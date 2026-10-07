"""A folder or archive scan names the subfolders it skipped.

Discovery left out every subfolder with no Windows, Linux or macOS root and
said nothing: a triage folder holding one Windows host, a Linux log export
and a copy of a home folder reported "1 host(s)" as if that were all. The
skipped names are now printed and kept in the run's status, also when
triage enrichment is skipped. A disk image's volumes are reported their
own way, so a volume's top folders are never listed. Values are synthetic.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from unittest.mock import MagicMock

import pytest
from _helpers import make_windows_tree

from opensearch_mcp import ingest as ing
from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv

NOTE = "home-copy, linuxlogs: no Windows, Linux or macOS root found; nothing in them was parsed"


def _triage_folder(root):
    make_windows_tree(root / "wks10")
    (root / "linuxlogs" / "var" / "log").mkdir(parents=True)
    (root / "linuxlogs" / "var" / "log" / "auth.log").write_text("x\n")
    (root / "home-copy" / "alice").mkdir(parents=True)
    (root / "home-copy" / "alice" / ".bash_history").write_text("ls\n")
    (root / ".cache").mkdir()  # hidden: not a host folder, not reported
    return root


@pytest.fixture
def scan(tmp_path, monkeypatch, capsys):
    """scan(path) -> (stderr, the run's status as idx_ingest_status shows it)."""
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-skipped")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "get_client"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ing, "parse_and_index", MagicMock(return_value=(5, 0, 0)))
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")

    def run(path):
        args = argparse.Namespace(
            path=str(path), case="c1", yes=True, hostname=None, all_logs=False,
            no_hayabusa=True, skip_triage=True,
        )  # fmt: skip
        cli.cmd_scan(args)
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return capsys.readouterr().err, status

    return run


def test_a_folder_scan_names_the_subfolders_it_skipped(scan, tmp_path):
    err, status = scan(_triage_folder(tmp_path / "triage"))
    assert NOTE in err
    assert NOTE in json.dumps(status)  # kept in the status, with triage skipped
    assert ".cache" not in err
    assert "wks10" in json.dumps(status)  # the Windows host is still ingested


def test_an_archive_scan_names_the_subfolders_it_skipped(scan, tmp_path):
    folder = _triage_folder(tmp_path / "triage")
    archive = tmp_path / "triage.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for f in folder.rglob("*"):
            if f.is_file():
                z.write(f, f.relative_to(folder))
            elif not any(f.iterdir()):
                z.writestr(str(f.relative_to(folder)) + "/", "")
    err, status = scan(archive)
    assert NOTE in err and NOTE in json.dumps(status)


def test_a_folder_of_hosts_only_gets_no_note(scan, tmp_path):
    root = tmp_path / "hosts"
    make_windows_tree(root / "wks10")
    make_windows_tree(root / "wks11")
    err, status = scan(root)
    assert "nothing in them was parsed" not in err + json.dumps(status)


def test_a_disk_images_volume_folders_are_not_listed(tmp_path):
    windows, linux = tmp_path / "vol1", tmp_path / "vol2"
    make_windows_tree(windows)
    for top in ("bin", "etc", "home", "var"):
        (linux / top).mkdir(parents=True)
    notes: list = []
    hosts = cli._discover_volumes([windows, linux], None, False, "img", notes)
    assert [h.hostname for h in hosts]
    assert not [n for label, n in notes if "bin" in n or "home" in n]
