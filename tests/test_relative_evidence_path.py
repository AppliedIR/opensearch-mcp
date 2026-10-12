"""A relative evidence path is read in the case folder, and a folder ingest
never reads a link the gate skipped.

case-mcp registers `evidence/sec.json` as `<case>/evidence/sec.json`. The
five path tools join a relative path to the active case's folder the same way
(not normalised, no realpath), before anything uses it: never the server's
cwd, which holds a decoy here. An absolute path is unchanged. A folder
ingest's listing skips links, as the gate's walk and the registry's do.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from _helpers import make_windows_tree

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status, mappings, paths, shard_capacity
from opensearch_mcp import server as srv

NO_CASE = "No active case. Run 'vhir case activate' first."
FILES = {  # tool -> the relative path it is given
    "idx_ingest": "evidence/host-a",
    "idx_ingest_json": "evidence/sec.json",
    "idx_ingest_delimited": "evidence/sec.csv",
    "idx_ingest_accesslog": "evidence/access.log",
    "idx_ingest_memory": "evidence/mem.raw",
}


def _evidence(root: Path) -> None:
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "sec.json").write_text('{"ts": "2026-10-01T00:00:00Z", "msg": "registered"}\n')
    (ev / "sec.csv").write_text("when,what\n2026-10-01T00:00:00Z,registered\n")
    (ev / "access.log").write_text(
        '192.0.2.1 - - [01/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n'
    )
    (ev / "mem.raw").write_bytes(b"\0" * 16)
    make_windows_tree(ev / "host-a")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Two cases; the server's cwd is elsewhere and holds decoys of the same
    names. `activate(name or None)`."""
    vhir = tmp_path / "vhir"
    vhir.mkdir()
    cases = {}
    for name in ("INC-RP1", "INC-RP2"):
        c = tmp_path / "cases" / name
        c.mkdir(parents=True)
        (c / "CASE.yaml").write_text(f"case_id: {name}\n")
        _evidence(c)
        cases[name] = c
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.setattr(paths, "vhir_dir", lambda: vhir)

    def activate(name):
        f = vhir / "active_case"
        if name:
            f.write_text(str(cases[name]))
        elif f.exists():
            f.unlink()

    activate("INC-RP1")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    launched: list[list[str]] = []
    monkeypatch.setattr(srv, "get_client", lambda: mock.MagicMock())
    monkeypatch.setattr(
        srv,
        "_spawn_ingest",
        lambda cmd, *a, **k: launched.append(list(cmd)) or mock.MagicMock(pid=4242),
    )
    monkeypatch.setattr(shard_capacity, "check_shard_headroom", lambda *a, **k: (True, ""))
    monkeypatch.setattr(mappings, "ensure_winlog_pipeline", lambda c, audit=None: {"status": "ok"})
    monkeypatch.setattr(ingest_status, "write_status", lambda *a, **k: None)
    monkeypatch.setattr(ingest_status, "read_active_ingests", lambda *a, **k: [])
    return SimpleNamespace(cases=cases, cwd=cwd, activate=activate, launched=launched)


def _tool(name, path, dry_run):
    return getattr(srv, name)(path=path, hostname="h1", dry_run=dry_run)


# --- the join -------------------------------------------------------------------


def test_a_relative_path_joins_the_case_folder_as_case_mcp_does(env):
    c = env.cases["INC-RP1"]
    join = getattr(srv, "_case_path", lambda p: (p, None))
    assert join("evidence/x") == (str(c / "evidence/x"), None)
    assert join("evidence/./x") == (str(Path(c) / "evidence/./x"), None)
    assert join("evidence/lnk/../y") == (str(c) + "/evidence/lnk/../y", None)  # not normalised


@pytest.mark.parametrize("path", ["/evidence/x", "/a/b/../c", "/tmp/link/../x"])
def test_an_absolute_path_is_unchanged(env, path):
    join = getattr(srv, "_case_path", lambda p: (p, None))
    assert join(path) == (path, None)
    env.activate(None)
    assert join(path) == (path, None)


def test_with_no_case_a_relative_path_is_refused(env):
    env.activate(None)
    join = getattr(srv, "_case_path", lambda p: (p, None))
    assert join("evidence/x") == ("evidence/x", NO_CASE)


# --- every path tool, through the server ----------------------------------------


@pytest.mark.parametrize("tool", list(FILES))
def test_each_tool_launches_on_the_case_file_not_the_cwd_decoy(env, tool):
    _evidence(env.cwd)  # decoys at the server's cwd
    resp = _tool(tool, FILES[tool], dry_run=False)
    want = str(env.cases["INC-RP1"] / FILES[tool])
    assert env.launched and want in env.launched[-1], (resp, env.launched)
    assert not any(a.startswith(str(env.cwd)) for a in env.launched[-1])


@pytest.mark.parametrize("tool", list(FILES))
def test_a_relative_dry_run_previews_what_the_absolute_one_does(env, tool):
    """Run before any decoy exists: the heads fail these with Errno 2."""
    absolute = _tool(tool, str(env.cases["INC-RP1"] / FILES[tool]), dry_run=True)
    assert "error" not in absolute, absolute
    assert _tool(tool, FILES[tool], dry_run=True) == absolute


def test_after_a_case_switch_the_path_joins_the_new_case(env):
    _tool("idx_ingest_json", "evidence/sec.json", dry_run=False)
    env.activate("INC-RP2")
    _tool("idx_ingest_json", "evidence/sec.json", dry_run=False)
    first, second = env.launched[-2:]
    assert str(env.cases["INC-RP1"] / "evidence/sec.json") in first
    assert str(env.cases["INC-RP2"] / "evidence/sec.json") in second


@pytest.mark.parametrize("tool", ["idx_ingest_json", "idx_ingest_memory"])
def test_with_no_case_a_relative_dry_run_is_refused_not_read_at_the_cwd(env, tool):
    _evidence(env.cwd)
    env.activate(None)
    assert _tool(tool, FILES[tool], dry_run=True) == {"error": NO_CASE}
    assert env.launched == []


# --- a folder ingest reads no link the gate skipped -----------------------------


class _Stop(Exception):
    pass


@pytest.fixture
def worker(tmp_path, monkeypatch):
    """The worker up to its names scan: the files it would read, recorded."""
    seen: dict[str, list] = {}

    def open_unit(case_id, path, hostname, source, origin="argument", files=None):
        seen.setdefault("files", []).extend(Path(f).name for f in files or [])
        raise _Stop

    def gate_walk(case_id, leaves, run_id=""):
        seen["leaves"] = [(Path(p).name, sorted(Path(f).name for f in fs)) for p, _, fs in leaves]
        raise _Stop

    monkeypatch.setattr(cli, "_open_unit", open_unit)
    monkeypatch.setattr(cli, "_gate_walk", gate_walk)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "INC-RP1")
    monkeypatch.setattr(cli, "get_client", lambda: mock.MagicMock())
    for n in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter", "_run_writer"):
        monkeypatch.setattr(cli, n, mock.MagicMock(), raising=False)
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.delenv("VHIR_INGEST_RUN_ID", raising=False)
    outside = tmp_path / "other-case"
    outside.mkdir()
    folder = tmp_path / "evidence" / "f"
    folder.mkdir(parents=True)

    def run(command, args):
        with pytest.raises(_Stop):
            command(args)
        return seen

    return SimpleNamespace(folder=folder, outside=outside, run=run)


def _plant(w, name, body):
    """`a.<ext>` in the folder, and a link to a file outside it."""
    (w.folder / f"a{Path(name).suffix}").write_text(body)
    (w.outside / name).write_text(body)
    os.symlink(w.outside / name, w.folder / f"linked{Path(name).suffix}")


def test_a_json_folder_reads_no_linked_file(worker):
    _plant(worker, "secret.json", '{"Computer": "HIDDEN-J"}\n')
    args = argparse.Namespace(path=str(worker.folder), case=None, hostname="h1")
    assert worker.run(cli.cmd_ingest_json, args)["files"] == ["a.json"]


def test_a_delimited_folder_reads_no_linked_file(worker):
    _plant(worker, "secret.csv", "when,Computer\n2026-10-01T00:00:00Z,HIDDEN-D\n")
    args = argparse.Namespace(path=str(worker.folder), case=None, hostname="h1", time_field="when")
    assert worker.run(cli.cmd_ingest_delimited, args)["files"] == ["a.csv"]


def test_an_accesslog_folder_reads_no_linked_file(worker):
    _plant(worker, "access.log", '192.0.2.9 - - [01/Oct/2026:00:00:00 +0000] "GET /" 200 1\n')
    args = argparse.Namespace(
        path=str(worker.folder), hostname="web01", case=None, time_from=None, time_to=None,
        index_suffix=None, batch_size=1000,
    )  # fmt: skip
    assert worker.run(cli.cmd_ingest_accesslog, args)["files"] == ["a.log"]


def test_an_auto_hosts_folder_reads_no_linked_file(worker):
    (worker.folder / "a-h1.csv").write_text("when,x\n2026-10-01T00:00:00Z,1\n")
    (worker.outside / "secret-h1.csv").write_text("when,x\n2026-10-01T00:00:00Z,2\n")
    os.symlink(worker.outside / "secret-h1.csv", worker.folder / "linked-h1.csv")
    args = argparse.Namespace(path=str(worker.folder), case=None, hostname="", time_field="when",
                              auto_hosts="h1")  # fmt: skip
    assert worker.run(cli.cmd_ingest_delimited, args)["leaves"] == [("f", ["a-h1.csv"])]


def test_a_recursive_walk_skips_a_linked_host_folder_and_linked_files(worker):
    host = worker.folder / "host1"
    host.mkdir()
    (host / "a.csv").write_text("when,x\n2026-10-01T00:00:00Z,1\n")
    (worker.outside / "b.csv").write_text("when,x\n2026-10-01T00:00:00Z,2\n")
    os.symlink(worker.outside / "b.csv", host / "linked.csv")
    os.symlink(worker.outside, worker.folder / "host2")  # a linked host folder
    args = argparse.Namespace(path=str(worker.folder), case=None, hostname="", time_field="when",
                              recursive=True)  # fmt: skip
    assert worker.run(cli.cmd_ingest_delimited, args)["leaves"] == [("host1", ["a.csv"])]


# --- detection and previews see the files the worker reads ----------------------


@pytest.fixture
def linked_hosts(tmp_path):
    """One regular events-host01.csv, and three linked *-host02.csv."""
    folder = tmp_path / "evidence" / "multi"
    outside = tmp_path / "elsewhere"
    folder.mkdir(parents=True)
    outside.mkdir()
    (folder / "events-host01.csv").write_text("when,x\n2026-10-01T00:00:00Z,1\n")
    for tool in ("a", "b", "c"):
        (outside / f"{tool}-host02.csv").write_text("when,x\n2026-10-01T00:00:00Z,2\n")
        os.symlink(outside / f"{tool}-host02.csv", folder / f"{tool}-host02.csv")
    return folder


def test_auto_host_detection_counts_no_linked_file(env, linked_hosts):
    assert srv._detect_hostnames_from_filenames(linked_hosts) == {"host01"}
    preview = srv.idx_ingest_delimited(path=str(linked_hosts), hostname="auto", dry_run=True)
    assert preview["detected_hostnames"] == ["host01"], preview


def test_previews_list_no_linked_file(env, linked_hosts):
    flat = srv.idx_ingest_delimited(path=str(linked_hosts), hostname="h1", dry_run=True)
    assert flat["files"] == ["events-host01.csv"], flat
    (linked_hosts / "j.json").write_text("{}\n")
    os.symlink(linked_hosts / "a-host02.csv", linked_hosts / "k.json")
    js = srv.idx_ingest_json(path=str(linked_hosts), hostname="h1", dry_run=True)
    assert js["files"] == ["j.json"], js
    walk = linked_hosts.parent / "walk"
    (walk / "host1").mkdir(parents=True)
    (walk / "host1" / "a.csv").write_text("when\n")
    os.symlink(linked_hosts.parent.parent / "elsewhere", walk / "host2")
    rec = srv.idx_ingest_delimited(path=str(walk), hostname="", recursive=True, dry_run=True)
    assert [h["hostname"] for h in rec["hosts"]] == ["host1"], rec


# --- a skipped link is named, never dropped silently ----------------------------


def _with_links(tmp_path, regular=("a.json",), linked=("l1.json", "l2.json")):
    folder = tmp_path / "evidence" / "lj"
    outside = tmp_path / "elsewhere-j"
    folder.mkdir(parents=True)
    outside.mkdir()
    for n in regular:
        (folder / n).write_text("{}\n")
    for n in linked:
        (outside / n).write_text('{"Computer": "HIDDEN"}\n')
        os.symlink(outside / n, folder / n)
    return folder


@pytest.mark.parametrize("regular", [("a.json",), ()], ids=["mixed", "links only"])
def test_a_json_preview_names_the_links_it_skips(env, tmp_path, regular):
    folder = _with_links(tmp_path, regular)
    preview = srv.idx_ingest_json(path=str(folder), hostname="h1", dry_run=True)
    assert preview["files"] == list(regular), preview
    assert preview.get("skipped_links") == ["l1.json", "l2.json"], preview


def test_a_delimited_and_an_accesslog_preview_name_the_links_they_skip(env, linked_hosts):
    flat = srv.idx_ingest_delimited(path=str(linked_hosts), hostname="h1", dry_run=True)
    assert flat.get("skipped_links") == ["a-host02.csv", "b-host02.csv", "c-host02.csv"], flat
    os.symlink(linked_hosts / "a-host02.csv", linked_hosts / "access.log")
    log = srv.idx_ingest_accesslog(path=str(linked_hosts), hostname="w", dry_run=True)
    assert log.get("skipped_links") == ["access.log"], log


@pytest.mark.parametrize("regular", [("a.json",), ()], ids=["mixed", "links only"])
def test_the_worker_names_the_links_it_skips_in_its_output_and_status(
    worker, tmp_path, monkeypatch, capsys, regular
):
    folder = _with_links(tmp_path, regular)
    written = []
    monkeypatch.setattr(cli, "write_status", lambda *a, **k: written.append(k or a))
    monkeypatch.setattr(cli, "_linked_skipped", [], raising=False)
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-l")
    args = argparse.Namespace(path=str(folder), case=None, hostname="h1")
    assert worker.run(cli.cmd_ingest_json, args)["files"] == list(regular)
    out = capsys.readouterr()
    said = out.out + out.err
    assert "Skipped 2 linked file(s)" in said and "l1.json, l2.json" in said, said
    if not regular:  # the two files are links, and the diagnostic says so
        assert "2 linked file(s) skipped" in said, said
    (status,) = [w for w in written if isinstance(w, dict)]
    note = status["hosts"][0]["artifacts"][0].get("note", "")
    assert "2 linked file(s) or folder(s) skipped" in note and "l1.json" in note, note


# --- every level of every walk names the links it skips -------------------------


@pytest.fixture
def two_levels(tmp_path):
    """host1: a.csv and a linked l.csv; host2: only linked CSVs; host3: a
    linked folder."""
    root = tmp_path / "evidence" / "hosts"
    outside = tmp_path / "elsewhere-h"
    outside.mkdir()
    (outside / "x.csv").write_text("when,Computer\n2026-10-01T00:00:00Z,HIDDEN\n")
    (root / "host1").mkdir(parents=True)
    (root / "host1" / "a.csv").write_text("when,x\n2026-10-01T00:00:00Z,1\n")
    os.symlink(outside / "x.csv", root / "host1" / "l.csv")
    (root / "host2").mkdir()
    os.symlink(outside / "x.csv", root / "host2" / "m.csv")
    os.symlink(outside / "x.csv", root / "host2" / "n.csv")
    os.symlink(outside, root / "host3")
    return root


WANT_SKIPPED = ["host1/l.csv", "host2/m.csv", "host2/n.csv", "host3"]


def test_a_recursive_preview_names_every_link_it_skips(env, two_levels):
    rec = srv.idx_ingest_delimited(path=str(two_levels), hostname="", recursive=True, dry_run=True)
    assert [h["hostname"] for h in rec["hosts"]] == ["host1"], rec
    assert rec.get("skipped_links") == WANT_SKIPPED, rec


def test_a_recursive_walk_names_every_link_it_skips(worker, two_levels, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_linked_skipped", [], raising=False)
    args = argparse.Namespace(path=str(two_levels), case=None, hostname="", time_field="when",
                              recursive=True)  # fmt: skip
    assert worker.run(cli.cmd_ingest_delimited, args)["leaves"] == [("host1", ["a.csv"])]
    names = sorted(str(Path(p).relative_to(two_levels)) for p in cli._linked_skipped)
    assert names == WANT_SKIPPED, names
    said = capsys.readouterr().out
    assert "m.csv, n.csv" in said and "host3" in said, said


def test_an_unrelated_link_doesnt_hide_the_no_json_diagnostic(worker, tmp_path, capsys):
    folder = tmp_path / "evidence" / "nojson"
    folder.mkdir(parents=True)
    (tmp_path / "readme.txt").write_text("x")
    os.symlink(tmp_path / "readme.txt", folder / "readme.txt")
    (folder / "notes.txt").write_text("x")
    args = argparse.Namespace(path=str(folder), case=None, hostname="h1")
    worker.run(cli.cmd_ingest_json, args)
    err = capsys.readouterr().err
    assert "No .json/.jsonl/.ndjson files directly under" in err, err


def test_a_links_only_json_folder_says_the_files_are_skipped_links(worker, tmp_path, capsys):
    folder = _with_links(tmp_path, ())
    worker.run(cli.cmd_ingest_json, argparse.Namespace(path=str(folder), case=None, hostname="h1"))
    err = capsys.readouterr().err
    assert "2 linked file(s) skipped" in err, err


def test_auto_host_detection_names_the_links_it_skips(env, linked_hosts):
    preview = srv.idx_ingest_delimited(path=str(linked_hosts), hostname="auto", dry_run=True)
    assert preview["detected_hostnames"] == ["host01"], preview
    assert preview.get("skipped_links") == ["a-host02.csv", "b-host02.csv", "c-host02.csv"]
