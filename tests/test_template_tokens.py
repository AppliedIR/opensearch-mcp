"""An index name never depends on a template file's health: the type tokens
come from the pattern table, so a missing, unreadable or unparseable template
file neither crashes an ingest nor changes the name its index gets."""

from __future__ import annotations

import contextlib
import io
import shutil
import sys

import pytest
from opensearchpy import helpers

from opensearch_mcp import ingest_cli
from opensearch_mcp import mappings as mp
from opensearch_mcp.paths import stem_type

# every shipped template pattern's type, by name (not read from the code)
TOKENS = frozenset({
    "accesslog", "amcache", "bodyfile", "defender", "delim", "evtx", "firewall", "hayabusa",
    "httperr", "iis", "json", "jumplists", "lnk", "mft", "plaso", "prefetch", "recyclebin",
    "registry", "shellbags", "shimcache", "srum", "ssh", "tasks", "timeline", "transcripts",
    "usn", "vol", "wer", "zeek",
})  # fmt: skip
FILES = ["evtx_ecs_template.json"] + [f for _, f in mp._TEMPLATES_REGISTRY]


@pytest.fixture
def broken(monkeypatch, tmp_path):
    """A copy of the shipped template files, read in place of the package's
    (the evtx file too), with one file broken the row's way."""
    d = tmp_path / "mappings"
    shutil.copytree(mp._MAPPINGS_DIR, d, ignore=shutil.ignore_patterns("*.py", "__pycache__"))
    monkeypatch.setattr(mp, "_MAPPINGS_DIR", d)
    monkeypatch.setattr(mp, "_EVTX_TEMPLATE_FILE", d / "evtx_ecs_template.json")
    monkeypatch.setattr(mp, "_PIPELINE_FILE", d / "winlog_data_normalize_v1.json")

    def make(name, how):
        f = d / name
        if how == "garbled":
            f.write_text("not json {")
        elif how == "missing":
            f.unlink()
        elif how == "unreadable":
            f.chmod(0)
        elif how == "list":
            f.write_text("[]")
        return d

    return make


def test_the_tokens_are_every_shipped_patterns_type():
    assert mp.template_type_tokens() == TOKENS


def test_a_new_table_pattern_is_a_token(monkeypatch):
    """The tokens follow the table: a template added to it names its type."""
    table = dict(mp._TEMPLATE_PATTERNS, **{"vhir-newtype": (30, ("case-*-newtype-*",))})
    monkeypatch.setattr(mp, "_TEMPLATE_PATTERNS", table)
    assert mp.template_type_tokens() == TOKENS | {"newtype"}
    assert stem_type("json", "newtype") == "json-newtype_"


def test_no_template_file_is_read(monkeypatch):
    """Every read raises: the tokens are unchanged, wherever a reader looks."""

    def refuse(*a, **kw):
        raise OSError("read refused")

    monkeypatch.setattr(mp, "_load_json", refuse)
    monkeypatch.setattr(mp.Path, "read_text", refuse)
    monkeypatch.setattr(mp.Path, "read_bytes", refuse)
    assert mp.template_type_tokens() == TOKENS
    assert stem_type("json", "evtx") == "json-evtx_"


def test_the_pattern_table_is_what_every_file_says_evtx_included():
    """What the names are decided from is what each shipped file says."""
    evtx = mp._load_json(mp._EVTX_TEMPLATE_FILE)
    assert evtx["index_patterns"] == [mp._TEMPLATE_PATTERN]
    assert evtx["priority"] == mp._TEMPLATE_PRIORITY


@pytest.mark.parametrize("how", ["garbled", "missing", "unreadable", "list"])
@pytest.mark.parametrize("name", FILES)
def test_a_broken_template_file_changes_no_index_name(broken, name, how):
    broken(name, how)
    assert mp.template_type_tokens() == TOKENS
    assert stem_type("json", "evtx") == "json-evtx_"
    assert stem_type("delim", "prefetch") == "delim-prefetch_"
    assert stem_type("accesslog", "plaso") == "accesslog-plaso_"
    assert stem_type("json", "events") == "json-events"
    assert ingest_cli.accesslog_suffix("evtx") == "accesslog-evtx_"


@pytest.mark.template_install
@pytest.mark.parametrize(
    "name,stem,index_type,said",
    [
        ("ssh_template.json", "events", "json-events", None),
        ("evtx_ecs_template.json", "evtx", "json-evtx_", None),
        ("json_template.json", "events", "json-events",
         "index template vhir-json is not installed (json_template.json couldn't be loaded: "),
    ],
    ids=["other", "evtx-name", "own"],
)  # fmt: skip
def test_the_json_command_with_a_broken_template_file(
    broken, monkeypatch, tmp_path, capsys, name, stem, index_type, said
):
    """The deployed command: another type's broken file costs nothing, a name
    stays the healthy run's, and the type's own broken file refuses its file."""
    from test_cli_templates import Client

    from opensearch_mcp import write_context as wc

    broken(name, "garbled")
    client = Client()
    bulked: list[str] = []

    def fake_bulk(c, actions, **kw):
        actions = list(actions)
        bulked.extend(sorted({a["_index"] for a in actions}))
        return len(actions), []

    monkeypatch.setattr(helpers, "bulk", fake_bulk)
    monkeypatch.setattr(wc, "_prepared", set())
    monkeypatch.setattr(ingest_cli, "get_client", lambda *a, **kw: client)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "test-case")
    monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda c: None)
    monkeypatch.setattr(ingest_cli, "_preflight_shard_capacity", lambda *a, **kw: None)
    f = tmp_path / f"{stem}.jsonl"
    f.write_text('{"@timestamp": "2026-10-01T10:00:00Z", "action": "a1"}\n')
    monkeypatch.setattr(sys, "argv", ["opensearch-ingest", "json", str(f), "--hostname", "h1"])
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        if said is None:
            ingest_cli.main()
        else:  # its only file refused: no file read, so the run fails and exits 1
            with pytest.raises(SystemExit) as e:
                ingest_cli.main()
            assert e.value.code == 1
            assert err.getvalue().count("Error: no_file_read: none of 1 file(s) was read") == 1
    out = capsys.readouterr().out
    index = wc.index_name(index_type)
    assert f"{f.name} -> {index}..." in out
    if said is None:
        assert bulked == [index]
        assert "Done. 1 indexed" in out
    else:
        assert bulked == []
        assert said in out and "*** 1 files failed to parse" in out
    assert "template_type_tokens" not in err.getvalue()
