"""A process's first write installs the index templates before it creates an
index (cli-templates-065), and a non-evtx index whose own template was
refused is not created.

The client records every call in order. It refuses the templates a row
names, and, as OpenSearch does, a composable template composed of a
component that isn't there.
"""

from __future__ import annotations

import contextlib
import io
import sys

import pytest
from opensearchpy import helpers
from opensearchpy.exceptions import RequestError

from opensearch_mcp import bulk, ingest_cli, ops
from opensearch_mcp import mappings as mp
from opensearch_mcp import write_context as wc

pytestmark = pytest.mark.template_install

# C1a: what the install PUTs, by name (not read from the registry)
TEMPLATES = {
    "vhir-csv", "vhir-prefetch", "vhir-plaso", "vhir-srum", "vhir-transcripts", "vhir-w3c",
    "vhir-defender", "vhir-tasks", "vhir-wer", "vhir-ssh", "vhir-vol3", "vhir-json",
    "vhir-delimited", "vhir-accesslog", "vhir-hayabusa", "vhir-evtx-ecs",
}  # fmt: skip
COMPONENT = "vhir-json-type-stability"
PIPELINE = "winlog_data_normalize_v1"
WRITES = ("put", "create", "delete", "_bulk")  # any call whose name starts so


def _refused(kind: str, reason: str) -> RequestError:
    """As the cluster answers: the reason in the body, so str() shows it."""
    return RequestError(400, kind, {"error": {"root_cause": [{"type": kind, "reason": reason}]}})


class _Space:
    def __init__(self, client, space):
        self._client, self._space = client, space

    def __getattr__(self, name):
        def call(*a, **kw):
            key = kw.get("name") or kw.get("id") or kw.get("index")
            self._client.calls.append((f"{self._space}.{name}", key))
            handler = getattr(self._client, f"_{self._space}_{name}", None)
            return handler(**kw) if handler else {}

        return call


class Client:
    """A cluster that records each call as (namespace.method, name or index)."""

    def __init__(self, indices=(), templates=(), refuse=()):
        self.calls: list[tuple[str, object]] = []
        self.existing = set(indices)
        self.templates = set(templates)  # already on the cluster (an older release's)
        self.components: set[str] = set()
        self.refuse = set(refuse)
        self.indices = _Space(self, "indices")
        self.cluster = _Space(self, "cluster")
        self.ingest = _Space(self, "ingest")
        self.cat = _Space(self, "cat")

    def _cluster_put_component_template(self, name, body):
        if name in self.refuse:
            raise _refused("illegal_argument_exception", f"{name} refused")
        self.components.add(name)
        return {"acknowledged": True}

    def _indices_put_index_template(self, name, body):
        missing = [c for c in body.get("composed_of", []) if c not in self.components]
        if missing:
            raise _refused("invalid_index_template_exception",
                           f"index template [{name}] specifies component templates "
                           f"{missing} that do not exist")  # fmt: skip
        if name in self.refuse:
            raise _refused("illegal_argument_exception", f"{name} refused")
        self.templates.add(name)
        return {"acknowledged": True}

    def _indices_exists_index_template(self, name):
        return name in self.templates

    def _indices_exists(self, index):
        return index in self.existing

    def _indices_create(self, index, body=None, **kw):
        self.existing.add(index)
        return {"acknowledged": True}

    def _indices_stats(self, index=None, **kw):
        return {"indices": {}}

    def _cat_indices(self, **kw):
        return [{"index": i} for i in sorted(self.existing)]

    def _ingest_simulate(self, body):
        docs = []
        for d in body["docs"]:
            src = d["_source"]
            ed = (src.get("winlog") or {}).get("event_data") or src.get("winlog.event_data")
            ed["Data_raw"] = str(ed.get("Data"))
            if not isinstance(ed.get("Data"), dict):
                del ed["Data"]
            docs.append({"doc": {"_source": src}})
        return {"docs": docs}

    def named(self, call: str) -> list:
        return [k for c, k in self.calls if c == call]

    def at(self, call: str, key) -> int:
        return self.calls.index((call, key))

    def writes(self) -> list:
        return [(c, k) for c, k in self.calls
                if c.split(".")[-1].startswith(WRITES)]  # fmt: skip


@pytest.fixture
def sent(monkeypatch, tmp_path):
    """A run open in a case of the row's own (its host logs stay there), and
    helpers.bulk recorded on the client as `_bulk`."""

    def fake(client, actions, **kw):
        actions = list(actions)
        for index in sorted({a["_index"] for a in actions}):
            client.calls.append(("_bulk", index))
        return len(actions), []

    monkeypatch.setattr(helpers, "bulk", fake)
    monkeypatch.setattr(wc, "_prepared", set())
    case = tmp_path / "tpl"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: tpl\n")
    wc._imported.add(case)  # nothing from before 0.6.4 to look for
    ctx = wc.open_unit(case, "evidence/wkstn", "wkstn", source="test")
    with wc.writing(ctx), wc.op("tpl-001"):
        yield


def write(client, artifact_type: str) -> str:
    index = wc.index_name(artifact_type)
    bulk.flush_bulk(client, [{"_index": index, "_source": {"message": "one record"}}])
    return index


def new_process(monkeypatch):
    monkeypatch.setattr(mp, "_INSTALLED", None)
    monkeypatch.setattr(wc, "_prepared", set())


class Audit:
    def __init__(self):
        self.entries: list[dict] = []

    def _next_audit_id(self):
        return f"t-{len(self.entries) + 1:03d}"

    def log(self, **kw):
        self.entries.append(kw)
        return kw


# --------------------------------------------------------------------------
# C1: installed before the first index is created, once per process


def test_the_first_write_puts_every_template_before_the_index_and_the_bulk(sent):
    client = Client()
    index = write(client, "json")
    put = client.named("indices.put_index_template")
    assert sorted(put) == sorted(TEMPLATES)  # C1a: each once
    assert client.named("cluster.put_component_template") == [COMPONENT]
    assert client.named("ingest.put_pipeline") == [PIPELINE]
    assert client.named("indices.create") == [index]  # C1c: exactly one index
    first_template = min(client.at("indices.put_index_template", t) for t in TEMPLATES)
    last_install = max(
        [client.at("indices.put_index_template", t) for t in TEMPLATES]
        + [client.at("cluster.put_component_template", COMPONENT),
           client.at("ingest.put_pipeline", PIPELINE)]
    )  # fmt: skip
    assert first_template < last_install < client.at("indices.create", index)  # C1b
    assert client.at("indices.create", index) < client.at("_bulk", index)


def test_templates_an_older_release_left_are_put_again(sent):
    """C1e: every template is already on the cluster (an older release's
    bodies): the run still PUTs all of them."""
    client = Client(templates=TEMPLATES | {COMPONENT})
    write(client, "csv")
    assert sorted(client.named("indices.put_index_template")) == sorted(TEMPLATES)


def test_the_install_runs_once_per_process(sent):
    client = Client()
    write(client, "json")
    write(client, "accesslog")
    assert sorted(client.named("indices.put_index_template")) == sorted(TEMPLATES)
    assert client.named("ingest.put_pipeline") == [PIPELINE]


def test_a_second_process_into_an_index_that_exists_installs_again_under_its_run(
    sent, monkeypatch
):
    """C1f: a second CLI process in the same case, whose index already
    exists, PUTs every template again, and its run's audit records the
    stamp-field patch."""
    client = Client()
    index = write(client, "json")
    new_process(monkeypatch)
    client.calls.clear()
    audit = Audit()
    ops.set_run(audit, wc.current().case_dir)
    try:
        assert write(client, "json") == index
    finally:
        ops.set_run(None, None)
    assert sorted(client.named("indices.put_index_template")) == sorted(TEMPLATES)
    assert client.named("indices.create") == []
    (entry,) = [e for e in audit.entries if e["tool"] == "put_stamp_fields"]
    assert index in entry["params"]["indices"]


# --------------------------------------------------------------------------
# C2: a non-evtx index whose template was refused is not created


def _refused_write(client, artifact_type):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(Exception) as e:
        write(client, artifact_type)
    assert type(e.value).__name__ == "TemplateNotInstalled", e.value
    return str(e.value), err.getvalue()


@pytest.mark.parametrize(
    "artifact_type,template", [("json", "vhir-json"), ("shimcache", "vhir-csv")]
)
def test_an_index_whose_template_was_refused_is_not_created(sent, artifact_type, template):
    """C2a"""
    client = Client(refuse={template})
    index = wc.index_name(artifact_type)
    said, err = _refused_write(client, artifact_type)
    assert said.startswith(f"index template {template} is not installed (")
    assert said.endswith(f"): {index} was not created, so its fields aren't mapped by guess")
    assert f"{template} refused" in said
    assert client.named("indices.create") == [] and client.named("_bulk") == []
    assert err.count("WARNING: index templates not installed: ") == 1
    assert f"{template}: " in err


def test_a_refused_template_is_warned_about_once_per_process(sent):
    client = Client(refuse={"vhir-json"})
    _, first = _refused_write(client, "json")
    _, again = _refused_write(client, "json")
    assert "WARNING: index templates not installed: vhir-json: " in first
    assert "WARNING" not in again
    assert len(client.named("indices.put_index_template")) == len(TEMPLATES)  # tried once


def test_another_types_refused_template_only_warns(sent):
    """C2b: vhir-ssh refused; the json index is still created and written."""
    client = Client(refuse={"vhir-ssh"})
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        index = write(client, "json")
    assert client.named("indices.create") == [index]
    assert client.named("_bulk") == [index]
    assert "WARNING: index templates not installed: vhir-ssh: " in err.getvalue()


def test_a_missing_component_refuses_the_templates_composed_of_it(sent):
    """The client, as OpenSearch: no component, no composable template that
    names it, so their indices aren't created either."""
    client = Client(refuse={COMPONENT})
    said, err = _refused_write(client, "json")
    assert "specifies component templates ['vhir-json-type-stability'] that do not exist" in said
    assert "vhir-json-type-stability: " in err


def test_an_index_that_exists_is_written_whatever_its_template(sent):
    index = wc.index_name("json")
    client = Client(indices={index}, refuse={"vhir-json"})
    with contextlib.redirect_stderr(io.StringIO()):
        write(client, "json")
    assert client.named("_bulk") == [index]


def test_an_unanswered_exists_still_refuses(sent, monkeypatch):
    """Not known to exist: refused, not left to the bulk to create by guess."""
    client = Client(refuse={"vhir-json"})

    def unanswered(**kw):
        raise ConnectionError("no answer")

    monkeypatch.setattr(client, "_indices_exists", unanswered)
    _refused_write(client, "json")
    assert client.named("_bulk") == []


def test_an_install_that_raises_refuses_every_new_non_evtx_index(sent, monkeypatch):
    def broken(client, audit=None, stamp_indices=""):
        raise RuntimeError("cluster went away")

    monkeypatch.setattr(mp, "ensure_winlog_pipeline", broken)
    said, err = _refused_write(Client(), "json")
    assert "index template vhir-json is not installed (cluster went away)" in said
    assert "WARNING: index templates not installed: vhir-evtx-ecs: cluster went away" in err


# --------------------------------------------------------------------------
# G1: a process that writes nothing installs nothing


@pytest.mark.parametrize(
    "argv",
    [["json", "/nonexistent/x.json", "--hostname", "h1", "--dry-run"],
     ["enrich-intel", "--dry-run"],
     []],
    ids=["json-dry-run", "enrich-intel-dry-run", "bare"],
)  # fmt: skip
def test_a_command_that_writes_nothing_sends_no_write(monkeypatch, capsys, argv):
    client = Client()
    monkeypatch.setattr(ingest_cli, "get_client", lambda *a, **kw: client)
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda c: "test-case")
    monkeypatch.setattr(ingest_cli, "_ensure_case_active", lambda c: None)
    from opensearch_mcp import case_scope, threat_intel

    monkeypatch.setattr(case_scope, "case_read_scope", lambda *a, **kw: ["case-x-*"])
    monkeypatch.setattr(threat_intel, "extract_unique_iocs",
                        lambda *a, **kw: {"ip": [], "hash": [], "domain": []})  # fmt: skip
    monkeypatch.setattr(sys, "argv", ["opensearch-ingest", *argv])
    with contextlib.suppress(SystemExit):
        ingest_cli.main()
    assert client.writes() == []


# --------------------------------------------------------------------------
# The template an index gets is decided by pattern, not by reading every file:
# a missing or broken file refuses its own indices and no others


@pytest.fixture
def files(monkeypatch, tmp_path):
    """A copy of the shipped template files the row can break."""
    import shutil

    d = tmp_path / "mappings"
    shutil.copytree(mp._MAPPINGS_DIR, d, ignore=shutil.ignore_patterns("*.py", "__pycache__"))
    monkeypatch.setattr(mp, "_MAPPINGS_DIR", d)
    return d


@pytest.mark.parametrize(
    "broken,how,artifact_type,refused",
    [
        ("ssh_template.json", "garbled", "json", None),
        ("ssh_template.json", "missing", "json", None),
        ("ssh_template.json", "unreadable", "json", None),
        ("ssh_template.json", "null-template", "json", None),
        ("json_template.json", "unreadable", "json",
         "vhir-json is not installed (json_template.json couldn't be loaded: [Errno 13]"),
        ("json_template.json", "null-template", "json",
         "vhir-json is not installed (json_template.json couldn't be loaded: "),
        ("ssh_template.json", "garbled", "ssh",
         "vhir-ssh is not installed (ssh_template.json couldn't be loaded: Expecting value"),
        ("json_template.json", "garbled",  "json",
         "vhir-json is not installed (json_template.json couldn't be loaded: Expecting value"),
        ("json_template.json", "missing", "json",
         "vhir-json is not installed (its file json_template.json is missing)"),
        ("srum_template.json", "missing", "srum",
         "vhir-srum is not installed (its file srum_template.json is missing)"),
    ],
    ids=["other-garbled", "other-missing", "other-unreadable", "other-null-template",
         "own-unreadable", "own-null-template", "own-garbled-ssh", "own-garbled", "own-missing",
         "own-missing-where-another-template-also-matches"],
)  # fmt: skip
def test_a_broken_template_file_refuses_its_own_indices_only(
    sent, files, broken, how, artifact_type, refused
):
    if how == "missing":
        (files / broken).unlink()
    elif how == "unreadable":
        (files / broken).chmod(0)
    elif how == "null-template":
        (files / broken).write_text('{"index_patterns": ["case-*-x-*"], "template": null}')
    else:
        (files / broken).write_text("not json {")
    client = Client()
    if refused is None:
        with contextlib.redirect_stderr(io.StringIO()):
            index = write(client, artifact_type)
        assert client.named("_bulk") == [index]
        own = mp.template_for(index)  # and its own template was installed
        assert own in client.named("indices.put_index_template") and own in client.templates
        return
    said, _ = _refused_write(client, artifact_type)
    assert f"index template {refused}" in said
    assert client.named("indices.create") == [] and client.named("_bulk") == []


def test_each_templates_patterns_and_priority_are_its_files():
    """What selection decides from is what each shipped file says."""
    files = {
        name: mp._load_json(mp._MAPPINGS_DIR / filename)
        for name, filename in mp._TEMPLATES_REGISTRY
    }
    assert mp._TEMPLATE_PATTERNS == {
        name: (body["priority"], tuple(body["index_patterns"])) for name, body in files.items()
    }
