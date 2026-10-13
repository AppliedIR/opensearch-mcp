"""A case index is never created under a template that isn't vhir's own,
and the install says what it didn't install.

- An evtx index isn't created when its template didn't install, except where
  an operator's template already governs the evtx pattern (the install's own
  collision check found it).
- Before a case index is created, OpenSearch is asked which template governs
  it; when another outranks vhir's, the index is refused.
- The stamp-field patch touches only the run's own case's indices.
- A template file whose priority or patterns differ from the registry is a
  failed install, never installed as if it agreed.
- Non-ASCII stems get a short hash suffix, so two never share an index.

The client is test_cli_templates' recording stand-in.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import io
import json

import pytest

from opensearch_mcp import mappings as mp
from opensearch_mcp import ops, server
from opensearch_mcp import write_context as wc
from opensearch_mcp.paths import build_index_name, stem_type

from .test_cli_templates import (  # noqa: F401 (fixtures)
    Audit,
    Client,
    _refused_write,
    files,
    sent,
    write,
)

pytestmark = pytest.mark.template_install

EVTX = "vhir-evtx-ecs"
OTHER_CASE = "case-ffffffffffff-json-auth-0"


class Cluster(Client):
    """Answers _simulate_index as OpenSearch does: `overlapping` holds the
    templates that match too but don't apply. `outranked` names vhir
    templates another template outranks; `probe` answers the evtx install's
    own collision probe (`case-PROBE-evtx-PROBE`), and with `above` an
    operator's template outranks every vhir one there: vhir-evtx-ecs is then in
    `overlapping` once it's on the cluster (as measured on 3.5.0, which never
    names a priority)."""

    def __init__(self, *a, outranked=(), probe=None, simulate_fails=False, above=False, **kw):
        super().__init__(*a, **kw)
        self.outranked, self.probe, self.simulate_fails = set(outranked), probe, simulate_fails
        self.above = above

    def _indices_simulate_index_template(self, name):
        if "PROBE" in name:
            reply = dict(self.probe or {})
            if self.above and EVTX in self.templates:
                reply["overlapping"] = [{"name": EVTX, "index_patterns": ["case-*-evtx-*"]}]
            return reply
        if self.simulate_fails:
            raise ConnectionError("no answer")
        patterns = {t: list(ps) for t, (_, ps) in mp._TEMPLATE_PATTERNS.items()}
        overlapping = [{"name": t, "index_patterns": patterns.get(t, [])}
                       for t in sorted(self.outranked)]  # fmt: skip
        return {"template": {"settings": {}, "mappings": {}}, "overlapping": overlapping}

    def _cat_indices(self, **kw):
        return [{"index": i} for i in sorted(self.existing) if fnmatch.fnmatchcase(i, kw["index"])]


# an operator's template on the evtx pattern, answered as OpenSearch 3.5.0 does
OPERATOR = {
    "priority": dict(above=True, probe={"template": {"settings": {"index": {
        "number_of_replicas": "0"}}, "aliases": {}}, "overlapping": []}),
    "default_pipeline": dict(probe={"template": {"settings": {"index": {
        "default_pipeline": "theirs"}}}}),
}  # fmt: skip


# --------------------------------------------------------------------------
# An evtx index without its template


@pytest.mark.usefixtures("sent")
def test_an_evtx_index_whose_template_failed_is_refused():
    """Was: written anyway, its fields mapped by guess."""
    client = Cluster(refuse={EVTX})
    said, err = _refused_write(client, "evtx")
    assert said.startswith(f"index template {EVTX} is not installed (")
    assert client.named("indices.create") == [] and client.named("_bulk") == []
    assert f"WARNING: index templates not installed: {EVTX}: " in err


@pytest.mark.parametrize("operator", OPERATOR)
@pytest.mark.usefixtures("sent")
def test_an_evtx_index_an_operator_template_governs_is_written(operator):
    """The evtx install stopped because an operator's template governs the
    pattern: the index is created under it, even when vhir's own is on the
    cluster from an earlier install (outranked)."""
    client = Cluster(**OPERATOR[operator], outranked={EVTX})
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        index = write(client, "evtx")
    assert client.named("indices.create") == [index] and client.named("_bulk") == [index]
    assert f"{EVTX}: " in err.getvalue()  # still warned about


def test_an_operator_return_is_marked_and_an_evtx_failure_is_not():
    client = Cluster(**OPERATOR["priority"])
    assert mp.ensure_winlog_pipeline(client)["operator_template"] is True
    assert "operator_template" not in mp.ensure_winlog_pipeline(Cluster(refuse={EVTX}))


# --------------------------------------------------------------------------
# Another template outranks vhir's


@pytest.mark.parametrize(
    "artifact_type,template", [("json", "vhir-json"), ("shimcache", "vhir-csv"), ("evtx", EVTX)]
)
@pytest.mark.usefixtures("sent")
def test_an_index_another_template_governs_is_refused(artifact_type, template):
    """Was: created under the other template, silently."""
    client = Cluster(outranked={template})
    index = wc.index_name(artifact_type)
    said, _ = _refused_write(client, artifact_type)
    assert said == (
        f"index template {template} is outranked: another index template of higher "
        f"priority governs {index}, so it was not created"
    )
    assert ("indices.simulate_index_template", index) in client.calls
    assert client.named("indices.create") == [] and client.named("_bulk") == []


@pytest.mark.parametrize("cluster", ["vhir's own governs", "unanswered"])
@pytest.mark.usefixtures("sent")
def test_an_index_vhirs_template_governs_is_created(cluster):
    """Controls: overlapping names only templates vhir's outranks, or the
    simulate call isn't answered (as for exists: the bulk creates it)."""
    client = Cluster(outranked={"vhir-csv"}, simulate_fails=cluster == "unanswered")
    index = write(client, "json")
    assert client.named("indices.create") == [index] and client.named("_bulk") == [index]


@pytest.mark.usefixtures("sent")
def test_an_index_that_exists_is_not_simulated():
    index = wc.index_name("json")
    client = Cluster(indices={index}, outranked={"vhir-json"})
    write(client, "json")
    assert client.named("_bulk") == [index]
    assert ("indices.simulate_index_template", index) not in client.calls


# --------------------------------------------------------------------------
# The stamp-field patch stays in the run's case


@pytest.mark.usefixtures("sent")
def test_the_stamp_fields_patch_only_this_runs_case():
    """Was: every open case-* index, every case, recorded in this run's audit."""
    own = wc.index_name("evtx")
    client = Cluster(indices={own, OTHER_CASE})
    audit = Audit()
    ops.set_run(audit, wc.current().case_dir)
    try:
        write(client, "json")
    finally:
        ops.set_run(None, None)
    c12 = own.split("-")[1]
    patched = [k for c, k in client.calls if c == "indices.put_mapping"]
    assert own in patched and OTHER_CASE not in patched
    assert ("cat.indices", f"case-{c12}-*") in client.calls
    (entry,) = [e for e in audit.entries if e["tool"] == "put_stamp_fields"]
    assert OTHER_CASE not in entry["params"]["indices"] and own in entry["params"]["indices"]


def test_with_no_case_the_stamp_fields_patch_nothing():
    client = Cluster(indices={OTHER_CASE})
    assert mp.put_stamp_fields(client) == {"patched": [], "failed": []}
    assert client.calls == []


@pytest.mark.parametrize("active", [True, False], ids=["active case", "no active case"])
def test_the_servers_install_patches_only_the_active_case(monkeypatch, active):
    seen = []
    monkeypatch.setattr(server, "_client", Cluster())
    monkeypatch.setattr(server, "_client_verified", False)
    monkeypatch.setattr(server, "_install_settled", False, raising=False)
    monkeypatch.setattr(server, "_install_at", None, raising=False)
    monkeypatch.setattr(server, "_get_active_case", lambda: "CASE-A" if active else None)
    monkeypatch.setattr(server, "_case_c12", lambda cid: "0123456789ab" if cid else "")
    monkeypatch.setattr(mp, "ensure_winlog_pipeline",
                        lambda c, audit=None, stamp_indices="": seen.append(stamp_indices)
                        or {"status": "ok"})  # fmt: skip
    server._get_os()
    assert seen == (["case-0123456789ab-*"] if active else [""])


# --------------------------------------------------------------------------
# A file that disagrees with the registry fails its install


def _edit(folder, name, **changes):
    path = folder / name
    body = json.loads(path.read_text())
    body.update(changes)
    path.write_text(json.dumps(body))


@pytest.mark.parametrize(
    "artifact_type,template,filename,changes,field",
    [
        ("srum", "vhir-srum", "srum_template.json", {"priority": 5}, "priority"),
        ("ssh", "vhir-ssh", "ssh_template.json", {"index_patterns": ["case-*-sshx-*"]},
         "index_patterns"),
    ],
    ids=["srum-priority", "ssh-patterns"],
)  # fmt: skip
@pytest.mark.usefixtures("sent", "files")
def test_a_file_that_differs_from_the_registry_is_a_failed_install(
    artifact_type, template, filename, changes, field
):
    """Was: installed, and the index created under another template (vhir-csv
    for srum) or none (ssh)."""
    _edit(mp._MAPPINGS_DIR, filename, **changes)  # the files fixture's copy
    client = Cluster()
    said, err = _refused_write(client, artifact_type)
    why = f"{filename}: its {field} doesn't match what vhir expects"
    assert f"index template {template} is not installed ({why})" in said
    assert template not in client.named("indices.put_index_template")
    assert f"{template}: {why}" in err
    assert client.named("indices.create") == []


# --------------------------------------------------------------------------
# Non-ASCII stems


@pytest.mark.parametrize(
    "a,b", [("日志", "記録"), ("событие", "приказы"), ("\u212aelvin", "kelvin")]
)
def test_non_ascii_stems_never_share_an_index(a, b):
    """Was: `日志` and `記録` both json-__. (U+212A, the Kelvin sign, lowers to k.)"""
    ta, tb = stem_type("json", a), stem_type("json", b)
    assert ta != tb
    assert ta == stem_type("json", a)  # the same file, the same index
    for stem, t in ((a, ta), (b, tb)):
        if not stem.isascii():
            assert t.rsplit("_", 1)[1] == hashlib.sha256(stem.encode()).hexdigest()[:7]


@pytest.mark.parametrize(
    "stem,expected",
    [("events", "json-events"), ("auth-log", "json-auth_log"), ("json", "json-json_"),
     ("json_", "json-")],
)  # fmt: skip
def test_ascii_stems_are_unchanged(stem, expected):
    assert stem_type("json", stem) == expected
    assert build_index_name("0123456789ab", expected).startswith("case-0123456789ab-json-")


# --------------------------------------------------------------------------
# The server retries a failed install, at most once a minute


@pytest.fixture
def server_install(monkeypatch):
    """The server's first connection, with ensure_winlog_pipeline answering
    from `answers` in turn and its clock under the row's control."""
    calls, answers, clock = [], [], [1000.0]
    monkeypatch.setattr(server, "_client", Cluster())
    monkeypatch.setattr(server, "_client_verified", False)
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(server, "_get_active_case", lambda: "CASE-A")
    monkeypatch.setattr(server, "_case_c12", lambda cid: "0123456789ab" if cid else "")

    def install(c, audit=None, stamp_indices=""):
        calls.append(stamp_indices)
        return answers.pop(0) if answers else {"status": "ok"}

    monkeypatch.setattr(mp, "ensure_winlog_pipeline", install)
    return calls, answers, clock


def test_a_failed_install_is_retried_after_a_minute_until_ok(server_install):
    """Was: one attempt in the server's life."""
    calls, answers, clock = server_install
    answers.extend([{"status": "error", "error": "simulate failed"}, {"status": "partial"}])
    server._get_os()
    clock[0] += 30
    server._get_os()  # within the minute: not again
    assert len(calls) == 1
    clock[0] += 31
    server._get_os()  # partial
    clock[0] += 61
    server._get_os()  # ok
    clock[0] += 61
    server._get_os()  # settled
    assert len(calls) == 3
    # only the first attempt gives the active case's indices the stamp fields
    assert calls == ["case-0123456789ab-*", "", ""]


def test_an_operator_template_return_is_not_retried(server_install):
    calls, answers, clock = server_install
    answers.append({"status": "error", "error": "priority 500", "operator_template": True})
    server._get_os()
    clock[0] += 120
    server._get_os()
    assert len(calls) == 1


def test_a_new_connection_installs_again(server_install):
    """As before: each verified connection (after a lost one) installs."""
    calls, _, _ = server_install
    server._get_os()
    server._client_verified = False  # what _os_call does on a lost connection
    server._get_os()
    assert calls == ["case-0123456789ab-*", "case-0123456789ab-*"]


# --------------------------------------------------------------------------
# What the install says


@pytest.mark.usefixtures("sent", "files")
def test_a_missing_template_file_is_named_in_the_warning():
    """Was: nothing said, except by its own type's refusal."""
    (mp._MAPPINGS_DIR / "plaso_template.json").unlink()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        write(Cluster(), "json")
    (line,) = err.getvalue().splitlines()
    assert line == (
        "WARNING: index templates not installed: "
        "vhir-plaso: its file plaso_template.json is missing"
    )


GARBLED_EVTX = """
import pathlib, sys
from opensearch_mcp import mappings as mp
from test_cli_templates import Client
d = pathlib.Path(sys.argv[1])
mp._MAPPINGS_DIR, mp._EVTX_TEMPLATE_FILE = d, d / "evtx_ecs_template.json"
mp.ensure_installed_once(Client())
"""


def test_a_garbled_evtx_template_prints_one_line(tmp_path):
    """A new process, as a CLI ingest: nothing configures logging, so a logged
    traceback reaches stderr. Was: 14 lines, a traceback before the WARNING."""
    import os
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    d = tmp_path / "mappings"
    shutil.copytree(mp._MAPPINGS_DIR, d, ignore=shutil.ignore_patterns("*.py", "__pycache__"))
    (d / "evtx_ecs_template.json").write_text('{"index_patterns": [')
    tests = str(Path(__file__).parent)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([tests, os.environ.get("PYTHONPATH", "")])}
    run = subprocess.run([sys.executable, "-c", GARBLED_EVTX, str(d)], env=env,
                         capture_output=True, text=True, timeout=60)  # fmt: skip
    assert run.returncode == 0, run.stderr
    assert "Traceback" not in run.stderr
    (line,) = run.stderr.splitlines()
    assert line.startswith(f"WARNING: index templates not installed: {EVTX}: Expecting value")


@pytest.mark.usefixtures("files")
def test_a_broken_template_retried_n_times_writes_one_stamp_entry(monkeypatch):
    """By design, the retry installs again, but only a
    connection's first attempt gives the active case's indices the stamp
    fields, so a template file that stays broken writes one put_stamp_fields
    entry into the case's audit, not one a minute."""
    (mp._MAPPINGS_DIR / "ssh_template.json").write_text("not json {")  # status partial
    case = "case-0123456789ab-json-x-0"
    client, audit, clock = Cluster(indices={case}), Audit(), [1000.0]
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_client_verified", False)
    monkeypatch.setattr(server, "audit", audit)
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(server, "_get_active_case", lambda: "CASE-A")
    monkeypatch.setattr(server, "_case_c12", lambda cid: "0123456789ab")
    for _ in range(5):
        server._get_os()
        clock[0] += 61
    assert len(client.named("ingest.put_pipeline")) == 5  # installed on each attempt
    entries = [e for e in audit.entries if e["tool"] == "put_stamp_fields"]
    assert len(entries) == 1 and entries[0]["params"]["indices"] == [case]


# --------------------------------------------------------------------------
# Every caller of ensure_winlog_pipeline says what failed, in one
# line, now that its own log of the error is debug. The CLI's caller,
# ensure_installed_once, is the garbled-evtx row above.


@pytest.fixture
def garbled_evtx(request, monkeypatch):
    path = request.getfixturevalue("files") / "evtx_ecs_template.json"
    path.write_text('{"index_patterns": [')
    monkeypatch.setattr(mp, "_EVTX_TEMPLATE_FILE", path)


@pytest.mark.usefixtures("garbled_evtx")
def test_the_servers_install_warns_of_a_broken_evtx_template(monkeypatch, caplog):
    monkeypatch.setattr(server, "_client", Cluster())
    monkeypatch.setattr(server, "_client_verified", False)
    monkeypatch.setattr(server, "_get_active_case", lambda: None)
    with caplog.at_level("DEBUG"):
        server._get_os()
    warned = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    (line,) = [m for m in warned if m.startswith("winlog pipeline install reported error")]
    assert "Expecting value" in line and "\n" not in line


@pytest.mark.usefixtures("garbled_evtx")
def test_idx_install_pipelines_answers_with_a_broken_evtx_template(monkeypatch):
    monkeypatch.setattr(server, "_client", Cluster())
    monkeypatch.setattr(server, "_client_verified", True)
    monkeypatch.setattr(server, "audit", Audit())
    monkeypatch.setattr(server, "_get_active_case", lambda: None)
    result = server.idx_install_pipelines()
    assert result["status"] == "error" and "Expecting value" in result["error"]


# --------------------------------------------------------------------------
# codex M2: an operator's template outranking ours is read from `overlapping`
# after our PUT (_simulate_index names no priority: measured on 3.5.0)


@pytest.mark.usefixtures("sent")
@pytest.mark.parametrize("ours_before", [False, True], ids=["fresh cluster", "ours installed"])
def test_an_operator_template_above_ours_is_an_operator_return(ours_before):
    """Was: read from a priority the reply never has, so missed; the evtx index
    was then refused as outranked (the operator template's exemption lost)."""
    client = Cluster(**OPERATOR["priority"], templates={EVTX} if ours_before else set())
    result = mp.ensure_winlog_pipeline(client)
    assert (result["status"], result.get("operator_template")) == ("error", True), result
    assert result["error"].startswith(f"Another index template outranks ours ({EVTX}, ")
    mp._INSTALLED = None
    wc._prepared.clear()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        index = write(Cluster(**OPERATOR["priority"], outranked={EVTX}), "evtx")
    assert index.endswith("-evtx-0")


@pytest.mark.usefixtures("sent")
def test_when_ours_outranks_the_operators_the_install_is_ok():
    """Control: the operator's template is in `overlapping`, not ours."""
    probe = {"template": {"settings": {"index": {}}, "aliases": {}},
             "overlapping": [{"name": "op-low", "index_patterns": ["case-*"]}]}  # fmt: skip
    client = Cluster(probe=probe)
    result = mp.ensure_winlog_pipeline(client)
    assert result["status"] == "ok" and "operator_template" not in result, result
    assert EVTX in client.named("indices.put_index_template")


# --------------------------------------------------------------------------
# codex M1: the evtx template file is checked against what vhir expects


@pytest.mark.usefixtures("sent")
@pytest.mark.parametrize(
    "changes", [{"index_patterns": ["unrelated-*"]}, {"priority": 5}], ids=["patterns", "priority"]
)
def test_an_evtx_template_file_that_differs_fails_its_install(request, monkeypatch, changes):
    """Was: installed, and the evtx index created under no template of ours."""
    folder = request.getfixturevalue("files")
    path = folder / "evtx_ecs_template.json"
    _edit(folder, path.name, **changes)
    monkeypatch.setattr(mp, "_EVTX_TEMPLATE_FILE", path)
    client = Cluster()
    said, _ = _refused_write(client, "evtx")
    field = next(iter(changes))
    assert f"evtx_ecs_template.json: its {field} doesn't match what vhir expects" in said
    assert EVTX not in client.named("indices.put_index_template")
    assert client.named("indices.create") == []
