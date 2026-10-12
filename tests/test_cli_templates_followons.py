"""cli-templates follow-ons (0.6.5): a case index is never created under a
template that isn't vhir's own, and the install says what it didn't install.

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
    own collision probe (`case-PROBE-evtx-PROBE`)."""

    def __init__(self, *a, outranked=(), probe=None, simulate_fails=False, **kw):
        super().__init__(*a, **kw)
        self.outranked, self.probe, self.simulate_fails = set(outranked), probe, simulate_fails

    def _indices_simulate_index_template(self, name):
        if "PROBE" in name:
            return self.probe or {}
        if self.simulate_fails:
            raise ConnectionError("no answer")
        patterns = {t: list(ps) for t, (_, ps) in mp._TEMPLATE_PATTERNS.items()}
        overlapping = [{"name": t, "index_patterns": patterns.get(t, [])}
                       for t in sorted(self.outranked)]  # fmt: skip
        return {"template": {"settings": {}, "mappings": {}}, "overlapping": overlapping}

    def _cat_indices(self, **kw):
        return [{"index": i} for i in sorted(self.existing) if fnmatch.fnmatchcase(i, kw["index"])]


OPERATOR = {
    "priority": {"template": {"priority": 500}},
    "default_pipeline": {"template": {"settings": {"index": {"default_pipeline": "theirs"}}}},
}


# --------------------------------------------------------------------------
# SPEC-001: an evtx index without its template


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
    client = Cluster(probe=OPERATOR[operator], outranked={EVTX})
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        index = write(client, "evtx")
    assert client.named("indices.create") == [index] and client.named("_bulk") == [index]
    assert f"{EVTX}: " in err.getvalue()  # still warned about


def test_an_operator_return_is_marked_and_an_evtx_failure_is_not():
    client = Cluster(probe=OPERATOR["priority"])
    assert mp.ensure_winlog_pipeline(client)["operator_template"] is True
    assert "operator_template" not in mp.ensure_winlog_pipeline(Cluster(refuse={EVTX}))


# --------------------------------------------------------------------------
# SPEC-002: another template outranks vhir's


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
# SPEC-003: the stamp-field patch stays in the run's case


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
    monkeypatch.setattr(server, "_install_ok", False, raising=False)
    monkeypatch.setattr(server, "_install_at", None, raising=False)
    monkeypatch.setattr(server, "_get_active_case", lambda: "CASE-A" if active else None)
    monkeypatch.setattr(server, "_case_c12", lambda cid: "0123456789ab" if cid else "")
    monkeypatch.setattr(mp, "ensure_winlog_pipeline",
                        lambda c, audit=None, stamp_indices="": seen.append(stamp_indices)
                        or {"status": "ok"})  # fmt: skip
    server._get_os()
    assert seen == (["case-0123456789ab-*"] if active else [""])


# --------------------------------------------------------------------------
# SPEC-004: a file that disagrees with the registry fails its install


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
# SPEC-005: non-ASCII stems


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
