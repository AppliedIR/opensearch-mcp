"""The same evidence ingested again by another route keeps its first ingest.

A record already in the case is never replaced: its unit, the step that read
it and its content hash stay as the first ingest wrote them (a finding may
cite them), and the second route's copy is counted as already in the case.
The cluster is a stand-in that answers `index` and `create` as OpenSearch
does. Values are synthetic.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

from sift_common import host_identity as hi

from opensearch_mcp import bulk
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost


def _case():
    cid = f"rk-{uuid.uuid4().hex[:8]}"
    d = wc.case_dir_for(cid)
    (d / "CASE.yaml").write_text(
        f"case_id: {cid}\ncase_uuid: {uuid.uuid4().hex}\nnaming_version: 2\n"
    )
    return d


def _cluster():
    """`helpers.bulk` as the cluster answers it: `create` of a stored id is a
    409, `index` replaces."""
    stored: dict = {}

    def answer(client, actions, **k):
        ok, errors = 0, []
        for a in actions:
            op, key = a.get("_op_type", "index"), (a["_index"], a["_id"])
            if op == "create" and key in stored:
                why = f"[{a['_id']}]: version conflict, document already exists"
                errors.append({"create": {
                    "_index": a["_index"], "_id": a["_id"], "status": 409, "error": {
                        "type": "version_conflict_engine_exception", "reason": why}}})  # fmt: skip
                continue
            stored[key] = dict(a["_source"])
            ok += 1
        return ok, errors

    return stored, answer


def _unit(d, route):
    """WKS01's evidence unit read through `route` (the E01, or a zip of it)."""
    host = DiscoveredHost(hostname="WKS01", volume_root=d / "mnt", unit_locator=route)
    return wc.host_context(d, d.name, host)


def _write(ctx, step, answer):
    """One run's write of WKS01's Security.evtx record 4242 under step `step`."""
    action = {"_index": f"case-{ctx.c12}-evtx-0", "_id": "rid-4242",
              "_source": {"event.code": "1117", "vhir.source_file":
                          "Windows/System32/winevt/Logs/Security.evtx"}}  # fmt: skip
    wc.stamp(ctx, [action], [step])
    with patch.object(bulk.helpers, "bulk", side_effect=answer):
        return bulk.flush_bulk(MagicMock(), [action])


def _join(d, key, ctx):
    """The examiner confirms the zip's WKS01 as the E01's machine (the gate)."""
    (m,) = [m for m in hi.load(d).machines.values() if key in m.keys]
    pairs = [list(x) for x in m.pairs] + [[ctx.unit, "WKS01"]]
    hi.append_decision(d, {"action": "confirm", "examiner": "ex1", "args": {"machines": [
        {"key": key, "canonical": m.canonical, "pairs": pairs}]}},
        hi.load(d).obs_offset)  # fmt: skip


def test_a_second_route_never_rewrites_a_record_the_first_wrote():
    d = _case()
    stored, answer = _cluster()
    bulk.reset_circuit_breaker()
    first = _unit(d, "evidence/rd01.E01")
    assert _write(first, "ingest-step-A", answer) == (1, 0)
    ((key, doc),) = stored.items()
    kept = dict(doc)
    assert kept["vhir.unit"] == first.unit and kept["vhir.ingest_audit_id"] == "ingest-step-A"
    second = _unit(d, "evidence/rd01.zip")
    _join(d, kept["vhir.host_key"], second)
    assert second.unit != first.unit  # another evidence unit, the same machine
    assert second.resolve("WKS01")[1] == kept["vhir.host_key"]
    assert _write(second, "ingest-step-B", answer) == (0, 0)  # kept, never a failure
    assert bulk.get_already_present() == 1
    assert list(stored) == [key]
    assert stored[key] == kept  # unit, step and content hash as the first wrote them


# -- a live record lost by an earlier run, its shadow-copy twin kept


def _client(stored):
    """A client whose mget reads the stand-in cluster."""
    client = MagicMock()
    client.mget.side_effect = lambda body, **k: {"docs": [
        {"_index": d["_index"], "_id": d["_id"], "found": (d["_index"], d["_id"]) in stored,
         "_source": stored.get((d["_index"], d["_id"]), {})} for d in body["docs"]]}  # fmt: skip
    return client


def _record(d, vss_id, step, answer, stored):
    """WKS01's record 4242 from one unit, read live or from a shadow copy."""
    host = DiscoveredHost(hostname="WKS01", volume_root=d / "mnt", vss_id=vss_id,
                          unit_locator="evidence/rd01.E01")  # fmt: skip
    ctx = wc.host_context(d, d.name, host)
    action = {"_index": f"case-{ctx.c12}-evtx-0", "_id": "rid-4242",
              "_source": {"event.code": "1117", "vhir.vss_id": vss_id}}  # fmt: skip
    wc.stamp(ctx, [action], [step])
    with patch.object(bulk.helpers, "bulk", side_effect=answer):
        return bulk.flush_bulk(_client(stored), [action])


def test_a_rerun_tags_a_record_live_when_only_its_shadow_copy_was_kept():
    """Run 1 kept the shadow copy's record and lost its live batch; run 2
    (the recovery re-run) writes it live."""
    d = _case()
    stored, answer = _cluster()
    bulk.reset_circuit_breaker()
    assert _record(d, "vss1", "run1-vss", answer, stored) == (1, 0)
    assert _record(d, "live", "run2-live", answer, stored) == (1, 0)
    ((_, doc),) = stored.items()
    assert doc["vhir.vss_id"] == "live" and doc["vhir.ingest_audit_id"] == "run2-live"
    assert bulk.get_already_present() == 0


def test_a_live_record_stays_and_a_shadow_copy_never_replaces_it():
    d = _case()
    stored, answer = _cluster()
    bulk.reset_circuit_breaker()
    assert _record(d, "live", "run1-live", answer, stored) == (1, 0)
    assert _record(d, "live", "run2-live", answer, stored) == (0, 0)  # kept: the first
    assert _record(d, "vss2", "run2-vss", answer, stored) == (0, 0)
    ((_, doc),) = stored.items()
    assert doc["vhir.vss_id"] == "live" and doc["vhir.ingest_audit_id"] == "run1-live"
    assert bulk.get_already_present() == 2


def test_a_shadow_copy_record_never_replaces_another_shadow_copys():
    d = _case()
    stored, answer = _cluster()
    bulk.reset_circuit_breaker()
    assert _record(d, "vss1", "run1-vss", answer, stored) == (1, 0)
    assert _record(d, "vss2", "run2-vss", answer, stored) == (0, 0)
    ((_, doc),) = stored.items()
    assert doc["vhir.vss_id"] == "vss1"
