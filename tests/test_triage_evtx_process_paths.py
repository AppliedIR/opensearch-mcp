"""Triage checks an evtx process by its path in either record shape: a record
written before the ECS fields holds the path in process.name, a later one a
bare file name there and the path in process.executable. check_file is given
the path for each, and each record is stamped once.

The stand-in is test_triage_command_lines' cluster, with the two query strings
triage sends evtx read as OpenSearch reads them; check_file answers EXPECTED for
the System32 path and SUSPICIOUS for anything else, as a bare name gets."""

from __future__ import annotations

from test_triage_command_lines import Cluster, _match

from opensearch_mcp import triage_remote as tr

CMD = "C:\\Windows\\System32\\cmd.exe"
EXPECTED = {"verdict": "EXPECTED", "confidence": "high", "reasons": ["in baseline"]}
SUSP = {"verdict": "SUSPICIOUS", "confidence": "high", "reasons": ["not a system path"]}
PROCESS = {"terms": {"event.code": [4688, 1]}}
STRINGS = {
    "event.code:(4688 OR 1)": PROCESS,
    "event.code:(4688 OR 1) AND NOT _exists_:process.executable": {
        "bool": {"filter": [PROCESS], "must_not": [{"exists": {"field": "process.executable"}}]}
    },
}


def _read(q):
    """The query with each query string triage sends evtx as its own query."""
    if isinstance(q, dict):
        if set(q) == {"query_string"} and q["query_string"]["query"] in STRINGS:
            return STRINGS[q["query_string"]["query"]]
        return {k: _read(v) for k, v in q.items()}
    return [_read(v) for v in q] if isinstance(q, list) else q


class Evtx(Cluster):
    def search(self, index=None, body=None, **kw):
        return super().search(index, _read(body), **kw)

    def update_by_query(self, index=None, body=None, **kw):
        body = _read(body)
        if "params.verdict" in body["script"]["source"]:
            for d in self._docs(index):
                if _match(body["query"], d):
                    d["stamps"] = d.get("stamps", 0) + 1
        return super().update_by_query(index, body, **kw)


def test_an_evtx_process_is_checked_by_its_path_in_either_shape(monkeypatch):
    sent = []

    def call_tool(name, args, timeout=None):
        if name != "check_file":
            return {}
        sent.append(args["path"])
        return dict(EXPECTED if args["path"] == CMD else SUSP)

    monkeypatch.setattr(tr, "call_tool", call_tool)
    monkeypatch.setattr(tr, "gateway_available", lambda: True)
    old = {"_id": "old", "event.code": 4688, "process.name": CMD}
    new = {"_id": "new", "event.code": 4688, "process.name": "cmd.exe", "process.executable": CMD}
    tr.enrich_remote(Evtx({"case-evtxproc-evtx-h1": [old, new]}), "evtxproc")
    stamps = {d["_id"]: (d.get("triage.verdict"), d.get("stamps")) for d in (old, new)}
    assert (stamps, sorted(set(sent))) == (
        {"old": ("EXPECTED", 1), "new": ("EXPECTED", 1)},
        [CMD],
    )
