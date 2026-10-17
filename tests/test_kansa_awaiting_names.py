"""A Kansa collection of 29 hosts by 24 modules that waits for host
confirmation names each host: the launch's answer and idx_ingest_status give
one distinct line per unit and raw name it shows, each carrying its host:
all 29 by host, and the first 50 of the 696 by module. The answer's hosts
are all 29 hosts, never a module. The names come from the real names
scan and gate; names are synthetic."""

from __future__ import annotations

import json
import os

import pytest
from sift_common import host_gate
from sift_common import host_identity as hi
from test_host_gate_ingest import RUN, _answer, _awaiting, _lines, gate  # noqa: F401
from test_kansa_file_names import MODULES_24, files

from opensearch_mcp import ingest_status, names_scan
from opensearch_mcp import server as srv

pytestmark = pytest.mark.host_gate

HOSTS = [f"wkstn{i:02d}.shieldbase.com" for i in range(1, 30)]


def _by_host(evidence):
    """One folder per host, each ingested with its host name."""
    return [
        (evidence / "kansa-by-host" / h.split(".")[0], h,
         files(evidence / "kansa-by-host" / h.split(".")[0], [f"{h}-{m}.csv" for m in MODULES_24]))
        for h in HOSTS
    ]  # fmt: skip


def _by_module(evidence):
    """Kansa's own layout: one folder per module, each holding every host's
    file, each ingested without a host name."""
    return [
        (evidence / "kansa-by-module" / m, "",
         files(evidence / "kansa-by-module" / m, [f"{h}-{m}.csv" for h in HOSTS]))
        for m in MODULES_24
    ]  # fmt: skip


def _pending(case_dir, layout):
    units = [names_scan.files_unit(folder, host, fs, case_dir) for folder, host, fs in layout]
    names_scan.record(case_dir, units)
    return host_gate.unresolved(hi.load(case_dir), [u.key for u in units])


@pytest.mark.parametrize(
    "layout, listed",
    [(_by_host, 29), (_by_module, 50)],  # 29 entries; 696 entries, of which a status lists 50
    ids=["by-host", "by-module"],
)
def test_a_waiting_kansa_collection_names_each_host(gate, monkeypatch, layout, listed):  # noqa: F811
    pending = _pending(gate.case_dir, layout(gate.case_dir / "evidence"))
    assert {e["raw"] for e in pending} == set(HOSTS)  # the gate waits on the hosts, no module
    data = _awaiting(gate, monkeypatch, pending)
    out = _answer(gate, monkeypatch, data, {"status": "started", "hosts": []})
    lines = out["unresolved_hosts"]
    assert len(lines) == listed and len(set(lines)) == listed
    assert lines == _lines(pending[:listed])  # the status carries the first entries
    assert all(ln.split(": ")[1] in HOSTS for ln in lines)  # each line names its host
    assert out["hosts"] == HOSTS  # the first 50 by-module entries hold all 29 names
    assert not any(m.lower() in ln.lower().split(": ")[1] for m in MODULES_24 for ln in lines)
    ingest_status._status_path_safe(gate.case_id, 4250, RUN).unlink()  # the answer's run
    p = ingest_status._status_path_safe(gate.case_id, os.getpid(), RUN)
    p.write_text(json.dumps(data))
    (status,) = srv.idx_ingest_status(case_id=gate.case_id)["ingests"]
    assert status["warnings"] == lines
