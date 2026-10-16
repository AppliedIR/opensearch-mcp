"""What a run waiting at the host gate says about how many hosts it waits on.

The real gate runs: the worker's `_gate` (unresolved, summary and on_wait's
stderr and status), cancelled at its first sleep, then the launch answer read
from that status. Kansa's own layout, one file per module naming every host,
waits on 29 hosts in 696 entries (29 names on each of 24 units), more than
the 50 a status lists. Every count is fixed here. Values are synthetic.
"""

from __future__ import annotations

import types

import pytest
from sift_common import host_gate
from test_host_gate_ingest import RUN, _answer, gate  # noqa: F401  (gate is a fixture)
from test_kansa_file_names import MODULES_24, files

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import names_scan

pytestmark = pytest.mark.host_gate

WAITING = "Waiting for host confirmation"
CUT = (
    ". Only 50 of the 696 waiting entries (one per host name in each unit) are "
    "listed. The Portal's Hosts tab lists every one"
)


def _hosts(n):
    return [f"wkstn{i:02d}.example.com" for i in range(1, n + 1)]


def _by_module(ev, hosts):
    d = ev / "by-module"
    return [(d / m, "", files(d / m, [f"{h}-{m}.csv" for h in hosts])) for m in MODULES_24]


def _by_host(ev, hosts):
    d = ev / "by-host"
    return [(d / h, h, files(d / h, [f"{h}-{m}.csv" for m in MODULES_24])) for h in hosts]


def _wait(gate, monkeypatch, capsys, layout, hosts):  # noqa: F811
    """Run the gate until its first sleep: (stderr lines, status, answer)."""
    units = [
        names_scan.files_unit(f, h, fs, gate.case_dir)
        for f, h, fs in layout(gate.case_dir / "evidence", hosts)
    ]
    names_scan.record(gate.case_dir, units)
    seen: list[dict] = []

    def first_sleep(_poll):  # on_wait has printed and written the status
        seen.append(gate.status())
        raise host_gate.RunCancelled("cancelled for the row")

    monkeypatch.setattr(host_gate, "time", types.SimpleNamespace(sleep=first_sleep))
    with pytest.raises(SystemExit):
        cli._gate(gate.case_id, [u.key for u in units], RUN)
    (data,) = seen
    out = _answer(gate, monkeypatch, data, {"status": "started", "hosts": []})
    return capsys.readouterr().err.splitlines(), data, out


def test_29_hosts_in_kansas_module_layout_wait_as_29_and_the_cut_list_says_so(
    gate,  # noqa: F811
    monkeypatch,
    capsys,
):
    hosts = _hosts(29)
    err, data, out = _wait(gate, monkeypatch, capsys, _by_module, hosts)
    (line,) = [ln for ln in err if ln.startswith(WAITING)]
    assert line == f"{WAITING} (29 host name(s)): {host_gate.WAIT_MESSAGE}{CUT}."
    assert len([ln for ln in err if ln.startswith("  ")]) == 50
    assert data["totals"] == {"unresolved": 29}
    assert data["message"] == host_gate.WAIT_MESSAGE + CUT
    assert out["unresolved"] == 29 and len(out["unresolved_hosts"]) == 50
    assert sorted(out["hosts"]) == hosts
    assert CUT in out["message"]


def test_3_hosts_wait_as_3_with_nothing_said_about_a_cut(gate, monkeypatch, capsys):  # noqa: F811
    hosts = _hosts(3)
    err, data, out = _wait(gate, monkeypatch, capsys, _by_host, hosts)
    (line,) = [ln for ln in err if ln.startswith(WAITING)]
    assert line == f"{WAITING} (3 host name(s)): {host_gate.WAIT_MESSAGE}."
    assert len([ln for ln in err if ln.startswith("  ")]) == 3
    assert data["totals"] == {"unresolved": 3}
    assert data["message"] == host_gate.WAIT_MESSAGE
    assert out["unresolved"] == 3 and len(out["unresolved_hosts"]) == 3
    assert sorted(out["hosts"]) == hosts
    assert "Only 50" not in out["message"]
