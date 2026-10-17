"""The status reply for a run that waits says what it waits for.

A run held at the host gate writes its status with the gate's message and how
many host names wait. A run whose hosts are confirmed but which has no free
place writes the slot message. idx_ingest_status gives the AI client that
message, and the count for a host wait, so it can tell the examiner what the
run waits for. The host-wait rows hold a real run in the real gate and ask
for the status at the gate's first sleep. Values are synthetic.
"""

from __future__ import annotations

import os
import time
import types

import pytest
from sift_common import host_gate
from test_host_gate_ingest import RUN, gate  # noqa: F401
from test_kansa_file_names import MODULES_24, files

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status, names_scan
from opensearch_mcp import server as srv

pytestmark = pytest.mark.host_gate


def _hold_at_the_gate(gate, monkeypatch, capsys, n):  # noqa: F811
    """Start a run over n hosts' Kansa folders; at the gate's first sleep return
    the status file, the reply and what the CLI printed, then cancel it."""
    ev = gate.case_dir / "evidence" / "by-host"
    hosts = [f"wkstn{i:02d}.example.com" for i in range(1, n + 1)]
    units = [
        names_scan.files_unit(
            ev / h.split(".")[0],
            h,
            files(ev / h.split(".")[0], [f"{h}-{m}.csv" for m in MODULES_24]),
            gate.case_dir,
        )
        for h in hosts
    ]
    names_scan.record(gate.case_dir, units)
    seen: dict = {}

    def first_sleep(_poll):
        seen["file"] = gate.status()
        (seen["reply"],) = srv.idx_ingest_status(case_id=gate.case_id)["ingests"]
        seen["err"] = capsys.readouterr().err
        raise host_gate.RunCancelled("done")

    monkeypatch.setattr(host_gate, "time", types.SimpleNamespace(sleep=first_sleep))
    with pytest.raises(SystemExit):
        cli._gate(gate.case_id, [u.key for u in units], RUN)
    return seen["file"], seen["reply"], seen["err"]


def _cli_line(err: str) -> str:
    (line,) = [x for x in err.splitlines() if x.startswith("Waiting for host confirmation")]
    return line


def test_a_host_wait_reply_gives_the_message_and_the_count(gate, monkeypatch, capsys):  # noqa: F811
    n = 60  # more than the 50 hosts the file lists
    file, reply, err = _hold_at_the_gate(gate, monkeypatch, capsys, n)
    assert file["status"] == reply["status"] == host_gate.AWAITING
    assert file["totals"] == {"unresolved": n}
    assert reply["unresolved"] == n
    assert reply["message"] == _cli_line(err)
    assert f"({n} host name(s))" in reply["message"]
    assert file["message"] in reply["message"]


def _write(case_id, status, totals=None, **kw):
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ingest_status.write_status(case_id, os.getpid(), RUN, status, [], totals or {}, started, **kw)
    (reply,) = srv.idx_ingest_status(case_id=case_id)["ingests"]
    return reply


def test_a_slot_wait_reply_gives_the_slot_message_and_no_count(gate):  # noqa: F811
    reply = _write(gate.case_id, host_gate.AWAITING, message=ingest_status.SLOT_WAIT)
    assert reply["status"] == host_gate.AWAITING
    assert reply["message"] == ingest_status.SLOT_WAIT
    assert "unresolved" not in reply


@pytest.mark.parametrize("totals", [{}, {"unresolved": 3}])
def test_a_wait_with_no_message_gives_no_message_and_no_count(gate, totals):  # noqa: F811
    """A waiting file written without a message: the reply says nothing it
    doesn't have, and still answers."""
    reply = _write(gate.case_id, host_gate.AWAITING, totals)
    assert reply["status"] == host_gate.AWAITING
    assert "message" not in reply
    assert "unresolved" not in reply


def test_a_run_past_the_gate_says_it_runs_not_the_wait_it_left(gate):  # noqa: F811
    """Once the hosts are confirmed the file says running but keeps the wait's
    message and count, as the confirmation leaves them."""
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ingest_status.write_status(
        gate.case_id,
        os.getpid(),
        RUN,
        host_gate.AWAITING,
        [],
        {"unresolved": 4},
        started,
        message=host_gate.WAIT_MESSAGE,
    )
    ingest_status.mark_hosts_confirmed(gate.case_id, os.getpid(), RUN)
    file = gate.status()
    assert file["status"] == "running" and file["message"] == host_gate.WAIT_MESSAGE
    (reply,) = srv.idx_ingest_status(case_id=gate.case_id)["ingests"]
    assert reply["message"].startswith("Ingest in progress.")
    assert host_gate.WAIT_MESSAGE not in reply["message"]
    assert "unresolved" not in reply
