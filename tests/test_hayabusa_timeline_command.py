"""Hayabusa's timeline command, and what a run that exits non-zero leaves behind.

Hayabusa 4.0.0 replaced `csv-timeline` with `dfir-timeline` (CSV is still its
default output) and rejects the old name with exit 2. Earlier releases have
only `csv-timeline`. Measured on the 2.18.0, 3.9.0, 3.10.0, 4.0.0 and 4.1.0
release binaries: `<command> --help` exits 0 when the command exists and 2
when it doesn't. A host with no detections exits 0 and writes an empty file.
"""

import shutil
from types import SimpleNamespace

import pytest

import opensearch_mcp.ingest as ingest
import opensearch_mcp.parse_delimited as parse_delimited

# Models those binaries. HB_KNOWS names the timeline command this release has.
STUB = """#!/bin/sh
cmd="$1"; shift
if [ "$cmd" != "$HB_KNOWS" ]; then
  echo "error: unrecognized subcommand '$cmd'" >&2
  exit 2
fi
for a in "$@"; do [ "$a" = "--help" ] && exit 0; done
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
echo "$cmd" >> "$HB_RAN"
case "$HB_MODE" in
  fail) echo "error: failed to load the rules" >&2; exit 1 ;;
  empty) : > "$out"; exit 0 ;;
esac
cp "$HB_FIXTURE" "$out"
"""
CSV = (
    "Timestamp,RuleTitle,Level,Computer,Channel,EventID\n"
    "2026-02-01 00:00:00,Log cleared,high,HOST1,Sec,1102\n"
    "2026-02-01 00:00:01,Mimikatz use,crit,HOST1,Sec,4688\n"
)


@pytest.fixture
def hb(tmp_path, monkeypatch):
    stub = tmp_path / "hayabusa"
    stub.write_text(STUB)
    stub.chmod(0o755)
    fixture = tmp_path / "alerts.csv"
    fixture.write_text(CSV)
    rules = tmp_path / "rules"
    (rules / "config").mkdir(parents=True)
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    vhir = tmp_path / "vhir"
    ran = tmp_path / "ran.txt"

    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda n, *a, **k: str(stub) if n == "hayabusa" else real_which(n)
    )
    monkeypatch.setattr(ingest, "vhir_dir", lambda: vhir)
    monkeypatch.setattr(ingest, "_resolve_hayabusa_rules_dir", lambda: rules)
    monkeypatch.setenv("HB_FIXTURE", str(fixture))
    monkeypatch.setenv("HB_RAN", str(ran))
    monkeypatch.delenv("HB_MODE", raising=False)

    def ingest_delimited(path, client, index, hostname, **kw):
        rows = path.read_text().splitlines()[1:]
        return len(rows), 0, 0, 0

    monkeypatch.setattr(parse_delimited, "ingest_delimited", ingest_delimited)

    def run(knows, mode=None, binary=None):
        if binary is not None:
            stub.write_bytes(binary)
        monkeypatch.setenv("HB_KNOWS", knows)
        if mode:
            monkeypatch.setenv("HB_MODE", mode)
        host = SimpleNamespace(hostname="HOST1", evtx_dir=evtx, volume_root=evtx)
        results = ingest.run_hayabusa_batch([host], None, "case1")
        commands = ran.read_text().split() if ran.exists() else []
        return results, commands

    return run


def test_a_release_with_dfir_timeline_indexes_its_alerts(hb):
    results, commands = hb("dfir-timeline")
    assert results == {"HOST1": 2}
    assert commands == ["dfir-timeline"]


def test_a_release_with_csv_timeline_still_uses_it(hb):
    results, commands = hb("csv-timeline")
    assert results == {"HOST1": 2}
    assert commands == ["csv-timeline"]


def test_a_release_with_neither_command_fails_the_host(hb):
    results, _ = hb("some-future-timeline")
    assert results["HOST1"]["status"] == "failed"
    assert results["HOST1"]["error"].startswith("exit 2: ")
    assert "unrecognized subcommand" in results["HOST1"]["error"]


def test_any_non_zero_exit_fails_the_host_with_hayabusas_error(hb):
    results, _ = hb("csv-timeline", mode="fail")
    assert results == {
        "HOST1": {"status": "failed", "error": "exit 1: error: failed to load the rules\n"}
    }


def test_a_host_with_no_detections_is_not_a_failure(hb):
    results, commands = hb("csv-timeline", mode="empty")
    (outcome,) = results.values()
    assert outcome["status"] == "empty" and "no rule matched" in outcome["note"]
    assert commands == ["csv-timeline"]


def test_a_probe_that_fails_to_run_falls_back_to_csv_timeline(hb, monkeypatch):
    import subprocess

    real = subprocess.run

    def run(cmd, *a, **k):
        if "--help" in cmd:
            raise subprocess.TimeoutExpired(cmd, 60)
        return real(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", run)
    results, commands = hb("csv-timeline")
    assert results == {"HOST1": 2}
    assert commands == ["csv-timeline"]
