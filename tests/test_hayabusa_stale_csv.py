"""A Hayabusa run must not ingest an earlier run's CSV.

Hayabusa 3.9.0 doesn't overwrite an existing output file: it prints
"[ERROR] ... already exists" on stderr, exits 0 and leaves the file as it
was. The output name is fixed per case and host, so a second evtx ingest for
a host indexed the first run's alerts as the new run's. It also exits 0
without writing when it finds no .evtx files.
"""

import shutil
from types import SimpleNamespace

import pytest

import opensearch_mcp.ingest as ingest
import opensearch_mcp.parse_delimited as parse_delimited

# Models measured Hayabusa 3.9.0 (no -C given).
STUB = """#!/bin/sh
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
if [ -e "$out" ]; then
  echo "[ERROR]  The file $out already exists. Please specify a different filename" \
    "or add the -C, --clobber option to overwrite." >&2
  exit 0
fi
case "$HB_MODE" in
  untouched) exit 0 ;;
  empty) : > "$out"; exit 0 ;;
  *) cp "$HB_FIXTURE" "$out" ;;
esac
"""
HEADER = "Timestamp,RuleTitle,Level,Computer,Channel,EventID\n"
OLD = HEADER + "2026-01-01 00:00:00,Old System alert,low,HOST1,System,7045\n"
NEW = HEADER + (
    "2026-02-01 00:00:00,Log cleared,high,HOST1,Security,1102\n"
    "2026-02-01 00:00:01,Logon,info,HOST1,Security,4624\n"
)


@pytest.fixture
def hb(tmp_path, monkeypatch):
    stub = tmp_path / "hayabusa"
    stub.write_text(STUB)
    stub.chmod(0o755)
    fixture = tmp_path / "new.csv"
    fixture.write_text(NEW)
    rules = tmp_path / "rules"
    (rules / "config").mkdir(parents=True)
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    vhir = tmp_path / "vhir"
    out_dir = vhir / "hayabusa-output"
    out_dir.mkdir(parents=True)

    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda n, *a, **k: str(stub) if n == "hayabusa" else real_which(n)
    )
    monkeypatch.setattr(ingest, "vhir_dir", lambda: vhir)
    monkeypatch.setattr(ingest, "_resolve_hayabusa_rules_dir", lambda: rules)
    monkeypatch.setenv("HB_FIXTURE", str(fixture))
    monkeypatch.delenv("HB_MODE", raising=False)

    sent = []

    def ingest_delimited(path, client, index, hostname, **kw):
        rows = path.read_text().splitlines()[1:]
        sent.extend(rows)
        return len(rows), 0, 0, 0

    monkeypatch.setattr(parse_delimited, "ingest_delimited", ingest_delimited)

    def run():
        events = []
        host = SimpleNamespace(hostname="HOST1", evtx_dir=evtx)
        results = ingest.run_hayabusa_batch(
            [host], None, "case1", on_progress=lambda ev, **kw: events.append((ev, kw))
        )
        return results, events

    csv = out_dir / "hayabusa-case1-host1.csv"
    prev = out_dir / "hayabusa-case1-host1.prev.csv"
    return SimpleNamespace(run=run, sent=sent, csv=csv, prev=prev, monkeypatch=monkeypatch)


def _failed(events):
    return [kw for ev, kw in events if ev == "hayabusa_failed"]


def test_a_second_run_ingests_only_its_own_output(hb):
    hb.csv.write_text(OLD)
    results, events = hb.run()
    assert hb.sent == NEW.splitlines()[1:], hb.sent
    assert results == {"HOST1": 2} and not _failed(events)
    assert hb.prev.read_text() == OLD


def test_a_run_that_writes_nothing_fails_and_sends_nothing(hb):
    hb.csv.write_text(OLD)
    hb.monkeypatch.setenv("HB_MODE", "untouched")
    results, events = hb.run()
    assert hb.sent == [] and "HOST1" not in results
    assert _failed(events) == [{"hostname": "HOST1", "error": "no output"}]
    assert hb.prev.read_text() == OLD and not hb.csv.exists()


def test_the_previous_prev_is_replaced(hb):
    hb.prev.write_text("older\n")
    hb.csv.write_text(OLD)
    hb.run()
    assert hb.prev.read_text() == OLD


def test_a_failed_move_fails_the_host_and_sends_nothing(hb):
    hb.csv.write_text(OLD)
    hb.prev.mkdir()  # the rename can't replace a directory
    results, events = hb.run()
    assert hb.sent == [] and "HOST1" not in results
    assert len(_failed(events)) == 1 and hb.csv.read_text() == OLD


def test_anchor_a_first_run_is_unchanged(hb):
    results, events = hb.run()
    assert hb.sent == NEW.splitlines()[1:] and results == {"HOST1": 2}
    assert not _failed(events) and not hb.prev.exists()


def test_anchor_a_zero_detection_run_is_unchanged(hb):
    """Reported as a failure today (pre-existing)."""
    hb.monkeypatch.setenv("HB_MODE", "empty")
    results, events = hb.run()
    assert hb.sent == [] and "HOST1" not in results
    assert _failed(events) == [{"hostname": "HOST1", "error": "no output"}]
