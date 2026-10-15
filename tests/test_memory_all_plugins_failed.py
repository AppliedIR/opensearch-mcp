"""A memory ingest where every plugin failed ends "failed", with the cause.

On a SANS SIFT OVA, Volatility 3 2.27.0 can't save the symbols it downloads
(its folder is root-owned), so every Windows plugin failed, and the ingest
still ended "complete" with 0 documents. The cause was only in the log. It
now ends "failed" with the first stderr line that names the cause, plus the
SIFT update when the cause is the symbol write. Volatility is a stub script
printing 2.27.0's stderr as measured on the OVA (windows.pslist, no -s).
"""

from __future__ import annotations

import argparse
from unittest import mock

import pytest

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import ingest_status
from opensearch_mcp import parse_memory as pm
from opensearch_mcp import server as srv

SYMBOL_WRITE = (
    "WARNING  volatility3.framework.symbols.windows.pdbutil: Cannot write necessary "
    "symbol file, please check permissions on /opt/volatility3/lib/python3.12/"
    "site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/"
    "3D494B8E9FF6FB289E3AA55B3133EF37-1.json.xz"
)
STDERR_2_27 = "\n".join(
    [
        "Volatility 3 Framework 2.27.0",
        "",
        "Unsatisfied requirement plugins.PsList.kernel.symbol_table_name: ",
        "",
        SYMBOL_WRITE,
        SYMBOL_WRITE.replace("/volatility3/symbols/", "/volatility3/framework/symbols/"),
        "WARNING  volatility3.framework.symbols.windows.pdbutil: Cannot write downloaded "
        "symbols, please add the appropriate symbols or add/modify a symbols directory "
        "that is writable",
        "Unable to validate the plugin requirements: ['plugins.PsList.kernel.symbol_table_name']",
        "",
    ]
)
UNREADABLE = "Volatility 3 Framework 2.28.2\nUnable to validate the plugin requirements: []\n"

# Answers the pre-flight (windows.info) when INFO_OK is set; every other run
# prints $VOL_STDERR's text and exits 1, or nothing and 0 for $VOL_EMPTY.
STUB = """#!/bin/sh
for a in "$@"; do last="$a"; done
if [ "$last" = "windows.info" ] && [ -n "$INFO_OK" ]; then exit 0; fi
if [ "$last" = "$VOL_EMPTY" ]; then exit 0; fi
cat "$VOL_STDERR" >&2
exit 1
"""


@pytest.fixture
def ingest(tmp_path, monkeypatch):
    stub = tmp_path / "vol"
    stub.write_text(STUB)
    stub.chmod(0o755)
    stderr = tmp_path / "stderr.txt"
    monkeypatch.setenv("VOL_STDERR", str(stderr))
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(cli, "get_client", lambda: mock.MagicMock())
    for name in ("_preflight_shard_capacity", "_ensure_case_active"):
        monkeypatch.setattr(cli, name, mock.MagicMock())
    audit = mock.MagicMock()
    audit.return_value._next_audit_id.return_value = "aid-1"
    monkeypatch.setattr(cli, "AuditWriter", audit)
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(pm, "_find_vol3", lambda: str(stub))
    image = tmp_path / "m.raw"
    image.write_bytes(b"\0" * 64)

    def run(text: str, plugins: str, run_id: str, info_ok=True, empty=""):
        stderr.write_text(text)
        monkeypatch.setenv("INFO_OK", "1" if info_ok else "")
        monkeypatch.setenv("VOL_EMPTY", empty)
        monkeypatch.setenv("VHIR_INGEST_RUN_ID", run_id)
        args = argparse.Namespace(
            path=str(image), case="c1", hostname="h", tier=1, plugins=plugins,
            yes=True, timeout=10,
        )  # fmt: skip
        cli.cmd_ingest_memory(args)
        (status,) = [
            s for s in srv.idx_ingest_status(case_id="c1")["ingests"] if s["run_id"] == run_id
        ]
        return status

    return run


def test_every_plugin_failing_to_save_symbols_fails_the_run_and_names_the_update(ingest, capsys):
    status = ingest(STDERR_2_27, "windows.pslist,windows.netscan", "mem-a")
    assert (status["status"], status["halt_reason"]) == ("failed", "all_plugins_failed")
    # whole, not cut at 200 characters: the update comes after the cause
    assert status["message"] == (
        "Ingest failed (all_plugins_failed): every plugin failed (2); "
        f"the first cause: {SYMBOL_WRITE}. {pm.SYMBOL_WRITE_FIX}"
    )
    assert "sudo cast install teamdfir/sift" in capsys.readouterr().out


def test_the_pre_flight_finding_it_fails_the_run_and_names_the_update(ingest, capsys):
    status = ingest(STDERR_2_27, "windows.pslist", "mem-b", info_ok=False)
    assert (status["status"], status["halt_reason"]) == ("failed", "all_plugins_failed")
    assert status["message"].endswith(f"the first cause: {SYMBOL_WRITE}. {pm.SYMBOL_WRITE_FIX}")
    # its own hint (download the symbols) would not help: the write fails
    err = capsys.readouterr().err
    assert pm.SYMBOL_WRITE_FIX in err and "Download symbols" not in err


def test_another_cause_is_named_without_the_update(ingest):
    status = ingest(UNREADABLE, "windows.pslist,windows.netscan", "mem-c")
    assert (status["status"], status["halt_reason"]) == ("failed", "all_plugins_failed")
    assert status["message"] == (
        "Ingest failed (all_plugins_failed): every plugin failed (2); the first cause: "
        "Unable to validate the plugin requirements: []"
    )


def test_a_long_cause_is_cut_and_the_update_still_follows():
    cause = "WARNING  x: Cannot write necessary symbol file " + "p" * 1000
    results = {"windows.pslist": {"status": "failed", "error": "e", "cause": cause}}
    error = pm.all_failed_error(results)
    assert error == (
        f"all_plugins_failed: every plugin failed (1); the first cause: {cause[:300]}. "
        f"{pm.SYMBOL_WRITE_FIX}"
    )


def test_the_status_shows_the_cast_command_after_a_long_cause(ingest):
    # a symbol path long enough that a 200-character cut would end in the cause
    long_write = SYMBOL_WRITE.replace("ntkrnlmp.pdb/", "ntkrnlmp.pdb/" + "d" * 400 + "/")
    status = ingest(STDERR_2_27.replace(SYMBOL_WRITE, long_write), "windows.pslist", "mem-e")
    assert (status["status"], status["halt_reason"]) == ("failed", "all_plugins_failed")
    assert len(status["message"]) > 200
    assert "`sudo cast install teamdfir/sift`" in status["message"]
    assert status["message"].endswith(
        f"the first cause: {long_write[:300]}. {pm.SYMBOL_WRITE_FIX}"
    )


def test_a_run_where_one_plugin_ran_is_complete(ingest):
    # windows.netscan exits 0 with no rows: it ran, so the run did
    status = ingest(
        STDERR_2_27, "windows.pslist,windows.netscan", "mem-d", empty="windows.netscan"
    )
    assert status["status"] == "complete"


@pytest.mark.parametrize(
    "stderr,cause",
    [
        (STDERR_2_27, SYMBOL_WRITE),
        ("Volatility 3 Framework 2.28.2\n\nERROR    x: bad image\nWARNING  y: later\n",
         "ERROR    x: bad image"),
        ("Volatility 3 Framework 2.28.2\n\nsomething broke\n", "something broke"),
        ("Volatility 3 Framework 2.28.2\n", ""),
        ("", ""),
    ],
)  # fmt: skip
def test_the_cause_is_the_first_logged_problem_not_the_banner(stderr, cause):
    assert pm._cause_line(stderr) == cause
