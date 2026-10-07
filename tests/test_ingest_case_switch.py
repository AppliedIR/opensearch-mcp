"""An ingest into a case that isn't active says whether it became active.

The ingest CLI makes its case the active one through the gateway's
case_activate, which also moves the evidence share. That switch was silent,
and when the gateway couldn't be reached a fallback pointed the active case
at a holder under the install directory and rewrote the Samba share itself.
The run now reads the pointer afterwards and says on stderr either that the
case is now active (naming the one before) or that it wasn't made active and
how to do it; nothing but the gateway writes the pointer or Samba.
"""

from __future__ import annotations

import argparse
import types
from pathlib import Path

import pytest

from opensearch_mcp import gateway, ingest_cli


@pytest.fixture
def install(tmp_path, monkeypatch):
    """An install directory whose pointer names OLD, with a holder for NEW
    under it (an earlier image ingest makes one)."""
    home = tmp_path / "vhir"
    (home / "cases" / "NEW" / "tmp").mkdir(parents=True)
    (home / "active_case").write_text(str(tmp_path / "cases" / "OLD"))
    monkeypatch.setattr(ingest_cli, "vhir_dir", lambda: home)

    written, ran = [], []
    real_write = Path.write_text

    def write_text(self, *a, **k):
        written.append(str(self))
        return real_write(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", write_text)
    monkeypatch.setattr("subprocess.run", lambda cmd, *a, **k: ran.append(cmd))
    return types.SimpleNamespace(home=home, root=tmp_path, written=written, ran=ran)


def _gateway(monkeypatch, answer):
    """The gateway's case_activate: `answer(case_id)` returns its result or
    raises; the calls are kept."""
    calls = []

    def call_tool(tool, arguments, timeout=60):
        calls.append((tool, arguments))
        return answer(arguments["case_id"])

    monkeypatch.setattr(gateway, "call_tool", call_tool)
    return calls


def _ingest(tmp_path, monkeypatch, capsys) -> str:
    """`vhir ingest json` of an empty folder into case NEW; its stderr."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(ingest_cli, "_resolve_case_id", lambda _c: "NEW")
    monkeypatch.setattr(ingest_cli, "get_client", lambda: object())
    monkeypatch.setattr(ingest_cli, "_preflight_shard_capacity", lambda *a, **k: None)
    audit = types.SimpleNamespace(_next_audit_id=lambda: "aid", log=lambda *a, **k: None)
    monkeypatch.setattr(ingest_cli, "AuditWriter", lambda mcp_name="": audit)
    args = argparse.Namespace(path=str(empty), hostname="", case="NEW", time_field=None,
                              time_from=None, time_to=None, batch_size=1000, dry_run=False,
                              index_suffix=None)  # fmt: skip
    ingest_cli.cmd_ingest_json(args)
    return capsys.readouterr().err


def _pointer(install) -> str:
    return (install.home / "active_case").read_text()


def test_an_ingest_into_another_case_says_it_is_now_active(install, monkeypatch, capsys):
    def activate(case_id):  # as case-mcp does
        (install.home / "active_case").write_text(str(install.root / "cases" / case_id))
        return {"status": "activated", "case_id": case_id}

    _gateway(monkeypatch, activate)
    err = _ingest(install.root, monkeypatch, capsys)
    assert (
        "Case NEW is now the active case (it was OLD); "
        "findings recorded from now on go to NEW." in err
    )


def test_an_ingest_into_the_active_case_says_nothing(install, monkeypatch, capsys):
    (install.home / "active_case").write_text(str(install.root / "cases" / "NEW"))
    calls = _gateway(monkeypatch, lambda c: pytest.fail("activated again"))
    err = _ingest(install.root, monkeypatch, capsys)
    assert calls == [] and "active case" not in err and "made active" not in err


def test_with_the_gateway_unreachable_the_pointer_stays(install, monkeypatch, capsys):
    def unreachable(case_id):
        raise ConnectionError("connection refused")

    _gateway(monkeypatch, unreachable)
    err = _ingest(install.root, monkeypatch, capsys)
    assert _pointer(install) == str(install.root / "cases" / "OLD")
    assert (
        "Case NEW wasn't made active (the gateway couldn't be reached: connection refused); "
        "run `vhir case activate NEW`." in err
    )


def test_an_error_result_isn_t_taken_as_activated(install, monkeypatch, capsys):
    _gateway(monkeypatch, lambda c: {"error": "Case not found: NEW"})
    err = _ingest(install.root, monkeypatch, capsys)
    assert "is now the active case" not in err
    assert (
        "Case NEW wasn't made active (Case not found: NEW); run `vhir case activate NEW`." in err
    )


def test_nothing_but_the_gateway_writes_the_share(install, monkeypatch, capsys):
    def unreachable(case_id):
        raise ConnectionError("connection refused")

    _gateway(monkeypatch, unreachable)
    (install.home / "samba.yaml").write_text("force_user: examiner\n")  # Samba configured
    install.written.clear()
    _ingest(install.root, monkeypatch, capsys)
    assert not [p for p in install.written if p.startswith("/etc/samba")]
    assert not [p for p in install.written if p.endswith(("samba.yaml", "active_case"))]
    assert not [c for c in install.ran if "sudo" in c or "smbcontrol" in c]


def test_a_success_result_with_the_pointer_unmoved_isn_t_taken_as_activated(
    install, monkeypatch, capsys
):
    """Whether the case became active is read from the pointer, not the reply."""
    _gateway(monkeypatch, lambda c: {"status": "activated", "case_id": c})
    err = _ingest(install.root, monkeypatch, capsys)
    assert "is now the active case" not in err
    assert (
        "Case NEW wasn't made active (the active case didn't change); "
        "run `vhir case activate NEW`." in err
    )
