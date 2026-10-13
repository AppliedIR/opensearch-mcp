"""wintools-mcp is available when the gateway is configured AND gateway.yaml
names an enabled wintools-mcp backend, as the gateway itself decides. On an
installed box with a gateway but no wintools backend, Timeline says to
provision wintools-mcp with WxTCmd, rather than failing a call with "Tool not
found: run_windows_command". A join that adds the backend while the process
runs is seen on the next call."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import yaml

from opensearch_mcp import gateway, paths, wintools

GATEWAY = {
    "gateway": {"port": 4508},
    "api_keys": {"vhir_gw_000000000000000000000000": {"examiner": "x"}},
}
WINTOOLS = {
    "url": "https://192.0.2.10:4624/mcp",
    "bearer_token": "vhir_wt_000000000000000000000000",
}


@pytest.fixture
def vhir(tmp_path, monkeypatch):
    d = tmp_path / ".vhir"
    d.mkdir()
    monkeypatch.setattr(paths, "vhir_dir", lambda: d)
    monkeypatch.setattr(gateway, "vhir_dir", lambda: d)
    monkeypatch.setattr(gateway, "_cached_config", None)
    monkeypatch.setattr(gateway, "_config_loaded", False)
    monkeypatch.setattr(wintools, "_wintools_down", False)
    return d


def _write(d, backends):
    config = dict(GATEWAY)
    if backends is not None:
        config["backends"] = backends
    (d / "gateway.yaml").write_text(yaml.safe_dump(config))


@pytest.mark.parametrize(
    "backends",
    [
        None,
        {},
        {"forensic-mcp": {"type": "stdio"}},
        {"wintools-mcp": dict(WINTOOLS, enabled=False)},
    ],
    ids=["no backends", "empty backends", "other backends only", "wintools disabled"],
)
def test_a_gateway_without_a_wintools_backend_is_not_wintools(vhir, backends):
    _write(vhir, backends)
    assert gateway.gateway_available()
    assert not wintools.wintools_available()


def test_a_configured_wintools_backend_is_available(vhir):
    _write(vhir, {"forensic-mcp": {"type": "stdio"}, "wintools-mcp": WINTOOLS})
    assert wintools.wintools_available()


def test_no_gateway_is_not_wintools(vhir):
    assert not wintools.wintools_available()


def test_a_join_while_running_is_seen_on_the_next_call(vhir):
    _write(vhir, {"forensic-mcp": {"type": "stdio"}})
    assert not wintools.wintools_available()
    _write(vhir, {"forensic-mcp": {"type": "stdio"}, "wintools-mcp": WINTOOLS})
    assert wintools.wintools_available()


def test_timeline_on_a_gateway_without_wintools_says_to_provision_it(vhir, tmp_path):
    from opensearch_mcp.parse_timeline import NO_WINTOOLS, parse_timeline

    _write(vhir, {"forensic-mcp": {"type": "stdio"}})
    db = tmp_path / "ActivitiesCache.db"
    db.write_bytes(b"x")
    with pytest.raises(RuntimeError) as e:
        parse_timeline(db, MagicMock(), "case-x-timeline-0", "RD01")
    assert str(e.value) == NO_WINTOOLS
