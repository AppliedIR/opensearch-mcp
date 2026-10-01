"""Finding Volatility 3 by its banner.

Volatility 3 has no `--version`. Up to some release it printed its
"Volatility 3 Framework" banner before argparse rejected the flag; 2.28
rejects it first, so a probe with `--version` saw no banner and memory
ingestion reported Volatility 3 as missing. Bare, 2.28 prints the banner to
stdout and exits 2. The candidates here are scripts on an isolated PATH that
answer as each program does.
"""

from __future__ import annotations

import stat

import pytest

from opensearch_mcp import parse_memory

USAGE = (
    "usage: vol [-h] [-c CONFIG] [-f FILE] plugin ...\n"
    "vol: error: the following arguments are required: plugin"
)

# Volatility 3 2.28: `--version` is an unknown argument, rejected before the banner.
VOL3_228 = f"""
case " $* " in *" --version "*) echo "{USAGE}" >&2; exit 2;; esac
echo "Volatility 3 Framework 2.28.0"
echo "{USAGE}" >&2
exit 2
"""
VOL2 = """
echo "Volatility Foundation Volatility Framework 2.6.1" >&2
echo "ERROR   : volatility.debug    : You must specify something to do (try -h)" >&2
exit 1
"""
NOT_VOLATILITY = """
echo "vol: usage: vol [-l] [percent]" >&2
exit 1
"""


@pytest.fixture
def path(monkeypatch, tmp_path):
    """An empty PATH directory, and a fresh probe cache."""
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(parse_memory, "_VOL3_CMD", None)

    def install(name: str, body: str) -> None:
        script = tmp_path / name
        script.write_text(f"#!/bin/sh\necho run >> {tmp_path / (name + '.calls')}\n{body}")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def calls(name: str) -> int:
        log = tmp_path / f"{name}.calls"
        return len(log.read_text().splitlines()) if log.exists() else 0

    install.calls = calls
    return install


def test_volatility_3_2_28_is_found(path):
    path("vol", VOL3_228)
    assert parse_memory._find_vol3() == "vol"


@pytest.mark.parametrize("body", [VOL2, NOT_VOLATILITY], ids=["volatility 2", "another vol"])
def test_a_vol_that_is_not_volatility_3_is_rejected(path, body):
    path("vol", body)
    with pytest.raises(RuntimeError, match="Volatility 3 not found. Tried: vol3, vol"):
        parse_memory._find_vol3()


def test_vol3_is_tried_first_and_the_answer_is_kept(path):
    path("vol3", VOL3_228)
    path("vol", VOL3_228)
    assert parse_memory._find_vol3() == "vol3"
    assert parse_memory._find_vol3() == "vol3"
    assert (path.calls("vol3"), path.calls("vol")) == (1, 0)
