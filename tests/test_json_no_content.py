"""A JSON/JSONL file with no content, 0 bytes or only JSON whitespace (space,
tab, CR, LF) after an optional UTF-8 BOM, is an empty result (SPEC-HC-028):
its format is "empty", it gives 0 rows and no error, and the single-file
preview says "empty". A file with content that isn't JSON, "#" lines only or
other whitespace (NBSP, U+3000, \\x1c-\\x1f) included, stays an error."""

from __future__ import annotations

import argparse
from unittest import mock

import pytest
from test_relative_evidence_path import env  # noqa: F401

from opensearch_mcp import parse_json as pj
from opensearch_mcp import server as srv
from opensearch_mcp.ingest_status import read_active_ingests

NO_CONTENT = {"0-byte": b"", "whitespace": b" \n\t\r\n  \n", "bom": b"\xef\xbb\xbf",
              "bom-whitespace": b"\xef\xbb\xbf \n\n"}  # fmt: skip
NOT_JSON = {"garbage": b"{not json\n", "comments": b"# a comment\n#\n",
            "nbsp": "\u00a0\n".encode(), "x1c": b"\x1c\x1d\x1e\x1f\n",
            "ideographic-space": "\u3000".encode(), "nul": b"\0\0\0"}  # fmt: skip


def _file(tmp_path, content: bytes):
    f = tmp_path / "result.json"
    f.write_bytes(content)
    return f


@pytest.mark.parametrize("content", NO_CONTENT.values(), ids=NO_CONTENT.keys())
def test_a_file_with_no_content_is_detected_as_empty(tmp_path, content):
    assert pj._detect_json_format(_file(tmp_path, content)) == "empty"


@pytest.mark.parametrize("content", NO_CONTENT.values(), ids=NO_CONTENT.keys())
def test_a_file_with_no_content_ingests_as_zero_rows(tmp_path, content):
    client = mock.MagicMock()
    assert pj.ingest_json(_file(tmp_path, content), client, "x", "h") == (0, 0, 0, 0)
    assert not client.mock_calls


@pytest.mark.parametrize("content", NOT_JSON.values(), ids=NOT_JSON.keys())
def test_a_file_with_content_that_is_not_json_stays_an_error(tmp_path, content):
    f = _file(tmp_path, content)
    assert pj._detect_json_format(f) == "unknown"
    with pytest.raises(ValueError, match="Cannot detect JSON format"):
        pj.ingest_json(f, mock.MagicMock(), "x", "h")


CHUNK = 65536  # _no_content reads this many bytes at a time
ACROSS_A_CHUNK = {"spaces-70k": (b" " * 70000, "empty"),
                  "spaces-then-nbsp": (b" " * CHUNK + " ".encode(), "unknown"),
                  "bom-newlines-then-x": (NO_CONTENT["bom"] + b"\n" * CHUNK + b"x", "unknown"),
                  }  # fmt: skip


@pytest.mark.parametrize("content,fmt", ACROSS_A_CHUNK.values(), ids=ACROSS_A_CHUNK.keys())
def test_content_past_the_first_read_is_still_seen(tmp_path, content, fmt):
    assert pj._detect_json_format(_file(tmp_path, content)) == fmt


@pytest.mark.parametrize("content", [NO_CONTENT["0-byte"], NO_CONTENT["bom"]], ids=["0", "bom"])
def test_the_preview_of_a_file_with_no_content_says_empty(env, content):  # noqa: F811
    f = env.cases["INC-RP1"] / "evidence" / "none.json"
    f.write_bytes(content)
    preview = srv.idx_ingest_json(path=str(f), hostname="h1", dry_run=True)
    assert preview == {"status": "preview", "file": "none.json", "format": "empty"}, preview


# -- the demo's shape: a Velociraptor result file ingested on its own for a host
VR_RESULT = "F.CF9K2SUB86DNA.json"


def _ingest_one(env, monkeypatch, tmp_path, content: bytes):  # noqa: F811
    from opensearch_mcp import ingest_cli as cli
    from opensearch_mcp import ingest_status

    f = env.cases["INC-RP1"] / "evidence" / VR_RESULT
    f.write_bytes(content)
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setattr(ingest_status, "read_active_ingests", read_active_ingests)  # env stubs it
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-empty")
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "INC-RP1")
    monkeypatch.setattr(cli, "_load_case_host_dict", lambda *a, **k: None)
    for n in ("get_client", "_preflight_shard_capacity", "_ensure_case_active", "_run_writer"):
        monkeypatch.setattr(cli, n, mock.MagicMock())
    args = dict(case=None, time_field=None, time_from=None, time_to=None, batch_size=1000,
                dry_run=False, index_suffix=None)  # fmt: skip
    try:
        cli.cmd_ingest_json(argparse.Namespace(path=str(f), hostname="wkstn05", **args))
    except SystemExit:
        pass  # a failed run exits non-zero; the status says why
    (status,) = srv.idx_ingest_status(case_id="INC-RP1")["ingests"]
    return status


@pytest.mark.parametrize("content", NO_CONTENT.values(), ids=NO_CONTENT.keys())
def test_a_result_with_no_content_is_a_complete_ingest_of_0(env, monkeypatch, tmp_path, content):  # noqa: F811
    s = _ingest_one(env, monkeypatch, tmp_path, content)
    assert (s["status"], s["total_indexed"]) == ("complete", 0), s
    assert s["message"].startswith("Ingest complete. 0 new docs across 1 host(s)"), s
    ((host, art, row, detail),) = [tuple(c.values()) for c in s["checklist"]]
    assert (host, art, row) == ("wkstn05", "json", "done") and "0 files not read" in detail
    assert not s.get("warnings") and not s.get("halt_reason"), s


@pytest.mark.parametrize("content", NOT_JSON.values(), ids=NOT_JSON.keys())
def test_a_result_that_is_not_json_still_fails_to_be_read(env, monkeypatch, tmp_path, content):  # noqa: F811
    s = _ingest_one(env, monkeypatch, tmp_path, content)
    assert s["status"] == "failed" and s["message"].startswith("Ingest failed: no_file_read"), s
    ((host, art, row, detail),) = [tuple(c.values()) for c in s["checklist"]]
    assert (host, art, row) == ("wkstn05", "json", "failed")
    assert f"Cannot detect JSON format in {VR_RESULT}" in detail
