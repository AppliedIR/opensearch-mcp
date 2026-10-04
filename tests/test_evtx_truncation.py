"""An evtx file cut short is reported, and what it holds is still indexed.

The parser walks whole 64 KiB chunks by file size: it silently drops a
partial last chunk and never compares the file with the chunk count its
header declares. A copied or carved file that ended early was ingested as
complete with no warning. The files here are synthetic: an evtx signature
and a chunk count in an otherwise empty header, with the real geometry.
"""

from __future__ import annotations

import os
import struct
from unittest.mock import MagicMock, patch

import pytest
from test_evtx_dropped_status import _scan

from opensearch_mcp import ingest_status
from opensearch_mcp import server as srv
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

CHUNK = 65536


def _evtx(path, declared: int, size: int, signature: bytes = b"ElfFile\x00"):
    header = bytearray(4096)
    header[:8] = signature
    struct.pack_into("<H", header, 42, declared)  # the header's chunk count
    path.write_bytes(bytes(header) + b"\0" * (size - 4096))
    return path


@pytest.mark.parametrize(
    "declared,size,want",
    [
        (20, 1_000_000, ["ends mid-chunk at byte 1,000,000", "15 of 20 declared chunks present"]),
        (20, 4096 + 10 * CHUNK, ["10 of 20 declared chunks present"]),
        # a live log's count is often stale: 22 chunks are there, 20 declared
        (20, 1_500_000, ["ends mid-chunk at byte 1,500,000"]),
        (20, 4096 + 33 * CHUNK, []),  # whole chunks, more than declared: intact
        (20, 4096 + 20 * CHUNK, []),
    ],
    ids=[
        "mid-chunk and short",
        "short on a chunk boundary",
        "mid-chunk above a stale count",
        "anchor more than declared",
        "anchor exactly declared",
    ],
)
def test_each_way_a_file_is_cut_short_is_named(tmp_path, declared, size, want):
    from opensearch_mcp.parse_evtx import evtx_truncation

    assert evtx_truncation(_evtx(tmp_path / "Security.evtx", declared, size)) == want


def test_a_file_without_the_evtx_signature_is_left_to_the_parser(tmp_path):
    from opensearch_mcp.parse_evtx import evtx_truncation

    bad = _evtx(tmp_path / "Security.evtx", 20, 1_000_000, signature=b"\0" * 8)
    assert evtx_truncation(bad) == []  # the parser fails it, as before


# --- Through ingest and the status an examiner reads ----------------------


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    evtx = tmp_path / "evtx"
    evtx.mkdir()
    h = DiscoveredHost(hostname="HOST1", volume_root=tmp_path)
    h.evtx_dir = evtx
    return h


def _ingest(host):
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    with (
        patch("opensearch_mcp.ingest.parse_and_index", return_value=(1206, 0, 0)) as parse,
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
    ):
        result = ingest(
            hosts=[host],
            client=client,
            audit=audit,
            case_id="c1",
            status_pid=os.getpid(),
            status_run_id="run-cut",
        )
    (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
    summaries = [c.kwargs["result_summary"] for c in audit.log.call_args_list]
    return result, parse, status, summaries


def test_a_cut_file_is_indexed_and_named_in_the_status_and_audit(host):
    _evtx(host.evtx_dir / "Security.evtx", 20, 1_000_000)
    result, parse, status, summaries = _ingest(host)
    assert parse.called and result.hosts[0].artifacts[0].indexed == 1206  # still indexed
    assert status["status"] == "complete"  # no new run status
    cut = "ends mid-chunk at byte 1,000,000; 15 of 20 declared chunks present"
    assert [w for w in status.get("warnings", []) if "cut short" in w] == [
        "HOST1: 1 evtx file(s) are cut short: records past the cut, and any in a partial "
        f"last chunk, were not indexed (Security.evtx: {cut})"
    ]
    assert summaries == [f"1206 indexed, 0 skipped, truncated: {cut}"]


def test_anchor_an_intact_file_reads_as_before(host):
    _evtx(host.evtx_dir / "Security.evtx", 20, 4096 + 33 * CHUNK)
    _, _, status, summaries = _ingest(host)
    assert not [w for w in status.get("warnings", []) if "cut short" in w]
    assert summaries == ["1206 indexed, 0 skipped"]


@pytest.mark.parametrize("hayabusa", [True, False])
def test_the_final_status_names_a_cut_file(host, monkeypatch, hayabusa):
    # the hayabusa phase rebuilds the status from the host's result
    _evtx(host.evtx_dir / "Security.evtx", 20, 4096 + 10 * CHUNK)
    warnings = _scan(host, monkeypatch, hayabusa)
    assert [w for w in warnings if "cut short" in w] == [
        "HOST1: 1 evtx file(s) are cut short: records past the cut, and any in a partial "
        "last chunk, were not indexed (Security.evtx: 10 of 20 declared chunks present)"
    ]


def test_every_cut_file_on_a_host_is_named(host):
    _evtx(host.evtx_dir / "Security.evtx", 20, 1_000_000)
    _evtx(host.evtx_dir / "System.evtx", 20, 4096 + 10 * CHUNK)
    _, _, status, _ = _ingest(host)
    assert [w for w in status.get("warnings", []) if "cut short" in w] == [
        "HOST1: 2 evtx file(s) are cut short: records past the cut, and any in a partial "
        "last chunk, were not indexed (Security.evtx: ends mid-chunk at byte 1,000,000; "
        "15 of 20 declared chunks present, System.evtx: 10 of 20 declared chunks present)"
    ]
