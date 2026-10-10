"""A parser's Plaso fallback gives each record one id, whatever mounted it.

SrumECmd and PECmd fall back to Plaso, which reports the absolute path of the
file it read: under the run's temp folder and the volume's (or shadow copy's)
mount. The fallback now strips the volume root, as the whole-volume route
does, so the same record from another run or another store has the same id
and keep-first and live-first apply. Its records still get no @timestamp from
it. Plaso is a stand-in that writes JSONL the way it reports these records.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp import bulk, ingest_status, parse_plaso
from opensearch_mcp.discover import DiscoveredHost
from opensearch_mcp.ingest import ingest

SRUM = "Windows/System32/sru/SRUDB.dat"


@pytest.fixture
def status_dir(tmp_path, monkeypatch):
    path = tmp_path / "status"
    monkeypatch.setattr(ingest_status, "_STATUS_DIR", path)
    return path


def _volume(root: Path) -> Path:
    srum = root / SRUM
    srum.parent.mkdir(parents=True)
    srum.write_bytes(b"x")
    return root


def _plaso(parser, input_path, tmpdir):
    """Plaso's JSONL for one SRUM record: the absolute (resolved) path in
    filename, display_name and its event values hash."""
    path = str(Path(input_path).resolve())
    out = Path(tmpdir) / "out.jsonl"
    out.write_text(json.dumps({
        "data_type": "windows:srum:network_usage", "identifier": 3333,
        "timestamp": 1668233774935026, "filename": path, "display_name": f"OS:{path}",
        "_event_values_hash": f"hash-of-{path}", "pathspec": {"location": path},
    }) + "\n")  # fmt: skip
    return out


def _scan(roots: list[tuple[Path, str]]) -> list[dict]:
    """One ingest run over `roots` ((volume root, vss_id)): the records the
    SRUM fallback sends, as it sends them (before the write's stamp)."""
    sent: list[dict] = []

    def flush(client, actions, **k):
        sent.extend({"_id": a["_id"], **a["_source"]} for a in actions)
        return len(actions), 0

    hosts = []
    for root, vss in roots:
        host = DiscoveredHost(hostname="RD01", volume_root=root, vss_id=vss)
        host.artifacts.append(("srum", root / SRUM))
        hosts.append(host)
    audit = MagicMock()
    audit._next_audit_id.return_value = "aid-1"
    client = MagicMock()
    client.count.side_effect = Exception("no index")
    bulk.reset_circuit_breaker()
    with (
        patch("opensearch_mcp.ingest.sha256_file", return_value="h"),
        patch("opensearch_mcp.wintools.wintools_available", return_value=False),
        patch.object(parse_plaso, "_run_plaso", side_effect=_plaso),
        patch.object(parse_plaso, "flush_bulk", side_effect=flush),
    ):
        ingest(hosts=hosts, client=client, audit=audit, case_id="c1", include={"srum"},
               status_pid=os.getpid(), status_run_id=f"run-{uuid.uuid4().hex[:6]}")  # fmt: skip
    return sent


def test_two_runs_with_their_own_temp_folders_give_one_id(tmp_path, status_dir):
    first = _scan([(_volume(tmp_path / "tmp" / "ingest-A" / "vol2"), "")])
    again = _scan([(_volume(tmp_path / "tmp" / "ingest-B" / "vol2"), "")])
    assert len(first) == len(again) == 1
    assert first[0]["_id"] == again[0]["_id"]


def test_the_live_volume_and_a_shadow_copy_give_one_id(tmp_path, status_dir):
    """Equal ids: the write's live-first rule keeps the live record."""
    run = tmp_path / "tmp" / "ingest-A"
    sent = _scan([(_volume(run / "vol2"), "live"), (_volume(run / "vss1"), "vss1")])
    assert len(sent) == 2 and sent[0]["_id"] == sent[1]["_id"]
    assert [s["vhir.vss_id"] for s in sent] == ["live", "vss1"]


def test_the_records_name_the_path_on_the_evidence_and_keep_no_timestamp(tmp_path, status_dir):
    (sent,) = _scan([(_volume(tmp_path / "tmp" / "ingest-A" / "vol2"), "")])
    assert sent["vhir.source_file"] == SRUM
    assert sent["filename"] == SRUM
    assert "@timestamp" not in sent  # ids only: the fallback's records keep none
