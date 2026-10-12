"""EZ-tool dates are read as dates, and an ingest into an index made before
0.6.5 says so.

The EZ tools write dates as `2023-01-21 13:00:59.3935272` (AppCompatCacheParser
without the fraction), which the default date format doesn't parse, so every
value went to `_ignored`. The csv template's 10 date fields now carry a format
list that parses them, ISO first. A date format can't change in place, so an
index made before 0.6.5 keeps the old mapping: the scan route says so once per
index it targets, whether or not the run stored a record.

The template strings and the mapping check are exact here; how OpenSearch
parses, prints and bounds them is measured on a real cluster, not a fake.
"""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import ingest_cli as cli
from opensearch_mcp import mappings as mp

FORMAT = (
    "strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSSSSSS||yyyy-MM-dd HH:mm:ss||epoch_millis"
)
EZ_DATES = sorted([
    "Created0x10", "DeletedOn", "FileKeyLastWriteTimestamp", "LastInteracted", "LastModified",
    "LastModifiedTime", "LastModifiedTimeUTC", "LastWriteTimestamp", "TargetModified",
    "UpdateTimestamp",
])  # fmt: skip


def _csv_template() -> dict:
    return json.loads((mp._MAPPINGS_DIR / "csv_template.json").read_text())


def test_every_ez_date_field_carries_the_format_list():
    props = _csv_template()["template"]["mappings"]["properties"]
    formatted = {f: p.get("format") for f, p in props.items() if f in EZ_DATES}
    assert formatted == dict.fromkeys(EZ_DATES, FORMAT)
    assert all(props[f]["type"] == "date" and props[f]["ignore_malformed"] for f in EZ_DATES)
    assert "format" not in props["threat_intel.enriched_at"]


def mapping(fmt=None, field_type="date"):
    """A client whose every index maps the 10 EZ date fields so: with `fmt`,
    or none as a 0.6.4 index; or as `field_type`."""
    props = {f: {"type": field_type, **({"format": fmt} if fmt else {})} for f in EZ_DATES}
    client = MagicMock()
    client.indices.get_mapping.side_effect = lambda index=None, **k: {
        index: {"mappings": {"properties": dict(props)}}
    }
    return client


def test_an_index_made_before_0_6_5_has_every_ez_date_field_stale():
    assert mp.stale_date_fields(mapping(), "case-x-mft-0") == EZ_DATES


def test_an_index_made_from_this_template_has_none():
    assert mp.stale_date_fields(mapping(FORMAT), "case-x-mft-0") == []


def test_a_mapping_that_cant_be_read_is_none():
    client = MagicMock()
    client.indices.get_mapping.side_effect = RuntimeError("no cluster")
    assert mp.stale_date_fields(client, "case-x-mft-0") is None


def test_text_dates_are_not_counted():
    """An index 0.6.4's CLI made without a template maps them as text: not
    this check's (the text-field repair names those)."""
    assert mp.stale_date_fields(mapping(field_type="text"), "case-x-mft-0") == []


# --- the scan route's note --------------------------------------------------

EXAMPLE = {  # each tool's own time field names the example
    "amcache": "FileKeyLastWriteTimestamp", "shimcache": "LastModifiedTimeUTC",
    "recyclebin": "DeletedOn",
}  # fmt: skip


@pytest.fixture
def ez_scan(tmp_path, monkeypatch):
    """`run(client, stored, hosts)`: a scan of `hosts` (each with an amcache,
    shimcache and recyclebin artifact) against `client`, the EZ tool runs
    standing in and each storing `stored` records; returns its status."""
    from opensearch_mcp import ingest as ing
    from opensearch_mcp import ingest_status
    from opensearch_mcp import server as srv
    from opensearch_mcp.discover import DiscoveredHost

    monkeypatch.setattr(ingest_status, "_STATUS_DIR", tmp_path / "status")
    monkeypatch.setenv("VHIR_INGEST_RUN_ID", "run-ez")
    monkeypatch.setattr(ingest_status, "_is_process_alive", lambda pid, run_id: True)
    for name in ("_preflight_shard_capacity", "_ensure_case_active", "AuditWriter"):
        monkeypatch.setattr(cli, name, MagicMock())
    monkeypatch.setattr(cli, "_resolve_case_id", lambda c: "c1")
    monkeypatch.setattr(ing, "sha256_file", lambda p: "h")

    def run(client, stored, hosts=("dev01",)):
        found = []
        for h in hosts:
            root = tmp_path / "M" / h
            root.mkdir(parents=True, exist_ok=True)
            host = DiscoveredHost(hostname=h, volume_root=root)
            for a in EXAMPLE:
                (root / a).write_bytes(b"x")
                host.artifacts.append((a, root / a))
            found.append(host)
        monkeypatch.setattr(cli, "discover", lambda *a, **k: found)
        monkeypatch.setattr(cli, "get_client", lambda *a, **k: client)
        monkeypatch.setattr(ing, "run_and_ingest", lambda **kw: (stored, 0, 0))
        args = argparse.Namespace(path=str(tmp_path), case="c1", yes=True, all_logs=False,
                                  hostname=None if len(hosts) > 1 else hosts[0],
                                  no_hayabusa=True, skip_triage=True)  # fmt: skip
        cli.cmd_scan(args)
        (status,) = srv.idx_ingest_status(case_id="c1")["ingests"]
        return status

    return run


def note(host, index, example):
    return (f"{host}: {index} was made before 0.6.5, so its EZ date fields (e.g. {example}) "
            "aren't read as dates: date-range queries and timelines on them miss its records. "
            "Fix: delete the index and re-ingest, then re-run "
            "idx_enrich_triage/intel")  # fmt: skip


def _said(status):
    return [w for w in status.get("warnings", []) if "was made before 0.6.5" in w]


@pytest.mark.parametrize("stored", [10, 0], ids=["first-ingest", "nothing-new"])
def test_a_scan_into_indices_made_before_0_6_5_says_so_once_per_index(ez_scan, stored):
    """Once per index the run targets, whether or not it stored a record."""
    said = _said(ez_scan(mapping(), stored))
    assert len(said) == len(EXAMPLE)
    for artifact, example in EXAMPLE.items():
        (line,) = [w for w in said if f"-{artifact}-0 was made" in w]
        index = line.split(": ", 1)[1].split(" was made")[0]
        assert line == note("dev01", index, example)


def test_two_hosts_into_one_index_are_said_once(ez_scan):
    said = _said(ez_scan(mapping(), 10, hosts=("dev01", "dev02")))
    assert len(said) == len(EXAMPLE)  # dev02 wrote to the same indices


def test_a_scan_into_indices_made_from_this_template_says_nothing(ez_scan):
    assert _said(ez_scan(mapping(FORMAT), 10)) == []
