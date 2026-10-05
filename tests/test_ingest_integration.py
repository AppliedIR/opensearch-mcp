"""Integration tests requiring OpenSearch Docker container.

All tests are marked with @pytest.mark.integration and will be skipped
when OpenSearch is not running.

To run: pytest tests/test_ingest_integration.py -m integration
"""

from __future__ import annotations

import csv
import time
import uuid

import _scratch_templates
import pytest

# Skip entire module if opensearchpy is not installed
opensearchpy = pytest.importorskip("opensearchpy")


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def scratch():
    """An OpenSearch client and a run tag, or skip if no cluster is available.

    Integration tests create indices directly without going through MCP, so
    they install the tree's templates themselves, under the tag: the real
    installer would rewrite the live templates every case on the cluster uses.
    Test indices are named `case-{tag}-...` so only these copies match them.
    """
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        health = client.cluster.health()
        if health.get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception:
        pytest.skip("OpenSearch not available")
    tag = f"pytest-tpl-{uuid.uuid4().hex[:8]}"
    created = _scratch_templates.install(client, tag)
    try:
        yield client, tag
    finally:
        client.indices.delete(index=f"case-{tag}-*", ignore=[404])
        _scratch_templates.remove(client, created)


@pytest.fixture
def os_client(scratch):
    return scratch[0]


@pytest.fixture
def tag(scratch):
    return scratch[1]


@pytest.fixture
def test_index(os_client, tag):
    """Create a unique test index and clean up after test."""
    index_name = f"case-{tag}-{uuid.uuid4().hex[:8]}-evtx-testhost"
    yield index_name
    # Cleanup
    try:
        os_client.indices.delete(index=index_name, ignore=[404])
    except Exception:
        pass


@pytest.fixture
def test_csv_index(os_client, tag):
    """Create a unique test index for CSV and clean up after."""
    index_name = f"case-{tag}-{uuid.uuid4().hex[:8]}-amcache-testhost"
    yield index_name
    try:
        os_client.indices.delete(index=index_name, ignore=[404])
    except Exception:
        pass


def _write_csv(path, rows, encoding="utf-8"):
    """Write rows as CSV."""
    with open(path, "w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def _wait_for_count(client, index, expected, timeout=10):
    """Wait for document count to reach expected value."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client.indices.refresh(index=index)
            r = client.count(index=index)
            if r["count"] >= expected:
                return r["count"]
        except Exception:
            pass
        time.sleep(0.5)
    client.indices.refresh(index=index)
    return client.count(index=index)["count"]


# ---------------------------------------------------------------------------
# Evtx integration tests
# ---------------------------------------------------------------------------


class TestEvtxIntegration:
    def test_search_returns_correct_results(self, os_client, test_index):
        """Documents indexed via bulk are searchable."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": f"doc-{i}",
                "_source": {
                    "event.code": 4624,
                    "host.name": "testhost",
                    "@timestamp": f"2024-01-15T10:0{i}:00Z",
                    "user.name": f"user{i}",
                    "pipeline_version": "test",
                },
            }
            for i in range(5)
        ]
        flushed, failed = flush_bulk(os_client, actions)
        assert flushed == 5
        assert failed == 0

        count = _wait_for_count(os_client, test_index, 5)
        assert count == 5

        # Search for specific event code
        result = os_client.search(
            index=test_index,
            body={"query": {"term": {"event.code": 4624}}},
        )
        assert result["hits"]["total"]["value"] == 5

    def test_count_matches_expected(self, os_client, test_index):
        """Count API returns correct document count."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": f"cnt-{i}",
                "_source": {"event.code": 1000 + i, "host.name": "testhost"},
            }
            for i in range(10)
        ]
        flush_bulk(os_client, actions)
        count = _wait_for_count(os_client, test_index, 10)
        assert count == 10

    def test_reingest_produces_same_count_dedup(self, os_client, test_index):
        """Re-ingest with same IDs produces same doc count (dedup works)."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": f"dedup-{i}",
                "_source": {"event.code": 4624, "host.name": "testhost"},
            }
            for i in range(5)
        ]

        # First ingest
        flush_bulk(os_client, actions)
        count1 = _wait_for_count(os_client, test_index, 5)
        assert count1 == 5

        # Second ingest (same IDs)
        flush_bulk(os_client, actions)
        os_client.indices.refresh(index=test_index)
        count2 = os_client.count(index=test_index)["count"]
        assert count2 == 5  # same count, dedup worked

    def test_provenance_fields_present(self, os_client, test_index):
        """Every document has provenance fields present and searchable."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "prov-1",
                "_source": {
                    "event.code": 4624,
                    "host.name": "testhost",
                    "vhir.source_file": "/evidence/Security.evtx",
                    "vhir.ingest_audit_id": "audit-001",
                    "pipeline_version": "opensearch-mcp-0.1.0",
                },
            }
        ]
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 1)

        doc = os_client.get(index=test_index, id="prov-1")
        src = doc["_source"]
        assert src["pipeline_version"] == "opensearch-mcp-0.1.0"
        assert src["vhir.source_file"] == "/evidence/Security.evtx"
        assert src["vhir.ingest_audit_id"] == "audit-001"

    def test_vhir_source_file_searchable(self, os_client, test_index):
        """vhir.source_file is searchable via term query."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "sf-1",
                "_source": {
                    "event.code": 4624,
                    "vhir.source_file": "/evidence/Security.evtx",
                },
            }
        ]
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 1)

        # vhir.source_file is keyword type — use term (exact) or wildcard
        result = os_client.search(
            index=test_index,
            body={"query": {"term": {"vhir.source_file": "/evidence/Security.evtx"}}},
        )
        assert result["hits"]["total"]["value"] >= 1

    def test_aggregation_on_host_name(self, os_client, test_index):
        """Aggregation on host.name works correctly."""
        from opensearch_mcp.bulk import flush_bulk

        actions = []
        for i in range(10):
            host = "host-a" if i < 6 else "host-b"
            actions.append(
                {
                    "_index": test_index,
                    "_id": f"agg-{i}",
                    "_source": {"event.code": 4624, "host.name": host},
                }
            )
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 10)

        result = os_client.search(
            index=test_index,
            body={
                "aggs": {"hosts": {"terms": {"field": "host.name"}}},
                "size": 0,
            },
        )
        buckets = result["aggregations"]["hosts"]["buckets"]
        bucket_dict = {b["key"]: b["doc_count"] for b in buckets}
        assert bucket_dict.get("host-a") == 6
        assert bucket_dict.get("host-b") == 4

    def test_time_range_filtering(self, os_client, test_index):
        """Time range query excludes events outside the range."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "tr-1",
                "_source": {
                    "event.code": 4624,
                    "@timestamp": "2024-01-10T00:00:00Z",
                },
            },
            {
                "_index": test_index,
                "_id": "tr-2",
                "_source": {
                    "event.code": 4624,
                    "@timestamp": "2024-01-15T12:00:00Z",
                },
            },
            {
                "_index": test_index,
                "_id": "tr-3",
                "_source": {
                    "event.code": 4624,
                    "@timestamp": "2024-01-20T00:00:00Z",
                },
            },
        ]
        flush_bulk(os_client, actions)
        _wait_for_count(os_client, test_index, 3)

        result = os_client.search(
            index=test_index,
            body={
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "2024-01-14",
                            "lte": "2024-01-16",
                        }
                    }
                }
            },
        )
        assert result["hits"]["total"]["value"] == 1

    def test_source_ip_accepts_valid_ip(self, os_client, test_index):
        """source.ip field accepts valid IP addresses."""
        from opensearch_mcp.bulk import flush_bulk

        actions = [
            {
                "_index": test_index,
                "_id": "ip-1",
                "_source": {
                    "event.code": 4624,
                    "source.ip": "192.168.1.100",
                },
            }
        ]
        flushed, failed = flush_bulk(os_client, actions)
        # If source.ip is mapped as 'ip' type, valid IPs should index fine
        assert flushed == 1 or failed == 0


# ---------------------------------------------------------------------------
# CSV integration tests
# ---------------------------------------------------------------------------


class TestCsvIntegration:
    def test_utf16le_csv_ingest(self, os_client, test_csv_index, tmp_path):
        """UTF-16LE CSV (PowerShell 5.1 format) ingests correctly."""
        from opensearch_mcp.parse_csv import ingest_csv

        csv_file = tmp_path / "test.csv"
        content = "Path,LastModified\nC:\\evil.exe,2024-01-15\nC:\\good.exe,2024-01-16\n"
        csv_file.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))

        count, sk, bf = ingest_csv(
            csv_path=csv_file,
            client=os_client,
            index_name=test_csv_index,
            hostname="testhost",
        )
        assert count == 2

        actual_count = _wait_for_count(os_client, test_csv_index, 2)
        assert actual_count == 2

    def test_mft_natural_key_dedup(self, os_client, tag, tmp_path):
        """MFT natural key dedup: same E:S:F:P = same doc."""
        from opensearch_mcp.parse_csv import ingest_csv

        index_name = f"case-{tag}-{uuid.uuid4().hex[:8]}-mft-testhost"
        try:
            csv_file = tmp_path / "mft.csv"
            rows = [
                {
                    "EntryNumber": "100",
                    "SequenceNumber": "5",
                    "FileName": "test.txt",
                    "ParentEntryNumber": "50",
                    "Created0x10": "2024-01-15",
                },
                {
                    "EntryNumber": "100",
                    "SequenceNumber": "5",
                    "FileName": "test.txt",
                    "ParentEntryNumber": "50",
                    "Created0x10": "2024-01-15",
                },
            ]
            _write_csv(csv_file, rows)

            natural_key = "EntryNumber:SequenceNumber:FileName:ParentEntryNumber"
            count, _, _ = ingest_csv(
                csv_path=csv_file,
                client=os_client,
                index_name=index_name,
                hostname="testhost",
                natural_key=natural_key,
            )

            actual = _wait_for_count(os_client, index_name, 1, timeout=5)
            # Both rows have same natural key -> should dedup to 1 doc
            assert actual == 1
        finally:
            try:
                os_client.indices.delete(index=index_name, ignore=[404])
            except Exception:
                pass


# ---------------------------------------------------------------------------
# idx_status integration
# ---------------------------------------------------------------------------


class TestIdxStatusIntegration:
    def test_idx_status_shows_case_indices(self, os_client, test_index):
        """idx_status returns case-* indices."""
        from opensearch_mcp.bulk import flush_bulk

        # Create a doc to make the index exist
        flush_bulk(os_client, [{"_index": test_index, "_id": "st-1", "_source": {"test": True}}])
        _wait_for_count(os_client, test_index, 1)

        indices = os_client.cat.indices(format="json")
        case_indices = [i for i in indices if i["index"].startswith("case-")]
        assert any(i["index"] == test_index for i in case_indices)


# ---------------------------------------------------------------------------
# Domain enrichment on keyword-only json and Zeek fields
# ---------------------------------------------------------------------------


class TestDomainFieldsKeywordOnly:
    """The real ingest path into names no other template's words match: the
    fields must come out keyword with no sub-field, or the row proves nothing
    (on a text + .keyword mapping the old field list already read them)."""

    def test_bare_domain_fields_are_extracted(self, os_client, tag, tmp_path):
        from opensearch_mcp.parse_delimited import ingest_delimited
        from opensearch_mcp.parse_json import ingest_json
        from opensearch_mcp.threat_intel import extract_unique_iocs

        base = f"case-{tag}-xa"
        dns = tmp_path / "dns.jsonl"
        dns.write_text('{"query": "q.evil.example.com", "dns": {"query": "d.evil.example.com"}}\n')
        ssl = tmp_path / "ssl.log"
        ssl.write_text(
            "#separator \\x09\n#fields\tts\tserver_name\n#types\ttime\tstring\n"
            "1700000000.0\ts.evil.example.com\n"
        )
        try:
            ingest_json(dns, os_client, f"{base}-json-dns-host1", "host1")
            ingest_delimited(ssl, os_client, f"{base}-zeek-ssl-host1", "host1")
            os_client.indices.refresh(index=f"{base}-*")
            for index, field in (
                (f"{base}-json-dns-host1", "query"),
                (f"{base}-json-dns-host1", "dns.query"),
                (f"{base}-zeek-ssl-host1", "server_name"),
            ):
                got = os_client.indices.get_field_mapping(index=index, fields=field)
                leaf = got[index]["mappings"][field]["mapping"][field.split(".")[-1]]
                assert leaf.get("type") == "keyword" and "fields" not in leaf, (
                    f"precondition: {index} {field} is {leaf}, not keyword-only"
                )
            found = extract_unique_iocs(os_client, f"{base}-*", force=True)["domain"]
            assert {
                "q.evil.example.com",
                "d.evil.example.com",
                "s.evil.example.com",
            } <= set(found)
        finally:
            os_client.indices.delete(index=f"{base}-*", ignore=[404])


# ---------------------------------------------------------------------------
# The MFT hint's queries on both MFT ingest paths
# ---------------------------------------------------------------------------


class TestMftHintClauses:
    """MFTECmd CSV through the csv path (text + .keyword) and the delimited
    path (keyword only). Names carry no other template's word; each mapping is
    asserted first, or the row proves nothing."""

    def test_each_hint_clause_finds_the_flagged_entry_on_both_paths(
        self, os_client, tag, tmp_path, monkeypatch
    ):
        from test_mft_hint import flag_clauses, mft_hint

        from opensearch_mcp.parse_csv import ingest_csv
        from opensearch_mcp.parse_delimited import ingest_delimited

        header = ["EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber"]
        header += ["FileName", "SI<FN", "uSecZeros", "HasAds"]
        rows = [
            dict(zip(header, ["100", "1", "False", "5", "evil.exe", "True", "True", "True"])),
            dict(zip(header, ["101", "1", "True", "5", "good.exe", "False", "False", "False"])),
        ]
        mft_csv = tmp_path / "mftout.csv"
        _write_csv(mft_csv, rows)
        base = f"case-{tag}-xb"
        indices = {"csv": f"{base}-mft-host1", "delimited": f"{base}-delim-mftout-host1"}
        try:
            ingest_csv(
                csv_path=mft_csv, client=os_client, index_name=indices["csv"], hostname="host1"
            )
            ingest_delimited(mft_csv, os_client, indices["delimited"], "host1")
            os_client.indices.refresh(index=f"{base}-*")
            for path, index in indices.items():
                for field in ("InUse", "SI<FN"):
                    got = os_client.indices.get_field_mapping(index=index, fields=field)
                    leaf = got[index]["mappings"][field]["mapping"][field]
                    want = ("text", True) if path == "csv" else ("keyword", False)
                    assert (leaf.get("type"), "fields" in leaf) == want, (
                        f"precondition: {index} {field} is {leaf}"
                    )
            clauses = flag_clauses(mft_hint(monkeypatch))
            assert len(clauses) == 4
            for path, index in indices.items():
                for clause in clauses:
                    body = {"query": {"query_string": {"query": clause}}}  # as idx_search
                    hits = os_client.search(index=index, body=body)["hits"]["hits"]
                    names = [h["_source"]["FileName"] for h in hits]
                    assert names == ["evil.exe"], (path, clause, names)
        finally:
            os_client.indices.delete(index=f"{base}-*", ignore=[404])

    def test_the_zone_clause_finds_only_exe_dll_ps1_zone_identifiers_on_both_paths(
        self, os_client, tag, tmp_path, monkeypatch
    ):
        """The clause as the hint gives it, on both paths. A file and
        its Zone.Identifier stream are separate rows; only the stream rows of
        .exe/.dll/.ps1 files are wanted. The shipped clause matched the files."""
        from test_mft_hint import mft_hint, zone_clause

        from opensearch_mcp.parse_csv import ingest_csv
        from opensearch_mcp.parse_delimited import ingest_delimited

        zone = "[ZoneTransfer]\nZoneId=3\n"
        want = [  # returned
            "node.exe:Zone.Identifier",
            "Tool64.exe:Zone.Identifier",  # a digit before the dot
            "dbghelp.dll:Zone.Identifier",
            "script.ps1:Zone.Identifier",
        ]
        not_wanted = [  # not returned
            ("evil.exe", "False", ""),  # a file, not a stream; empty ZoneIdContents
            ("builder.js:Zone.Identifier", "True", zone),
            ("Installer.exe:SmartScreen", "True", ""),
            ("notes-exe:Zone.Identifier", "True", zone),
            ("node.exe.Zone.Identifier", "False", ""),  # a file; "?" matched the "."
            ("script.ps1_Zone.Identifier", "False", ""),  # and the "_"
        ]
        header = ["EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber"]
        header += ["FileName", "IsAds", "ZoneIdContents"]
        planted = [(n, "True", zone) for n in want] + not_wanted
        rows = [
            dict(zip(header, [str(200 + i), "1", "True", "5", n, ads, z]))
            for i, (n, ads, z) in enumerate(planted)
        ]
        mft_csv = tmp_path / "mftout.csv"
        _write_csv(mft_csv, rows)
        base = f"case-{tag}-xc"
        indices = {"csv": f"{base}-mft-host1", "delimited": f"{base}-delim-mftout-host1"}
        try:
            ingest_csv(
                csv_path=mft_csv, client=os_client, index_name=indices["csv"], hostname="host1"
            )
            ingest_delimited(mft_csv, os_client, indices["delimited"], "host1")
            os_client.indices.refresh(index=f"{base}-*")
            for path, index in indices.items():
                got = os_client.indices.get_field_mapping(index=index, fields="FileName")
                leaf = got[index]["mappings"]["FileName"]["mapping"]["FileName"]
                want_map = ("text", True) if path == "csv" else ("keyword", False)
                assert (leaf.get("type"), "fields" in leaf) == want_map, (
                    f"precondition: {index} FileName is {leaf}"
                )
                count = os_client.count(index=index)["count"]
                assert count == len(planted), f"precondition: {index} holds {count}"
            clause = zone_clause(mft_hint(monkeypatch))
            for path, index in indices.items():
                body = {"query": {"query_string": {"query": clause}}, "size": 50}  # as idx_search
                hits = os_client.search(index=index, body=body)["hits"]["hits"]
                names = sorted(h["_source"]["FileName"] for h in hits)
                assert names == sorted(want), (path, clause, names)
        finally:
            os_client.indices.delete(index=f"{base}-*", ignore=[404])


# ---------------------------------------------------------------------------
# A failed artifact's partly written index is flagged
# ---------------------------------------------------------------------------

_RECMD_STUB = """#!{python}
import os, sys
out = sys.argv[sys.argv.index("--csv") + 1]
with open(os.path.join(out, "20261003000000_RECmd_Batch_Output.csv"), "w") as f:
    f.write("HivePath,KeyPath,ValueName,ValueData,LastWriteTimestamp\\n")
    for i in range(1500):
        big = os.environ["SR_BIG"] == "1" and i == 1200
        vd = "x" * (11 * 1024 * 1024) if big else f"v{{i}}"  # past csv.field_size_limit
        f.write(f"C:\\\\SYSTEM,ROOT\\\\Key{{i}},Val{{i}},{{vd}},2026-01-01 00:00:00\\n")
"""


# Where SIFT's tool .dlls and dotnet are installed, the tool's .dll is launched
# with dotnet; this dotnet hands that call to the stub named after the .dll.
_DOTNET_SHIM = '#!/bin/bash\nexec "$(dirname "$0")/$(basename "$1" .dll)" "${@:2}"\n'


class TestFailedArtifactWarning:
    """The real scan path with RECmd stubbed: its CSV fails to parse after the
    first 1,000 rows are flushed. Not a NUL: only Python 3.10 fails on that."""

    @pytest.fixture
    def scan(self, tmp_path, tag, monkeypatch):
        import os
        import shutil
        import subprocess
        import sys
        from pathlib import Path

        cid = f"{tag}-partial"
        case_dir = tmp_path / "cases" / cid
        (case_dir / "audit").mkdir(parents=True)
        (case_dir / "CASE.yaml").write_text(f"case_id: {cid}\n")
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        shutil.copy(Path.home() / ".vhir" / "opensearch.yaml", home / ".vhir")
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "RECmd").write_text(_RECMD_STUB.format(python=sys.executable))
        (bin_dir / "RECmd").chmod(0o755)
        (bin_dir / "dotnet").write_text(_DOTNET_SHIM)
        (bin_dir / "dotnet").chmod(0o755)
        monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))  # what the summary reads

        def run(host, fail):
            config = tmp_path / host / "Windows" / "System32" / "config"
            config.mkdir(parents=True, exist_ok=True)
            for hive in ("SYSTEM", "SOFTWARE"):
                (config / hive).write_bytes(b"regf" * 1024)
            env = {
                "HOME": str(home),
                "PATH": f"{bin_dir}:{Path(sys.executable).parent}:/usr/bin:/bin",
                "VHIR_CASE_DIR": str(case_dir),
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                "LANG": "C.UTF-8",
                "SR_BIG": "1" if fail else "0",
            }
            p = subprocess.run(
                [sys.executable, "-m", "opensearch_mcp.ingest_cli", "scan", str(tmp_path / host)]
                + ["--hostname", host, "--case", cid, "--include", "registry"]
                + ["--exclude", "shimcache,amcache,shellbags", "--yes", "--skip-triage"],
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
            )
            return p.stdout + p.stderr

        return cid, run  # its indices go with the module fixture's case-{tag}-* delete

    @staticmethod
    def incomplete(cid):
        from opensearch_mcp import server

        resp = server.idx_case_summary(case_id=cid)
        return [w for w in resp.get("warnings", []) if "may be incomplete" in w]

    def test_a_partial_failure_is_flagged_with_the_index_count(self, os_client, scan):
        cid, run = scan
        out = run("dev01", fail=True)
        index = f"case-{cid}-registry-dev01"
        os_client.indices.refresh(index=index)
        assert os_client.count(index=index)["count"] == 1000, out  # one flush, then the failure
        assert self.incomplete(cid) == [
            f"{index} (1,000 docs) may be incomplete: the most recent ingest of registry"
            " on dev01 failed (FAILED: field larger than field limit (10485760))"
        ], out

    def test_only_the_failed_host_and_only_until_it_succeeds(self, os_client, scan):
        cid, run = scan
        run("dev01", fail=True)
        out = run("dev02", fail=False)
        os_client.indices.refresh(index=f"case-{cid}-*")
        assert os_client.count(index=f"case-{cid}-registry-dev02")["count"] == 1500, out
        (warning,) = self.incomplete(cid)
        assert warning.startswith(f"case-{cid}-registry-dev01 (1,000 docs) may be incomplete")
        out = run("dev01", fail=False)
        os_client.indices.refresh(index=f"case-{cid}-*")
        assert self.incomplete(cid) == [], out
