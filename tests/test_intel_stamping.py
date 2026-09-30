"""Stamping reaches every document carrying an extracted IOC.

Stamping matched a document by a term on the LOOKUP value in each listed
field. The lookup value is lower-cased, and a Sysmon `Hashes` part is stored
inside the whole string, so an upper-case Kansa hash and every Sysmon hash
were extracted and looked up but never stamped. It now matches each
(field, value as stored) pair extraction recorded.

Values are derived (hashes of fixed strings, public resolver addresses).
"""

from __future__ import annotations

import hashlib

import pytest
from _intel_case import intel_case
from _intel_gateway import FakeGateway, not_found

from opensearch_mcp import threat_intel


def _h(algo: str, text: str) -> str:
    return hashlib.new(algo, text.encode()).hexdigest()


PSLIST = {"MD5": _h("md5", "ps"), "SHA1": _h("sha1", "ps"), "SHA256": _h("sha256", "ps")}
KANSA = _h("md5", "kansa").upper()
SYSMON_MD5 = _h("md5", "sysmon").upper()
SYSMON_SHA256 = _h("sha256", "sysmon").upper()
SYSMON = f"MD5={SYSMON_MD5},SHA256={SYSMON_SHA256},IMPHASH={_h('md5', 'imp').upper()}"
AMCACHE = _h("sha1", "amcache")
BODYFILE = _h("md5", "bodyfile")

# Three documents per source, so "every carrying document" is more than one.
DOCS = {
    "json-pslist": [{"Pid": i, "Hash": PSLIST} for i in range(3)],
    # As in the real data (16 of Kansa's 23 hashes are also pslist's): the same
    # MD5 stored upper-case by Kansa and lower-case by pslist.
    "delim-procswmi": [
        {"ProcessId": "1", "Hash": PSLIST["MD5"].upper()},
        {"ProcessId": "2", "Hash": PSLIST["MD5"].upper()},
        {"ProcessId": "3", "Hash": KANSA},
    ],
    "winevt-sysmon": [{"winlog": {"event_data": {"Hashes": SYSMON}}} for _ in range(3)],
    # Sysmon hashing MD5 only, of the same file pslist and Kansa saw: this
    # document carries one IOC, stored under a third field.
    "winevt-sysmonmd5": [
        {"winlog": {"event_data": {"Hashes": f"MD5={PSLIST['MD5'].upper()}"}}} for _ in range(3)
    ],
    "amcache-dev01": [{"SHA1": AMCACHE} for _ in range(3)],  # live csv template
    "delim-netstat": [{"ForeignAddress": "8.8.8.8"} for _ in range(3)],
    "winevt-network": [{"winlog": {"event_data": {"DestinationIp": "1.1.1.1"}}} for _ in range(3)],
    "winevt-logon": [{"winlog": {"event_data": {"IpAddress": "9.9.9.9"}}} for _ in range(3)],
    "winevt-ecs": [{"source": {"ip": "8.8.4.4"}} for _ in range(3)],
    "delim-ecs": [{"source.ip": "8.8.4.4"} for _ in range(3)],
    "winevt-dns": [{"winlog": {"event_data": {"QueryName": "Example.COM"}}} for _ in range(3)],
    "delim-bodyfile": [{"name": f"/f{i}", "md5": BODYFILE} for i in range(3)],
}

# index name -> the lookup values its documents carry
CARRIED = {
    "json-pslist": {PSLIST["MD5"], PSLIST["SHA1"], PSLIST["SHA256"]},
    "delim-procswmi": {PSLIST["MD5"], KANSA.lower()},
    "winevt-sysmon": {SYSMON_MD5.lower(), SYSMON_SHA256.lower()},
    "winevt-sysmonmd5": {PSLIST["MD5"]},
    "amcache-dev01": {AMCACHE},
    "delim-netstat": {"8.8.8.8"},
    "winevt-network": {"1.1.1.1"},
    "winevt-logon": {"9.9.9.9"},
    "winevt-ecs": {"8.8.4.4"},
    "delim-ecs": {"8.8.4.4"},
    "winevt-dns": {"example.com"},
    "delim-bodyfile": {BODYFILE},
}


@pytest.fixture(scope="module")
def os_client():
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
        return client
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")


@pytest.fixture(scope="module")
def enriched(os_client):
    """One case with every source, enriched once through the real pipeline."""
    mp = pytest.MonkeyPatch()
    try:
        with intel_case(os_client, DOCS, prefix="pytest-stamp") as case_id:
            import tempfile
            from pathlib import Path

            cov = Path(tempfile.mkdtemp()) / "cov.json"
            mp.setenv("VHIR_INTEL_MIN_INTERVAL_MS", "10")
            mp.setattr(threat_intel, "_coverage_path_for_run", lambda run: cov)
            gateway = FakeGateway(not_found).install(mp)
            threat_intel.enrich_case(os_client, case_id, include_filesystem=True)
            os_client.indices.refresh(index=f"case-{case_id}-*")
            yield os_client, case_id, gateway
    finally:
        mp.undo()


@pytest.mark.integration
class TestEveryCarryingDocumentIsStamped:
    @pytest.mark.parametrize("name", sorted(DOCS))
    def test_per_source(self, enriched, name):
        client, case_id, gateway = enriched
        index = f"case-{case_id}-{name}"
        assert CARRIED[name] <= set(gateway.asked), "control: the values were looked up"
        hits = client.search(index=index, body={"size": 10})["hits"]["hits"]
        assert len(hits) == 3
        for hit in hits:
            source = hit["_source"]
            assert source.get("threat_intel.checked") is True, (name, source)
            assert source.get("threat_intel.ioc_value") in CARRIED[name], (name, source)
