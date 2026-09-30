"""IOC extraction reads the fields the evidence uses.

On three real cases (FOR508 pslist, Kansa, bodyfile, Sysmon/Security evtx)
extraction returned 0 IPs, 0 hashes and 0 domains: the evidence held them
under names the field lists never read. Each record below has the shape of
one real source; the values are DERIVED (hashes of fixed strings, public
resolver addresses, example.com), not taken from evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opensearch_mcp import threat_intel
from opensearch_mcp.threat_intel import extract_unique_iocs

_MAPPINGS_DIR = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"


def _h(algo: str, text: str) -> str:
    return hashlib.new(algo, text.encode()).hexdigest()


# Derived values, one set per source.
PSLIST = {
    "MD5": _h("md5", "pslist"),
    "SHA1": _h("sha1", "pslist"),
    "SHA256": _h("sha256", "pslist"),
}
KANSA_MD5 = _h("md5", "kansa").upper()  # ProcsWMI writes upper case
SYSMON_MD5 = _h("md5", "sysmon").upper()
SYSMON_SHA256 = _h("sha256", "sysmon").upper()
IMPHASH = _h("md5", "imphash").upper()
SYSMON_HASHES = f"MD5={SYSMON_MD5},SHA256={SYSMON_SHA256},IMPHASH={IMPHASH}"
AMCACHE_SHA1 = _h("sha1", "amcache")
BODYFILE_MD5 = _h("md5", "bodyfile")
PREFETCH_PATH_HASH = "1A2B3C4D"  # PECmd's hash of the executable's path

DEFAULT_HASHES = {
    PSLIST["MD5"],
    PSLIST["SHA1"],
    PSLIST["SHA256"],
    KANSA_MD5.lower(),
    SYSMON_MD5.lower(),
    SYSMON_SHA256.lower(),
    AMCACHE_SHA1,
}
EXTERNAL_IPS = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"}

# The evtx template maps winlog.event_data.* strings `keyword` and source.ip
# `ip`; this mirrors the fields read here.
EVTX_MAPPING = {
    "properties": {
        "source": {"properties": {"ip": {"type": "ip"}}},
        "winlog": {
            "properties": {
                "event_data": {
                    "properties": {
                        name: {"type": "keyword"}
                        for name in (
                            "Hashes",
                            "QueryName",
                            "IpAddress",
                            "SourceIp",
                            "DestinationIp",
                        )
                    }
                }
            }
        },
    }
}


# ---------------------------------------------------------------------------
# No cluster
# ---------------------------------------------------------------------------


class TestSysmonHashes:
    def test_keeps_md5_sha1_sha256_and_drops_imphash(self):
        value = "SHA1=AA,MD5=BB,SHA256=CC,IMPHASH=DD"
        assert threat_intel._sysmon_hashes(value) == ["AA", "BB", "CC"]

    def test_tolerates_spaces_and_case(self):
        assert threat_intel._sysmon_hashes(" md5 = BB , imphash=DD") == ["BB"]


class TestLookupForm:
    @pytest.mark.parametrize(
        "ioc_type,value,expected",
        [
            ("hash", "ABCDEF0123456789ABCDEF0123456789", "abcdef0123456789abcdef0123456789"),
            ("ip", "2001:DB8::1", "2001:db8::1"),
            ("domain", "Example.COM", "example.com"),
            ("hash", "3:AbC+/x:AbC", "3:AbC+/x:AbC"),  # SSDEEP is base64: case is meaning
        ],
    )
    def test_case_is_folded_only_where_it_carries_no_meaning(self, ioc_type, value, expected):
        assert threat_intel._lookup_form(ioc_type, value) == expected


class TestAFailedRequestRaises:
    def test_an_exception_on_one_field(self):
        """Skipped, it read as "no IOCs" for that field."""
        field = threat_intel._HASH_FIELDS[0]

        def search(**kw):
            if kw["body"]["aggs"]["values"]["terms"]["field"] == field:
                raise RuntimeError("503 unavailable")
            return {"aggregations": {"values": {"buckets": []}}}

        client = MagicMock()
        client.search.side_effect = search
        with pytest.raises(threat_intel.IOCExtractionError, match=field):
            extract_unique_iocs(client, "case-x-*")


class TestIsExternal:
    @pytest.mark.parametrize(
        "address", ["224.0.0.251", "239.255.255.250", "224.0.0.22", "ff02::fb"]
    )
    def test_multicast_is_not_external(self, address):
        """`is_global` is True for these; Sysmon DestinationIp and Kansa ARP
        carry them."""
        assert threat_intel._is_external(address) is False

    @pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:3031::ac43:d701"])
    def test_a_routable_unicast_address_is(self, address):
        assert threat_intel._is_external(address) is True


# ---------------------------------------------------------------------------
# Cluster rows, through the shipped json / delimited composition
# ---------------------------------------------------------------------------


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
def case(os_client):
    """One case holding every source, each in the index kind that produces it."""
    tag = f"pytest-extract-{uuid.uuid4().hex[:8]}"
    component = json.loads((_MAPPINGS_DIR / "json_type_stability.json").read_text())
    os_client.cluster.put_component_template(name=f"{tag}-comp", body=component)
    for kind, filename in (("json", "json_template.json"), ("delim", "delimited_template.json")):
        body = copy.deepcopy(json.loads((_MAPPINGS_DIR / filename).read_text()))
        body["template"].pop("aliases", None)
        body["index_patterns"] = [f"{tag}-{kind}-*"]
        body["composed_of"] = [f"{tag}-comp"]
        body["priority"] = 900
        os_client.indices.put_index_template(name=f"{tag}-{kind}", body=body)
    os_client.indices.create(index=f"{tag}-evtx-dev01", body={"mappings": EVTX_MAPPING})

    docs = {
        f"{tag}-json-pslist": [{"Pid": 4, "Name": "a.exe", "Hash": PSLIST}],
        f"{tag}-delim-procswmi": [{"ProcessName": "b.exe", "Hash": KANSA_MD5}],
        f"{tag}-delim-prefetch": [{"ExecutableName": "C.EXE", "Hash": PREFETCH_PATH_HASH}],
        f"{tag}-delim-bodyfile": [{"name": "/Windows/x.dll", "md5": BODYFILE_MD5}],
        f"{tag}-csv-amcache": [{"SHA1": AMCACHE_SHA1}],  # no template: text + .keyword
        # Derived network evidence: Kansa netstat, Sysmon 3 and 22, a logon.
        f"{tag}-delim-netstat": [{"ForeignAddress": "8.8.8.8", "LocalAddress": "10.0.0.5"}],
        f"{tag}-evtx-dev01": [
            {"winlog": {"event_data": {"Hashes": SYSMON_HASHES}}},
            {"winlog": {"event_data": {"SourceIp": "10.0.0.5", "DestinationIp": "1.1.1.1"}}},
            {
                "winlog": {
                    "event_data": {"SourceIp": "10.0.0.5", "DestinationIp": "239.255.255.250"}
                }
            },
            {"winlog": {"event_data": {"QueryName": "Example.COM"}}},
            {"winlog": {"event_data": {"IpAddress": "9.9.9.9"}}},
            {"source": {"ip": "8.8.4.4"}},
        ],
        # The same field as the evtx `source.ip`, from an ECS-header CSV —
        # with netstat's unbound-address forms.
        f"{tag}-delim-ecs": [{"source.ip": "10.1.2.3"}, {"source.ip": "*"}, {"source.ip": "[::]"}],
        f"{tag}-delim-arp": [{"IPAddress": "224.0.0.22"}, {"ForeignAddress": "ff02::fb"}],
    }
    for index, records in docs.items():
        for i, record in enumerate(records):
            os_client.index(index=index, id=str(i), body=record)
    os_client.indices.refresh(index=f"{tag}-*")
    yield f"{tag}-*"
    os_client.indices.delete(index=f"{tag}-*", ignore=[404])
    for kind in ("json", "delim"):
        os_client.indices.delete_index_template(name=f"{tag}-{kind}", ignore=[404])
    os_client.cluster.delete_component_template(name=f"{tag}-comp", ignore=[404])


@pytest.mark.integration
class TestExtractionReadsTheEvidence:
    def test_every_default_source_hash_is_extracted(self, os_client, case):
        """pslist, upper-case Kansa, the Sysmon parts and Amcache — and not
        IMPHASH, a Prefetch path hash or bodyfile, all lower case."""
        iocs = extract_unique_iocs(os_client, case, force=True)
        assert set(iocs["hash"]) == DEFAULT_HASHES

    def test_each_value_keeps_the_form_it_is_stored_in(self, os_client, case):
        iocs = extract_unique_iocs(os_client, case, force=True)
        assert iocs["hash"][KANSA_MD5.lower()] == {("Hash", KANSA_MD5)}
        assert iocs["hash"][SYSMON_MD5.lower()] == {("winlog.event_data.Hashes", SYSMON_HASHES)}
        assert iocs["hash"][PSLIST["SHA256"]] == {("Hash.SHA256", PSLIST["SHA256"])}

    def test_bodyfile_hashes_only_on_request(self, os_client, case):
        default = extract_unique_iocs(os_client, case, force=True)
        assert BODYFILE_MD5 not in default["hash"]
        assert not any(f == "md5" for origins in default["hash"].values() for f, _ in origins)
        flagged = extract_unique_iocs(os_client, case, force=True, include_filesystem=True)
        assert flagged["hash"][BODYFILE_MD5] == {("md5", BODYFILE_MD5)}

    def test_external_ips_and_domains(self, os_client, case):
        """Derived fixture (routable values), pending test's inventory of
        real evidence with routable values."""
        iocs = extract_unique_iocs(os_client, case, force=True)
        assert set(iocs["ip"]) == EXTERNAL_IPS
        assert iocs["domain"] == {"example.com": {("winlog.event_data.QueryName", "Example.COM")}}

    def test_evtx_and_ecs_csv_source_ip_in_one_case(self, os_client, case):
        """source.ip was `ip` in evtx and `keyword` in an ECS CSV, and one
        aggregation over both returned 8.8.4.4 as 16 raw bytes, with no shard
        failure; validation then dropped it. Both now map `ip`."""
        iocs = extract_unique_iocs(os_client, case, force=True)
        assert iocs["ip"]["8.8.4.4"] == {("source.ip", "8.8.4.4")}

    def test_an_ecs_csv_row_whose_source_ip_is_not_an_address_is_kept(self, os_client, case):
        index = case.replace("*", "delim-ecs")
        assert os_client.count(index=index)["count"] == 3
        ignored = {"query": {"term": {"_ignored": "source.ip"}}}
        assert os_client.count(index=index, body=ignored)["count"] == 2

    def test_multicast_is_never_extracted(self, os_client, case):
        iocs = extract_unique_iocs(os_client, case, force=True)
        assert not {"239.255.255.250", "224.0.0.22", "ff02::fb"} & set(iocs["ip"])
