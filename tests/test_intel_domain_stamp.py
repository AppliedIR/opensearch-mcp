"""Domain stamps only ever land where the field matches values exactly.

Stamping matched each domain's documents with a case-wide `term` on the field
extraction found it under. Where that field is text, a term matches an analysed
token: `evil.example.com`'s verdict landed on `x-evil.example.com`. Each domain
clause is now limited to the indices that map that exact field as keyword, read
when stamping starts, and a failed read stamps no domains. The real
enrich_case runs against a cluster (skipped without one; the gate points it at
a throwaway container); only the threat-intel lookup is a stand-in. Every
document says which verdict it should get.
"""

from __future__ import annotations

import uuid

import _scratch_templates
import pytest

opensearchpy = pytest.importorskip("opensearchpy")

pytestmark = pytest.mark.integration

MAL = {"evil.example.com", "45.33.32.156", "a" * 64, "b" * 40}
KW = {"type": "keyword"}
TX = {"type": "text"}
TXK = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}


@pytest.fixture(scope="module")
def scratch():
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    tag = f"pytest-dstamp-{uuid.uuid4().hex[:8]}"
    created = _scratch_templates.install(client, tag)  # for the deployed-form row
    try:
        yield client, tag
    finally:
        client.indices.delete(index=f"case-{tag}-*", ignore=[404])
        _scratch_templates.remove(client, created)


class Case:
    def __init__(self, client, tag):
        self.client = client
        self.id = f"{tag}-{uuid.uuid4().hex[:6]}"
        self.prefix = f"case-{self.id}"

    def explicit(self, name, props, docs):
        props = {**props, "note": KW, "exp": KW}
        index = f"{self.prefix}-{name}"
        self.client.indices.create(
            index=index,
            body={"settings": {"number_of_replicas": 0}, "mappings": {"properties": props}},
        )
        for d in docs:
            self.client.index(index=index, body=d)

    def deployed(self, name, docs):  # mapped by the tree's templates, as an ingest would
        for d in docs:
            self.client.index(index=f"{self.prefix}-{name}", body=d)

    def enrich(self, monkeypatch, during_lookup=lambda: None):
        import opensearch_mcp.threat_intel as ti

        def lookup(iocs, on_progress=None):
            res, cov = {}, {"enriched": [], "skipped": {}}
            for kind, values in iocs.items():
                for v in values:
                    cov["enriched"].append(v)
                    base = {"threat_intel.ioc_type": kind, "threat_intel.ioc_value": v}
                    res[v] = (
                        {
                            **base,
                            "threat_intel.verdict": "MALICIOUS",
                            "threat_intel.confidence": 90,
                        }
                        if v in MAL
                        else {**base, "threat_intel.checked": True}
                    )
            during_lookup()
            res["_intel_coverage"] = cov
            return res

        monkeypatch.setattr(ti, "batch_lookup", lookup)
        self.client.indices.refresh(index=f"{self.prefix}-*")
        try:
            outcome = ti.enrich_case(self.client, self.id)
        except ti.IntelEnrichmentHalted as e:
            outcome = e
        self.client.indices.refresh(index=f"{self.prefix}-*")
        return outcome

    def wrong(self):
        """Documents whose verdict isn't the one they say they should get."""
        hits = self.client.search(
            index=f"{self.prefix}-*", body={"size": 200, "query": {"match_all": {}}}
        )["hits"]["hits"]
        out = []
        for h in hits:
            s = h["_source"]
            malicious = s.get("threat_intel.verdict") == "MALICIOUS"
            if malicious != (s["exp"] == "MAL"):
                out.append((h["_index"][len(self.prefix) + 1 :], s["note"], malicious))
        return sorted(out)


@pytest.fixture
def case(scratch):
    return Case(*scratch)


def test_a_text_field_never_gets_a_neighbours_verdict(case, monkeypatch):
    case.explicit("kw", {"query": KW}, [{"query": "evil.example.com", "note": "kw", "exp": "MAL"}])
    case.explicit(
        "tx",
        {"query": TX},
        [
            {"query": "not-evil.example.com", "note": "tx other", "exp": "no"},
            {"query": "unrelated.example.org", "note": "tx unrelated", "exp": "no"},
        ],
    )
    case.explicit(
        "txk", {"query": TXK}, [{"query": "not-evil.example.com", "note": "txk", "exp": "no"}]
    )
    case.enrich(monkeypatch)
    assert case.wrong() == []


def test_arrays_objects_sub_fields_and_a_missing_field(case, monkeypatch):
    case.explicit(
        "kw4",
        {"query": KW},
        [
            {"query": "evil.example.com", "note": "kw scalar", "exp": "MAL"},
            {"query": ["good.example.net", "evil.example.com"], "note": "kw array", "exp": "MAL"},
        ],
    )
    case.explicit(
        "tx4",
        {"query": TX},
        [  # text-only, the same value: never stamped (accepted loss)
            {"query": "evil.example.com", "note": "text-only same value", "exp": "no"},
            {
                "query": ["fine.example.org", "not-evil.example.com"],
                "note": "tx array",
                "exp": "no",
            },
        ],
    )
    case.explicit(
        "obj4",
        {"query": {"properties": {"name": KW}}},
        [{"query": {"name": "evil.example.com"}, "note": "query an object", "exp": "no"}],
    )
    case.explicit(
        "nest4",
        {"dns": {"properties": {"query": KW}}},
        [{"dns": {"query": "evil.example.com"}, "note": "dns.query kw", "exp": "MAL"}],
    )
    case.explicit(
        "nesttx4",
        {"dns": {"properties": {"query": TX}}},
        [{"dns": {"query": "not-evil.example.com"}, "note": "dns.query text", "exp": "no"}],
    )
    case.explicit(
        "miss4", {"other": KW}, [{"other": "evil.example.com", "note": "no query", "exp": "no"}]
    )
    case.enrich(monkeypatch)
    assert case.wrong() == []


def test_a_field_that_turns_text_during_stamping_gets_no_stamp(case, monkeypatch):
    case.explicit(
        "kw6",
        {"query": KW},
        [
            {"query": "evil.example.com", "note": "kw", "exp": "MAL"},
            {"query": "aaa.example.com", "note": "kw other (stamped first)", "exp": "no"},
        ],
    )
    late = f"{case.prefix}-late6"
    case.client.indices.create(index=late, body={"settings": {"number_of_replicas": 0}})
    case.client.index(index=late, body={"other": "x", "note": "late6 before", "exp": "no"})
    real, calls = case.client.update_by_query, []

    def ubq(*a, **k):
        calls.append(1)
        if len(calls) == 1:  # dynamic mapping makes query text + .keyword here
            case.client.index(
                index=late,
                body={"query": "not-evil.example.com", "note": "late6 during", "exp": "no"},
                refresh=True,
            )
        return real(*a, **k)

    monkeypatch.setattr(case.client, "update_by_query", ubq)
    case.enrich(monkeypatch)
    assert case.wrong() == []


def test_query_name_no_longer_stamps_a_text_field(case, monkeypatch):
    ev = lambda m: {"winlog": {"properties": {"event_data": {"properties": {"QueryName": m}}}}}  # noqa: E731
    case.explicit(
        "ev7",
        ev(KW),
        [{"winlog.event_data.QueryName": "evil.example.com", "note": "kw", "exp": "MAL"}],
    )
    case.explicit(
        "tx7",
        ev(TXK),
        [{"winlog.event_data.QueryName": "x-evil.example.com", "note": "text+kw", "exp": "no"}],
    )
    case.enrich(monkeypatch)
    assert case.wrong() == []


def test_unreadable_mappings_stamp_no_domains_and_say_so(case, monkeypatch):
    case.explicit(
        "kw",
        {"query": KW, "SHA256": KW},
        [
            {"query": "evil.example.com", "note": "kw domain: no stamp", "exp": "no"},
            {"SHA256": "a" * 64, "note": "hash still stamped", "exp": "MAL"},
        ],
    )
    case.explicit(
        "txk", {"query": TXK}, [{"query": "not-evil.example.com", "note": "txk", "exp": "no"}]
    )
    real, calls = case.client.field_caps, []

    def field_caps(*a, **k):  # extraction's read works; stamping's fails
        calls.append(1)
        if len(calls) >= 2:
            raise RuntimeError("injected field_caps failure")
        return real(*a, **k)

    monkeypatch.setattr(case.client, "field_caps", field_caps)
    outcome = case.enrich(monkeypatch)
    assert case.wrong() == []
    assert "stamp requests failed" in str(outcome)


def test_d_deployed_mappings_stamp_keyword_fields_only(case, monkeypatch):
    """The tree's templates map these; evtx, hash and IP stamps are anchors."""
    case.deployed(
        "json-dns-host1", [{"query": "evil.example.com", "note": "json query", "exp": "MAL"}]
    )
    case.deployed(
        "zeek-ssl-host1",
        [{"server_name": "evil.example.com", "note": "zeek server_name", "exp": "MAL"}],
    )
    case.deployed(
        "json-netlog-host1",
        [{"dns.query": "evil.example.com", "note": "json dns.query", "exp": "MAL"}],
    )
    case.deployed(
        "zeek-ssh-host1",
        [
            {
                "query": "not-evil.example.com",
                "server_name": "anti-evil.example.com",
                "note": "zeek-ssh collision",
                "exp": "no",
            }
        ],
    )
    case.deployed(
        "json-netlog-vol-host1",
        [
            {
                "dns.query": "not-evil.example.com",
                "winlog.event_data.QueryName": "x-evil.example.com",
                "note": "json-vol collision",
                "exp": "no",
            }
        ],
    )
    case.deployed(
        "evtx-host1",
        [
            {
                "winlog.event_data.QueryName": "evil.example.com",
                "source.ip": "45.33.32.156",
                "note": "evtx QueryName + IP (anchor)",
                "exp": "MAL",
            }
        ],
    )
    case.deployed(
        "delim-procs-host1", [{"SHA256": "a" * 64, "note": "delim SHA256", "exp": "MAL"}]
    )
    case.deployed("amcache-host1", [{"SHA1": "b" * 40, "note": "csv SHA1", "exp": "MAL"}])
    case.enrich(monkeypatch)
    assert case.wrong() == []
