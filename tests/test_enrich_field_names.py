"""Enrichment reads the hash and IP columns real collectors name differently.

Kansa Autorunsc and Velociraptor Autoruns write `SHA-256`/`SHA-1`, Kansa
SvcAll `PathMD5Sum`/`ServiceDLLMD5Sum`, and a Volatility netscan CSV
ingested as delimited has a keyword `ForeignAddr`; none were read. The
client is a stand-in that reports per-index field types the way OpenSearch
does (delimited/json indices: keyword; dynamic ones: text plus .keyword) and
answers a terms aggregation from the keyword indices. Values are derived.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

from opensearch_mcp.threat_intel import extract_unique_iocs


def _h(algo: str, text: str) -> str:
    return hashlib.new(algo, text.encode()).hexdigest()


def _type(index: dict, field: str):
    """(type, source column) of field in an index, or (None, None)."""
    types = index["types"]
    if field in types:
        return types[field], field
    if field.endswith(".keyword") and types.get(field[: -len(".keyword")]) == "text":
        return "keyword", field[: -len(".keyword")]
    return None, None


def _index(docs, kind="keyword"):
    return {"types": {k: kind for d in docs for k, v in d.items() if v}, "docs": docs}


def _client(indices: dict) -> MagicMock:
    client = MagicMock()

    def field_caps(*, index, fields, **kw):
        out = {}
        for field in fields.split(","):
            by_type: dict = {}
            for name, ix in indices.items():
                t, _ = _type(ix, field)
                if t:
                    by_type.setdefault(t, []).append(name)
            if by_type:
                out[field] = {
                    t: {
                        "type": t,
                        "aggregatable": t == "keyword",
                        **({"indices": names} if len(by_type) > 1 else {}),
                    }
                    for t, names in by_type.items()
                }
        return {"indices": list(indices), "fields": out}

    def search(*, index, body, **kw):
        field = body["aggs"]["values"]["terms"]["field"]
        values = set()
        for ix in indices.values():
            t, column = _type(ix, field)
            if t == "keyword":
                values |= {d[column] for d in ix["docs"] if d.get(column)}
        buckets = [{"key": v, "doc_count": 1} for v in sorted(values)]
        return {"aggregations": {"values": {"buckets": buckets}}}

    client.field_caps.side_effect = field_caps
    client.search.side_effect = search
    return client


def _iocs(indices: dict) -> dict:
    return extract_unique_iocs(_client(indices), "case-x-*", force=True)


def _fields(found: dict) -> set:
    return {f for origins in found.values() for f, _ in origins}


# The real Kansa Autorunsc header; PESHA (Authenticode) and IMP stay unread.
AUTORUNSC = [
    {
        "Entry": f"svc{i}",
        "MD5": _h("md5", f"a{i}"),
        "SHA-1": _h("sha1", f"a{i}"),
        "PESHA-1": _h("sha1", f"pe{i}"),
        "PESHA-256": _h("sha256", f"pe{i}"),
        "SHA-256": _h("sha256", f"a{i}"),
        "IMP": _h("md5", f"imp{i}"),
    }
    for i in range(3)
]


def test_autorunsc_hyphenated_hashes_are_read():
    found = _iocs({"case-x-delim-autorunsc-wkstn09": _index(AUTORUNSC)})["hash"]
    for row in AUTORUNSC:
        assert row["SHA-256"] in found and row["SHA-1"] in found
    assert {"SHA-256", "SHA-1"} <= _fields(found)
    assert not _fields(found) & {"PESHA-1", "PESHA-256", "IMP"}


def test_velociraptor_autoruns_sha256_is_read():
    docs = [{"Entry": "x", "SHA-256": _h("sha256", "vr")}]
    found = _iocs({"case-x-json-vr-autoruns-h": _index(docs)})["hash"]
    assert _h("sha256", "vr") in found


def test_svcall_md5_sums_are_read_and_placeholders_skipped():
    docs = [
        {"Name": "a", "PathMD5Sum": _h("md5", "path"), "ServiceDLLMD5Sum": "NULLSTRING"},
        {"Name": "b", "PathMD5Sum": "NULLSTRING", "ServiceDLLMD5Sum": _h("md5", "dll")},
    ]
    found = _iocs({"case-x-delim-svcall-wkstn09": _index(docs)})["hash"]
    assert {_h("md5", "path"), _h("md5", "dll")} <= set(found)
    assert "nullstring" not in {k.lower() for k in found}


def test_netscan_foreignaddr_as_delimited_keyword_is_read():
    docs = [
        {"Proto": "TCPv4", "ForeignAddr": "45.33.32.156", "LocalAddr": "10.0.0.5"},
        {"Proto": "TCPv4", "ForeignAddr": "10.0.0.9", "LocalAddr": "10.0.0.5"},
    ]
    found = _iocs({"case-x-delim-netscan-amadey": _index(docs)})["ip"]
    assert "45.33.32.156" in found and "10.0.0.9" not in found


def test_text_mapped_indices_read_as_before():
    """The vol3 template's dynamic text fields: only the .keyword forms answer."""
    docs = [{"ForeignAddr": "45.33.32.156", "LocalAddr": "8.8.8.8"}]
    found = _iocs({"case-x-vol-netscan-amadey": _index(docs, "text")})["ip"]
    assert set(found) == {"45.33.32.156", "8.8.8.8"}
    assert _fields(found) == {"ForeignAddr.keyword", "LocalAddr.keyword"}
