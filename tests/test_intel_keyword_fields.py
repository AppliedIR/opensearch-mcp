"""Enrichment reads SHA256, MD5 and LocalAddr where an index maps them as keyword.

Delimited and json indices map these columns as plain keyword, but only the
`.keyword` sub-field (what a dynamically mapped text field gets) was listed,
so their values were never extracted. The client is a stand-in that reports
per-index field types the way OpenSearch 3.5.0 does: field_caps lists each
type with its indices, and a terms aggregation returns the keyword indices'
buckets. Values are derived.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

from opensearch_mcp.threat_intel import extract_unique_iocs


def _h(algo: str, text: str) -> str:
    return hashlib.new(algo, text.encode()).hexdigest()


def _type(mapping: dict, field: str) -> str | None:
    if field in mapping:
        return mapping[field][0]
    if field.endswith(".keyword") and mapping.get(field[: -len(".keyword")], ("",))[0] == "text":
        return "keyword"
    return None


def _client(indices: dict) -> MagicMock:
    """indices: {index: {field: ("text" | "keyword", value)}}"""
    client = MagicMock()

    def field_caps(*, index, fields, **kw):
        out = {}
        for field in fields.split(","):
            by_type: dict[str, list[str]] = {}
            for name, mapping in indices.items():
                t = _type(mapping, field)
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
        base = field[: -len(".keyword")] if field.endswith(".keyword") else field
        values = [
            m.get(field, m.get(base))[1] for m in indices.values() if _type(m, field) == "keyword"
        ]
        return {
            "aggregations": {"values": {"buckets": [{"key": v, "doc_count": 1} for v in values]}}
        }

    client.field_caps.side_effect = field_caps
    client.search.side_effect = search
    return client


def _iocs(indices: dict) -> dict[str, set]:
    found = extract_unique_iocs(_client(indices), "case-x-*", force=True)
    return {kind: set(found.get(kind, {})) for kind in ("hash", "ip")}


def test_keyword_sha256_and_md5_in_a_delimited_index():
    sha256, md5 = _h("sha256", "delim"), _h("md5", "delim")
    index = {"case-x-delim-a": {"SHA256": ("keyword", sha256), "MD5": ("keyword", md5)}}
    assert {sha256, md5} <= _iocs(index)["hash"]


def test_sha256_mixed_text_and_keyword_reads_both():
    amcache, delim = _h("sha256", "csv"), _h("sha256", "delim")
    got = _iocs(
        {
            "case-x-amcache-h": {"SHA256": ("text", amcache)},
            "case-x-delim-a": {"SHA256": ("keyword", delim)},
        }
    )["hash"]
    assert {amcache, delim} <= got


def test_keyword_localaddr_in_a_delimited_index():
    assert (
        "45.33.32.156"
        in _iocs({"case-x-delim-n": {"LocalAddr": ("keyword", "45.33.32.156")}})["ip"]
    )


def test_amcache_alone_is_read_as_before():
    sha1, sha256 = _h("sha1", "csv"), _h("sha256", "csv")
    got = _iocs({"case-x-amcache-h": {"SHA1": ("text", sha1), "SHA256": ("text", sha256)}})["hash"]
    assert got == {sha1, sha256}
