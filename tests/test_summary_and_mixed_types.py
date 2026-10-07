"""Case summaries say when they are cut or empty; aggregations refuse mixed types.

- The summary's host list stops at 500 host.name values. It now says so,
  with the number of documents whose names aren't listed.
- A summary of a case id that matches no index used to read as an empty
  case. It is now an error naming the pattern.
- A field mapped `ip` in some indices and `keyword` in others (an index made
  before source.ip became ip, beside one made after) gave raw-byte buckets or
  a 400, depending on index order. idx_aggregate and idx_field_values now
  refuse, naming each index set, so each can be aggregated on its own.

Runs against a cluster, under this run's own template names. The keyword
indices are created with the keyword mapping older releases gave source.ip;
the rest go through the real ingest paths. Addresses are synthetic.
"""

from __future__ import annotations

import re
import uuid

import _scratch_templates
import pytest

from opensearch_mcp import server as srv

pytestmark = pytest.mark.integration

NETSTAT_OLD = """Process,source.ip,LocalPort,State
svchost.exe,10.1.2.3,445,LISTENING
svchost.exe,10.1.2.3,135,LISTENING
chrome.exe,10.1.2.4,50123,ESTABLISHED
chrome.exe,192.168.7.9,50124,ESTABLISHED
system,*,0,LISTENING
"""
NETSTAT_NEW = """Process,source.ip,LocalPort,State
svchost.exe,10.1.2.3,445,LISTENING
svchost.exe,10.1.2.4,135,LISTENING
chrome.exe,10.1.2.4,50125,ESTABLISHED
lsass.exe,172.16.5.1,50126,ESTABLISHED
lsass.exe,172.16.5.1,50127,ESTABLISHED
lsass.exe,172.16.5.1,50128,ESTABLISHED
"""
FIELDS = (
    "date time action protocol src-ip dst-ip src-port dst-port size tcpflags"
    " tcpsyn tcpack tcpwin icmptype icmpcode info path"
)
FIREWALL = f"""#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: {FIELDS}
2026-01-01 10:00:00 ALLOW TCP 10.1.2.3 172.16.5.1 50000 445 0 - - - - - - - SEND
2026-01-01 10:00:01 ALLOW TCP 10.1.2.3 172.16.5.1 50001 445 0 - - - - - - - SEND
2026-01-01 10:00:02 ALLOW TCP 10.1.2.4 192.0.2.53 50002 53 0 - - - - - - - SEND
"""
CONN = """Process,destination.ip,DPort
chrome.exe,172.16.5.1,443
chrome.exe,192.0.2.53,53
"""
KEYWORD_SOURCE_IP = {
    "mappings": {
        "properties": {"source": {"properties": {"ip": {"type": "keyword", "ignore_above": 2048}}}}
    }
}
IP_SET = {"172.16.5.1": 3, "10.1.2.4": 2, "10.1.2.3": 1}
KEYWORD_SET = {"10.1.2.3": 2, "10.1.2.4": 1, "192.168.7.9": 1, "*": 1}


def _types(client, index, field):
    return set(client.field_caps(index=index, fields=field)["fields"].get(field, {}))


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
    except Exception:
        pytest.skip("OpenSearch not available")
    from opensearchpy import helpers

    from opensearch_mcp import parse_delimited, parse_w3c
    from opensearch_mcp.paths import build_index_name

    tag = f"pytest-tpl-{uuid.uuid4().hex[:8]}"
    d = tmp_path_factory.mktemp("evidence")
    for name, text in (
        ("old.csv", NETSTAT_OLD),
        ("new.csv", NETSTAT_NEW),
        ("pfirewall.log", FIREWALL),
        ("conn.csv", CONN),
    ):
        (d / name).write_text(text)
    created = _scratch_templates.install(client, tag)
    try:

        def old(case, host):
            index = f"case-{tag}-{case}-delim-netstat-{host}"
            client.indices.create(index=index, body=KEYWORD_SOURCE_IP)
            parse_delimited.ingest_delimited(d / "old.csv", client, index, host)

        def new(case, host):
            index = f"case-{tag}-{case}-delim-netstat-{host}"
            parse_delimited.ingest_delimited(d / "new.csv", client, index, host)

        old("mix", "oldhost")
        new("mix", "newhost")
        old("mix2", "aold")  # the keyword index sorts first
        new("mix2", "bnew")
        new("other", "newhost")
        old("tri2", "aold")
        new("tri2", "bnew")
        new("iptext", "newhost")
        for case in ("tri2", "iptext"):
            for i, ip in enumerate(["10.1.2.3", "10.1.2.3", "192.0.2.44"]):
                client.index(
                    index=f"case-{tag}-{case}-timeline-h1",  # no string rule here: text
                    id=str(i),
                    body={"source.ip": ip, "host.name": "h1"},
                )
        parse_w3c.parse_w3c_log(
            d / "pfirewall.log", client, f"case-{tag}-dst2-firewall-fw1", "fw1"
        )
        parse_delimited.ingest_delimited(
            d / "conn.csv", client, f"case-{tag}-dst2-delim-conn-h1", "h1"
        )

        actions = []
        for n in range(90):  # 540 names, one document each
            h = f"ws{n:03d}"
            index = build_index_name(f"{tag}-big", "delim-netstat", h)
            for form in (f"{h.upper()}.CORP.EXAMPLE", f"{h}.corp.example", h.upper(), h):
                actions.append({"_index": index, "_source": {"host.name": form}})
            for form in (f"10.20.0.{n}", f"fe80::{n:x}"):
                actions.append({"_index": index, "_source": {"host.name": form}})
        for case, extra in (("b500", False), ("b501", True)):
            for n in range(100):  # 500 names, two documents each
                h = f"pc{n:03d}"
                index = build_index_name(f"{tag}-{case}", "delim-netstat", h)
                for k in range(5):
                    actions += [{"_index": index, "_source": {"host.name": f"{h}-{k}"}}] * 2
            if extra:
                index = build_index_name(f"{tag}-{case}", "delim-netstat", "zz-late")
                actions.append({"_index": index, "_source": {"host.name": "zz-late"}})
        helpers.bulk(client, actions)
        client.indices.refresh(index=f"case-{tag}-*")

        assert _types(client, f"case-{tag}-mix-*", "source.ip") == {"ip", "keyword"}
        assert _types(client, f"case-{tag}-tri2-*", "source.ip") == {"ip", "keyword", "text"}
        assert _types(client, f"case-{tag}-dst2-*", "destination.ip") == {"ip", "keyword"}
        assert _types(client, f"case-{tag}-other-*", "source.ip") == {"ip"}
        assert _types(client, f"case-{tag}-iptext-*", "source.ip") == {"ip", "text"}
        yield client, tag
    finally:
        client.indices.delete(index=f"case-{tag}-*", ignore=[404])
        _scratch_templates.remove(client, created)


AUDITED = []


@pytest.fixture
def tools(cluster, monkeypatch):
    """The real tools on the test cluster; searches and field_caps recorded."""
    client, tag = cluster
    seen = {"search": [], "field_caps": []}
    spy = _Spy(client, seen)
    monkeypatch.setattr(srv, "_get_os", lambda: spy)
    monkeypatch.setattr(srv, "_get_active_case", lambda: None)
    AUDITED.clear()

    def log(**kw):
        AUDITED.append(kw)
        return f"aid-{len(AUDITED)}"

    monkeypatch.setattr(srv.audit, "log", log)
    return tag, seen


class _Spy:
    def __init__(self, client, seen):
        self._client, self._seen = client, seen

    def __getattr__(self, name):
        return getattr(self._client, name)

    def search(self, *a, **kw):
        result = self._client.search(*a, **kw)
        self._seen["search"].append((kw.get("index"), (result.get("_shards") or {}).get("failed")))
        return result

    def field_caps(self, *a, **kw):
        self._seen["field_caps"].append(kw.get("index"))
        return self._client.field_caps(*a, **kw)


def _buckets(result):
    rows = result.get("buckets") or result.get("values") or []
    return {str(r.get("key", r.get("value"))): r["count"] for r in rows}


def _cut(summary):
    found = [w for w in summary.get("warnings", []) if "Host list cut" in w]
    if not found:
        return None
    (warning,) = found
    return int(re.search(r"(\d+) documents carry", warning).group(1))


# The host list


@pytest.mark.parametrize(
    "case, hosts, cut",
    [("big", 500, 40), ("b501", 500, 1), ("b500", 500, None), ("mix", 2, None)],
    ids=["540 names", "501 names, one on one document", "exactly 500 names", "two hosts"],
)
def test_a_cut_host_list_says_how_many_documents_it_left_out(tools, case, hosts, cut):
    tag, _ = tools
    summary = srv.idx_case_summary(case_id=f"{tag}-{case}")
    assert len(summary["hosts"]) == hosts
    assert _cut(summary) == cut


# A case id that matches no index


@pytest.mark.parametrize(
    "case_id, pattern",
    [
        ("{tag}-nonexistent", "case-{tag}-nonexistent-*"),
        ("..", "case-..-*"),
        ("../mix", "case-..-mix-*"),
    ],
    ids=["a mistyped id", "dot-dot", "dot-dot then a case"],
)
def test_a_summary_of_a_case_id_matching_no_index_is_an_error(tools, case_id, pattern):
    tag, _ = tools
    summary = srv.idx_case_summary(case_id=case_id.format(tag=tag))
    assert repr(pattern.format(tag=tag)) in summary["error"]
    assert "nothing was summarized" in summary["error"]
    assert "hosts" not in summary and "total_docs" not in summary
    assert "audit_id" not in summary and AUDITED == []


def test_the_active_case_with_nothing_ingested_is_an_error_too(tools, monkeypatch):
    tag, _ = tools
    monkeypatch.setattr(srv, "_get_active_case", lambda: f"{tag}-empty")
    summary = srv.idx_case_summary()
    assert repr(f"case-{tag}-empty-*") in summary["error"]
    assert "ingest evidence" in summary["error"] and "hosts" not in summary


def test_a_summary_of_an_ingested_case_is_unchanged(tools):
    tag, _ = tools
    summary = srv.idx_case_summary(case_id=f"{tag}-mix")
    assert sorted(summary["hosts"]) == ["newhost", "oldhost"]
    assert summary["total_docs"] == 11
    assert "error" not in summary and summary["audit_id"] == "aid-1"


# A field that is ip in some indices and keyword in others

TOOLS = ("idx_aggregate", "idx_field_values")


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "where, field, ip, keyword",
    [
        ("mix2", "source.ip", ["mix2-delim-netstat-bnew"], ["mix2-delim-netstat-aold"]),
        ("mix", "source.ip", ["mix-delim-netstat-newhost"], ["mix-delim-netstat-oldhost"]),
        ("dst2", "destination.ip", ["dst2-firewall-fw1"], ["dst2-delim-conn-h1"]),
        ("tri2", "source.ip", ["tri2-delim-netstat-bnew"], ["tri2-delim-netstat-aold"]),
        ("*", "source.ip", ["mix-delim-netstat-newhost", "other-delim-netstat-newhost"], []),
    ],
    ids=[
        "keyword index first",
        "ip index first",
        "destination.ip from firewall and delimited ingest",
        "ip, keyword and text",
        "every case",
    ],
)
def test_a_field_mixing_ip_and_keyword_is_refused_naming_each_set(
    tools, tool, where, field, ip, keyword
):
    tag, seen = tools
    kw = {"index": f"case-{tag}-*"} if where == "*" else {"case_id": f"{tag}-{where}"}
    result = getattr(srv, tool)(field=field, **kw)
    error = result["error"]
    assert field in error and "index=" in error
    for name in ip + keyword:
        assert f"case-{tag}-{name}" in error
    assert seen["search"] == []


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "index, expected",
    [("mix-delim-netstat-newhost", IP_SET), ("mix-delim-netstat-oldhost", KEYWORD_SET)],
    ids=["the ip set", "the keyword set"],
)
def test_each_set_on_its_own_aggregates_readable_addresses(tools, tool, index, expected):
    tag, seen = tools
    result = getattr(srv, tool)(field="source.ip", index=f"case-{tag}-{index}")
    assert _buckets(result) == expected
    assert seen["search"] == [(f"case-{tag}-{index}", 0)]


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "case, field, expected",
    [
        ("mix", "host.name", {"newhost": 6, "oldhost": 5}),
        ("other", "source.ip", IP_SET),
    ],
    ids=["a keyword field in a mixed case", "an ip-only case"],
)
def test_a_field_of_one_type_aggregates_as_before(tools, tool, case, field, expected):
    tag, seen = tools
    result = getattr(srv, tool)(field=field, case_id=f"{tag}-{case}")
    assert _buckets(result) == expected
    assert [index for index, _ in seen["search"]] == [f"case-{tag}-{case}-*"]


@pytest.mark.parametrize("tool", TOOLS)
def test_the_type_check_reads_the_indices_the_aggregation_reads(tools, tool):
    """Not every case: another case's mix must not refuse this one."""
    tag, seen = tools
    getattr(srv, tool)(field="source.ip", case_id=f"{tag}-other")
    assert seen["field_caps"] == [f"case-{tag}-other-*"]


@pytest.mark.parametrize("tool", TOOLS)
def test_ip_mixed_with_text_alone_is_not_refused(tools, tool):
    """Only an ip/keyword mix is refused; an ip/text one still aggregates
    (its text indices give no buckets: a known gap, not this check's)."""
    tag, seen = tools
    result = getattr(srv, tool)(field="source.ip", case_id=f"{tag}-iptext")
    assert "mapped as ip" not in str(result.get("error", ""))
    assert [index for index, _ in seen["search"]] == [f"case-{tag}-iptext-*"]
