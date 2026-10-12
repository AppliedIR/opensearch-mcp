"""A window, the default timeline and the case time range name the indices they leave out."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from opensearchpy.exceptions import AuthorizationException, ConnectionTimeout
from sift_common import host_identity

import opensearch_mcp.server as srv
from opensearch_mcp import write_context as wc

C = "case-0123456789ab"
TAIL = "; query them by their own field with index="
EMPTY = {
    "hits": {"total": {"value": 0}, "hits": []},
    "aggregations": {"timeline": {"buckets": []}},
}
EZ = ["amcache", "lnk", "mft", "recyclebin", "shellbags", "shimcache", "usn"]


def _mapping(timed=(), untimed=()):
    out = {
        n: {"mappings": {"@timestamp": {"full_name": "@timestamp", "mapping": {}}}} for n in timed
    }
    out.update({n: {"mappings": {}} for n in untimed})
    return out


@pytest.fixture
def client(monkeypatch):
    c = MagicMock()
    c.cluster.health.return_value = {"status": "green"}
    c.search.return_value = EMPTY
    monkeypatch.setattr(srv, "_client", None)
    monkeypatch.setattr(srv, "_client_verified", False)
    with (patch("opensearch_mcp.server.get_client", return_value=c),
          patch("opensearch_mcp.server._get_active_case", return_value="test-case")):  # fmt: skip
        yield c


def test_names_untimed_indices_from_the_mapping():
    c = MagicMock()
    c.indices.get_field_mapping.return_value = _mapping(
        [f"{C}-evtx-0"], [f"{C}-mft-0", f"{C}-prefetch-0"]
    )
    assert srv._untimed_note(c, f"{C}-*", "aren't in time_range") == (
        f"2 index(es) have no event time and aren't in time_range: {C}-mft-0 "
        f"(time field Created0x10), {C}-prefetch-0{TAIL}"
    )
    c.indices.get_field_mapping.assert_called_once_with(
        index=f"{C}-*", fields="@timestamp", allow_no_indices=True, ignore_unavailable=True
    )
    c.search.assert_not_called()


def test_names_at_most_five():
    c = MagicMock()
    c.indices.get_field_mapping.return_value = _mapping(untimed=[f"{C}-{t}-0" for t in EZ])
    note = srv._untimed_note(c, f"{C}-*", "w")
    assert note.endswith(f"{C}-shellbags-0 (time field LastInteracted), and 2 more indices{TAIL}")
    assert f"{C}-shimcache-0" not in note and note.startswith("7 index(es)")


@pytest.mark.parametrize("reply", [_mapping([f"{C}-evtx-0"]), {}])
def test_silent_when_every_index_is_timed(reply):
    c = MagicMock()
    c.indices.get_field_mapping.return_value = reply
    assert srv._untimed_note(c, f"{C}-*", "w") == ""


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionTimeout("TIMEOUT", "read timed out", None),
        AuthorizationException(403, "security_exception", {}),
    ],
)
def test_a_failed_mapping_read_says_so(exc):
    c = MagicMock()
    c.indices.get_field_mapping.side_effect = exc
    assert srv._untimed_note(c, f"{C}-*", "are left out of time_from/time_to") == (
        f"couldn't check which indices lack an event time ({type(exc).__name__}); "
        "EZ-tool CSV indices are left out of time_from/time_to"
    )


def test_search_window_notes_and_drops_the_extension_hint(client):
    client.indices.get_field_mapping.return_value = _mapping(untimed=[f"{C}-mft-0"])
    r = srv.idx_search(query="*", time_from="2023-01-21T00:00:00Z", time_to="2023-01-23T23:59:59Z")
    assert r["time_note"] == (
        "1 index(es) have no event time and are left out of time_from/time_to: "
        f"{C}-mft-0 (time field Created0x10){TAIL}"
    )
    assert r["hint"] == ("No results with an event time in the window. The indices in "
                         "time_note have none, so the window left them out.")  # fmt: skip


def test_search_without_a_window_reads_no_mapping(client):
    r = srv.idx_search(query="*")
    assert "time_note" not in r and r["hint"].startswith("No results. If searching for filenames")
    client.indices.get_field_mapping.assert_not_called()


@pytest.mark.parametrize("field, window, why", [
    ("@timestamp", False, "aren't in this timeline"),
    ("@timestamp", True, "are left out of time_from/time_to"),
    ("Created0x10", True, None),
])  # fmt: skip
def test_timeline(client, field, window, why):
    client.indices.get_field_mapping.return_value = _mapping(untimed=[f"{C}-mft-0"])
    kw = {"time_from": "2023-01-21T00:00:00Z"} if window else {}
    r = srv.idx_timeline(interval="1d", time_field=field, **kw)
    assert r.get("time_note") == (
        f"1 index(es) have no event time and {why}: {C}-mft-0 (time field Created0x10){TAIL}"
        if why
        else None
    )


def test_summary_warns_once_and_keeps_its_range(monkeypatch):
    mft = f"case-{host_identity.ensure_case_uuid(wc.case_dir_for('acme'), 2)[0]}-mft-0"
    c = MagicMock()
    c.cat.indices.return_value = [{"index": mft, "docs.count": "4"}]
    c.search.return_value = {
        "aggregations": {
            "min_ts": {},
            "max_ts": {},
            "hosts": {"buckets": []},
            "by_index": {"buckets": []},
        }
    }
    c.count.return_value = {"count": 0}
    c.indices.get_field_mapping.return_value = _mapping(untimed=[mft])
    monkeypatch.setattr(srv, "_get_os", lambda: c)
    r = srv.idx_case_summary(case_id="acme")
    assert r["time_range"] == {} and [w for w in r["warnings"] if "event time" in w] == [
        f"Time range: 1 index(es) have no event time and aren't in time_range: {mft} "
        f"(time field Created0x10){TAIL}"
    ]


@pytest.mark.parametrize(
    "keys, own_field", [({"usn"}, True), ({"delim-usn_", "json-usnjrnl"}, False)]
)
def test_usn_hint_says_no_event_time_only_for_the_ez_index(keys, own_field):
    resp: dict = {}
    srv._add_investigation_hints(resp, {k: {"docs": 1} for k in keys}, f"c-usn-{own_field}")
    first = resp["investigation_hints"][0]
    assert first.startswith(
        "USN Journal indexed. It has no event time, so time_from/time_to skip it: "
        "filter on its own field, UpdateTimestamp:[<from> TO <to>], with index=. "
        if own_field
        else "USN Journal indexed. Use time_from/time_to. "
    )


def test_a_failed_mapping_read_makes_no_have_none_claim(client):
    """An empty window whose mapping read timed out: the note says it couldn't
    check, and the hint claims nothing about which indices have no time."""
    client.indices.get_field_mapping.side_effect = ConnectionTimeout(
        "TIMEOUT", "read timed out", None
    )
    r = srv.idx_search(query="event.code:4624", time_from="2023-01-21T00:00:00Z")
    assert r["time_note"].startswith("couldn't check which indices lack an event time")
    assert "have none" not in r["hint"]
    assert r["hint"].startswith("No results. If searching for filenames")


def test_a_page_past_the_end_is_not_said_to_have_no_event_time(client):
    """total 5, offset 5: the page is empty but the window found records."""
    client.search.return_value = {"hits": {"total": {"value": 5}, "hits": []}}
    client.indices.get_field_mapping.return_value = _mapping(untimed=[f"{C}-mft-0"])
    r = srv.idx_search(query="*", time_from="2023-01-21T00:00:00Z", offset=5)
    assert r["total"] == 5 and "time_note" in r
    assert not r.get("hint", "").startswith("No results with an event time")
