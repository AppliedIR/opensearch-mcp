"""The template copies helper turns the outranked check off only while its
copies are installed (codex on 7e8f6b8): an install whose PUT fails leaves the
check on and removes what it made, so a later install/remove pair still
restores the check, and a refusal regression can't hide behind a failed
setup. A stand-in client; no cluster."""

from __future__ import annotations

from unittest.mock import MagicMock

import _scratch_templates as st
import pytest

from opensearch_mcp import write_context as wc


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(st, "_installed", 0)
    monkeypatch.setattr(wc, "_outranked", st._REAL_OUTRANKED)


def test_a_put_that_fails_leaves_the_check_on_and_removes_what_it_made():
    put = []

    def refuse_the_second(name, body):
        put.append(name)
        if len(put) == 2:
            raise RuntimeError("refused")

    client = MagicMock()
    client.indices.put_index_template.side_effect = refuse_the_second
    with pytest.raises(RuntimeError, match="refused"):
        st.install(client, "t1")
    assert wc._outranked is st._REAL_OUTRANKED and st._installed == 0
    deleted = [c.kwargs["name"] for c in client.indices.delete_index_template.call_args_list]
    assert deleted == put[:1]  # the one template it made; the refused one wasn't
    assert client.cluster.delete_component_template.called
    assert client.ingest.delete_pipeline.called


def test_a_later_install_and_remove_still_restore_the_check():
    failing = MagicMock()
    failing.ingest.put_pipeline.side_effect = RuntimeError("refused")
    with pytest.raises(RuntimeError):
        st.install(failing, "t1")
    created = st.install(MagicMock(), "t2")
    assert wc._outranked is st._copies_govern  # off while the copies are installed
    nested = st.install(MagicMock(), "t3")
    st.remove(MagicMock(), nested)
    assert wc._outranked is st._copies_govern  # one install still open
    st.remove(MagicMock(), created)
    assert wc._outranked is st._REAL_OUTRANKED and st._installed == 0
