"""The MFT hint's queries use field forms that exist on both MFT ingest paths.

`"SI<FN".keyword:True` parsed as a phrase plus an unmapped field and matched
nothing anywhere; the other `.keyword` clauses matched nothing on the delimited
path, where MFTECmd's columns are keyword. A text guard; the cluster leg in
test_ingest_integration.py runs the clauses.
"""

import re

from opensearch_mcp import server


def mft_hint(monkeypatch) -> str:
    monkeypatch.setattr(server, "_hints_delivered", set())
    resp: dict = {}
    server._add_investigation_hints(resp, {"mft": {}}, "case")
    return next(h for h in resp["investigation_hints"] if h.startswith("MFT indexed"))


def flag_clauses(hint: str) -> list[str]:
    return re.findall(r"\S+:(?:True|False)", hint)


def test_the_mft_hint_uses_the_bare_field_names(monkeypatch):
    hint = mft_hint(monkeypatch)
    assert ".keyword" not in hint and '"SI<FN"' not in hint
    assert flag_clauses(hint) == ["SI<FN:True", "uSecZeros:True", "InUse:False", "HasAds:True"]
