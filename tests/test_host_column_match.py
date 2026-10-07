"""A record's host column is read whatever the case of its name.

Host columns were matched by exact name, so `computername`, `HOSTNAME` or a
lower-case `host` gave no host, and every row of such an export was filed
under one host. They are now matched ignoring case, in the same priority
order, and two documented export fields follow the list: `DeviceName`
(Microsoft Defender for Endpoint advanced hunting) and `PSComputerName`
(PowerShell remoting output).
"""

from __future__ import annotations

import pytest

from opensearch_mcp.hostname import extract_host_from_record


@pytest.mark.parametrize(
    "record",
    [
        {"host": "WKS01"},
        {"HOST": "WKS01"},
        {"computername": "WKS01"},
        {"COMPUTERNAME": "WKS01"},
        {"computerName": "WKS01"},
        {"computer": "WKS01"},
        {"COMPUTER": "WKS01"},
        {"hostname": "WKS01"},
        {"HostName": "WKS01"},
        {"HOSTNAME": "WKS01"},
        {"clientinfo": {"HOSTNAME": "WKS01"}},
        {"Host": {"Name": "WKS01"}},
        {"DeviceName": "WKS01"},
        {"devicename": "WKS01"},
        {"PSComputerName": "WKS01"},
        {"pscomputername": "WKS01"},
    ],
    ids=lambda r: repr(r),
)
def test_every_spelling_of_a_host_column_is_read(record):
    assert extract_host_from_record({"Other": "x", **record}) == "WKS01"


def test_the_priority_order_holds_across_cases():
    assert extract_host_from_record({"DeviceName": "MDE01", "Computer": "WKS01"}) == "WKS01"
    assert extract_host_from_record({"computer": "WKS01", "devicename": "MDE01"}) == "WKS01"
    assert extract_host_from_record({"PSComputerName": "PS01", "DeviceName": "MDE01"}) == "MDE01"


def test_an_exact_name_wins_over_another_case_of_it():
    assert extract_host_from_record({"host": "lower", "Host": "exact"}) == "exact"


def test_anchor_columns_of_unclear_meaning_still_give_no_host():
    record = {"MachineName": "M1", "Workstation": "W1", "computer_name": "C1", "host_name": "H1"}
    assert extract_host_from_record(record) is None
