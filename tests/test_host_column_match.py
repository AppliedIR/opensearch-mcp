"""A record's machine-name column is read whatever the case of its name.

Host columns were matched by exact name, so `computername` or `HOSTNAME`
gave no host, and every row of such an export was filed under one host.
Names that only ever mean a machine are now matched ignoring case, in the
same priority order, and two documented export fields follow the list:
`DeviceName` (Microsoft Defender for Endpoint advanced hunting) and
`PSComputerName` (PowerShell remoting output). `Host` stays exact (Kansa's
spelling): a lower-case `host` in a web log is the HTTP Host header, a
website, not a machine. Dotted fields stay exact too.
"""

from __future__ import annotations

import pytest

from opensearch_mcp.hostname import extract_host_from_record


@pytest.mark.parametrize(
    "record",
    [
        {"Host": "WKS01"},  # Kansa
        {"computername": "WKS01"},
        {"COMPUTERNAME": "WKS01"},
        {"computerName": "WKS01"},
        {"computer": "WKS01"},
        {"COMPUTER": "WKS01"},
        {"hostname": "WKS01"},
        {"HostName": "WKS01"},
        {"HOSTNAME": "WKS01"},
        {"ts": 1, "hostname": "WKS01", "assigned_addr": "10.0.0.5"},  # Zeek dhcp.log client
        {"ClientInfo": {"Hostname": "WKS01"}},
        {"host": {"name": "WKS01"}},
        {"DeviceName": "WKS01"},
        {"devicename": "WKS01"},
        {"PSComputerName": "WKS01"},
        {"pscomputername": "WKS01"},
    ],
    ids=lambda r: repr(r),
)
def test_every_spelling_of_a_host_column_is_read(record):
    assert extract_host_from_record({"Other": "x", **record}) == "WKS01"


@pytest.mark.parametrize(
    "record",
    [
        {"ts": 1, "uid": "C1", "id.orig_h": "10.0.0.5", "host": "www.example.com",
         "uri": "/"},  # Zeek http.log: the HTTP Host header
        {"time_local": "x", "remote_addr": "10.0.0.5", "host": "www.example.com",
         "request": "GET / HTTP/1.1"},  # nginx JSON log
        {"HOST": "www.example.com"},
        {"clientinfo": {"hostname": "WKS01"}},  # dotted fields stay exact
        {"clientinfo": {"Hostname": "WKS01"}},
        {"HOST": {"name": "WKS01"}},
        {"Host": {"Name": "WKS01"}},
    ],
    ids=["zeek http.log", "nginx json", "HOST", "lower dotted", "clientinfo.Hostname",
         "HOST.name", "Host.Name"],
)  # fmt: skip
def test_a_website_or_another_spelling_of_host_isn_t_read_as_the_machine(record):
    assert extract_host_from_record(record) is None


def test_the_priority_order_holds_across_cases():
    assert extract_host_from_record({"DeviceName": "MDE01", "Computer": "WKS01"}) == "WKS01"
    assert extract_host_from_record({"computer": "WKS01", "devicename": "MDE01"}) == "WKS01"
    assert extract_host_from_record({"PSComputerName": "PS01", "DeviceName": "MDE01"}) == "MDE01"


def test_an_exact_name_wins_over_another_case_of_it():
    assert extract_host_from_record({"computername": "lower", "ComputerName": "exact"}) == "exact"


def test_anchor_columns_of_unclear_meaning_still_give_no_host():
    record = {"MachineName": "M1", "Workstation": "W1", "computer_name": "C1", "host_name": "H1"}
    assert extract_host_from_record(record) is None
