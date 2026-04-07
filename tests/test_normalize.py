"""Tests for normalize_event and helpers."""

from opensearch_mcp.normalize import _clean_ip, normalize_event


class TestCleanIp:
    def test_valid_ipv4(self):
        assert _clean_ip("10.0.0.1") == "10.0.0.1"

    def test_valid_ipv6(self):
        assert _clean_ip("::1") == "::1"

    def test_dash(self):
        assert _clean_ip("-") is None

    def test_empty(self):
        assert _clean_ip("") is None

    def test_none(self):
        assert _clean_ip(None) is None

    def test_local(self):
        assert _clean_ip("LOCAL") is None

    def test_double_colon(self):
        assert _clean_ip("::") is None

    def test_whitespace(self):
        assert _clean_ip("  10.0.0.1  ") == "10.0.0.1"


class TestNormalizeEvent:
    def test_simple_event_id(self):
        data = {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Computer": "WS05",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:30:00Z"}},
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                },
                "EventData": {
                    "TargetUserName": "jsmith",
                    "SubjectUserName": "SYSTEM",
                    "IpAddress": "10.0.0.50",
                    "LogonType": "3",
                },
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 4624
        assert doc["winlog.event_id"] == 4624
        assert doc["winlog.channel"] == "Security"
        assert doc["host.name"] == "WS05"
        assert doc["@timestamp"] == "2024-01-15T10:30:00Z"
        assert doc["winlog.provider_name"] == "Microsoft-Windows-Security-Auditing"
        assert doc["user.name"] == "jsmith"
        assert doc["user.effective.name"] == "SYSTEM"
        assert doc["source.ip"] == "10.0.0.50"
        assert doc["winlog.logon.type"] == "3"

    def test_event_id_with_qualifiers(self):
        data = {
            "Event": {
                "System": {
                    "EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 6009},
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "EventLog"}},
                },
                "EventData": {},
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 6009

    def test_event_id_text_as_string(self):
        data = {
            "Event": {
                "System": {
                    "EventID": {"#attributes": {"Qualifiers": "32768"}, "#text": "1"},
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Sysmon"}},
                },
                "EventData": {},
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 1
        assert isinstance(doc["event.code"], int)

    def test_event_data_null(self):
        data = {
            "Event": {
                "System": {
                    "EventID": 1100,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "EventLog"}},
                },
                "EventData": None,
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 1100
        assert "user.name" not in doc  # None-stripped
        assert "source.ip" not in doc  # None-stripped
        assert doc["winlog.event_data"] == {}

    def test_event_data_missing(self):
        data = {
            "Event": {
                "System": {
                    "EventID": 1100,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "EventLog"}},
                },
            }
        }
        doc = normalize_event(data)
        assert doc["winlog.event_data"] == {}

    def test_invalid_ip_filtered(self):
        data = {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Security"}},
                },
                "EventData": {"IpAddress": "-"},
            }
        }
        doc = normalize_event(data)
        assert "source.ip" not in doc  # invalid IP → None → stripped

    def test_user_name_separation(self):
        """TargetUserName and SubjectUserName must map to different fields."""
        data = {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Security"}},
                },
                "EventData": {
                    "TargetUserName": "victim",
                    "SubjectUserName": "attacker",
                },
            }
        }
        doc = normalize_event(data)
        assert doc["user.name"] == "victim"
        assert doc["user.effective.name"] == "attacker"

    def test_process_fields(self):
        data = {
            "Event": {
                "System": {
                    "EventID": 1,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Sysmon"}},
                },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "ParentImage": "C:\\Windows\\explorer.exe",
                },
            }
        }
        doc = normalize_event(data)
        assert doc["process.name"] == "C:\\Windows\\System32\\cmd.exe"
        assert doc["process.command_line"] == "cmd.exe /c whoami"
        assert doc["process.parent.name"] == "C:\\Windows\\explorer.exe"

    def test_event_data_preserved_in_winlog(self):
        """All EventData fields must be preserved in winlog.event_data."""
        data = {
            "Event": {
                "System": {
                    "EventID": 7045,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Service Control Manager"}},
                },
                "EventData": {
                    "ServiceName": "EvilService",
                    "ImagePath": "C:\\evil.exe",
                    "ServiceType": "user mode service",
                },
            }
        }
        doc = normalize_event(data)
        assert doc["winlog.event_data"]["ServiceName"] == "EvilService"
        assert doc["winlog.event_data"]["ImagePath"] == "C:\\evil.exe"
        # ServiceName is only in winlog.event_data (flattened), not as a separate field
        assert "winlog.event_data.ServiceName" not in doc

    def test_invalid_event_id(self):
        data = {
            "Event": {
                "System": {
                    "EventID": "not_a_number",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Test"}},
                },
                "EventData": {},
            }
        }
        doc = normalize_event(data)
        assert "event.code" not in doc  # invalid → None → stripped

    def test_user_data_fallback(self):
        """Events with UserData instead of EventData should have data preserved."""
        data = {
            "Event": {
                "System": {
                    "EventID": 5858,
                    "Channel": "Microsoft-Windows-WMI-Activity/Operational",
                    "Computer": "RD01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-WMI-Activity"}},
                },
                "EventData": None,
                "UserData": {
                    "Operation_ClientFailure": {
                        "#attributes": {
                            "xmlns": "http://manifests.microsoft.com/win/2006/windows/WMI"
                        },
                        "Id": "{ABC-123}",
                        "ClientMachine": "RD01",
                        "User": "NT AUTHORITY\\SYSTEM",
                        "ClientProcessId": 3952,
                        "Operation": "Start IWbemServices::ExecQuery",
                    }
                },
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 5858
        # winlog.event_data contains flattened UserData (wrapper stripped, #attributes removed)
        assert "ClientMachine" in doc["winlog.event_data"]
        assert doc["winlog.event_data"]["ClientMachine"] == "RD01"
        assert "#attributes" not in doc["winlog.event_data"]
        assert "Operation_ClientFailure" not in doc["winlog.event_data"]

    def test_user_data_not_used_when_event_data_exists(self):
        """EventData takes priority over UserData when both exist."""
        data = {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Security"}},
                },
                "EventData": {"TargetUserName": "admin"},
                "UserData": {"SomeWrapper": {"Field": "value"}},
            }
        }
        doc = normalize_event(data)
        assert doc["user.name"] == "admin"
        assert doc["winlog.event_data"] == {"TargetUserName": "admin"}

    def test_user_data_terminal_services(self):
        """TerminalServices RDP events use UserData with session info."""
        data = {
            "Event": {
                "System": {
                    "EventID": 21,
                    "Channel": "Microsoft-Windows-TerminalServices-LocalSessionManager"
                    "/Operational",
                    "Computer": "RD01",
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T09:00:00Z"}},
                    "Provider": {
                        "#attributes": {
                            "Name": "Microsoft-Windows-TerminalServices-LocalSessionManager"
                        }
                    },
                },
                "EventData": None,
                "UserData": {
                    "EventXML": {
                        "#attributes": {"xmlns": "Event_NS"},
                        "User": "CONTOSO\\jsmith",
                        "SessionID": "3",
                        "Address": "203.0.113.4",
                    }
                },
            }
        }
        doc = normalize_event(data)
        assert doc["event.code"] == 21
        # UserData flattened: wrapper stripped, #attributes removed
        assert "User" in doc["winlog.event_data"]
        assert "EventXML" not in doc["winlog.event_data"]
