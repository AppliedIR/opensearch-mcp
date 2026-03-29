"""Tests for _coerce_scalars and string coercion in normalize_event."""

from __future__ import annotations

from opensearch_mcp.normalize import _coerce_scalars, normalize_event

# ---------------------------------------------------------------------------
# _coerce_scalars unit tests
# ---------------------------------------------------------------------------


class TestCoerceScalarsBasic:
    def test_string_unchanged(self):
        assert _coerce_scalars({"k": "v"}) == {"k": "v"}

    def test_int_to_string(self):
        assert _coerce_scalars({"k": 3}) == {"k": "3"}

    def test_bool_to_string(self):
        assert _coerce_scalars({"k": True}) == {"k": "True"}

    def test_float_to_string(self):
        assert _coerce_scalars({"k": 3.14}) == {"k": "3.14"}

    def test_none_preserved(self):
        assert _coerce_scalars({"k": None}) == {"k": None}

    def test_empty_dict(self):
        assert _coerce_scalars({}) == {}

    def test_empty_string_preserved(self):
        assert _coerce_scalars({"k": ""}) == {"k": ""}

    def test_zero_to_string(self):
        assert _coerce_scalars({"k": 0}) == {"k": "0"}


class TestCoerceScalarsNested:
    def test_nested_dict_recursed(self):
        result = _coerce_scalars({"outer": {"inner": 42}})
        assert result == {"outer": {"inner": "42"}}

    def test_deeply_nested(self):
        result = _coerce_scalars({"a": {"b": {"c": 99}}})
        assert result == {"a": {"b": {"c": "99"}}}

    def test_nested_dict_none_preserved(self):
        result = _coerce_scalars({"outer": {"k": None}})
        assert result == {"outer": {"k": None}}


class TestCoerceScalarsList:
    def test_list_scalars_coerced(self):
        result = _coerce_scalars({"k": [1, 2, 3]})
        assert result == {"k": ["1", "2", "3"]}

    def test_list_none_preserved(self):
        result = _coerce_scalars({"k": [1, None, 3]})
        assert result == {"k": ["1", None, "3"]}

    def test_list_strings_unchanged(self):
        result = _coerce_scalars({"k": ["a", "b"]})
        assert result == {"k": ["a", "b"]}

    def test_list_dicts_recursed(self):
        """Dicts inside lists must also be coerced."""
        result = _coerce_scalars({"k": [{"n": 42}]})
        assert result == {"k": [{"n": "42"}]}

    def test_list_mixed_types(self):
        result = _coerce_scalars({"k": ["str", 42, True, None]})
        assert result == {"k": ["str", "42", "True", None]}

    def test_empty_list_preserved(self):
        result = _coerce_scalars({"k": []})
        assert result == {"k": []}


class TestCoerceScalarsTypeConflict:
    """Test the specific type conflict scenarios that motivated coercion."""

    def test_logon_type_int_and_string_same_output(self):
        """LogonType as int 3 and string "3" produce identical coerced output."""
        r1 = _coerce_scalars({"LogonType": 3})
        r2 = _coerce_scalars({"LogonType": "3"})
        assert r1 == r2 == {"LogonType": "3"}

    def test_process_id_int_and_string(self):
        r1 = _coerce_scalars({"ProcessId": 1234})
        r2 = _coerce_scalars({"ProcessId": "1234"})
        assert r1 == r2

    def test_session_id_int(self):
        result = _coerce_scalars({"SessionID": 3})
        assert result["SessionID"] == "3"


# ---------------------------------------------------------------------------
# Coercion in normalize_event (integration)
# ---------------------------------------------------------------------------


class TestCoercionInNormalize:
    def _make_event(self, event_data):
        return {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-15T10:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "Security"}},
                },
                "EventData": event_data,
            }
        }

    def test_event_data_values_are_strings(self):
        """All scalar EventData values in winlog.event_data are strings."""
        data = self._make_event({"LogonType": 3, "ProcessId": 1234, "Flag": True})
        doc = normalize_event(data)
        ed = doc["winlog.event_data"]
        assert ed["LogonType"] == "3"
        assert ed["ProcessId"] == "1234"
        assert ed["Flag"] == "True"

    def test_top_level_ecs_fields_not_coerced(self):
        """Top-level ECS fields keep proper types (int, ip)."""
        data = self._make_event(
            {
                "IpAddress": "10.0.0.1",
                "LogonType": "3",
                "TargetUserName": "admin",
            }
        )
        doc = normalize_event(data)
        assert doc["event.code"] == 4624  # int, not "4624"
        assert isinstance(doc["event.code"], int)
        assert doc["source.ip"] == "10.0.0.1"  # string from _clean_ip
        assert doc["user.name"] == "admin"

    def test_coercion_applied_after_ecs_extraction(self):
        """ECS extraction uses original values, then coercion applies to stored data."""
        data = self._make_event({"IpAddress": "192.168.1.1", "LogonType": 3})
        doc = normalize_event(data)
        # source.ip extracted from original (string "192.168.1.1")
        assert doc["source.ip"] == "192.168.1.1"
        # winlog.event_data has coerced version
        assert doc["winlog.event_data"]["LogonType"] == "3"

    def test_event_data_none_produces_empty_dict(self):
        """EventData=None still produces empty winlog.event_data."""
        data = self._make_event(None)
        doc = normalize_event(data)
        assert doc["winlog.event_data"] == {}

    def test_event_data_empty_dict_preserved(self):
        data = self._make_event({})
        doc = normalize_event(data)
        assert doc["winlog.event_data"] == {}

    def test_nested_dict_in_event_data_coerced(self):
        """Nested dicts (e.g., Data elements) have scalars coerced too."""
        data = self._make_event({"Data": {"Name": "value", "Count": 5}})
        doc = normalize_event(data)
        assert doc["winlog.event_data"]["Data"]["Count"] == "5"

    def test_user_data_also_coerced(self):
        """UserData fallback path also gets coerced."""
        data = {
            "Event": {
                "System": {
                    "EventID": 21,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "TSLocal"}},
                },
                "EventData": None,
                "UserData": {
                    "EventXML": {
                        "#attributes": {"xmlns": "ns"},
                        "SessionID": 3,
                        "User": "admin",
                    }
                },
            }
        }
        doc = normalize_event(data)
        inner = doc["winlog.event_data"]["EventXML"]
        assert inner["SessionID"] == "3"
        assert inner["User"] == "admin"  # string stays string

    def test_attributes_dict_preserved_in_user_data(self):
        """#attributes dict inside UserData is recursed, scalars coerced."""
        data = {
            "Event": {
                "System": {
                    "EventID": 5858,
                    "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                    "Provider": {"#attributes": {"Name": "WMI"}},
                },
                "EventData": None,
                "UserData": {
                    "Wrapper": {
                        "#attributes": {"xmlns": "ns", "version": 1},
                        "ClientProcessId": 3952,
                    }
                },
            }
        }
        doc = normalize_event(data)
        inner = doc["winlog.event_data"]["Wrapper"]
        assert inner["ClientProcessId"] == "3952"
        assert inner["#attributes"]["version"] == "1"
