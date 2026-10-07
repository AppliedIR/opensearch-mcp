"""A stand-in for the gateway's REST endpoint, answering `lookup_ioc` with the
response shapes the threat-intel backend produces.

Shapes from sift-mcp `opencti_mcp/server.py::_lookup_ioc`: an aggregate
`outcome` (MATCH, NO_MATCH, UNAVAILABLE), `providers` holding each platform's
answer verbatim, `found` (null when UNAVAILABLE) and `note` on UNAVAILABLE, and
the error reply of the backend's own query limit. The gateway wraps a tool
result as {"tool", "backend", "result": [{"type": "text", "text": <json>}]},
which `opensearch_mcp.gateway.call_tool` unwraps — so the real client code
runs; only the HTTP exchange is replaced.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable

from opensearch_mcp import gateway

_CAVEATS = ["Absence from CTI does not mean benign"]


def _wrap(result: dict) -> dict:
    result = dict(result)
    result["audit_id"] = "opencti-test-001"
    result["examiner"] = "tester"
    if "error" not in result:
        result["caveats"] = _CAVEATS
        result["interpretation_constraint"] = "CTI context, not a verdict"
    return result


_QUERIED_AT = "2026-10-07T12:00:00+00:00"


def opencti_record(ioc: str, confidence: int = 90, labels=None, revoked: bool = False) -> dict:
    """An OpenCTI indicator record as the adapter passes it through."""
    return {
        "id": f"indicator--{abs(hash(ioc)) % 10**12:012d}",
        "name": ioc,
        "created": "2026-01-01T00:00:00Z",
        "revoked": revoked,
        "confidence": confidence,
        "x_opencti_score": confidence,
        "valid_until": "2027-01-01T00:00:00Z",
        "objectLabel": [{"value": v} for v in (labels or ["malware"])],
    }


def block(outcome: str, matches=(), reason: str = "", version: str = "6.9.10") -> dict:
    answer = {
        "outcome": outcome,
        "version": version,
        "queried_at": _QUERIED_AT,
        "matches": list(matches),
    }
    if reason:
        answer["reason"] = reason
    return answer


def reply(ioc: str, providers: dict) -> dict:
    """lookup_ioc's reply for these providers' answers."""
    outcomes = [p["outcome"] for p in providers.values()]
    outcome = (
        "MATCH"
        if "MATCH" in outcomes
        else "UNAVAILABLE"
        if "UNAVAILABLE" in outcomes
        else "NO_MATCH"
    )
    result = {
        "ioc": ioc,
        "outcome": outcome,
        "found": None if outcome == "UNAVAILABLE" else outcome == "MATCH",
        "providers": providers,
    }
    if outcome == "UNAVAILABLE":
        result["reason"] = "; ".join(
            f"{n}: {p['reason']}" for n, p in providers.items() if p["outcome"] == "UNAVAILABLE"
        )
        result["note"] = f"Not answered: {result['reason']}"
    return _wrap(result)


def found(
    ioc: str,
    confidence: int,
    labels: list[str] | None = None,
    *,
    name: str | None = None,
    entity_type: str = "indicator",
) -> dict:
    """OpenCTI's own indicator for `ioc`. With another `name` or kind (a
    full-text neighbour, an observable), the adapter has no exact record:
    NO_MATCH. Names compare as the adapter compares them: ignoring case,
    except for a fuzzy hash (SSDEEP's case carries meaning)."""
    fuzzy = ioc.count(":") == 2 and ioc.split(":", 1)[0].isdigit()
    same = name is None or (name == ioc if fuzzy else name.lower() == ioc.lower())
    if not same or entity_type != "indicator":
        return not_found(ioc)
    record = opencti_record(ioc, confidence, labels)
    return reply(ioc, {"opencti": block("MATCH", [record])})


def not_found(ioc: str) -> dict:
    return reply(ioc, {"opencti": block("NO_MATCH")})


def unconfirmed(ioc: str) -> dict:
    """OpenCTI couldn't be asked: UNAVAILABLE, with the reason."""
    return reply(ioc, {"opencti": block("UNAVAILABLE", reason="can't reach OpenCTI")})


def errored(ioc: str) -> dict:
    return _wrap({"error": "query_failed", "message": "Query failed. Check server logs."})


def text_reply(ioc: str) -> str:
    """Tool output that is not JSON: the gateway passes it on as text, and
    `call_tool` returns it as {"text": ...}. This is the gateway's measured
    reply to a lookup_ioc call without `ioc`."""
    return "Input validation error: 'ioc' is a required property"


def rate_limited() -> dict:
    return _wrap(
        {
            "error": "rate_limit_exceeded",
            "message": "Rate limit exceeded for query. Wait 0.0s.",
            "wait_seconds": 0.0,
        }
    )


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeGateway:
    """`answer(ioc)` returns a lookup result, a string the tool printed
    instead of JSON, or an exception to raise as the HTTP call's failure."""

    def __init__(self, answer: Callable[[str], dict | str | Exception]):
        self.answer = answer
        self.asked: list[str] = []

    def install(self, monkeypatch, available: bool = True) -> FakeGateway:
        config = (
            {"url": "http://gateway.test:4508", "token": "", "tls": False} if available else None
        )
        monkeypatch.setattr(gateway, "load_gateway_config", lambda: config)
        monkeypatch.setattr(gateway.urllib.request, "urlopen", self._urlopen)
        return self

    def _urlopen(self, req, **kwargs):
        ioc = json.loads(req.data)["arguments"]["ioc"]
        self.asked.append(ioc)
        result = self.answer(ioc)
        if isinstance(result, Exception):
            raise result
        text = result if isinstance(result, str) else json.dumps(result)
        body = {
            "tool": "lookup_ioc",
            "backend": "opencti-mcp",
            "result": [{"type": "text", "text": text}],
        }
        return _Response(json.dumps(body).encode())
