"""A stand-in for the gateway's REST endpoint, answering `lookup_ioc` with the
response shapes opencti-mcp produces.

Shapes from sift-mcp `opencti_mcp/client.py::get_indicator_context` (found,
not found, and the not-found whose observable search did not complete) and
`opencti_mcp/server.py` (`_wrap_response`, the RateLimitError handler). The
gateway wraps a tool result as {"tool", "backend", "result": [{"type":
"text", "text": <json>}]}, which `opensearch_mcp.gateway.call_tool` unwraps —
so the real client code runs; only the HTTP exchange is replaced.
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


def found(ioc: str, confidence: int, labels: list[str] | None = None) -> dict:
    return _wrap(
        {
            "found": True,
            "ioc": ioc,
            "entity_type": "indicator",
            "type": "stix",
            "name": ioc,
            "description": "",
            "created": "2026-01-01T00:00:00Z",
            "confidence": confidence,
            "labels": labels or ["malware"],
            "related_threat_actors": [],
            "related_malware": [],
            "mitre_techniques": [],
            "source": "opencti",
            "ioc_type": "hash",
        }
    )


def not_found(ioc: str) -> dict:
    return _wrap({"found": False, "ioc": ioc, "ioc_type": "hash"})


def unconfirmed(ioc: str) -> dict:
    """The observable search failed, so the absence is unconfirmed."""
    return _wrap(
        {
            "found": False,
            "ioc": ioc,
            "note": (
                "Observable lookup did not complete (ConnectionResetError: reset) — "
                "absence of a match is unconfirmed, not a negative result."
            ),
            "ioc_type": "hash",
        }
    )


def errored(ioc: str) -> dict:
    return _wrap({"found": False, "ioc": ioc, "error": "Context unavailable: schema mismatch"})


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
