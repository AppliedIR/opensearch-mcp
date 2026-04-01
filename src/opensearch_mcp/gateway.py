"""Gateway REST API client for opensearch-mcp."""

from __future__ import annotations

import json
import ssl
import urllib.request

from opensearch_mcp.paths import vhir_dir

_cached_config: dict | None = None
_config_loaded: bool = False


def load_gateway_config() -> dict | None:
    """Load gateway config. Returns {"url": ..., "token": ..., "tls": bool}.

    Cached after first load — gateway.yaml doesn't change mid-process.
    """
    global _cached_config, _config_loaded
    if _config_loaded:
        return _cached_config

    gw_config = vhir_dir() / "gateway.yaml"
    if not gw_config.exists():
        _config_loaded = True
        return None
    try:
        import yaml

        config = yaml.safe_load(gw_config.read_text()) or {}
        gw = config.get("gateway", {})
        port = gw.get("port", 4508)
        tls = gw.get("tls", {})
        scheme = "https" if tls.get("certfile") else "http"
        api_keys = config.get("api_keys", {})
        token = next(iter(api_keys.keys()), "") if api_keys else ""
        _cached_config = {
            "url": f"{scheme}://localhost:{port}",
            "token": token,
            "tls": bool(tls.get("certfile")),
        }
    except Exception:
        _cached_config = None
    _config_loaded = True
    return _cached_config


def call_tool(tool_name: str, arguments: dict, timeout: int = 60) -> dict:
    """Call MCP tool through gateway REST API. Returns parsed result dict."""
    config = load_gateway_config()
    if not config:
        raise RuntimeError("Gateway not configured")
    body = json.dumps({"arguments": arguments}).encode()
    headers = {"Content-Type": "application/json"}
    if config["token"]:
        headers["Authorization"] = f"Bearer {config['token']}"
    req = urllib.request.Request(
        f"{config['url']}/api/v1/tools/{tool_name}",
        data=body,
        headers=headers,
        method="POST",
    )
    open_kwargs: dict = {"timeout": timeout}
    if config.get("tls"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        open_kwargs["context"] = ctx
    try:
        with urllib.request.urlopen(req, **open_kwargs) as resp:
            raw = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError(f"Tool not found: {tool_name}") from e
        raise
    # Gateway REST returns {"result": [...], "tool": ..., "backend": ...}
    result_array = raw.get("result", raw.get("content", []))
    if result_array and isinstance(result_array, list):
        text = result_array[0].get("text", "")
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
    return raw


def gateway_available() -> bool:
    """Check if gateway config exists. Cheap — no network call."""
    config = load_gateway_config()
    return config is not None and bool(config.get("url"))
