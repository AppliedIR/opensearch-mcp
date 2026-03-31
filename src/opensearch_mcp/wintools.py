"""Wintools-mcp integration — run Windows-only EZ tools via gateway."""

from __future__ import annotations

import json
import ssl
import urllib.request
from pathlib import Path

from opensearch_mcp.paths import vhir_dir


def _load_gateway_config() -> dict | None:
    """Load gateway config to find wintools endpoint."""
    gw_config = vhir_dir() / "gateway.yaml"
    if not gw_config.exists():
        return None
    try:
        import yaml

        config = yaml.safe_load(gw_config.read_text()) or {}
        backends = config.get("backends", {})
        wt = backends.get("wintools-mcp") or backends.get("wintools")
        if not wt:
            return None
        # Gateway base URL — strip MCP endpoint suffix if present
        url = wt.get("url", "")
        return {
            "url": url,
            "token": wt.get("token", config.get("api_key", "")),
        }
    except Exception:
        return None


def _get_gateway_base_url(config: dict) -> str:
    """Extract gateway base URL from config, stripping MCP endpoint suffix."""
    url = config.get("url", "").rstrip("/")
    if "/mcp/" in url:
        return url.split("/mcp/")[0]
    return url


_wintools_down = False


def wintools_available() -> bool:
    """Check if wintools-mcp is configured. Caches failure to avoid repeated timeouts."""
    global _wintools_down
    if _wintools_down:
        return False
    config = _load_gateway_config()
    if not config or not config.get("url"):
        return False
    return True


def mark_wintools_down() -> None:
    """Mark wintools as unreachable for the rest of this process."""
    global _wintools_down
    _wintools_down = True


def _call_gateway_tool(
    base_url: str, token: str, tool_name: str, arguments: dict, timeout: int = 60
) -> dict:
    """Call any MCP tool via gateway REST API.

    Uses POST /api/v1/tools/{tool_name} with {"arguments": {...}}.
    Parses the double-wrapped response: {"content": [{"text": "..."}]}.
    """
    body = json.dumps({"arguments": arguments}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        f"{base_url}/api/v1/tools/{tool_name}",
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        raw = json.loads(resp.read())
    # Gateway wraps tool output in MCP content array
    if "content" in raw and raw["content"]:
        text = raw["content"][0].get("text", "")
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
    return raw


def run_windows_tool(
    command: list[str],
    purpose: str,
    input_files: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """Call run_windows_command on wintools-mcp via gateway REST API."""
    config = _load_gateway_config()
    if not config or not config.get("url"):
        raise RuntimeError("wintools-mcp not configured")

    base_url = _get_gateway_base_url(config)
    token = config.get("token", "")
    tool_name = "mcp__wintools-mcp__run_windows_command"

    arguments: dict = {
        "command": command,
        "purpose": purpose,
        "save_output": True,
        "timeout": timeout,
    }
    if input_files:
        arguments["input_files"] = input_files

    try:
        return _call_gateway_tool(base_url, token, tool_name, arguments, timeout + 30)
    except Exception as e:
        raise RuntimeError(f"wintools-mcp call failed: {e}") from e


def run_tool_and_get_csv(
    tool_binary: str,
    input_flag: str,
    evidence_path: str,
    output_dir: str | None = None,
    extra_args: list[str] | None = None,
    purpose: str = "",
) -> list[Path]:
    """Run an EZ tool on Windows and return paths to CSV output files.

    The evidence must be accessible to the Windows machine (via SMB share).
    Output is written to the case directory (also on the share).
    """
    cmd = [tool_binary, input_flag, evidence_path]
    if output_dir:
        cmd.extend(["--csv", output_dir])
    if extra_args:
        cmd.extend(extra_args)

    result = run_windows_tool(
        command=cmd,
        purpose=purpose or f"Run {tool_binary}",
        input_files=[evidence_path],
    )

    if not result.get("success"):
        error = result.get("error", result.get("stderr", "unknown error"))
        raise RuntimeError(f"{tool_binary} failed: {error}")

    # Collect CSV output files from the output path
    output_path = result.get("full_output_path", "")
    if output_path:
        csv_files = []
        out = Path(output_path)
        if out.exists() and out.suffix.lower() == ".csv":
            csv_files.append(out)
        elif out.is_dir():
            csv_files = sorted(out.glob("*.csv"))
        return csv_files

    return []
