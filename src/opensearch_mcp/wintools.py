"""Wintools-mcp integration — run Windows-only EZ tools via gateway."""

from __future__ import annotations

from pathlib import Path

from opensearch_mcp.gateway import call_tool, gateway_available

_wintools_down = False


def wintools_available() -> bool:
    """Check if wintools-mcp is configured. Caches failure to avoid repeated timeouts."""
    if _wintools_down:
        return False
    return gateway_available()


def mark_wintools_down() -> None:
    """Mark wintools as unreachable for the rest of this process."""
    global _wintools_down
    _wintools_down = True


def run_windows_tool(
    command: list[str],
    purpose: str,
    input_files: list[str] | None = None,
    timeout: int = 300,
) -> dict:
    """Call run_windows_command on wintools-mcp via gateway REST API."""
    arguments: dict = {
        "command": command,
        "purpose": purpose,
        "save_output": True,
        "timeout": timeout,
    }
    if input_files:
        arguments["input_files"] = input_files
    try:
        return call_tool("run_windows_command", arguments, timeout=timeout + 30)
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
