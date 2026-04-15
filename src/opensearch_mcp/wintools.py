"""Wintools-mcp integration — run Windows-only EZ tools via gateway."""

from __future__ import annotations

import time as _time
from pathlib import Path

from opensearch_mcp.gateway import call_tool, gateway_available

_wintools_down = False
_wintools_down_since: float = 0
_WINTOOLS_RETRY_INTERVAL = 300  # 5 minutes


def wintools_available() -> bool:
    """Check if wintools-mcp is configured. Retries after 5 minutes."""
    global _wintools_down
    if _wintools_down:
        if _time.monotonic() - _wintools_down_since > _WINTOOLS_RETRY_INTERVAL:
            _wintools_down = False  # retry
        else:
            return False
    return gateway_available()


def mark_wintools_down() -> None:
    """Mark wintools as temporarily unreachable (retries after 5 min)."""
    global _wintools_down, _wintools_down_since
    _wintools_down = True
    _wintools_down_since = _time.monotonic()


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
    hostname: str = "",
) -> list[Path]:
    """Run an EZ tool on Windows and return paths to CSV output files.

    Automatically stages evidence to the SMB share if the path is
    outside the case directory (e.g., inside a VHDX temp mount).
    Converts all paths to UNC for Windows accessibility.
    """
    import shutil

    from sift_common import resolve_case_dir

    case_dir_str = resolve_case_dir()
    if not case_dir_str:
        raise RuntimeError("No active case directory")
    case_dir = Path(case_dir_str)
    evidence = Path(evidence_path)

    # Check if evidence is under case dir (accessible via SMB)
    needs_staging = False
    try:
        evidence.resolve().relative_to(case_dir.resolve())
    except ValueError:
        needs_staging = True

    if needs_staging:
        # Stage to extractions (on the SMB share)
        # Clean staging dir first to prevent stale data contamination
        artifact_name = evidence.name
        suffix = f"-{hostname}" if hostname else ""
        staging = case_dir / "extractions" / f"{artifact_name}{suffix}"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)
        if evidence.is_dir():
            shutil.copytree(str(evidence), str(staging), dirs_exist_ok=True)
        else:
            shutil.copy2(str(evidence), str(staging / evidence.name))
        # Convert staged path to UNC
        rel = str(staging.relative_to(case_dir))
        unc_evidence = _to_unc_path(rel)
    else:
        # Already under case dir — convert to UNC
        rel = str(evidence.resolve().relative_to(case_dir.resolve()))
        unc_evidence = _to_unc_path(rel)

    cmd = [tool_binary, input_flag, unc_evidence]
    if output_dir:
        cmd.extend(["--csv", output_dir])
    if extra_args:
        cmd.extend(extra_args)

    result = run_windows_tool(
        command=cmd,
        purpose=purpose or f"Run {tool_binary}",
        input_files=[unc_evidence],
    )

    if not result.get("success"):
        error = result.get("error", result.get("stderr", "unknown error"))
        raise RuntimeError(f"{tool_binary} failed: {error}")

    # Collect CSV output files from the share-relative output dir
    csv_rel = result.get("csv_output_dir", "")
    if csv_rel:
        out = Path(case_dir_str) / csv_rel
        if out.is_dir():
            return sorted(out.glob("*.csv"))
        elif out.exists() and out.suffix.lower() == ".csv":
            return [out]

    # Fallback: try full_output_path (works if SMB share is mounted at exact path)
    output_path = result.get("full_output_path", "")
    if output_path:
        out = Path(output_path)
        if out.exists() and out.suffix.lower() == ".csv":
            return [out]
        elif out.is_dir():
            return sorted(out.glob("*.csv"))

    return []


def _to_unc_path(case_relative_path: str) -> str:
    """Convert a case-relative path to a UNC path via the SMB share."""
    from opensearch_mcp.paths import vhir_dir

    samba_yaml = vhir_dir() / "samba.yaml"
    sift_host = "sift"
    share_name = "cases"
    if samba_yaml.is_file():
        try:
            import yaml

            doc = yaml.safe_load(samba_yaml.read_text()) or {}
            sift_host = doc.get("sift_hostname", "sift")
            share_name = doc.get("share_name", "cases")
        except Exception:
            pass
    win_rel = case_relative_path.replace("/", "\\")
    return f"\\\\{sift_host}\\{share_name}\\{win_rel}"
