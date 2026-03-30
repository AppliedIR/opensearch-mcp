"""Tests for EZ tool configuration and command building."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.tools import (
    TOOLS,
    ToolConfig,
    _build_command,
    _run_tool,
    get_active_tools,
)

# ---------------------------------------------------------------------------
# TOOLS dictionary completeness
# ---------------------------------------------------------------------------


class TestToolsDict:
    def test_has_all_tools(self):
        """TOOLS dict contains all expected tools."""
        expected = {
            "amcache",
            "shimcache",
            "registry",
            "shellbags",
            "jumplists",
            "lnk",
            "recyclebin",
            "mft",
            "usn",
            "timeline",
            "evtxecmd",
        }
        assert set(TOOLS.keys()) == expected

    def test_amcache_tier_1(self):
        assert TOOLS["amcache"].tier == 1

    def test_shimcache_tier_1(self):
        assert TOOLS["shimcache"].tier == 1

    def test_registry_tier_1(self):
        assert TOOLS["registry"].tier == 1

    def test_shellbags_tier_1(self):
        assert TOOLS["shellbags"].tier == 1

    def test_jumplists_tier_2(self):
        assert TOOLS["jumplists"].tier == 2

    def test_lnk_tier_2(self):
        assert TOOLS["lnk"].tier == 2

    def test_recyclebin_tier_2(self):
        assert TOOLS["recyclebin"].tier == 2

    def test_mft_tier_3(self):
        assert TOOLS["mft"].tier == 3

    def test_usn_tier_3(self):
        assert TOOLS["usn"].tier == 3

    def test_timeline_tier_3(self):
        assert TOOLS["timeline"].tier == 3


# ---------------------------------------------------------------------------
# ToolConfig fields
# ---------------------------------------------------------------------------


class TestToolConfig:
    def test_natural_key_only_set_for_mft(self):
        """Only MFT should have a natural_key; all others use content hash."""
        for name, cfg in TOOLS.items():
            if name == "mft":
                assert cfg.natural_key is not None
                assert "EntryNumber" in cfg.natural_key
            else:
                assert cfg.natural_key is None, f"{name} should not have natural_key"

    def test_multi_csv_amcache(self):
        assert TOOLS["amcache"].multi_csv is True

    def test_multi_csv_registry(self):
        assert TOOLS["registry"].multi_csv is True

    def test_multi_csv_shimcache_false(self):
        assert TOOLS["shimcache"].multi_csv is False

    def test_every_tool_has_time_field(self):
        """Every tool must define a time_field for filtering."""
        for name, cfg in TOOLS.items():
            assert cfg.time_field is not None, f"{name} missing time_field"

    def test_every_tool_has_index_suffix(self):
        for name, cfg in TOOLS.items():
            assert cfg.index_suffix, f"{name} missing index_suffix"


# ---------------------------------------------------------------------------
# get_active_tools
# ---------------------------------------------------------------------------


class TestGetActiveTools:
    def test_no_flags_returns_tier_1_and_2(self):
        """Default (no flags) returns tier 1 + tier 2 tools (7 total)."""
        active = get_active_tools()
        names = {t.cli_name for t in active}
        # 4 tier-1 + 3 tier-2 = 7
        assert len(active) == 7
        # All tier 1 present
        assert {"amcache", "shimcache", "registry", "shellbags"}.issubset(names)
        # All tier 2 present
        assert {"jumplists", "lnk", "recyclebin"}.issubset(names)
        # No tier 3
        assert "mft" not in names
        assert "usn" not in names
        assert "timeline" not in names

    def test_include_mft_returns_tier_1_plus_mft(self):
        """--include mft returns tier 1 tools + mft only."""
        active = get_active_tools(include={"mft"})
        names = {t.cli_name for t in active}
        # tier 1 (always) + mft = 5
        assert len(active) == 5
        assert "mft" in names
        assert "amcache" in names
        # tier 2 NOT included (not in include set)
        assert "jumplists" not in names

    def test_exclude_jumplists(self):
        """--exclude jumplists returns all default minus jumplists."""
        active = get_active_tools(exclude={"jumplists"})
        names = {t.cli_name for t in active}
        assert "jumplists" not in names
        assert "amcache" in names
        assert "lnk" in names

    def test_include_and_exclude_combined(self):
        """--include mft --exclude shimcache: tier 1 + mft, minus shimcache."""
        active = get_active_tools(include={"mft"}, exclude={"shimcache"})
        names = {t.cli_name for t in active}
        assert "mft" in names
        assert "shimcache" not in names
        assert "amcache" in names

    def test_tier_3_not_included_without_flag(self):
        """Tier 3 tools are never included without explicit --include."""
        active = get_active_tools()
        names = {t.cli_name for t in active}
        tier3 = {"mft", "usn", "timeline"}
        assert not tier3.intersection(names)


# ---------------------------------------------------------------------------
# _build_command
# ---------------------------------------------------------------------------


class TestBuildCommand:
    def test_amcache_includes_nl_flag(self):
        """Amcache command includes --nl to skip transaction log check."""
        cfg = TOOLS["amcache"]
        cmd = _build_command(cfg, "amcache", Path("/evidence/Amcache.hve"), "/tmp/out")
        assert "--nl" in cmd
        assert "-f" in cmd
        assert str(Path("/evidence/Amcache.hve")) in cmd

    def test_shimcache_includes_nl_flag(self):
        """Regression: shimcache MUST have --nl flag.

        Shimcache uses the SYSTEM hive which, like Amcache, comes from
        live collection and may have dirty transaction logs. Without --nl,
        AppCompatCacheParser may fail on live-collected SYSTEM hives.
        """
        cfg = TOOLS["shimcache"]
        cmd = _build_command(cfg, "shimcache", Path("/evidence/SYSTEM"), "/tmp/out")
        assert "--nl" in cmd, (
            "shimcache command missing --nl flag; live-collected SYSTEM "
            "hives have dirty transaction logs"
        )

    def test_shimcache_uses_f_flag(self):
        cfg = TOOLS["shimcache"]
        cmd = _build_command(cfg, "shimcache", Path("/evidence/SYSTEM"), "/tmp/out")
        assert "-f" in cmd

    def test_shimcache_has_csvf(self):
        cfg = TOOLS["shimcache"]
        cmd = _build_command(cfg, "shimcache", Path("/evidence/SYSTEM"), "/tmp/out")
        assert "--csvf" in cmd
        idx = cmd.index("--csvf")
        assert cmd[idx + 1] == "shimcache.csv"

    def test_registry_uses_d_flag(self):
        """Registry (RECmd) uses -d for directory input, not -f."""
        cfg = TOOLS["registry"]
        cmd = _build_command(cfg, "registry", Path("/evidence/config"), "/tmp/out")
        assert "-d" in cmd
        assert "-f" not in cmd

    def test_registry_includes_nl_and_batch(self):
        """Registry command includes --nl and --bn Kroll_Batch.reb."""
        cfg = TOOLS["registry"]
        cmd = _build_command(cfg, "registry", Path("/evidence/config"), "/tmp/out")
        assert "--nl" in cmd
        assert "--bn" in cmd
        # Batch file path should follow --bn
        bn_idx = cmd.index("--bn")
        assert "Kroll_Batch.reb" in cmd[bn_idx + 1]

    def test_shellbags_uses_d_flag(self):
        """SBECmd uses -d for directory input (user profile dir)."""
        cfg = TOOLS["shellbags"]
        cmd = _build_command(cfg, "shellbags", Path("/evidence/Users/admin"), "/tmp/out")
        assert "-d" in cmd

    def test_mft_uses_f_and_csvf(self):
        """MFTECmd uses -f and --csvf for MFT parsing."""
        cfg = TOOLS["mft"]
        cmd = _build_command(cfg, "mft", Path("/evidence/$MFT"), "/tmp/out")
        assert "-f" in cmd
        assert "--csvf" in cmd

    def test_usn_checks_for_mft_sibling(self, tmp_path):
        """USN command includes -m $MFT when sibling exists."""
        j_file = tmp_path / "$J"
        j_file.touch()
        mft_file = tmp_path / "$MFT"
        mft_file.touch()

        cfg = TOOLS["usn"]
        cmd = _build_command(cfg, "usn", j_file, "/tmp/out")
        assert "-m" in cmd
        m_idx = cmd.index("-m")
        assert "$MFT" in cmd[m_idx + 1]

    def test_usn_no_mft_sibling(self, tmp_path):
        """USN command omits -m when no $MFT sibling."""
        j_file = tmp_path / "$J"
        j_file.touch()

        cfg = TOOLS["usn"]
        cmd = _build_command(cfg, "usn", j_file, "/tmp/out")
        assert "-m" not in cmd

    def test_lnk_includes_all_flag(self):
        """LECmd includes --all flag."""
        cfg = TOOLS["lnk"]
        cmd = _build_command(cfg, "lnk", Path("/evidence/Recent"), "/tmp/out")
        assert "--all" in cmd

    def test_unknown_tool_raises(self):
        """_build_command raises ValueError for unknown tool name."""
        cfg = ToolConfig(
            cli_name="bogus",
            binary="bogus",
            tier=1,
            index_suffix="bogus",
            time_field=None,
            natural_key=None,
            multi_csv=False,
        )
        with pytest.raises(ValueError, match="No command builder"):
            _build_command(cfg, "bogus", Path("/x"), "/tmp")


# ---------------------------------------------------------------------------
# _run_tool
# ---------------------------------------------------------------------------


class TestRunTool:
    @patch("opensearch_mcp.tools.subprocess.run")
    def test_raises_on_nonzero_exit(self, mock_run):
        """_run_tool raises RuntimeError on non-zero exit code."""
        mock_run.return_value = MagicMock(returncode=1, stderr="error msg")
        with pytest.raises(RuntimeError, match="failed.*exit 1"):
            _run_tool(["fake_tool", "-f", "test"], "FakeTool")

    @patch("opensearch_mcp.tools.subprocess.run")
    def test_success_no_exception(self, mock_run):
        """_run_tool does not raise on zero exit code."""
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        _run_tool(["fake_tool"], "FakeTool")  # should not raise


# ---------------------------------------------------------------------------
# run_and_ingest
# ---------------------------------------------------------------------------


class TestRunAndIngest:
    @patch("opensearch_mcp.tools._run_tool")
    @patch("opensearch_mcp.tools.ingest_csv")
    def test_calls_build_command_with_correct_args(self, mock_ingest, mock_run, tmp_path):
        """run_and_ingest calls _build_command and passes result to _run_tool."""
        from opensearch_mcp.tools import run_and_ingest

        # Create a CSV file that would be the tool output
        mock_run.return_value = None  # success
        mock_ingest.return_value = (10, 0, 0)

        # Mock tempfile to use tmp_path
        with patch("opensearch_mcp.tools.tempfile.mkdtemp", return_value=str(tmp_path)):
            # Create a fake CSV output file in tmp_path
            (tmp_path / "shimcache.csv").write_text(
                "Path,LastModifiedTimeUTC\nC:\\a.exe,2024-01-01\n"
            )
            cnt, sk, bf = run_and_ingest(
                tool_name="shimcache",
                artifact_path=Path("/evidence/SYSTEM"),
                client=MagicMock(),
                case_id="INC001",
                hostname="HOST1",
            )
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "AppCompatCacheParser" in cmd[0]
        assert cnt == 10

    @patch("opensearch_mcp.tools._run_tool")
    @patch("opensearch_mcp.tools.shutil.rmtree")
    def test_cleans_up_temp_directory_on_failure(self, mock_rmtree, mock_run, tmp_path):
        """run_and_ingest cleans up temp dir even when _run_tool fails."""
        from opensearch_mcp.tools import run_and_ingest

        mock_run.side_effect = RuntimeError("Tool crashed")

        with patch("opensearch_mcp.tools.tempfile.mkdtemp", return_value=str(tmp_path)):
            with pytest.raises(RuntimeError, match="Tool crashed"):
                run_and_ingest(
                    tool_name="amcache",
                    artifact_path=Path("/evidence/Amcache.hve"),
                    client=MagicMock(),
                    case_id="INC001",
                    hostname="HOST1",
                )
        mock_rmtree.assert_called_once_with(str(tmp_path), ignore_errors=True)

    @patch("opensearch_mcp.tools._run_tool")
    def test_returns_zero_when_no_csv_output(self, mock_run, tmp_path):
        """run_and_ingest returns (0, 0, 0) when no CSV output produced."""
        from opensearch_mcp.tools import run_and_ingest

        mock_run.return_value = None  # success but no CSV produced

        with patch("opensearch_mcp.tools.tempfile.mkdtemp", return_value=str(tmp_path)):
            cnt, sk, bf = run_and_ingest(
                tool_name="shimcache",
                artifact_path=Path("/evidence/SYSTEM"),
                client=MagicMock(),
                case_id="INC001",
                hostname="HOST1",
            )
        assert (cnt, sk, bf) == (0, 0, 0)


# ---------------------------------------------------------------------------
# _build_command regression guards
# ---------------------------------------------------------------------------


class TestBuildCommandRegressions:
    def test_amcache_uses_nl_flag(self):
        """Regression guard: amcache command must include --nl."""
        cfg = TOOLS["amcache"]
        cmd = _build_command(cfg, "amcache", Path("/evidence/Amcache.hve"), "/tmp/out")
        assert "--nl" in cmd

    def test_shimcache_uses_nl_flag(self):
        """Regression guard (Bug 2): shimcache command MUST include --nl.

        Without --nl, AppCompatCacheParser fails on live-collected
        SYSTEM hives that have dirty transaction logs.
        """
        cfg = TOOLS["shimcache"]
        cmd = _build_command(cfg, "shimcache", Path("/evidence/SYSTEM"), "/tmp/out")
        assert "--nl" in cmd

    def test_registry_uses_artifact_path_parent(self):
        """Regression guard (Bug 3): registry uses artifact_path.parent for files.

        RECmd uses -d (directory), but discovery finds individual hive files.
        _build_command must use artifact_path.parent when given a file.
        """
        cfg = TOOLS["registry"]
        # Simulate discovery finding a file path (e.g., config/SYSTEM)
        hive_file = Path("/evidence/Windows/System32/config/SYSTEM")
        cmd = _build_command(cfg, "registry", hive_file, "/tmp/out")
        assert "-d" in cmd
        d_idx = cmd.index("-d")
        # The directory argument should be the parent, not the file itself
        assert cmd[d_idx + 1] == str(hive_file.parent)
