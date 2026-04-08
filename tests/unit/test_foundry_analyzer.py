"""Unit tests for FoundryAnalyzer with mocked subprocess."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from contract_audit.analyzers.foundry.analyzer import FoundryAnalyzer
from contract_audit.core.models import AuditConfig, AuditContext


def _make_context(tmp_path: Path, with_foundry_toml: bool = True) -> AuditContext:
    if with_foundry_toml:
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    config = AuditConfig()
    return AuditContext(project_path=tmp_path, config=config)


class TestFoundryAnalyzerAvailability:
    def test_is_available_when_forge_installed(self):
        analyzer = FoundryAnalyzer()
        with patch("shutil.which", return_value="/usr/bin/forge"):
            assert analyzer.is_available() is True

    def test_not_available_when_forge_missing(self):
        analyzer = FoundryAnalyzer()
        with patch("shutil.which", return_value=None):
            assert analyzer.is_available() is False

    @pytest.mark.asyncio
    async def test_analyze_skips_when_not_available(self, tmp_path):
        analyzer = FoundryAnalyzer()
        context = _make_context(tmp_path)
        with patch("shutil.which", return_value=None):
            findings = await analyzer.analyze(context)
        assert findings == []

    @pytest.mark.asyncio
    async def test_analyze_skips_without_foundry_toml(self, tmp_path):
        analyzer = FoundryAnalyzer()
        context = _make_context(tmp_path, with_foundry_toml=False)
        with patch("shutil.which", return_value="/usr/bin/forge"):
            findings = await analyzer.analyze(context)
        assert findings == []


class TestFoundryAnalyzerRun:
    @pytest.mark.asyncio
    async def test_analyze_returns_empty_on_all_passing(self, tmp_path):
        """forge output with no failures should produce no findings."""
        analyzer = FoundryAnalyzer()
        context = _make_context(tmp_path)

        forge_output = {
            "src/Vault.t.sol": {
                "test_results": {
                    "testFuzz_deposit": {"status": "Success"},
                }
            }
        }

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(
            return_value=(json.dumps(forge_output).encode(), b"")
        )
        mock_proc.returncode = 0

        with patch("shutil.which", return_value="/usr/bin/forge"), \
             patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", new=AsyncMock(return_value=(json.dumps(forge_output).encode(), b""))):
            findings = await analyzer.analyze(context)

        assert findings == []

    @pytest.mark.asyncio
    async def test_analyze_returns_findings_on_failures(self, tmp_path):
        """Failing forge tests should produce findings."""
        analyzer = FoundryAnalyzer()
        context = _make_context(tmp_path)

        forge_output = {
            "src/Vault.t.sol": {
                "test_results": {
                    "test_reentrancy_withdraw": {
                        "status": "Failure",
                        "reason": "Assertion failed",
                    }
                }
            }
        }

        with patch("shutil.which", return_value="/usr/bin/forge"), \
             patch("asyncio.create_subprocess_exec") as mock_exec, \
             patch("asyncio.wait_for", new=AsyncMock(return_value=(json.dumps(forge_output).encode(), b""))):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(json.dumps(forge_output).encode(), b""))
            mock_exec.return_value = mock_proc
            findings = await analyzer.analyze(context)

        assert len(findings) == 1
        assert findings[0].source == "foundry"

    @pytest.mark.asyncio
    async def test_analyze_handles_empty_stdout(self, tmp_path):
        """Empty forge output should return empty list."""
        analyzer = FoundryAnalyzer()
        context = _make_context(tmp_path)

        with patch("shutil.which", return_value="/usr/bin/forge"), \
             patch("asyncio.create_subprocess_exec") as mock_exec, \
             patch("asyncio.wait_for", new=AsyncMock(return_value=(b"", b""))):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            findings = await analyzer.analyze(context)

        assert findings == []

    @pytest.mark.asyncio
    async def test_analyze_handles_invalid_json(self, tmp_path):
        """Invalid JSON from forge should return empty list."""
        analyzer = FoundryAnalyzer()
        context = _make_context(tmp_path)

        with patch("shutil.which", return_value="/usr/bin/forge"), \
             patch("asyncio.create_subprocess_exec") as mock_exec, \
             patch("asyncio.wait_for", new=AsyncMock(return_value=(b"not json", b""))):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"not json", b""))
            mock_exec.return_value = mock_proc
            findings = await analyzer.analyze(context)

        assert findings == []


class TestHarnessGeneratorParams:
    """Test that _extract_function_params correctly parses Solidity signatures."""

    def test_no_params(self):
        from contract_audit.analyzers.foundry.harness_generator import _extract_function_params
        result = _extract_function_params("function withdraw() external {}", "withdraw")
        assert result == []

    def test_single_uint_param(self):
        from contract_audit.analyzers.foundry.harness_generator import _extract_function_params
        result = _extract_function_params(
            "function withdraw(uint256 amount) external {}", "withdraw"
        )
        assert len(result) == 1
        assert result[0] == ("uint256", "amount")

    def test_multiple_params(self):
        from contract_audit.analyzers.foundry.harness_generator import _extract_function_params
        result = _extract_function_params(
            "function transfer(address to, uint256 amount) external {}", "transfer"
        )
        assert len(result) == 2
        assert result[0][0] == "address"
        assert result[1][0] == "uint256"

    def test_memory_keyword_stripped(self):
        from contract_audit.analyzers.foundry.harness_generator import _extract_function_params
        result = _extract_function_params(
            "function setData(bytes memory data) external {}", "setData"
        )
        assert len(result) == 1
        assert result[0][0] == "bytes"
        assert "memory" not in result[0][0]

    def test_function_not_found_returns_empty(self):
        from contract_audit.analyzers.foundry.harness_generator import _extract_function_params
        result = _extract_function_params("contract Foo {}", "nonexistent")
        assert result == []


class TestFoundryAnalyzerForgeCommand:
    """Test that forge command is assembled with correct fuzz config."""

    @pytest.mark.asyncio
    async def test_fuzz_runs_passed_to_forge_command(self, tmp_path):
        """Config fuzz_runs and fuzz_seed should appear in the forge command."""
        analyzer = FoundryAnalyzer()
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")
        config = AuditConfig(fuzz_runs=512, fuzz_seed="0xCAFEBABE")
        context = AuditContext(project_path=tmp_path, config=config)

        captured_cmd: list[str] = []

        async def fake_wait_for(coro, timeout):
            return (b"", b"")

        with patch("shutil.which", return_value="/usr/bin/forge"), \
             patch("asyncio.create_subprocess_exec") as mock_exec, \
             patch("asyncio.wait_for", side_effect=fake_wait_for):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))

            def capture_exec(*args, **kwargs):
                captured_cmd.extend(args)
                return mock_proc

            mock_exec.side_effect = capture_exec
            await analyzer.analyze(context)

        assert "--fuzz-runs" in captured_cmd
        assert "512" in captured_cmd
        assert "--fuzz-seed" in captured_cmd
        assert "0xCAFEBABE" in captured_cmd

    @pytest.mark.asyncio
    async def test_stderr_error_logged_as_warning(self, tmp_path, caplog):
        """When forge stderr contains 'error', a warning should be logged."""
        import logging

        analyzer = FoundryAnalyzer()
        (tmp_path / "foundry.toml").write_text("[profile.default]\n")
        config = AuditConfig()
        context = AuditContext(project_path=tmp_path, config=config)

        stderr_msg = b"Error: compilation failed: unknown contract"

        async def fake_wait_for(coro, timeout):
            return (b"", stderr_msg)

        with patch("shutil.which", return_value="/usr/bin/forge"), \
             patch("asyncio.create_subprocess_exec") as mock_exec, \
             patch("asyncio.wait_for", side_effect=fake_wait_for), \
             caplog.at_level(logging.WARNING, logger="contract_audit.analyzers.foundry.analyzer"):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", stderr_msg))
            mock_exec.return_value = mock_proc
            await analyzer.analyze(context)

        assert any("stderr" in r.message.lower() or "compilation" in r.message.lower()
                   for r in caplog.records)
