"""Foundry test runner: executes forge test --json and parses results."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil

from ...core.exceptions import AnalyzerError
from ...core.models import AuditContext, Finding
from .result_parser import parse_foundry_results

logger = logging.getLogger(__name__)

FORGE_CMD = "forge"


class FoundryAnalyzer:
    """Runs Foundry fuzz tests and invariant tests."""

    name = "foundry"

    def is_available(self) -> bool:
        return shutil.which(FORGE_CMD) is not None

    async def analyze(self, context: AuditContext) -> list[Finding]:
        """Run forge test and return failing test findings."""
        if not self.is_available():
            logger.warning("forge not installed, skipping Foundry analysis")
            return []

        # Check if foundry project exists
        foundry_toml = context.project_path / "foundry.toml"
        if not foundry_toml.exists():
            logger.info("No foundry.toml found, skipping Foundry analysis")
            return []

        try:
            return await self._run_forge(context)
        except Exception as e:
            logger.error(f"Foundry analysis failed: {e}")
            raise AnalyzerError(self.name, str(e)) from e

    async def _run_forge(self, context: AuditContext) -> list[Finding]:
        """Execute forge test --json."""
        cmd = [
            FORGE_CMD, "test",
            "--json",
            "--no-match-test", "testSkip",  # Skip explicitly skipped tests
        ]

        # Add fuzz seed for reproducibility
        cmd.extend(["--fuzz-seed", "0xDEADBEEF"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(context.project_path),
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=600  # 10 minute timeout
            )

            if not stdout:
                logger.warning("forge test produced no output")
                return []

            # forge test --json exits non-zero when tests fail (expected)
            try:
                output = json.loads(stdout.decode())
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse forge output: {e}")
                return []

            findings = parse_foundry_results(output)
            logger.info(f"Foundry: {len(findings)} failing tests")
            return findings

        except TimeoutError:
            logger.error("Foundry tests timed out after 10 minutes")
            return []
