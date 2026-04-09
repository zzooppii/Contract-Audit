"""Foundry test runner: executes forge test --json and parses results."""

from __future__ import annotations

import asyncio
import json
import logging
import os
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

        await self._ensure_foundry_project(context)

        try:
            return await self._run_forge(context)
        except Exception as e:
            logger.error(f"Foundry analysis failed: {e}")
            raise AnalyzerError(self.name, str(e)) from e

    async def _ensure_foundry_project(self, context: AuditContext) -> None:
        """Create minimal Foundry scaffolding if the project lacks it.

        If ``foundry.toml`` already exists, this is a no-op. Otherwise:
        - Writes a minimal ``foundry.toml`` with fuzz config from ``context.config``
        - Creates ``lib/`` directory
        - Runs ``forge install foundry-rs/forge-std`` (network errors are non-fatal)
        - Writes ``remappings.txt`` so ``import "forge-std/..."`` resolves
        """
        foundry_toml = context.project_path / "foundry.toml"
        if foundry_toml.exists():
            return

        logger.info("No foundry.toml found — creating minimal Foundry project scaffold")

        fuzz_runs = getattr(context.config, "fuzz_runs", 256)
        fuzz_seed = getattr(context.config, "fuzz_seed", "0xDEADBEEF")
        contracts_dir = str(getattr(context.config, "contracts_dir", "./src")).lstrip("./")

        foundry_toml.write_text(
            f"[profile.default]\n"
            f'src = "{contracts_dir}"\n'
            f'out = "out"\n'
            f'libs = ["lib"]\n'
            f"\n"
            f"[profile.default.fuzz]\n"
            f"runs = {fuzz_runs}\n"
            f'seed = "{fuzz_seed}"\n'
        )
        logger.info(f"Created {foundry_toml}")

        lib_dir = context.project_path / "lib"
        lib_dir.mkdir(exist_ok=True)

        # Install forge-std so import "forge-std/Test.sol" resolves
        try:
            proc = await asyncio.create_subprocess_exec(
                FORGE_CMD, "install", "foundry-rs/forge-std",
                "--no-git", "--no-commit",
                cwd=str(context.project_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                logger.warning(
                    f"forge install forge-std failed (rc={proc.returncode}). "
                    f"Stderr: {stderr.decode(errors='replace')[:500]}"
                )
            else:
                logger.info("Installed forge-std into lib/forge-std")
        except Exception as e:
            logger.warning(f"forge install forge-std failed: {e} — harnesses may not compile")

        # Write remappings so Solidity can resolve the import
        remappings = context.project_path / "remappings.txt"
        if not remappings.exists():
            remappings.write_text("forge-std/=lib/forge-std/src/\n")
            logger.info(f"Created {remappings}")

    async def _run_forge(self, context: AuditContext) -> list[Finding]:
        """Execute forge test --json."""
        fuzz_seed = getattr(context.config, "fuzz_seed", "0xDEADBEEF")
        fuzz_runs = getattr(context.config, "fuzz_runs", 256)

        cmd = [
            FORGE_CMD, "test",
            "--json",
            "--no-match-test", "testSkip",
        ]

        # Pass fuzz config via env vars — compatible with all Foundry versions
        env = {
            **os.environ,
            "FOUNDRY_FUZZ_RUNS": str(fuzz_runs),
            "FOUNDRY_FUZZ_SEED": str(fuzz_seed),
        }

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(context.project_path),
                env=env,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=600  # 10 minute timeout
            )

            # Log stderr — compilation errors surface here
            if stderr:
                stderr_text = stderr.decode(errors="replace")
                if "error" in stderr_text.lower():
                    logger.warning(f"Forge stderr:\n{stderr_text[:2000]}")
                else:
                    logger.debug(f"Forge stderr: {stderr_text[:500]}")

            if not stdout:
                if stderr:
                    logger.warning(
                        f"forge produced no output. Stderr:\n"
                        f"{stderr.decode(errors='replace')[:2000]}"
                    )
                else:
                    logger.warning("forge produced no output")
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
