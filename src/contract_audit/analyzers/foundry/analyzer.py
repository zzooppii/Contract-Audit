"""Foundry test runner: executes forge test --json and parses results."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path

from ...core.exceptions import AnalyzerError
from ...core.models import AuditContext, Finding
from .result_parser import parse_foundry_results

logger = logging.getLogger(__name__)

FORGE_CMD = "forge"


class FoundryAnalyzer:
    """Runs Foundry fuzz tests and invariant tests."""

    name = "foundry"

    def __init__(self) -> None:
        # Files/dirs created by _ensure_foundry_project (cleaned up after forge runs)
        self._scaffold_paths: list[Path] = []

    def is_available(self) -> bool:
        return shutil.which(FORGE_CMD) is not None

    def cleanup_scaffold(self) -> None:
        """Remove any files/dirs created by _ensure_foundry_project."""
        import shutil as _shutil
        for path in self._scaffold_paths:
            try:
                if path.is_dir():
                    _shutil.rmtree(path)
                elif path.exists():
                    path.unlink()
            except Exception as e:
                logger.debug(f"Scaffold cleanup failed for {path}: {e}")
        self._scaffold_paths.clear()

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
        self._scaffold_paths.append(foundry_toml)
        logger.info(f"Created {foundry_toml}")

        lib_dir = context.project_path / "lib"
        lib_dir.mkdir(exist_ok=True)
        self._scaffold_paths.append(lib_dir)

        # Install forge-std so import "forge-std/Test.sol" resolves
        try:
            proc = await asyncio.create_subprocess_exec(
                FORGE_CMD, "install", "foundry-rs/forge-std",
                "--no-git", "--no-commit",
                cwd=str(context.project_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning("forge install timed out — harnesses may not compile")
                return
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
            self._scaffold_paths.append(remappings)
            logger.info(f"Created {remappings}")

    async def _run_forge(self, context: AuditContext) -> list[Finding]:
        """Execute forge test --json with compilation error recovery."""
        fuzz_seed = getattr(context.config, "fuzz_seed", "0xDEADBEEF")
        fuzz_runs = getattr(context.config, "fuzz_runs", 256)

        cmd = [
            FORGE_CMD, "test",
            "--json",
            "--no-match-test", "testSkip",
        ]

        env = {
            **os.environ,
            "FOUNDRY_FUZZ_RUNS": str(fuzz_runs),
            "FOUNDRY_FUZZ_SEED": str(fuzz_seed),
        }

        max_retries = 3
        for attempt in range(max_retries):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(context.project_path),
                    env=env,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=600  # 10 minute timeout
                    )
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    logger.error("Foundry tests timed out after 10 minutes")
                    return []

                stderr_text = stderr.decode(errors="replace") if stderr else ""

                # Check for compilation errors in generated harness files
                if "error" in stderr_text.lower() or "parsererror" in stderr_text.lower():
                    # Parse problematic harness paths: e.g. test/audit_targeted/Targeted_Vault_deposit.t.sol
                    import re
                    err_paths = re.findall(r'(test/audit_\w+/[A-Za-z0-9_.-]+\.t\.sol)', stderr_text)
                    if err_paths:
                        unique_errs = list(set(err_paths))
                        removed_any = False
                        for path_str in unique_errs:
                            file_path = context.project_path / path_str
                            if file_path.exists():
                                try:
                                    file_path.unlink()
                                    logger.warning(
                                        f"Foundry compilation error in generated harness: {path_str}. "
                                        f"Removed file to recover build. Retrying ({attempt + 1}/{max_retries})..."
                                    )
                                    removed_any = True
                                except Exception as ue:
                                    logger.debug(f"Failed to remove broken harness {file_path}: {ue}")

                        if removed_any:
                            continue  # Retry forge command

                # Log non-fatal or generic stderr
                if stderr_text:
                    if "error" in stderr_text.lower():
                        logger.warning(f"Forge stderr:\n{stderr_text[:2000]}")
                    else:
                        logger.debug(f"Forge stderr: {stderr_text[:500]}")

                if not stdout:
                    if stderr_text:
                        logger.warning(f"forge produced no output. Stderr:\n{stderr_text[:2000]}")
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

            except Exception as e:
                raise AnalyzerError(self.name, str(e)) from e

        return []
