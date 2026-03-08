"""Slither static analysis wrapper using the Slither Python API."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ...core.exceptions import AnalyzerError
from ...core.models import AuditContext, Finding
from .result_mapper import map_slither_result

logger = logging.getLogger(__name__)

SLITHER_AVAILABLE = False
try:
    from slither import Slither
    from slither.detectors import all_detectors
    SLITHER_AVAILABLE = True
except ImportError:
    logger.debug("slither-analyzer not installed")


class SlitherAnalyzer:
    """Runs Slither analysis via the Python API."""

    name = "slither"

    def is_available(self) -> bool:
        return SLITHER_AVAILABLE

    async def analyze(self, context: AuditContext) -> list[Finding]:
        """Run Slither on the project and return findings."""
        if not self.is_available():
            logger.warning("Slither not installed, skipping")
            return []

        if not context.project_path.exists():
            raise AnalyzerError(self.name, f"Project path not found: {context.project_path}")

        try:
            return await self._run_slither(context)
        except Exception as e:
            logger.error(f"Slither analysis failed: {e}")
            raise AnalyzerError(self.name, str(e)) from e

    async def _run_slither(self, context: AuditContext) -> list[Finding]:
        """Execute Slither analysis."""
        import asyncio

        # Run in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync, context)

    def _run_sync(self, context: AuditContext) -> list[Finding]:
        """Synchronous Slither execution (called from thread pool)."""
        findings: list[Finding] = []

        target = context.project_path

        # Build solc options
        slither_kwargs: dict[str, Any] = {
            "disable_color": True,
        }

        if context.config.solidity_version != "auto":
            slither_kwargs["solc_args"] = f"--version {context.config.solidity_version}"

        # Determine targets: if directory without a compilation framework,
        # analyze each .sol file individually.
        targets = self._resolve_targets(target)

        for sol_target in targets:
            try:
                slither = Slither(str(sol_target), **slither_kwargs)

                # Store last instance for downstream use
                context.slither_instance = slither

                # Register built-in detectors
                self._register_builtin_detectors(slither)

                # Register custom detectors
                for detector_cls in self._get_custom_detectors():
                    try:
                        slither.register_detector(detector_cls)
                    except Exception as e:
                        logger.debug(f"Failed to register custom detector {detector_cls}: {e}")

                # Run all registered detectors
                results = slither.run_detectors()
                for result_group in results:
                    for r in result_group:
                        finding = map_slither_result(r)
                        if finding:
                            findings.append(finding)

            except Exception as e:
                logger.error(f"Slither failed on {sol_target}: {e}")

        logger.info(f"Slither found {len(findings)} findings")
        return findings

    def _resolve_targets(self, target: Path) -> list[Path]:
        """Resolve analysis targets. If the path is a directory with a build
        framework (foundry.toml, hardhat.config.*), return the directory itself.
        Otherwise, return individual .sol files found recursively."""
        if target.is_file():
            return [target]

        # Check for compilation framework config files
        framework_markers = [
            "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
            "brownie-config.yaml", "truffle-config.js",
        ]
        for marker in framework_markers:
            if (target / marker).exists():
                logger.info(f"Detected build framework ({marker}), passing directory to Slither")
                return [target]

        # No framework — collect individual .sol files
        sol_files = sorted(target.rglob("*.sol"))
        if not sol_files:
            logger.warning(f"No .sol files found in {target}")
            return []

        logger.info(
            f"No build framework detected, analyzing {len(sol_files)} .sol files individually"
        )
        return sol_files

    @staticmethod
    def _register_builtin_detectors(slither_instance: Any) -> None:
        """Register all built-in Slither detectors."""
        import inspect
        for _name, obj in inspect.getmembers(all_detectors, inspect.isclass):
            try:
                slither_instance.register_detector(obj)
            except Exception:
                pass

    def _get_custom_detectors(self) -> list[type]:
        """Return list of custom detector classes to register."""
        detectors: list[type] = []
        try:
            from .custom_detectors.flash_loan_taint import FlashLoanTaintDetector
            from .custom_detectors.oracle_manipulation import OracleManipulationDetector
            if hasattr(OracleManipulationDetector, "_detect"):
                detectors.append(OracleManipulationDetector)
            if hasattr(FlashLoanTaintDetector, "_detect"):
                detectors.append(FlashLoanTaintDetector)
        except ImportError:
            pass
        return detectors
