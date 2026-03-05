"""Slither static analysis wrapper using the Slither Python API."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from ...core.exceptions import AnalyzerError, ToolNotAvailableError
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

        target = str(context.project_path)

        # Build solc options
        slither_kwargs: dict[str, Any] = {
            "disable_color": True,
        }

        if context.config.solidity_version != "auto":
            slither_kwargs["solc_args"] = f"--version {context.config.solidity_version}"

        try:
            slither = Slither(target, **slither_kwargs)
            context.slither_instance = slither

            # Load custom detectors
            custom_detectors = self._get_custom_detectors()

            # Run all detectors
            for detector_cls in custom_detectors:
                try:
                    detector_instance = detector_cls(
                        slither,
                        slither.logger,
                        slither.config,
                        slither.logger,
                    )
                    results = detector_instance.detect()
                    for r in results:
                        finding = map_slither_result(r, source_name=f"slither:{detector_cls.ARGUMENT}")
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    logger.warning(f"Custom detector {detector_cls} failed: {e}")

            # Run built-in detectors
            slither.run_detectors()
            for result_group in slither.detectors_results:
                for r in result_group:
                    finding = map_slither_result(r)
                    if finding:
                        findings.append(finding)

            logger.info(f"Slither found {len(findings)} findings")
        except Exception as e:
            logger.error(f"Slither instantiation failed: {e}")

        return findings

    def _get_custom_detectors(self) -> list[type]:
        """Return list of custom detector classes to register."""
        detectors = []
        try:
            from .custom_detectors.oracle_manipulation import OracleManipulationDetector
            from .custom_detectors.flash_loan_taint import FlashLoanTaintDetector
            if hasattr(OracleManipulationDetector, "_detect"):
                detectors.append(OracleManipulationDetector)
            if hasattr(FlashLoanTaintDetector, "_detect"):
                detectors.append(FlashLoanTaintDetector)
        except ImportError:
            pass
        return detectors
