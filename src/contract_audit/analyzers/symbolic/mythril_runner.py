"""Mythril symbolic execution wrapper (optional)."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

MYTHRIL_AVAILABLE = False
try:
    import importlib.util
    if (
        importlib.util.find_spec("mythril.analysis.report")
        and importlib.util.find_spec("mythril.mythril")
    ):
        MYTHRIL_AVAILABLE = True
except ImportError:
    logger.debug("Mythril not installed")


class MythrilRunner:
    """Runs Mythril symbolic analysis."""

    def is_available(self) -> bool:
        return MYTHRIL_AVAILABLE

    async def analyze_source(
        self,
        source_file: str,
        source_code: str,
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """Analyze Solidity source with Mythril."""
        if not self.is_available():
            return []

        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._run_sync, source_file, source_code, timeout
        )

    def _run_sync(
        self, source_file: str, source_code: str, timeout: int
    ) -> list[dict[str, Any]]:
        """Synchronous Mythril execution."""
        try:
            from mythril.mythril import MythrilAnalyzer, MythrilDisassembler

            disassembler = MythrilDisassembler()
            disassembler.load_from_solidity([source_file])

            analyzer = MythrilAnalyzer(
                strategy="dfs",
                disassembler=disassembler,
                address=None,
                max_depth=12,
                execution_timeout=timeout,
            )

            report = analyzer.fire_lasers(
                modules=[
                    "arbitrary-storage-write",
                    "integer",
                    "ether-thief",
                    "suicide",
                    "exceptions",
                ]
            )

            return self._parse_report(report)
        except Exception as e:
            logger.error(f"Mythril analysis failed: {e}")
            return []

    def _parse_report(self, report: Any) -> list[dict[str, Any]]:
        """Parse Mythril report into dict format."""
        issues = []
        try:
            for issue in report.issues.values():
                issues.append({
                    "title": issue.title,
                    "description": issue.description,
                    "severity": issue.severity,
                    "location": {
                        "file": getattr(issue, "filename", ""),
                        "line": getattr(issue, "lineno", 1),
                    },
                    "tx_sequence": getattr(issue, "transaction_sequence", None),
                })
        except Exception as e:
            logger.warning(f"Failed to parse Mythril report: {e}")
        return issues
