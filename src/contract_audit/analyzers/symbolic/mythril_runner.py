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
        function_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze Solidity source with Mythril, optionally targeting a specific function."""
        if not self.is_available():
            return []

        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._run_sync, source_file, source_code, timeout, function_name
        )

    def _run_sync(
        self, source_file: str, source_code: str, timeout: int, function_name: str | None
    ) -> list[dict[str, Any]]:
        """Synchronous Mythril execution with optional function filter."""
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

            issues = self._parse_report(report)
            if function_name:
                # 특정 함수 이름이 지정된 경우 필터링 적용
                func_lower = function_name.lower()
                filtered_issues = []
                for issue in issues:
                    # issue의 function명이나 설명문 내에 해당 함수명이 있는지 대조
                    issue_func = issue.get("location", {}).get("function", "").lower()
                    desc = issue.get("description", "").lower()
                    if func_lower in issue_func or func_lower in desc:
                        filtered_issues.append(issue)
                return filtered_issues

            return issues
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
                        "function": getattr(issue, "function", ""),
                    },
                    "tx_sequence": getattr(issue, "transaction_sequence", None),
                })
        except Exception as e:
            logger.warning(f"Failed to parse Mythril report: {e}")
        return issues
