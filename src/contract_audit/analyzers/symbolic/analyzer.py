"""Symbolic execution coordinator (hevm primary, Mythril fallback)."""

from __future__ import annotations

import logging
from typing import Any

from ...core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from .hevm_runner import HevmRunner
from .mythril_runner import MythrilRunner

logger = logging.getLogger(__name__)


class SymbolicAnalyzer:
    """Coordinates symbolic execution across hevm and Mythril."""

    name = "symbolic"

    def __init__(self) -> None:
        self.hevm = HevmRunner()
        self.mythril = MythrilRunner()

    def is_available(self) -> bool:
        return self.hevm.is_available() or self.mythril.is_available()

    async def analyze(self, context: AuditContext) -> list[Finding]:
        """Run symbolic execution on compiled bytecode."""
        findings: list[Finding] = []

        if not self.is_available():
            logger.warning("No symbolic execution tools available")
            return []

        artifacts = context.compilation_artifacts
        if not artifacts:
            logger.warning("No compilation artifacts for symbolic execution")
            return []

        contracts = artifacts.get("contracts", {})

        for filename, file_contracts in contracts.items():
            for contract_name, contract_data in file_contracts.items():
                bytecode = (
                    contract_data.get("evm", {})
                    .get("bytecode", {})
                    .get("object", "")
                )
                if not bytecode or len(bytecode) < 10:
                    continue

                # Try hevm first (faster)
                if self.hevm.is_available():
                    violations = await self.hevm.run_symbolic(
                        bytecode=bytecode,
                        timeout=60,
                    )
                    for v in violations:
                        findings.append(
                            self._violation_to_finding(v, filename, contract_name, "hevm")
                        )

                # Fall back to Mythril for deep analysis
                elif self.mythril.is_available():
                    source = context.contract_sources.get(filename, "")
                    if source:
                        issues = await self.mythril.analyze_source(
                            filename, source, timeout=120
                        )
                        for issue in issues:
                            findings.append(
                                self._mythril_to_finding(issue, filename, contract_name)
                            )

        logger.info(f"Symbolic execution found {len(findings)} findings")
        return findings

    def _violation_to_finding(
        self,
        violation: dict[str, Any],
        filename: str,
        contract_name: str,
        tool: str,
    ) -> Finding:
        """Convert a symbolic execution violation to a Finding."""
        return Finding(
            title=f"Symbolic Execution Violation: {violation.get('type', 'Unknown')}",
            description=(
                f"hevm found a potential violation:\n\n"
                f"{violation.get('details', '')}\n\n"
                + (
                    "Trace:\n" + "\n".join(violation.get("trace", [])[:20])
                    if violation.get("trace")
                    else ""
                )
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.OTHER,
            source=tool,
            detector_name=f"{tool}-symbolic",
            locations=[
                SourceLocation(
                    file=filename,
                    start_line=1,
                    end_line=1,
                    contract=contract_name,
                )
            ],
            metadata={"contract": contract_name, "violation": violation},
        )

    def _mythril_to_finding(
        self,
        issue: dict[str, Any],
        filename: str,
        contract_name: str,
    ) -> Finding:
        """Convert a Mythril issue to a Finding."""
        severity_map = {
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }
        loc = issue.get("location", {})
        return Finding(
            title=issue.get("title", "Mythril Finding"),
            description=issue.get("description", ""),
            severity=severity_map.get(issue.get("severity", "Medium"), Severity.MEDIUM),
            confidence=Confidence.MEDIUM,
            category=FindingCategory.OTHER,
            source="mythril",
            detector_name="mythril-symbolic",
            locations=[
                SourceLocation(
                    file=loc.get("file", filename),
                    start_line=loc.get("line", 1),
                    end_line=loc.get("line", 1),
                    contract=contract_name,
                )
            ],
            metadata=issue,
        )
