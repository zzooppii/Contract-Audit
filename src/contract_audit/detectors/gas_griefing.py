"""Gas griefing vulnerability detector."""

from __future__ import annotations

import logging
import re

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class GasGriefingDetector:
    """Detects gas griefing attack vectors."""

    name = "gas_griefing"
    category = "gas-griefing"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect gas griefing vulnerabilities."""
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            findings.extend(self._check_unbounded_loops(filename, source))
            findings.extend(self._check_calls_in_loops(filename, source))
            findings.extend(self._check_dos_patterns(filename, source))
            findings.extend(self._check_pull_payment_pattern(filename, source))

        logger.info(f"Gas griefing detector found {len(findings)} findings")
        return findings

    def _check_unbounded_loops(self, filename: str, source: str) -> list[Finding]:
        """Check for loops without gas limits or bounded iteration."""
        findings = []
        lines = source.splitlines()

        loop_patterns = [
            (r'\bfor\s*\(', "for"),
            (r'\bwhile\s*\(', "while"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, loop_type in loop_patterns:
                if re.search(pattern, line):
                    body = "\n".join(lines[i - 1:min(len(lines), i + 30)])

                    # Check for dynamic array length in loop condition
                    is_unbounded = bool(
                        re.search(r'\.length\b', line)
                        or "mapping" in body
                    )

                    has_gas_guard = bool(
                        re.search(r'gasleft\(\)', body)
                        or re.search(r'gas\s*>', body)
                    )

                    if is_unbounded and not has_gas_guard:
                        findings.append(
                            Finding(
                                title=f"Unbounded {loop_type.title()} Loop",
                                description=(
                                    f"A `{loop_type}` loop iterates over an "
                                    "unbounded array/mapping. "
                                    "An attacker can force the array to grow large enough to "
                                    "cause the transaction to run out of gas, permanently blocking "
                                    "contract functionality (DoS via gas exhaustion)."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.GAS_GRIEFING,
                                source=self.name,
                                detector_name="unbounded-loop",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i,
                                        end_line=i,
                                    )
                                ],
                            )
                        )

        return findings

    def _check_calls_in_loops(self, filename: str, source: str) -> list[Finding]:
        """Check for external calls inside loops."""
        findings = []
        lines = source.splitlines()

        in_loop = False
        loop_start = 0
        loop_depth = 0
        brace_depth = 0

        for i, line in enumerate(lines, 1):
            if re.search(r'\bfor\s*\(|\bwhile\s*\(', line):
                in_loop = True
                loop_start = i
                loop_depth = brace_depth

            for char in line:
                if char == "{":
                    brace_depth += 1
                elif char == "}":
                    brace_depth -= 1
                    if in_loop and brace_depth <= loop_depth:
                        in_loop = False

            if in_loop:
                if re.search(r'\.(call|transfer|send|delegatecall)\s*[\(\{]', line):
                    findings.append(
                        Finding(
                            title="External Call Inside Loop",
                            description=(
                                "An external call is made inside a loop. A recipient with a "
                                "reverting fallback function or running out of gas can halt "
                                "the entire loop, causing a permanent DoS on the calling function."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.GAS_GRIEFING,
                            source=self.name,
                            detector_name="call-in-loop",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                            metadata={"loop_start": loop_start},
                        )
                    )

        return findings

    def _check_dos_patterns(self, filename: str, source: str) -> list[Finding]:
        """Check for denial-of-service patterns."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for revert/require inside try-catch that could cause DoS
            if "require(" in line and re.search(r'\.(call|transfer)\s*\(', line):
                findings.append(
                    Finding(
                        title="Potential DoS: require() After External Call",
                        description=(
                            "A `require()` check on an external call result can be used for DoS. "
                            "If the callee is a user-controlled contract "
                            "that always reverts, "
                            "this function becomes permanently unusable. "
                            "Consider using pull-payment."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        category=FindingCategory.GAS_GRIEFING,
                        source=self.name,
                        detector_name="dos-require-external-call",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                    )
                )

        return findings

    def _check_pull_payment_pattern(self, filename: str, source: str) -> list[Finding]:
        """Suggest pull-payment pattern where push-payment is used in loops."""
        findings = []
        lines = source.splitlines()

        in_loop = False
        loop_start = 0

        for i, line in enumerate(lines, 1):
            if re.search(r'\bfor\s*\(|\bwhile\s*\(', line):
                in_loop = True
                loop_start = i

            if in_loop and re.search(r'\btransfer\s*\(|\bsend\s*\(', line):
                findings.append(
                    Finding(
                        title="Push Payment Pattern in Loop",
                        description=(
                            "ETH is transferred inside a loop (push-payment pattern). "
                            "Consider using the pull-payment pattern where recipients withdraw "
                            "their own funds, preventing a single failing recipient from "
                            "blocking all payments."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.GAS_GRIEFING,
                        source=self.name,
                        detector_name="push-payment-loop",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                        metadata={"loop_start": loop_start},
                    )
                )
                in_loop = False  # Report once per loop

        return findings
