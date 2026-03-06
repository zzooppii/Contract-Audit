"""Oracle manipulation pattern detector."""

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

CHAINLINK_FUNCTIONS = {
    "latestRoundData",
    "latestAnswer",
    "getRoundData",
}

UNISWAP_PRICE_FUNCTIONS = {
    "getReserves",
    "slot0",
    "observe",
    "consult",
}

STALENESS_INDICATORS = {
    "updatedAt",
    "answeredInRound",
    "MAX_STALENESS",
    "STALE_PRICE_DELAY",
    "heartbeat",
}

TWAP_INDICATORS = {
    "observe",
    "consult",
    "TWAP",
    "twap",
    "timeWeighted",
    "period",
    "windowSize",
}


class OracleDetector:
    """Detects oracle manipulation vulnerabilities."""

    name = "oracle_detector"
    category = "oracle-manipulation"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect oracle-related vulnerabilities."""
        findings: list[Finding] = []

        max_staleness = context.config.oracle_max_staleness_seconds

        for filename, source in context.contract_sources.items():
            findings.extend(self._check_chainlink_staleness(filename, source, max_staleness))
            findings.extend(self._check_uniswap_spot_price(filename, source))
            findings.extend(self._check_round_completeness(filename, source))
            findings.extend(self._check_oracle_decimals(filename, source))

        logger.info(f"Oracle detector found {len(findings)} findings")
        return findings

    def _check_chainlink_staleness(
        self, filename: str, source: str, max_staleness: int
    ) -> list[Finding]:
        """Check for Chainlink price reads without staleness validation."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            for fn in CHAINLINK_FUNCTIONS:
                if re.search(rf'\b{re.escape(fn)}\s*\(', line):
                    # Skip function declarations (not calls)
                    if re.search(r'\bfunction\s+\w', line):
                        continue
                    # Look at enclosing function body (tighter window)
                    func_body = self._extract_function_body(lines, i - 1)

                    has_staleness = any(
                        indicator in func_body for indicator in STALENESS_INDICATORS
                    )

                    if not has_staleness:
                        findings.append(
                            Finding(
                                title=f"Chainlink Oracle: Missing Staleness Check ({fn})",
                                description=(
                                    f"`{fn}()` is called without checking `updatedAt` for staleness. "
                                    f"If the oracle stops updating, stale prices older than "
                                    f"{max_staleness}s could be used, enabling price manipulation attacks.\n\n"
                                    "**Fix:**\n"
                                    "```solidity\n"
                                    "(, int256 price, , uint256 updatedAt,) = oracle.latestRoundData();\n"
                                    f"require(block.timestamp - updatedAt <= {max_staleness}, 'Stale price');\n"
                                    "```"
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.ORACLE_MANIPULATION,
                                source=self.name,
                                detector_name="chainlink-staleness",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i,
                                        end_line=i,
                                    )
                                ],
                                metadata={"oracle_function": fn},
                            )
                        )
        return findings

    @staticmethod
    def _extract_function_body(lines: list[str], call_line_idx: int) -> str:
        """Extract the enclosing function body for a given line index."""
        # Walk backwards to find the function start
        func_start = call_line_idx
        for i in range(call_line_idx, max(0, call_line_idx - 50), -1):
            if re.search(r'\bfunction\s+\w', lines[i]):
                func_start = i
                break

        # Extract up to the closing brace of the function
        depth = 0
        started = False
        body_lines = []
        for i in range(func_start, min(len(lines), func_start + 100)):
            body_lines.append(lines[i])
            for char in lines[i]:
                if char == "{":
                    depth += 1
                    started = True
                elif char == "}" and started:
                    depth -= 1
                    if depth == 0:
                        return "\n".join(body_lines)
        return "\n".join(body_lines)

    def _check_uniswap_spot_price(self, filename: str, source: str) -> list[Finding]:
        """Check for Uniswap spot price reads vulnerable to flash loan manipulation."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if re.search(r'\bgetReserves\s*\(', line):
                # Check if TWAP is used in the same function
                context_block = "\n".join(lines[max(0, i - 10):min(len(lines), i + 30)])
                has_twap = any(t in context_block for t in TWAP_INDICATORS)

                if not has_twap:
                    findings.append(
                        Finding(
                            title="Uniswap V2 Spot Price: Flash Loan Manipulation Risk",
                            description=(
                                "`getReserves()` returns the current spot price, which can be "
                                "manipulated within a single transaction via flash loans. "
                                "Attackers can temporarily skew reserves to obtain favorable "
                                "pricing, then repay the flash loan in the same block.\n\n"
                                "**Fix:** Use Uniswap V3's TWAP via `observe()` or a dedicated "
                                "TWAP oracle with a 30-minute minimum period."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="uniswap-spot-price",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                        )
                    )

            if re.search(r'\.slot0\s*\(', line):
                context_block = "\n".join(lines[max(0, i - 5):min(len(lines), i + 20)])
                has_twap = any(t in context_block for t in TWAP_INDICATORS)

                if not has_twap:
                    findings.append(
                        Finding(
                            title="Uniswap V3 slot0: Spot Price Manipulation Risk",
                            description=(
                                "`slot0()` returns the current spot price from Uniswap V3, "
                                "which can be manipulated within a single transaction. "
                                "Use `observe()` with a TWAP period instead."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="uniswap-v3-slot0",
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

    def _check_round_completeness(self, filename: str, source: str) -> list[Finding]:
        """Check for missing answeredInRound validation in Chainlink reads."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if "latestRoundData" in line and not re.search(r'\bfunction\s+\w', line):
                func_body = self._extract_function_body(lines, i - 1)
                has_round_check = "answeredInRound" in func_body

                if not has_round_check:
                    findings.append(
                        Finding(
                            title="Chainlink: Missing Round Completeness Check",
                            description=(
                                "`latestRoundData()` is used without checking `answeredInRound >= roundId`. "
                                "During Chainlink aggregator downtime, it can return data from a previous "
                                "incomplete round, providing stale/incorrect prices."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.ORACLE_MANIPULATION,
                            source=self.name,
                            detector_name="chainlink-round-completeness",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                        )
                    )
                    break  # Only report once per file

        return findings

    def _check_oracle_decimals(self, filename: str, source: str) -> list[Finding]:
        """Check for hardcoded oracle decimals instead of querying decimals()."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for hardcoded 1e8 or 10**8 near oracle reads
            if re.search(r'1e8|10\*\*8|100000000', line):
                context_block = "\n".join(lines[max(0, i - 5):min(len(lines), i + 5)])
                if any(fn in context_block for fn in CHAINLINK_FUNCTIONS):
                    has_decimals_call = "decimals()" in context_block
                    if not has_decimals_call:
                        findings.append(
                            Finding(
                                title="Hardcoded Oracle Decimals",
                                description=(
                                    "Oracle price scaling uses hardcoded decimals (1e8) instead of "
                                    "calling `oracle.decimals()`. Different Chainlink feeds have "
                                    "different decimal places (e.g., ETH/USD is 8, some are 18)."
                                ),
                                severity=Severity.LOW,
                                confidence=Confidence.LOW,
                                category=FindingCategory.ORACLE_MANIPULATION,
                                source=self.name,
                                detector_name="hardcoded-oracle-decimals",
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
