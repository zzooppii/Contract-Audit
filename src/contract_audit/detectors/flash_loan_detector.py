"""Flash loan economic risk detector.

Taint analysis tracking flash loan callbacks to sensitive sinks.
"""

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

FLASH_LOAN_CALLBACKS = {
    "executeOperation",
    "onFlashLoan",
    "uniswapV2Call",
    "uniswapV3SwapCallback",
    "pancakeCall",
    "balancerFlashLoan",
    "flashLoan",
}

FLASH_LOAN_SOURCES = {
    "executeOperation",
    "onFlashLoan",
    "uniswapV2Call",
    "getReserves",
    "balanceOf",
}

VALUE_AFFECTING_SINKS = {
    "transfer",
    "transferFrom",
    "safeTransfer",
    "safeTransferFrom",
    "_mint",
    "_burn",
    "approve",
    "_update",
}

REENTRANCY_GUARDS = {
    "nonReentrant",
    "ReentrancyGuard",
    "reentrancyGuard",
    "_locked",
    "mutex",
}


class FlashLoanDetector:
    """Detects flash loan attack vectors and economic risks."""

    name = "flash_loan_detector"
    category = "flash-loan"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect flash loan vulnerabilities."""
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            findings.extend(self._check_flash_loan_callbacks(filename, source))
            findings.extend(self._check_unprotected_callbacks(filename, source))
            findings.extend(self._check_spot_price_reads(filename, source))

        logger.info(f"Flash loan detector found {len(findings)} findings")
        return findings

    def _check_flash_loan_callbacks(self, filename: str, source: str) -> list[Finding]:
        """Find flash loan callbacks that reach value-affecting state changes."""
        findings = []
        lines = source.splitlines()

        for callback_name in FLASH_LOAN_CALLBACKS:
            # Find callback function definitions
            pattern = rf'\bfunction\s+{re.escape(callback_name)}\b'
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    # Extract the function body (up to closing brace)
                    body = self._extract_function_body(lines, i - 1)

                    # Check for sink calls in body
                    sinks_found = []
                    for sink in VALUE_AFFECTING_SINKS:
                        if re.search(rf'\b{re.escape(sink)}\s*\(', body):
                            sinks_found.append(sink)

                    if sinks_found:
                        # Check for guards
                        has_guard = any(g in body for g in REENTRANCY_GUARDS)
                        severity = Severity.MEDIUM if has_guard else Severity.HIGH

                        findings.append(
                            Finding(
                                title=f"Flash Loan Callback Reaches Value Sink: {callback_name}",
                                description=(
                                    f"The `{callback_name}` flash loan callback calls "
                                    f"{', '.join(f'`{s}()`' for s in sinks_found)} "
                                    "which affects token balances/state. Without proper guards, "
                                    "an attacker can manipulate protocol state within a flash loan."
                                    + (" (Reentrancy guard detected)" if has_guard else "")
                                ),
                                severity=severity,
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.FLASH_LOAN,
                                source=self.name,
                                detector_name="flash-loan-callback-sink",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i,
                                        end_line=i,
                                        function=callback_name,
                                    )
                                ],
                                metadata={"callback": callback_name, "sinks": sinks_found},
                            )
                        )
        return findings

    def _check_unprotected_callbacks(self, filename: str, source: str) -> list[Finding]:
        """Check for flash loan callbacks without caller validation."""
        findings = []
        lines = source.splitlines()

        for callback_name in FLASH_LOAN_CALLBACKS:
            pattern = rf'\bfunction\s+{re.escape(callback_name)}\b'
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    body = self._extract_function_body(lines, i - 1)

                    # Check for caller validation (must be an active check, not just parameter name)
                    has_validation = bool(
                        re.search(r'\brequire\s*\(\s*msg\.sender', body)
                        or re.search(r'\bif\s*\(\s*msg\.sender', body)
                        or re.search(r'\brequire\s*\(\s*\w+\s*==\s*\w+', body)
                        or "onlyLendingPool" in body
                        or "onlyFlashLoan" in body
                    )

                    if not has_validation:
                        findings.append(
                            Finding(
                                title=f"Unvalidated Flash Loan Callback: {callback_name}",
                                description=(
                                    f"The `{callback_name}` callback does not validate "
                                    "msg.sender. Any contract can call this function, "
                                    "potentially triggering unintended state changes."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.LOW,
                                category=FindingCategory.FLASH_LOAN,
                                source=self.name,
                                detector_name="unvalidated-flash-loan-callback",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i,
                                        end_line=i,
                                        function=callback_name,
                                    )
                                ],
                            )
                        )
        return findings

    def _check_spot_price_reads(self, filename: str, source: str) -> list[Finding]:
        """Check for spot price reads that could be flash loan manipulated."""
        findings = []
        lines = source.splitlines()

        spot_price_patterns = [
            (r'\bgetReserves\s*\(', "Uniswap V2 getReserves()"),
            (r'\bslot0\s*\(', "Uniswap V3 slot0()"),
            (r'\.latestAnswer\s*\(', "Chainlink latestAnswer()"),
        ]

        for pattern, description in spot_price_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    # Check if TWAP is used elsewhere
                    context_block = "\n".join(lines[max(0, i-5):min(len(lines), i+10)])
                    has_twap = bool(
                        re.search(r'\bTWAP\b|\bobserve\s*\(|\bconsult\s*\(', context_block, re.I)
                    )

                    if not has_twap:
                        findings.append(
                            Finding(
                                title=f"Spot Price Oracle: {description}",
                                description=(
                                    f"Reading spot price from {description} "
                                    "without TWAP protection. "
                                    "This price can be manipulated within a single transaction "
                                    "via flash loans. Use time-weighted average prices (TWAP)."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.ORACLE_MANIPULATION,
                                source=self.name,
                                detector_name="spot-price-oracle",
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

    @staticmethod
    def _extract_function_body(lines: list[str], start: int) -> str:
        """Extract function body starting from line index."""
        depth = 0
        body_lines = []
        started = False

        for i in range(start, min(start + 200, len(lines))):
            line = lines[i]
            body_lines.append(line)
            for char in line:
                if char == "{":
                    depth += 1
                    started = True
                elif char == "}" and started:
                    depth -= 1
                    if depth == 0:
                        return "\n".join(body_lines)

        return "\n".join(body_lines)
