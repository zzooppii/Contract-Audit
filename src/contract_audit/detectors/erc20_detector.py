"""ERC20 token vulnerability detector.

Detects:
- Missing Transfer/Approval events
- Approval race condition (no increase/decrease pattern)
- Fee-on-transfer without documentation
- Unlimited minting (no supply cap)
- transferFrom ordering issues
"""

from __future__ import annotations

import logging
import re

from .utils import strip_interfaces

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class ERC20Detector:
    """Detects ERC20 token-specific vulnerabilities."""

    name = "erc20_detector"
    category = "token"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            if not self._is_erc20(source):
                continue

            findings.extend(self._check_missing_transfer_event(filename, source))
            findings.extend(self._check_approval_race(filename, source))
            findings.extend(self._check_fee_on_transfer(filename, source))
            findings.extend(self._check_unlimited_mint(filename, source))
            findings.extend(self._check_transfer_from_ordering(filename, source))

        logger.info(f"ERC20 detector found {len(findings)} findings")
        return findings

    def _is_erc20(self, source: str) -> bool:
        """Check if contract looks like an ERC20 token."""
        indicators = [
            r'\btotalSupply\b',
            r'\bbalanceOf\b',
            r'\ballowance\b',
            r'\btransfer\b',
            r'\btransferFrom\b',
            r'\bapprove\b',
        ]
        matches = sum(1 for p in indicators if re.search(p, source))
        # Need at least 4 of 6 indicators, and must have a contract (not just interface)
        has_contract = bool(re.search(r'\bcontract\s+\w+', source))
        return matches >= 4 and has_contract

    def _check_missing_transfer_event(
        self, filename: str, source: str
    ) -> list[Finding]:
        """Check if Transfer event is defined and emitted in transfer functions."""
        findings = []
        lines = source.splitlines()

        # Check if Transfer event is defined
        has_transfer_event = bool(
            re.search(r'event\s+Transfer\s*\(', source)
        )

        # Find transfer/transferFrom functions in contract body (not interface)
        contract_body = strip_interfaces(source)

        if not has_transfer_event and re.search(r'\bfunction\s+transfer\b', contract_body):
            # Find the transfer function line for location
            for i, line in enumerate(lines, 1):
                if re.search(r'\bfunction\s+transfer\b', line):
                    func_body = self._get_function_body(lines, i - 1)
                    # Skip if it's in an interface (no body)
                    if '{' not in func_body:
                        continue
                    findings.append(
                        Finding(
                            title="Missing Transfer Event in ERC20",
                            description=(
                                "The `transfer()` function does not emit a `Transfer` event. "
                                "This breaks ERC20 spec compliance (EIP-20 requires Transfer events). "
                                "Wallets, block explorers, and DeFi protocols rely on Transfer events "
                                "to track token movements.\n\n"
                                "**Fix:** Define `event Transfer(address indexed from, address indexed to, "
                                "uint256 value)` and emit it in transfer/transferFrom."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.OTHER,
                            source=self.name,
                            detector_name="missing-transfer-event",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                        )
                    )
                    break

        # Also check: event defined but not emitted
        if has_transfer_event:
            for i, line in enumerate(lines, 1):
                if re.search(r'\bfunction\s+transfer\s*\(', line):
                    func_body = self._get_function_body(lines, i - 1)
                    if '{' not in func_body:
                        continue
                    if not re.search(r'emit\s+Transfer\s*\(', func_body):
                        findings.append(
                            Finding(
                                title="Transfer Event Not Emitted",
                                description=(
                                    "The `transfer()` function does not emit the Transfer event "
                                    "even though it is defined. This breaks ERC20 compliance and "
                                    "makes token transfers invisible to off-chain services."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.OTHER,
                                source=self.name,
                                detector_name="transfer-event-not-emitted",
                                locations=[
                                    SourceLocation(file=filename, start_line=i, end_line=i)
                                ],
                            )
                        )
                    break

        return findings

    def _check_approval_race(self, filename: str, source: str) -> list[Finding]:
        """Check for approval race condition vulnerability."""
        findings = []
        lines = source.splitlines()

        contract_body = strip_interfaces(source)

        has_approve = bool(re.search(r'\bfunction\s+approve\b', contract_body))
        has_increase = bool(re.search(
            r'\bfunction\s+increaseAllowance\b', contract_body
        ))
        has_decrease = bool(re.search(
            r'\bfunction\s+decreaseAllowance\b', contract_body
        ))

        if has_approve and not has_increase and not has_decrease:
            for i, line in enumerate(lines, 1):
                if re.search(r'\bfunction\s+approve\b', line):
                    func_body = self._get_function_body(lines, i - 1)
                    if '{' not in func_body:
                        continue
                    # Check if it directly sets allowance without checking previous
                    if re.search(r'allowance\s*\[.*\]\s*\[.*\]\s*=\s*', func_body):
                        findings.append(
                            Finding(
                                title="ERC20 Approval Race Condition",
                                description=(
                                    "`approve()` directly sets the allowance without "
                                    "`increaseAllowance()`/`decreaseAllowance()` alternatives. "
                                    "An attacker can front-run `approve(newAmount)` to spend "
                                    "the old allowance first, then spend the new allowance.\n\n"
                                    "**Fix:** Add `increaseAllowance()` and `decreaseAllowance()` "
                                    "functions, or use OpenZeppelin's SafeERC20."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.OTHER,
                                source=self.name,
                                detector_name="approval-race-condition",
                                locations=[
                                    SourceLocation(file=filename, start_line=i, end_line=i)
                                ],
                            )
                        )
                    break

        return findings

    def _check_fee_on_transfer(self, filename: str, source: str) -> list[Finding]:
        """Check for fee-on-transfer issues."""
        findings = []
        lines = source.splitlines()

        contract_body = strip_interfaces(source)

        for i, line in enumerate(lines, 1):
            if re.search(r'\bfunction\s+transfer\s*\(', line):
                func_body = self._get_function_body(lines, i - 1)
                if '{' not in func_body:
                    continue

                # Detect fee deduction pattern
                has_fee = bool(re.search(
                    r'\bfee\b.*=.*\*.*\/|transferFee|feePercent|feeBasis',
                    func_body, re.IGNORECASE,
                ))

                if has_fee:
                    # Check for zero-address check
                    has_zero_check = bool(re.search(
                        r'require\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\)',
                        func_body,
                    ))
                    if not has_zero_check:
                        findings.append(
                            Finding(
                                title="Fee-on-Transfer Without Zero-Address Check",
                                description=(
                                    "The `transfer()` function deducts a fee but does not check "
                                    "for `address(0)` recipient. Tokens sent to the zero address "
                                    "are permanently burned, and fees on such transfers are "
                                    "collected incorrectly.\n\n"
                                    "**Fix:** Add `require(to != address(0))` before processing."
                                ),
                                severity=Severity.LOW,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.OTHER,
                                source=self.name,
                                detector_name="fee-transfer-no-zero-check",
                                locations=[
                                    SourceLocation(file=filename, start_line=i, end_line=i)
                                ],
                            )
                        )
                break

        return findings

    def _check_unlimited_mint(self, filename: str, source: str) -> list[Finding]:
        """Check for minting without supply cap."""
        findings = []
        lines = source.splitlines()

        contract_body = strip_interfaces(source)

        for i, line in enumerate(lines, 1):
            if re.search(r'\bfunction\s+mint\b', line):
                func_body = self._get_function_body(lines, i - 1)
                if '{' not in func_body:
                    continue

                # Strip comments before checking for cap
                func_code = re.sub(r'//.*$', '', func_body, flags=re.MULTILINE)
                func_code = re.sub(r'/\*.*?\*/', '', func_code, flags=re.DOTALL)

                has_cap = bool(re.search(
                    r'\bmaxSupply\b|\bMAX_SUPPLY\b|\bcap\b|\bmaxTotal\b|'
                    r'totalSupply\s*\+.*<=|totalSupply\s*\+.*<',
                    func_code, re.IGNORECASE,
                ))

                if not has_cap:
                    findings.append(
                        Finding(
                            title="Unlimited Token Minting (No Supply Cap)",
                            description=(
                                "The `mint()` function has no maximum supply check. "
                                "A minter can inflate the token supply without limit, "
                                "diluting all existing holders.\n\n"
                                "**Fix:** Add a `maxSupply` constant and check "
                                "`require(totalSupply + amount <= maxSupply)` in mint()."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.OTHER,
                            source=self.name,
                            detector_name="unlimited-mint",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                        )
                    )
                break

        return findings

    def _check_transfer_from_ordering(
        self, filename: str, source: str
    ) -> list[Finding]:
        """Check if transferFrom checks allowance after balance update."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if re.search(r'\bfunction\s+transferFrom\b', line):
                func_body = self._get_function_body(lines, i - 1)
                if '{' not in func_body:
                    continue

                func_lines = func_body.splitlines()

                # Find positions of balance update and allowance check
                balance_update_pos = -1
                allowance_check_pos = -1
                for j, fl in enumerate(func_lines):
                    if re.search(r'balanceOf\s*\[.*\]\s*[-+]?=', fl):
                        if balance_update_pos == -1:
                            balance_update_pos = j
                    if re.search(r'require\s*\(\s*allowance', fl):
                        allowance_check_pos = j

                if balance_update_pos >= 0 and allowance_check_pos > balance_update_pos:
                    findings.append(
                        Finding(
                            title="transferFrom: Allowance Check After Balance Update",
                            description=(
                                "`transferFrom()` updates balances before checking allowance. "
                                "If the token has callback mechanisms (ERC777-style hooks), "
                                "this ordering can be exploited to transfer tokens without "
                                "sufficient allowance.\n\n"
                                "**Fix:** Move the allowance check and deduction before "
                                "the balance updates."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ACCESS_CONTROL,
                            source=self.name,
                            detector_name="transfer-from-ordering",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                        )
                    )
                break

        return findings

    @staticmethod
    def _get_function_body(lines: list[str], start_idx: int) -> str:
        """Extract function body from start line."""
        depth = 0
        found_open = False
        body = []
        for j in range(start_idx, min(len(lines), start_idx + 80)):
            body.append(lines[j])
            depth += lines[j].count('{') - lines[j].count('}')
            if lines[j].count('{') > 0:
                found_open = True
            if found_open and depth <= 0:
                break
        return "\n".join(body)
