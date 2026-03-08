"""ERC-4626 vault vulnerability detector.

Detects inflation attacks, direct balance manipulation, missing slippage
protection, and incorrect rounding direction.
"""

from __future__ import annotations

import logging
import re

from .utils import strip_comments, strip_interfaces, extract_functions

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)

# Patterns indicating ERC-4626 vault functionality
VAULT_INDICATORS = [
    r'\bERC4626\b',
    r'\bdeposit\s*\(',
    r'\bredeem\s*\(',
    r'\bmint\s*\(',
    r'\bwithdraw\s*\(',
    r'\btotalAssets\b',
    r'\bconvertToShares\b',
    r'\bconvertToAssets\b',
    r'\bpreviewDeposit\b',
    r'\bpreviewRedeem\b',
    r'\bshares\b',
    r'\basset\b',
    r'\bvault\b',
]


class ERC4626Detector:
    """Detects ERC-4626 vault vulnerabilities."""

    name = "erc4626_detector"
    category = "erc4626-vulnerability"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            clean = strip_interfaces(clean)

            # Only analyze vault-like contracts
            vault_score = sum(
                1 for pat in VAULT_INDICATORS if re.search(pat, clean, re.IGNORECASE)
            )
            if vault_score < 3:
                continue

            functions = extract_functions(clean)

            findings.extend(self._check_inflation_attack(filename, clean, functions))
            findings.extend(self._check_direct_balance_manipulation(filename, clean, functions))
            findings.extend(self._check_missing_slippage_protection(filename, functions))
            findings.extend(self._check_rounding_direction(filename, clean, functions))

        logger.info(f"ERC4626 detector found {len(findings)} findings")
        return findings

    def _check_inflation_attack(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect vaults vulnerable to first-depositor inflation attack."""
        findings: list[Finding] = []

        # Check for protective measures
        has_virtual_offset = bool(re.search(
            r'\bvirtual\s*(shares|offset|assets)\b|\b_decimalsOffset\b|'
            r'\+ 1\b|\+ 10\b|\bDECIMALS_OFFSET\b',
            source
        ))
        has_initial_deposit = bool(re.search(
            r'\b_mint\s*\([^,]+,\s*\d+\s*\)|dead\s*shares|MINIMUM_LIQUIDITY|'
            r'initialDeposit|_initialDeposit',
            source
        ))
        has_dead_shares = bool(re.search(
            r'\baddress\s*\(\s*0\s*\)\s*.*_mint|\b_mint\s*\(\s*address\s*\(\s*0',
            source
        ))

        if has_virtual_offset or has_initial_deposit or has_dead_shares:
            return findings

        # Check if deposit function exists
        for func in functions:
            if func['name'].lower() == 'deposit':
                findings.append(
                    Finding(
                        title="ERC-4626 Inflation Attack Vulnerability",
                        description=(
                            "The vault's `deposit()` function lacks protection against "
                            "the first-depositor inflation attack. An attacker can:\n"
                            "1. Deposit 1 wei to get 1 share\n"
                            "2. Donate a large amount directly to the vault\n"
                            "3. Subsequent depositors get 0 shares due to rounding\n\n"
                            "**Fix:** Use OpenZeppelin's virtual offset pattern "
                            "(`_decimalsOffset()`) or mint dead shares to `address(0)` "
                            "on first deposit."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.ERC4626_VULNERABILITY,
                        source=self.name,
                        detector_name="inflation-attack",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )
                break

        return findings

    def _check_direct_balance_manipulation(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect totalAssets() using balanceOf(address(this))."""
        findings: list[Finding] = []

        for func in functions:
            if func['name'] != 'totalAssets':
                continue

            body = func['body']
            uses_balance_of = bool(re.search(
                r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
                body
            ))

            if uses_balance_of:
                findings.append(
                    Finding(
                        title="Direct Balance Manipulation in totalAssets()",
                        description=(
                            "`totalAssets()` uses `balanceOf(address(this))` which can "
                            "be manipulated by directly transferring tokens to the vault. "
                            "This enables donation attacks and share price manipulation.\n\n"
                            "**Fix:** Track deposited assets with an internal accounting "
                            "variable instead of reading the raw balance."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.ERC4626_VULNERABILITY,
                        source=self.name,
                        detector_name="direct-balance-manipulation",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings

    def _check_missing_slippage_protection(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect deposit/withdraw without slippage protection."""
        findings: list[Finding] = []

        target_funcs = ['deposit', 'withdraw', 'redeem', 'mint']

        for func in functions:
            if func['name'].lower() not in target_funcs:
                continue
            if func['visibility'] not in ('external', 'public'):
                continue
            if func['is_view_pure']:
                continue

            sig_lower = func['signature'].lower()
            body = func['body']

            has_slippage = bool(re.search(
                r'\bmin\w*\b|\bmax\w*\b|\bslippage\b',
                sig_lower
            ))

            has_slippage_check = bool(re.search(
                r'require\s*\(.*[<>]=?.*\bmin|require\s*\(.*[<>]=?.*\bmax|'
                r'revert\s*\(\s*\w*Slippage',
                body
            ))

            if not has_slippage and not has_slippage_check:
                findings.append(
                    Finding(
                        title=f"Missing Slippage Protection: {func['name']}()",
                        description=(
                            f"`{func['name']}()` has no minimum/maximum output parameter "
                            "for slippage protection. Users may receive fewer shares/assets "
                            "than expected if the exchange rate changes between submission "
                            "and execution.\n\n"
                            "**Fix:** Add a `minShares`/`maxAssets` parameter and validate "
                            "the output meets the user's expectation."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.ERC4626_VULNERABILITY,
                        source=self.name,
                        detector_name="vault-missing-slippage",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings

    def _check_rounding_direction(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect share conversions without explicit rounding direction."""
        findings: list[Finding] = []

        conversion_funcs = ['convertToShares', 'convertToAssets',
                           'previewDeposit', 'previewRedeem',
                           'previewMint', 'previewWithdraw']

        for func in functions:
            if func['name'] not in conversion_funcs:
                continue

            body = func['body']

            # Check for division without explicit rounding
            has_division = bool(re.search(r'\s/\s', body))
            has_rounding = bool(re.search(
                r'\bMath\.mulDiv\b|\bmulDiv\b|\bRounding\b|\bceilDiv\b|\bMath\.Rounding\b',
                body
            ))

            if has_division and not has_rounding:
                findings.append(
                    Finding(
                        title=f"Unspecified Rounding Direction: {func['name']}()",
                        description=(
                            f"`{func['name']}()` performs division without explicit "
                            "rounding direction. ERC-4626 requires deposits to round "
                            "down (favor vault) and withdrawals to round up (favor vault).\n\n"
                            "**Fix:** Use `Math.mulDiv` with explicit `Rounding.Up` or "
                            "`Rounding.Down` as appropriate."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.ERC4626_VULNERABILITY,
                        source=self.name,
                        detector_name="rounding-direction",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings
