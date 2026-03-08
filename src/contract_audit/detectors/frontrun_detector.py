"""Front-running vulnerability detector.

Detects missing slippage protection, missing deadlines, absent commit-reveal
patterns, and sandwich-vulnerable functions.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)
from .utils import extract_functions, strip_comments, strip_interfaces

logger = logging.getLogger(__name__)


class FrontrunDetector:
    """Detects front-running vulnerabilities."""

    name = "frontrun_detector"
    category = "front-running"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            clean = strip_interfaces(clean)
            functions = extract_functions(clean)

            findings.extend(self._check_missing_slippage(filename, functions))
            findings.extend(self._check_missing_deadline(filename, functions))
            findings.extend(self._check_commit_reveal_absence(filename, clean, functions))
            findings.extend(self._check_sandwich_vulnerable(filename, functions))

        logger.info(f"Frontrun detector found {len(findings)} findings")
        return findings

    def _check_missing_slippage(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect swap/trade functions without minAmountOut or slippage params."""
        findings: list[Finding] = []

        swap_keywords = ['swap', 'trade', 'exchange', 'sell', 'buy']

        for func in functions:
            name_lower = func['name'].lower()
            if not any(kw in name_lower for kw in swap_keywords):
                continue
            if func['is_view_pure']:
                continue

            sig_lower = func['signature'].lower()
            has_slippage = bool(re.search(
                r'\bmin\w*out\b|\bmin\w*amount\b|\bslippage\b|\bamountOutMin\b|\bminReturn\b',
                sig_lower, re.IGNORECASE
            ))

            if not has_slippage:
                findings.append(
                    Finding(
                        title=f"Missing Slippage Protection: {func['name']}()",
                        description=(
                            f"`{func['name']}()` performs a swap/trade without a "
                            "`minAmountOut` or slippage parameter. This allows MEV bots "
                            "to sandwich the transaction for profit.\n\n"
                            "**Fix:** Add a `minAmountOut` parameter and validate the "
                            "received amount meets the minimum."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.FRONT_RUNNING,
                        source=self.name,
                        detector_name="missing-slippage",
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

    def _check_missing_deadline(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect DEX functions without deadline checks."""
        findings: list[Finding] = []

        dex_keywords = ['swap', 'addLiquidity', 'removeLiquidity', 'trade']

        for func in functions:
            name_lower = func['name'].lower()
            if not any(kw.lower() in name_lower for kw in dex_keywords):
                continue
            if func['is_view_pure']:
                continue

            body = func['body']
            sig = func['signature']
            full = sig + '\n' + body

            has_deadline = bool(re.search(
                r'\bdeadline\b|\bexpir\w+\b', full, re.IGNORECASE
            ))
            has_timestamp_check = bool(re.search(
                r'block\.timestamp\s*[<>]=?\s*\w*deadline|'
                r'require\s*\(.*block\.timestamp.*[<>]',
                full
            ))

            if not has_deadline and not has_timestamp_check:
                findings.append(
                    Finding(
                        title=f"Missing Deadline Check: {func['name']}()",
                        description=(
                            f"`{func['name']}()` has no `deadline` parameter or "
                            "`block.timestamp` check. Transactions can be held in the "
                            "mempool and executed at an unfavorable time.\n\n"
                            "**Fix:** Add a `deadline` parameter and require "
                            "`block.timestamp <= deadline`."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.FRONT_RUNNING,
                        source=self.name,
                        detector_name="missing-deadline",
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

    def _check_commit_reveal_absence(
        self, filename: str, source: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect bid/auction functions without commit-reveal pattern."""
        findings: list[Finding] = []

        auction_keywords = ['bid', 'auction', 'offer']

        for func in functions:
            name_lower = func['name'].lower()
            if not any(kw in name_lower for kw in auction_keywords):
                continue
            if func['is_view_pure']:
                continue
            if func['visibility'] not in ('external', 'public'):
                continue

            # Check if contract has commit-reveal pattern
            has_commit_reveal = bool(re.search(
                r'\bcommit\b.*\breveal\b|\bcommitHash\b|\b_commits\b|\bcommitment\b',
                source, re.IGNORECASE
            ))

            if not has_commit_reveal:
                findings.append(
                    Finding(
                        title=f"Missing Commit-Reveal Pattern: {func['name']}()",
                        description=(
                            f"`{func['name']}()` accepts bids/offers without a "
                            "commit-reveal scheme. Front-runners can observe pending "
                            "bids and outbid them.\n\n"
                            "**Fix:** Implement a two-phase commit-reveal pattern where "
                            "users first commit a hash, then reveal their bid."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.FRONT_RUNNING,
                        source=self.name,
                        detector_name="missing-commit-reveal",
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

    def _check_sandwich_vulnerable(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect functions that modify reserves and transfer in same call without protection."""
        findings: list[Finding] = []

        for func in functions:
            if func['is_view_pure']:
                continue
            if func['visibility'] not in ('external', 'public'):
                continue

            body = func['body']

            has_reserve_change = bool(re.search(
                r'\breserve\w*\s*[+\-=]|\b_update\w*\(|\bsync\s*\(',
                body
            ))
            has_transfer = bool(re.search(
                r'\.transfer\s*\(|\.safeTransfer\s*\(|\.call\s*\{?\s*value',
                body
            ))
            has_protection = bool(re.search(
                r'\block\b|\bnonReentrant\b|\brequire\s*\(\s*msg\.sender\s*==',
                func['signature'] + '\n' + body
            ))

            if has_reserve_change and has_transfer and not has_protection:
                findings.append(
                    Finding(
                        title=f"Sandwich Attack Vulnerable: {func['name']}()",
                        description=(
                            f"`{func['name']}()` modifies reserves and transfers tokens "
                            "in the same call without protection. An attacker can sandwich "
                            "this transaction to extract value.\n\n"
                            "**Fix:** Add access control, reentrancy guards, or use an "
                            "oracle for price verification."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.FRONT_RUNNING,
                        source=self.name,
                        detector_name="sandwich-vulnerable",
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
