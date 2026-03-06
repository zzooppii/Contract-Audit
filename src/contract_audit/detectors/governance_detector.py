"""Governance attack surface detector.

Detects:
- Flash-loan voting (balanceOf vs getPastVotes)
- Low quorum thresholds (<4%)
- Missing/short timelocks (<24h)
- Centralized admin keys
- Zero proposal threshold
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

GOVERNANCE_PATTERNS = [
    "Governor",
    "Governance",
    "Timelock",
    "DAO",
    "Proposal",
    "quorum",
    "vote",
    "Vote",
    "ballot",
]

TIMELOCK_FUNCTIONS = [
    "schedule",
    "execute",
    "executeBatch",
    "delay",
    "minDelay",
    "timelockDelay",
]

CENTRALIZED_FUNCTIONS = [
    "onlyOwner",
    "onlyAdmin",
    "onlyGovernor",
    "onlySuperAdmin",
]


class GovernanceDetector:
    """Detects governance-related attack surfaces."""

    name = "governance_detector"
    category = "governance-attack"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect governance vulnerabilities."""
        findings: list[Finding] = []

        min_quorum = context.config.governance_min_quorum_threshold
        min_timelock = context.config.governance_min_timelock_seconds

        for filename, source in context.contract_sources.items():
            if not self._is_governance_contract(source):
                continue

            findings.extend(self._check_flash_loan_voting(filename, source))
            findings.extend(self._check_low_quorum(filename, source, min_quorum))
            findings.extend(self._check_timelock(filename, source, min_timelock))
            findings.extend(self._check_centralized_admin(filename, source))
            findings.extend(self._check_proposal_threshold(filename, source))

        logger.info(f"Governance detector found {len(findings)} findings")
        return findings

    def _is_governance_contract(self, source: str) -> bool:
        """Heuristic: check if contract is governance-related."""
        return any(p in source for p in GOVERNANCE_PATTERNS)

    def _check_flash_loan_voting(self, filename: str, source: str) -> list[Finding]:
        """Check for flash-loan exploitable voting (current balance vs checkpointed)."""
        findings = []

        uses_balance_of = bool(re.search(r'\bbalanceOf\s*\(', source))
        uses_past_votes = bool(
            re.search(r'\bgetPastVotes\s*\(|\bgetVotes\s*\(|\bcheckpoint', source)
        )

        if uses_balance_of and not uses_past_votes:
            # Find the line
            lines = source.splitlines()
            for i, line in enumerate(lines, 1):
                if re.search(r'\bbalanceOf\s*\(', line) and "vote" in source.lower():
                    findings.append(
                        Finding(
                            title="Flash Loan Voting: balanceOf Instead of getPastVotes",
                            description=(
                                "Governance uses `balanceOf()` to determine voting power, "
                                "which reflects current token balance. An attacker can take "
                                "a flash loan, acquire voting tokens, vote on a proposal, "
                                "and repay the loan in the same transaction.\n\n"
                                "**Fix:** Use `getPastVotes(voter, block.number - 1)` which "
                                "reads from a past snapshot that cannot be manipulated in the "
                                "current transaction."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.GOVERNANCE_ATTACK,
                            source=self.name,
                            detector_name="flash-loan-voting",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                        )
                    )
                    break  # Report once

        return findings

    def _check_low_quorum(
        self, filename: str, source: str, min_quorum: float
    ) -> list[Finding]:
        """Check for low quorum thresholds."""
        findings = []
        lines = source.splitlines()

        # Look for numeric quorum values
        quorum_pattern = re.compile(
            r'\bquorum\b[^=]*=\s*(\d+(?:\.\d+)?)', re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = quorum_pattern.search(line)
            if match:
                value = float(match.group(1))
                # Normalize: if value looks like a percentage (e.g., 4 = 4%)
                if value < 1 and value < min_quorum:
                    percentage = value * 100
                    findings.append(
                        Finding(
                            title=f"Low Governance Quorum: {percentage:.1f}%",
                            description=(
                                f"Quorum is set to {percentage:.1f}%, below the recommended "
                                f"minimum of {min_quorum * 100:.0f}%. A low quorum allows "
                                "a small group of token holders to pass proposals, "
                                "enabling governance attacks with minimal capital."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.GOVERNANCE_ATTACK,
                            source=self.name,
                            detector_name="low-quorum",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i,
                                    end_line=i,
                                )
                            ],
                            metadata={"quorum": value, "threshold": min_quorum},
                        )
                    )

        return findings

    def _check_timelock(
        self, filename: str, source: str, min_timelock: int
    ) -> list[Finding]:
        """Check for missing or insufficient timelocks."""
        findings = []
        lines = source.splitlines()

        has_timelock = any(t in source for t in TIMELOCK_FUNCTIONS)

        if not has_timelock and any(p in source for p in ["Governor", "Governance", "DAO"]):
            findings.append(
                Finding(
                    title="Missing Governance Timelock",
                    description=(
                        "Governance contract has no timelock mechanism. Without a timelock, "
                        f"proposals execute immediately after passing. The recommended minimum "
                        f"delay is {min_timelock // 3600}h to allow users to exit before "
                        "malicious proposals take effect."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.GOVERNANCE_ATTACK,
                    source=self.name,
                    detector_name="missing-timelock",
                    locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
                )
            )

        # Check for explicitly short timelock delays
        delay_pattern = re.compile(r'\bminDelay\s*=\s*(\d+)', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            match = delay_pattern.search(line)
            if match:
                delay = int(match.group(1))
                if delay < min_timelock:
                    findings.append(
                        Finding(
                            title=f"Insufficient Timelock: {delay}s < {min_timelock}s",
                            description=(
                                f"Timelock delay is {delay} seconds ({delay // 3600:.1f}h), "
                                f"below the recommended minimum of {min_timelock // 3600}h. "
                                "Short timelocks do not give users sufficient time to react "
                                "to malicious governance proposals."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.GOVERNANCE_ATTACK,
                            source=self.name,
                            detector_name="short-timelock",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                            metadata={"delay": delay, "min_delay": min_timelock},
                        )
                    )

        return findings

    def _check_centralized_admin(self, filename: str, source: str) -> list[Finding]:
        """Check for centralized admin control over sensitive functions."""
        findings = []
        lines = source.splitlines()

        sensitive_functions = [
            "pause", "unpause", "setFee", "setRewardRate", "setTreasury",
            "addMinter", "removeMinter", "setOracle", "updateConfig",
        ]

        for i, line in enumerate(lines, 1):
            for fn in sensitive_functions:
                if re.search(rf'\bfunction\s+{re.escape(fn)}\b', line):
                    context_block = "\n".join(lines[max(0, i - 1):min(len(lines), i + 5)])
                    if "onlyOwner" in context_block or "onlyAdmin" in context_block:
                        # Single-key control over sensitive function
                        findings.append(
                            Finding(
                                title=f"Centralization Risk: {fn}() Controlled by Single Key",
                                description=(
                                    f"`{fn}()` is protected by `onlyOwner`/`onlyAdmin`, meaning "
                                    "a single private key controls this sensitive function. "
                                    "If the key is compromised, an attacker can modify critical "
                                    "protocol parameters."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.CENTRALIZATION_RISK,
                                source=self.name,
                                detector_name="centralized-admin",
                                locations=[
                                    SourceLocation(file=filename, start_line=i, end_line=i)
                                ],
                                metadata={"function": fn},
                            )
                        )

        return findings

    def _check_proposal_threshold(self, filename: str, source: str) -> list[Finding]:
        """Check for zero or very low proposal thresholds."""
        findings = []
        lines = source.splitlines()

        threshold_pattern = re.compile(
            r'\bproposalThreshold\b[^=]*=\s*(\d+)', re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = threshold_pattern.search(line)
            if match:
                threshold = int(match.group(1))
                if threshold == 0:
                    findings.append(
                        Finding(
                            title="Zero Governance Proposal Threshold",
                            description=(
                                "The proposal threshold is 0, meaning any address can submit "
                                "governance proposals regardless of token holdings. "
                                "This enables spam attacks and lowers the bar for governance griefing."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.GOVERNANCE_ATTACK,
                            source=self.name,
                            detector_name="zero-proposal-threshold",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                            metadata={"threshold": threshold},
                        )
                    )

        return findings
