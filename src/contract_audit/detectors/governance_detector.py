"""Governance attack surface detector.

Detects:
- Flash-loan voting (balanceOf vs getPastVotes)
- Low quorum thresholds (<4%)
- Missing/short timelocks (<24h)
- Centralized admin keys
- Zero proposal threshold
- Missing quorum check in execute
- Guardian/role centralization
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
            findings.extend(self._check_missing_quorum_in_execute(filename, source))
            findings.extend(self._check_guardian_centralization(filename, source))

        logger.info(f"Governance detector found {len(findings)} findings")
        return findings

    def _is_governance_contract(self, source: str) -> bool:
        """Heuristic: check if contract is governance-related."""
        return any(p in source for p in GOVERNANCE_PATTERNS)

    def _check_flash_loan_voting(self, filename: str, source: str) -> list[Finding]:
        """Check for flash-loan exploitable voting (current balance vs checkpointed)."""
        findings = []

        # Strip interface blocks to avoid matching declarations
        contract_body = self._strip_interfaces(source)
        uses_balance_of = bool(re.search(r'\bbalanceOf\s*\(', contract_body))
        uses_past_votes = bool(
            re.search(r'\bgetPastVotes\s*\(|\bgetVotes\s*\(|\bcheckpoint', contract_body)
        )

        if uses_balance_of and not uses_past_votes:
            lines = source.splitlines()
            in_interface = False
            for i, line in enumerate(lines, 1):
                # Skip interface blocks
                if re.search(r'\binterface\s+\w+', line):
                    in_interface = True
                if in_interface:
                    if line.strip() == '}' and not any(c == '{' for c in line):
                        in_interface = False
                    continue

                if re.search(r'\bbalanceOf\s*\(', line):
                    # Check if this balanceOf is in a voting context
                    func_body = self._get_enclosing_function(lines, i - 1)
                    if any(kw in func_body.lower() for kw in ["vote", "voting", "weight", "power"]):
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

        # Match quorum-related variable assignments: quorum = X, quorumNumerator = X, etc.
        quorum_pattern = re.compile(
            r'\bquorum\w*\b[^=]*=\s*(\d+(?:\.\d+)?)', re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            match = quorum_pattern.search(line)
            if match:
                value = float(match.group(1))

                # Determine the effective quorum percentage
                # Check if there's a denominator in the contract (e.g., QUORUM_DENOMINATOR = 10000)
                denom_match = re.search(
                    r'QUORUM_DENOMINATOR\s*=\s*(\d+)', source, re.IGNORECASE
                )
                if denom_match:
                    denominator = float(denom_match.group(1))
                    percentage = (value / denominator) * 100
                elif value < 1:
                    percentage = value * 100
                elif value <= 100:
                    percentage = value
                else:
                    continue  # Can't determine, skip

                min_quorum_pct = min_quorum * 100
                if percentage < min_quorum_pct:
                    findings.append(
                        Finding(
                            title=f"Low Governance Quorum: {percentage:.1f}%",
                            description=(
                                f"Quorum is set to {percentage:.1f}%, below the recommended "
                                f"minimum of {min_quorum_pct:.0f}%. A low quorum allows "
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
                            metadata={"quorum_pct": percentage, "threshold_pct": min_quorum_pct},
                        )
                    )

        return findings

    def _check_timelock(
        self, filename: str, source: str, min_timelock: int
    ) -> list[Finding]:
        """Check for missing or insufficient timelocks."""
        findings = []
        lines = source.splitlines()

        # Check for zero or short timelock delay variables
        delay_pattern = re.compile(
            r'\b(?:minDelay|timelockDelay|timelock_delay|delay)\s*=\s*(\d+)',
            re.IGNORECASE,
        )
        found_delay = False
        for i, line in enumerate(lines, 1):
            match = delay_pattern.search(line)
            if match:
                found_delay = True
                delay = int(match.group(1))
                if delay < min_timelock:
                    sev = Severity.HIGH if delay == 0 else Severity.MEDIUM
                    title = (
                        "Zero Timelock Delay — Immediate Execution"
                        if delay == 0
                        else f"Insufficient Timelock: {delay}s < {min_timelock}s"
                    )
                    findings.append(
                        Finding(
                            title=title,
                            description=(
                                f"Timelock delay is {delay} seconds. "
                                "Proposals can be executed immediately (or near-immediately) "
                                "after voting ends, leaving no window for users to react.\n\n"
                                f"**Fix:** Set a minimum delay of {min_timelock // 3600}+ hours "
                                "to give token holders time to exit before malicious proposals "
                                "take effect."
                            ),
                            severity=sev,
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

        # If no delay variable found, check if governance contract has execute but no timelock
        if not found_delay:
            has_execute = bool(re.search(r'\bfunction\s+execute\b', source))
            is_governance = any(p in source for p in ["Governor", "Governance", "DAO", "Proposal"])
            # Make sure "timelock" concept is absent
            has_timelock_ref = bool(re.search(r'timelock|TimeLock|Timelock', source, re.IGNORECASE))
            if has_execute and is_governance and not has_timelock_ref:
                findings.append(
                    Finding(
                        title="Missing Governance Timelock",
                        description=(
                            "Governance contract has an execute function but no timelock mechanism. "
                            "Without a timelock, proposals execute immediately after passing. "
                            f"The recommended minimum delay is {min_timelock // 3600}h to allow "
                            "users to exit before malicious proposals take effect."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.GOVERNANCE_ATTACK,
                        source=self.name,
                        detector_name="missing-timelock",
                        locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
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

    def _check_missing_quorum_in_execute(self, filename: str, source: str) -> list[Finding]:
        """Check if execute() validates quorum was met."""
        findings = []
        lines = source.splitlines()

        # Only relevant if contract has a quorum concept
        has_quorum_concept = bool(re.search(r'\bquorum\b', source, re.IGNORECASE))
        if not has_quorum_concept:
            return findings

        # Find execute function
        for i, line in enumerate(lines, 1):
            if re.search(r'\bfunction\s+execute\b', line):
                func_body = self._get_enclosing_function(lines, i - 1)
                # Strip comments before checking for quorum reference
                func_code = re.sub(r'//.*$', '', func_body, flags=re.MULTILINE)
                func_code = re.sub(r'/\*.*?\*/', '', func_code, flags=re.DOTALL)
                if not re.search(r'\bquorum\b', func_code, re.IGNORECASE):
                    findings.append(
                        Finding(
                            title="Execute Without Quorum Validation",
                            description=(
                                "The `execute()` function does not check whether quorum was "
                                "reached before executing a proposal. Without quorum validation, "
                                "a proposal could pass with as few as 1 vote in favor.\n\n"
                                "**Fix:** Add `require(proposal.forVotes >= quorum(), "
                                "\"Quorum not reached\")` to the execute function."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.GOVERNANCE_ATTACK,
                            source=self.name,
                            detector_name="missing-quorum-check",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                        )
                    )
                break  # Only check first execute

        return findings

    def _check_guardian_centralization(self, filename: str, source: str) -> list[Finding]:
        """Check for guardian/privileged role that can bypass governance."""
        findings = []
        lines = source.splitlines()

        # Detect privileged roles: guardian, admin, operator with direct .call or cancel powers
        role_patterns = [
            (r'\bguardian\b', "guardian"),
            (r'\bkeeper\b', "keeper"),
            (r'\boperator\b', "operator"),
        ]

        for role_re, role_name in role_patterns:
            if not re.search(role_re, source, re.IGNORECASE):
                continue

            # Check for functions restricted to this role that perform dangerous operations
            for i, line in enumerate(lines, 1):
                func_match = re.search(r'\bfunction\s+(\w+)', line)
                if not func_match:
                    continue

                func_name = func_match.group(1)
                func_body = self._get_enclosing_function(lines, i - 1)

                # Does function require this role?
                has_role_check = bool(re.search(
                    rf'require\s*\(\s*msg\.sender\s*==\s*{role_name}\b|'
                    rf'modifier\s+only{role_name.capitalize()}',
                    func_body, re.IGNORECASE,
                ))
                if not has_role_check:
                    continue

                # Does it perform dangerous ops? (arbitrary call, cancel, transfer)
                has_arbitrary_call = bool(re.search(
                    r'\.call\s*\{|\.delegatecall\s*\(|\.transfer\s*\(', func_body
                ))
                has_cancel = bool(re.search(r'cancel', func_name, re.IGNORECASE))

                if has_arbitrary_call:
                    findings.append(
                        Finding(
                            title=f"Guardian Bypass: {func_name}() Can Execute Arbitrary Calls",
                            description=(
                                f"The `{role_name}` role can call `{func_name}()` which performs "
                                "arbitrary external calls, bypassing governance entirely. "
                                "A compromised guardian key allows full protocol takeover.\n\n"
                                "**Fix:** Remove arbitrary call capability, or require governance "
                                "approval for guardian actions, or implement a multi-sig guardian."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.CENTRALIZATION_RISK,
                            source=self.name,
                            detector_name="guardian-bypass",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                            metadata={"role": role_name, "function": func_name},
                        )
                    )
                elif has_cancel:
                    findings.append(
                        Finding(
                            title=f"Guardian Can Cancel Any Proposal: {func_name}()",
                            description=(
                                f"The `{role_name}` role can cancel any governance proposal "
                                "without restriction. This gives a single key veto power over "
                                "all governance actions, undermining decentralization.\n\n"
                                "**Fix:** Limit cancellation to the proposal creator, or require "
                                "the guardian to be a multi-sig with timelock."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.CENTRALIZATION_RISK,
                            source=self.name,
                            detector_name="guardian-veto",
                            locations=[
                                SourceLocation(file=filename, start_line=i, end_line=i)
                            ],
                            metadata={"role": role_name, "function": func_name},
                        )
                    )

        return findings

    @staticmethod
    def _strip_interfaces(source: str) -> str:
        """Remove interface blocks from source to avoid matching declarations."""
        result = []
        lines = source.splitlines()
        in_interface = False
        depth = 0
        for line in lines:
            if not in_interface and re.search(r'\binterface\s+\w+', line):
                in_interface = True
                depth = 0
            if in_interface:
                depth += line.count('{') - line.count('}')
                if depth <= 0 and depth + line.count('}') > 0:
                    in_interface = False
                continue
            result.append(line)
        return "\n".join(result)

    @staticmethod
    def _get_enclosing_function(lines: list[str], start_idx: int) -> str:
        """Extract the body of the function enclosing the given line index."""
        # Walk back to find function declaration
        func_start = start_idx
        for j in range(start_idx, max(-1, start_idx - 30), -1):
            if re.search(r'\bfunction\s+\w+', lines[j]):
                func_start = j
                break

        # Walk forward to find the first opening brace, then track depth
        depth = 0
        found_open = False
        func_end = min(len(lines) - 1, func_start + 80)
        for j in range(func_start, len(lines)):
            opens = lines[j].count('{')
            closes = lines[j].count('}')
            depth += opens - closes
            if opens > 0:
                found_open = True
            if found_open and depth <= 0:
                func_end = j
                break

        return "\n".join(lines[func_start:func_end + 1])
