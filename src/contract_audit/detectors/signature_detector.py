"""Signature verification vulnerability detector.

Detects:
- ecrecover without zero-address check
- Signature replay (missing chain ID / nonce)
- Signature malleability (s-value not checked)
- Missing EIP-712 domain separator
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


class SignatureDetector:
    """Detects signature verification vulnerabilities."""

    name = "signature_detector"
    category = "signature"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            if not self._uses_signatures(source):
                continue

            findings.extend(self._check_ecrecover_zero(filename, source))
            findings.extend(self._check_signature_replay(filename, source))
            findings.extend(self._check_s_malleability(filename, source))

        logger.info(f"Signature detector found {len(findings)} findings")
        return findings

    def _uses_signatures(self, source: str) -> bool:
        """Check if contract uses signature verification."""
        return bool(re.search(r'\becrecover\b|ECDSA\.recover|SignatureChecker', source))

    def _check_ecrecover_zero(self, filename: str, source: str) -> list[Finding]:
        """Check for ecrecover without address(0) validation."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if 'ecrecover' not in line:
                continue

            # Get surrounding context (function body)
            func_body = self._get_enclosing_function(lines, i - 1)

            # Check if result is validated against address(0)
            has_zero_check = bool(re.search(
                r'!=\s*address\s*\(\s*0\s*\)|'
                r'require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)|'
                r'==\s*address\s*\(\s*0\s*\).*revert|'
                r'if\s*\([^)]*==\s*address\s*\(\s*0\s*\)',
                func_body,
            ))

            if not has_zero_check:
                findings.append(
                    Finding(
                        title="ecrecover Without Zero-Address Check",
                        description=(
                            "`ecrecover()` returns `address(0)` for invalid signatures "
                            "instead of reverting. Without checking the return value against "
                            "`address(0)`, an attacker can forge signatures that appear valid.\n\n"
                            "**Fix:** Add `require(signer != address(0), \"Invalid signature\")` "
                            "after ecrecover, or use OpenZeppelin's ECDSA library which "
                            "handles this automatically."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.ACCESS_CONTROL,
                        source=self.name,
                        detector_name="ecrecover-zero-check",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                    )
                )
                break  # Report once per file

        return findings

    def _check_signature_replay(self, filename: str, source: str) -> list[Finding]:
        """Check for signature replay vulnerabilities."""
        findings = []
        lines = source.splitlines()

        # Find functions that verify signatures and execute actions
        for i, line in enumerate(lines, 1):
            func_match = re.search(r'\bfunction\s+(\w+)', line)
            if not func_match:
                continue

            func_name = func_match.group(1)
            func_body = self._get_enclosing_function(lines, i - 1)

            # Must use ecrecover or ECDSA.recover
            if not re.search(r'ecrecover|ECDSA\.recover', func_body):
                continue

            # Must have an external call or state change (actually does something)
            has_action = bool(re.search(
                r'\.call\s*\{|\.transfer\s*\(|\.send\s*\(|'
                r'\w+\s*[-+]?=\s*|'
                r'\.delegatecall\s*\(',
                func_body,
            ))
            if not has_action:
                continue

            issues = []

            # Check for chain ID in hash
            has_chain_id = bool(re.search(
                r'block\.chainid|chainId|chain_id|DOMAIN_SEPARATOR|domainSeparator|'
                r'EIP712',
                func_body, re.IGNORECASE,
            ))
            if not has_chain_id:
                issues.append("no chain ID")

            # Check for nonce
            has_nonce = bool(re.search(
                r'\bnonce\b.*\+\+|\bnonce\b\s*\+=\s*1|\bnonces\s*\[',
                func_body,
            ))
            if not has_nonce:
                issues.append("no nonce increment")

            if issues:
                issue_str = " and ".join(issues)
                findings.append(
                    Finding(
                        title=f"Signature Replay: {func_name}() ({issue_str})",
                        description=(
                            f"`{func_name}()` verifies signatures but the signed hash "
                            f"has {issue_str}. "
                            + ("Without chain ID, signatures valid on one chain can be "
                               "replayed on another (e.g., mainnet signature replayed on L2). "
                               if "no chain ID" in issues else "")
                            + ("Without a nonce, the same signature can be submitted "
                               "multiple times to execute the action repeatedly. "
                               if "no nonce" in issues else "")
                            + "\n\n**Fix:** Include `block.chainid`, contract address, "
                            "and an incrementing nonce in the signed hash. "
                            "Consider using EIP-712 typed data signing."
                        ),
                        severity=Severity.CRITICAL if "no nonce" in issues else Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.ACCESS_CONTROL,
                        source=self.name,
                        detector_name="signature-replay",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                        metadata={"function": func_name, "issues": issues},
                    )
                )
                break  # Report once per contract

        return findings

    def _check_s_malleability(self, filename: str, source: str) -> list[Finding]:
        """Check for signature malleability (s-value in upper half)."""
        findings = []
        lines = source.splitlines()

        # Only relevant if using raw ecrecover (not ECDSA library)
        if 'ECDSA' in source or 'SignatureChecker' in source:
            return findings

        for i, line in enumerate(lines, 1):
            if 'ecrecover' not in line:
                continue

            func_body = self._get_enclosing_function(lines, i - 1)

            # Check if s-value is validated
            # Standard check: s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
            has_s_check = bool(re.search(
                r'0x7[Ff]{63}5[Dd]576[Ee]7357[Aa]4501[Dd]{2}[Ff][Ee]92[Ff]46681[Bb]20[Aa]0|'
                r'\bs\s*<=?\s*|'
                r'malleab|'
                r'ECDSA',
                func_body, re.IGNORECASE,
            ))

            if not has_s_check:
                findings.append(
                    Finding(
                        title="Signature Malleability: s-Value Not Checked",
                        description=(
                            "Raw `ecrecover()` is used without checking that the `s` value "
                            "is in the lower half of the curve order. For every valid signature "
                            "(r, s, v), there exists another valid signature (r, N-s, 27+28-v) "
                            "for the same message. This allows signature forgery.\n\n"
                            "**Fix:** Use OpenZeppelin's ECDSA library, or add: "
                            "`require(uint256(s) <= "
                            "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)`"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.ACCESS_CONTROL,
                        source=self.name,
                        detector_name="signature-malleability",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                    )
                )
                break

        return findings

    @staticmethod
    def _get_enclosing_function(lines: list[str], start_idx: int) -> str:
        """Extract the function body enclosing the given line."""
        func_start = start_idx
        for j in range(start_idx, max(-1, start_idx - 30), -1):
            if re.search(r'\bfunction\s+\w+', lines[j]):
                func_start = j
                break

        depth = 0
        found_open = False
        func_end = min(len(lines) - 1, func_start + 80)
        for j in range(func_start, len(lines)):
            depth += lines[j].count('{') - lines[j].count('}')
            if lines[j].count('{') > 0:
                found_open = True
            if found_open and depth <= 0:
                func_end = j
                break

        return "\n".join(lines[func_start:func_end + 1])
