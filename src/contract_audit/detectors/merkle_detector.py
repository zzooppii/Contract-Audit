"""Merkle airdrop vulnerability detector.

Detects common vulnerabilities in Merkle-tree based airdrop contracts:
- Missing duplicate claim protection (no claimed mapping)
- Hash collision via abi.encodePacked
- Missing expiry / deadline mechanism
- Front-running claims (no msg.sender binding in leaf)
"""

from __future__ import annotations

import logging
import re

from .utils import strip_comments
from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class MerkleDetector:
    """Detects Merkle airdrop vulnerabilities."""

    name = "merkle_detector"
    category = "merkle-airdrop"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            if not re.search(r'\b(merkle|proof|airdrop|claim)\b', clean, re.IGNORECASE):
                continue
            findings.extend(self._check_duplicate_claim(filename, clean))
            findings.extend(self._check_encodepacked_collision(filename, clean))
            findings.extend(self._check_no_expiry(filename, clean))
            findings.extend(self._check_frontrun_claim(filename, clean))
        logger.info(f"Merkle detector found {len(findings)} findings")
        return findings

    def _check_duplicate_claim(self, filename: str, source: str) -> list[Finding]:
        """CRITICAL: claim function exists but no claimed/hasClaimed mapping."""
        findings: list[Finding] = []
        lines = source.splitlines()

        # Find claim functions
        claim_funcs = self._find_functions(lines, r'\bfunction\s+(claim\w*)\s*\(')
        if not claim_funcs:
            return findings

        # Check for claimed mapping anywhere in contract
        has_claimed_mapping = bool(re.search(
            r'\bmapping\s*\([^)]*=>\s*bool\s*\)\s*\w*(claimed|hasClaimed|isClaimed)\b',
            source, re.IGNORECASE
        ))

        # Also check for require(!claimed[...]) or claimed[...] = true patterns
        has_claimed_check = bool(re.search(
            r'(require\s*\(\s*!?\s*\w*(claimed|hasClaimed)\s*\[)'
            r'|(\w*(claimed|hasClaimed)\s*\[.*\]\s*=\s*true)',
            source, re.IGNORECASE
        ))

        if not has_claimed_mapping and not has_claimed_check:
            for func_name, line_num in claim_funcs:
                findings.append(Finding(
                    title=f"Missing Duplicate Claim Protection: {func_name}()",
                    description=(
                        f"`{func_name}()` does not track claimed status. "
                        "Users can call this function multiple times to drain the airdrop. "
                        "Add a `mapping(address => bool) public claimed` and check/set it in the claim function."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.MERKLE_AIRDROP,
                    source=self.name,
                    detector_name="missing-duplicate-claim-protection",
                    locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
                    metadata={"function": func_name},
                ))

        return findings

    def _check_encodepacked_collision(self, filename: str, source: str) -> list[Finding]:
        """HIGH: abi.encodePacked used for leaf hashing (hash collision risk)."""
        findings: list[Finding] = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Look for keccak256(abi.encodePacked(...)) with multiple dynamic args
            if re.search(r'keccak256\s*\(\s*abi\.encodePacked\s*\(', line):
                # Check if it has multiple arguments (collision risk)
                findings.append(Finding(
                    title="Hash Collision Risk: abi.encodePacked in Leaf Construction",
                    description=(
                        "Using `abi.encodePacked()` for Merkle leaf construction can lead to "
                        "hash collisions when multiple variable-length arguments are concatenated. "
                        "Use `abi.encode()` instead to prevent collision attacks."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.MERKLE_AIRDROP,
                    source=self.name,
                    detector_name="encodepacked-hash-collision",
                    locations=[SourceLocation(file=filename, start_line=i, end_line=i)],
                ))

        return findings

    def _check_no_expiry(self, filename: str, source: str) -> list[Finding]:
        """MEDIUM: No expiry/deadline mechanism for the airdrop."""
        findings: list[Finding] = []

        # Only check contracts that have claim functions
        if not re.search(r'\bfunction\s+claim\w*\s*\(', source):
            return findings

        has_expiry = bool(re.search(
            r'\b(expir|deadline|endTime|claimEnd|airdropEnd|expiresAt|claimDeadline)\b',
            source, re.IGNORECASE
        ))

        has_block_timestamp_check = bool(re.search(
            r'require\s*\([^)]*block\.timestamp\s*[<>]',
            source
        ))

        if not has_expiry and not has_block_timestamp_check:
            # Find the contract declaration line
            contract_match = re.search(r'\bcontract\s+(\w+)', source)
            line_num = 1
            if contract_match:
                for i, line in enumerate(source.splitlines(), 1):
                    if 'contract ' in line:
                        line_num = i
                        break

            findings.append(Finding(
                title="No Airdrop Expiry Mechanism",
                description=(
                    "The airdrop contract has no expiry or deadline mechanism. "
                    "Unclaimed tokens remain locked forever, and the airdrop owner "
                    "cannot reclaim remaining funds. Add an expiry timestamp and "
                    "a `sweep()` function for the owner to reclaim unclaimed tokens."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=FindingCategory.MERKLE_AIRDROP,
                source=self.name,
                detector_name="no-airdrop-expiry",
                locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
            ))

        return findings

    def _check_frontrun_claim(self, filename: str, source: str) -> list[Finding]:
        """MEDIUM: claim() does not bind msg.sender in leaf verification."""
        findings: list[Finding] = []
        lines = source.splitlines()

        claim_funcs = self._find_functions(lines, r'\bfunction\s+(claim\w*)\s*\(')
        if not claim_funcs:
            return findings

        for func_name, line_num in claim_funcs:
            # Get function body
            body = self._get_function_body(lines, line_num - 1)

            # Check if msg.sender is used in leaf construction
            has_sender_in_leaf = bool(re.search(
                r'(abi\.encode\w*\s*\([^)]*msg\.sender)'
                r'|(keccak256\s*\([^)]*msg\.sender)',
                body
            ))

            if not has_sender_in_leaf:
                findings.append(Finding(
                    title=f"Front-Running Risk: {func_name}() Does Not Bind msg.sender",
                    description=(
                        f"`{func_name}()` does not include `msg.sender` in the Merkle leaf hash. "
                        "An attacker can observe a pending claim transaction in the mempool, "
                        "extract the proof, and front-run it to claim tokens to their own address. "
                        "Include `msg.sender` in the leaf to bind the proof to the caller."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.MERKLE_AIRDROP,
                    source=self.name,
                    detector_name="frontrun-claim",
                    locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
                    metadata={"function": func_name},
                ))

        return findings

    def _find_functions(self, lines: list[str], pattern: str) -> list[tuple[str, int]]:
        """Find functions matching pattern, returns (name, 1-indexed line number)."""
        results = []
        for i, line in enumerate(lines):
            m = re.search(pattern, line)
            if m:
                results.append((m.group(1), i + 1))
        return results

    def _get_function_body(self, lines: list[str], start_idx: int) -> str:
        """Extract function body from start index (0-indexed)."""
        depth = 0
        found_open = False
        body_lines = []
        for k in range(start_idx, len(lines)):
            body_lines.append(lines[k])
            opens = lines[k].count('{')
            closes = lines[k].count('}')
            depth += opens - closes
            if opens > 0:
                found_open = True
            if found_open and depth <= 0:
                break
        return '\n'.join(body_lines)
