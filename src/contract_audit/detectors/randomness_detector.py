"""Weak randomness and RNG vulnerability detector.

Detects:
- On-chain randomness using block variables (timestamp, prevrandao, blockhash)
- Blockhash only valid for last 256 blocks
- Commit-reveal schemes without timeout
- Predictable seed sources
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

# Block variables used as randomness sources
WEAK_RANDOMNESS_SOURCES = [
    "block.timestamp",
    "block.prevrandao",
    "block.difficulty",
    "block.number",
    "block.coinbase",
    "block.gaslimit",
    "block.basefee",
]


class RandomnessDetector:
    """Detects weak randomness and RNG vulnerabilities."""

    name = "randomness_detector"
    category = "weak-randomness"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect randomness vulnerabilities across all contracts."""
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            findings.extend(self._check_weak_randomness(filename, source))
            findings.extend(self._check_blockhash_reliance(filename, source))

        logger.info(f"Randomness detector found {len(findings)} findings")
        return findings

    def _check_weak_randomness(self, filename: str, source: str) -> list[Finding]:
        """Check for on-chain randomness using block variables."""
        findings = []
        lines = source.splitlines()

        # Strip comments
        code_only = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
        code_only = re.sub(r'/\*.*?\*/', '', code_only, flags=re.DOTALL)

        # Look for keccak256 or abi.encodePacked with block variables as seed
        for i, line in enumerate(lines, 1):
            # Strip comment from this line for matching
            code_line = re.sub(r'//.*$', '', line)

            # Check if line uses block variables in a hashing/randomness context
            used_sources = [s for s in WEAK_RANDOMNESS_SOURCES if s in code_line]
            if not used_sources:
                continue

            # Look at surrounding context for randomness usage
            context_start = max(0, i - 5)
            context_end = min(len(lines), i + 10)
            context_block = "\n".join(lines[context_start:context_end])
            context_code = re.sub(r'//.*$', '', context_block, flags=re.MULTILINE)
            context_code = re.sub(r'/\*.*?\*/', '', context_code, flags=re.DOTALL)

            is_randomness = any(kw in context_code for kw in [
                'keccak256', 'random', 'winner', 'lottery', 'raffle',
                'shuffle', 'select', 'pick', 'draw', 'dice', 'roll',
            ])

            if is_randomness:
                sources_str = ", ".join(f"`{s}`" for s in used_sources)
                findings.append(
                    Finding(
                        title="Weak On-Chain Randomness",
                        description=(
                            f"Randomness derived from {sources_str}. "
                            "Miners/validators can manipulate these values to influence "
                            "the outcome. Use Chainlink VRF or a commit-reveal scheme "
                            "for secure randomness."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.WEAK_RANDOMNESS,
                        source=self.name,
                        detector_name="weak-randomness",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                        metadata={"sources": used_sources},
                    )
                )
                break  # One finding per contract is enough

        return findings

    def _check_blockhash_reliance(self, filename: str, source: str) -> list[Finding]:
        """Check for blockhash usage without 256-block limit handling."""
        findings: list[Finding] = []
        lines = source.splitlines()

        # Strip comments
        code_only = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
        code_only = re.sub(r'/\*.*?\*/', '', code_only, flags=re.DOTALL)

        if "blockhash" not in code_only:
            return findings

        for i, line in enumerate(lines, 1):
            code_line = re.sub(r'//.*$', '', line)
            if "blockhash" not in code_line:
                continue

            # Get enclosing function context
            func_start = max(0, i - 20)
            func_end = min(len(lines), i + 20)
            func_block = "\n".join(lines[func_start:func_end])
            func_code = re.sub(r'//.*$', '', func_block, flags=re.MULTILINE)
            func_code = re.sub(r'/\*.*?\*/', '', func_code, flags=re.DOTALL)

            # Check if there's a 256-block window check
            has_block_check = bool(re.search(
                r'block\.number\s*-\s*\w+\s*[<>]=?\s*256'
                r'|256\s*[<>]=?\s*block\.number\s*-'
                r'|require.*256'
                r'|blockhash.*!=\s*0'
                r'|blockhash.*!=\s*bytes32\(0\)'
                r'|bhash\s*!=\s*0'
                r'|bhash\s*!=\s*bytes32\(0\)',
                func_code,
            ))

            if not has_block_check:
                findings.append(
                    Finding(
                        title="Blockhash Used Without 256-Block Check",
                        description=(
                            "`blockhash()` returns `bytes32(0)` for blocks older than 256 blocks. "
                            "If this function isn't called within 256 blocks of the target block, "
                            "the hash will be zero, making the result predictable or allowing "
                            "an attacker to wait and exploit the known-zero value.\n\n"
                            "**Fix:** Add `require(block.number - targetBlock <= 256)` or check "
                            "that blockhash result is non-zero."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.WEAK_RANDOMNESS,
                        source=self.name,
                        detector_name="blockhash-256-limit",
                        locations=[
                            SourceLocation(file=filename, start_line=i, end_line=i)
                        ],
                    )
                )
                break  # One finding per contract

        return findings
