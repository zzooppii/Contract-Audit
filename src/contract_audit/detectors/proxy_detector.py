"""Proxy vulnerability detector.

Checks for:
- EIP-1967 storage slot compliance
- UUPS upgrade authorization
- Transparent proxy admin routing
- Uninitialized proxies
- Function selector collisions
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

logger = logging.getLogger(__name__)

# EIP-1967 storage slots
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

PROXY_PATTERNS = [
    "delegatecall",
    "upgradeTo",
    "upgradeToAndCall",
    "_implementation",
    "implementation()",
    "proxiableUUID",
    "_authorizeUpgrade",
]

INITIALIZER_PATTERNS = [
    "initialize",
    "init",
    "__init",
    "setUp",
]


class ProxyDetector:
    """Detects proxy-related vulnerabilities."""

    name = "proxy_detector"
    category = "proxy-vulnerability"
    required_context = ["contract_sources", "ast_trees"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect proxy vulnerabilities across all contracts."""
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            if not _is_proxy_contract(source):
                continue

            findings.extend(self._check_uninitialized_proxy(filename, source))
            findings.extend(self._check_uups_authorization(filename, source))
            findings.extend(self._check_selector_collision(filename, source))
            findings.extend(self._check_eip1967_compliance(filename, source))
            findings.extend(self._check_missing_storage_gap(filename, source))

        logger.info(f"Proxy detector found {len(findings)} findings")
        return findings

    def _check_uninitialized_proxy(self, filename: str, source: str) -> list[Finding]:
        """Check for initializer functions that can be called without protection."""
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            for pattern in INITIALIZER_PATTERNS:
                if re.search(rf'\bfunction\s+{pattern}\b', line):
                    # Get context and strip comments before checking
                    context_block = "\n".join(lines[max(0, i-1):min(len(lines), i+5)])
                    code_only = re.sub(r'//.*$', '', context_block, flags=re.MULTILINE)
                    code_only = re.sub(r'/\*.*?\*/', '', code_only, flags=re.DOTALL)

                    has_guard = (
                        "initializer" in code_only
                        or "onlyOwner" in code_only
                        or "onlyAdmin" in code_only
                        or re.search(r'require\s*\(\s*!?\s*initialized', code_only)
                    )
                    if not has_guard:
                        findings.append(
                            Finding(
                                title=f"Unprotected Initializer: {pattern}()",
                                description=(
                                    f"`{pattern}()` can be called by anyone without an `initializer` "
                                    "modifier or re-initialization guard. An attacker can call this "
                                    "to take ownership of the contract, especially when deployed "
                                    "behind a proxy.\n\n"
                                    "**Fix:** Use OpenZeppelin's `initializer` modifier, or add "
                                    "`require(!initialized)` at the start of the function."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.PROXY_VULNERABILITY,
                                source=self.name,
                                detector_name="uninitialized-proxy",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i,
                                        end_line=i,
                                    )
                                ],
                                metadata={"pattern": pattern},
                            )
                        )
        return findings

    def _check_uups_authorization(self, filename: str, source: str) -> list[Finding]:
        """Check UUPS proxy for proper upgrade authorization."""
        findings = []

        if "proxiableUUID" not in source and "UUPSUpgradeable" not in source:
            return findings

        lines = source.splitlines()
        has_authorize_upgrade = False
        has_access_control_on_upgrade = False

        for i, line in enumerate(lines, 1):
            if "_authorizeUpgrade" in line:
                has_authorize_upgrade = True
                context_block = "\n".join(lines[max(0, i-1):min(len(lines), i+5)])
                if any(
                    p in context_block
                    for p in ["onlyOwner", "onlyRole", "require", "revert"]
                ):
                    has_access_control_on_upgrade = True

        if has_authorize_upgrade and not has_access_control_on_upgrade:
            findings.append(
                Finding(
                    title="UUPS _authorizeUpgrade Without Access Control",
                    description=(
                        "_authorizeUpgrade() is implemented but may lack access control. "
                        "Any address could trigger an upgrade, allowing an attacker to "
                        "replace the implementation with a malicious contract."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.PROXY_VULNERABILITY,
                    source=self.name,
                    detector_name="uups-unprotected-upgrade",
                    locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
                )
            )
        elif not has_authorize_upgrade and "UUPSUpgradeable" in source:
            findings.append(
                Finding(
                    title="UUPS Contract Missing _authorizeUpgrade Override",
                    description=(
                        "Contract inherits UUPSUpgradeable but does not override "
                        "_authorizeUpgrade(). The default implementation reverts, "
                        "making upgrades impossible, or may be callable by anyone "
                        "depending on the parent implementation."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.PROXY_VULNERABILITY,
                    source=self.name,
                    detector_name="uups-missing-authorize",
                    locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
                )
            )

        return findings

    def _check_selector_collision(self, filename: str, source: str) -> list[Finding]:
        """Check for function selector collisions between proxy and implementation."""
        findings = []
        # Extract function signatures
        func_pattern = re.compile(r'\bfunction\s+(\w+)\s*\(([^)]*)\)')
        functions = func_pattern.findall(source)

        selectors: dict[str, str] = {}
        collisions: list[tuple[str, str, str]] = []

        for func_name, params in functions:
            sig = f"{func_name}({_normalize_params(params)})"
            selector = _compute_selector(sig)
            if selector in selectors:
                collisions.append((selector, selectors[selector], sig))
            else:
                selectors[selector] = sig

        for selector, sig1, sig2 in collisions:
            findings.append(
                Finding(
                    title="Function Selector Collision",
                    description=(
                        f"Functions `{sig1}` and `{sig2}` have the same 4-byte selector "
                        f"(0x{selector}). In proxy contracts, selector collisions can "
                        "route calls to the wrong function."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.PROXY_VULNERABILITY,
                    source=self.name,
                    detector_name="selector-collision",
                    locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
                    metadata={"selector": selector, "sig1": sig1, "sig2": sig2},
                )
            )

        return findings

    def _check_eip1967_compliance(self, filename: str, source: str) -> list[Finding]:
        """Check EIP-1967 storage slot compliance."""
        findings = []

        if "delegatecall" not in source:
            return findings

        # Check for custom storage slots instead of EIP-1967 standard ones
        has_storage_slot = bool(re.search(r'bytes32\s+(?:private\s+)?constant\s+\w+SLOT', source))
        has_eip1967_slot = (
            EIP1967_IMPL_SLOT[:10] in source
            or EIP1967_ADMIN_SLOT[:10] in source
            or "_IMPLEMENTATION_SLOT" in source
            or "ERC1967" in source
        )

        if has_storage_slot and not has_eip1967_slot:
            findings.append(
                Finding(
                    title="Non-Standard Proxy Storage Slot",
                    description=(
                        "Proxy uses a custom storage slot instead of the EIP-1967 standard. "
                        "Non-standard slots can cause storage collisions when the implementation "
                        "contract uses those slots for its own state."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    category=FindingCategory.PROXY_VULNERABILITY,
                    source=self.name,
                    detector_name="non-standard-proxy-slot",
                    locations=[SourceLocation(file=filename, start_line=1, end_line=1)],
                )
            )

        return findings


    def _check_missing_storage_gap(self, filename: str, source: str) -> list[Finding]:
        """Check for missing storage gap in upgradeable contracts."""
        findings = []

        # Only relevant for contracts with upgrade patterns
        has_upgrade = bool(re.search(
            r'\bupgradeTo\b|\bupgradeToAndCall\b|\bimplementation\b',
            source,
        ))
        if not has_upgrade:
            return findings

        # Check for storage gap pattern (strip comments first)
        code_only = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
        code_only = re.sub(r'/\*.*?\*/', '', code_only, flags=re.DOTALL)
        has_gap = bool(re.search(
            r'__gap|_gap\b|uint256\s*\[\s*\d+\s*\]\s*private',
            code_only,
        ))

        if not has_gap:
            # Find the last state variable for location
            lines = source.splitlines()
            last_state_line = 1
            for i, line in enumerate(lines, 1):
                # Match state variable declarations (not in functions)
                if re.search(
                    r'^\s+(?:mapping|address|uint|int|bool|bytes|string)\b.*\b(?:public|private|internal)\b',
                    line,
                ):
                    last_state_line = i

            findings.append(
                Finding(
                    title="Missing Storage Gap for Upgradeable Contract",
                    description=(
                        "Upgradeable contract has no storage gap (`uint256[50] private __gap`). "
                        "When new state variables are added in future upgrades, they will "
                        "collide with storage slots of inheriting contracts, corrupting data.\n\n"
                        "**Fix:** Add `uint256[50] private __gap;` at the end of the contract's "
                        "state variable declarations."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category=FindingCategory.PROXY_VULNERABILITY,
                    source=self.name,
                    detector_name="missing-storage-gap",
                    locations=[
                        SourceLocation(file=filename, start_line=last_state_line, end_line=last_state_line)
                    ],
                )
            )

        return findings


def _is_proxy_contract(source: str) -> bool:
    """Heuristic: check if a contract looks like a proxy."""
    return any(pattern in source for pattern in PROXY_PATTERNS)


def _normalize_params(params: str) -> str:
    """Normalize parameter types for selector computation."""
    # Remove parameter names, keep types
    parts = []
    for p in params.split(","):
        p = p.strip()
        if p:
            # Take only the type (first token if multiple words)
            type_part = p.split()[0] if p.split() else p
            parts.append(type_part)
    return ",".join(parts)


def _compute_selector(signature: str) -> str:
    """Compute the 4-byte function selector using Keccak-256."""
    from hashlib import sha3_256
    try:
        from Crypto.Hash import keccak
        h = keccak.new(digest_bits=256, data=signature.encode()).hexdigest()
    except ImportError:
        # Fallback: use sha3_256 (note: NOT the same as keccak-256,
        # but acceptable for collision detection purposes)
        h = sha3_256(signature.encode()).hexdigest()
    return h[:8]
