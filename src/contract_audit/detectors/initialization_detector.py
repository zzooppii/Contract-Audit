"""Initialization vulnerability detector.

Detects missing initializer modifiers, reinitializable proxies,
constructor/initializer conflicts, and missing _disableInitializers().
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


class InitializationDetector:
    """Detects initialization-related vulnerabilities in upgradeable contracts."""

    name = "initialization_detector"
    category = "initialization"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            clean = strip_interfaces(clean)
            functions = extract_functions(clean)

            findings.extend(self._check_missing_initializer_modifier(filename, functions))
            findings.extend(self._check_reinitializable(filename, clean, functions))
            findings.extend(self._check_constructor_initializer_conflict(
                filename, clean, functions
            ))
            findings.extend(self._check_missing_disable_initializers(filename, clean, functions))

        logger.info(f"Initialization detector found {len(findings)} findings")
        return findings

    def _check_missing_initializer_modifier(
        self, filename: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect initialize() functions without initializer modifier."""
        findings: list[Finding] = []

        for func in functions:
            name_lower = func['name'].lower()
            if name_lower not in ('initialize', 'init', '__init'):
                continue

            sig = func['signature']
            has_initializer_mod = bool(re.search(
                r'\binitializer\b|\breinitializer\b', sig
            ))

            if not has_initializer_mod:
                findings.append(
                    Finding(
                        title=f"Missing Initializer Modifier: {func['name']}()",
                        description=(
                            f"`{func['name']}()` lacks the `initializer` modifier from "
                            "OpenZeppelin's Initializable. Anyone can call this function "
                            "to take over the proxy contract.\n\n"
                            "**Fix:** Add the `initializer` modifier: "
                            f"`function {func['name']}(...) external initializer`"
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.INITIALIZATION,
                        source=self.name,
                        detector_name="missing-initializer-modifier",
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

    def _check_reinitializable(
        self, filename: str, source: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect initializers that can be called multiple times."""
        findings: list[Finding] = []

        for func in functions:
            name_lower = func['name'].lower()
            if name_lower not in ('initialize', 'init', '__init'):
                continue

            sig = func['signature']
            # If it has initializer modifier, it's protected
            if re.search(r'\binitializer\b|\breinitializer\b', sig):
                continue

            body = func['body']
            # Check for manual initialization guard
            has_guard = bool(re.search(
                r'\binitialized\b|\b_initialized\b|\bisInitialized\b|'
                r'require\s*\(\s*!\s*initialized',
                body
            ))

            if not has_guard:
                findings.append(
                    Finding(
                        title=f"Reinitializable Contract: {func['name']}()",
                        description=(
                            f"`{func['name']}()` can be called multiple times without "
                            "a version check or initialization guard. An attacker can "
                            "re-initialize the contract to reset critical state.\n\n"
                            "**Fix:** Use OpenZeppelin's `initializer` modifier or add "
                            "a manual guard: `require(!initialized); initialized = true;`"
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.INITIALIZATION,
                        source=self.name,
                        detector_name="reinitializable",
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

    def _check_constructor_initializer_conflict(
        self, filename: str, source: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect contracts with both constructor and initialize()."""
        findings: list[Finding] = []

        has_constructor = bool(re.search(r'\bconstructor\s*\(', source))
        has_initialize = any(
            func['name'].lower() in ('initialize', 'init')
            for func in functions
        )

        if has_constructor and has_initialize:
            # Check if constructor body is non-trivial (not just _disableInitializers)
            constructor_match = re.search(
                r'constructor\s*\([^)]*\)[^{]*\{([^}]*)\}',
                source, re.DOTALL
            )
            if constructor_match:
                constructor_body = constructor_match.group(1).strip()
                # If constructor only calls _disableInitializers, that's correct
                if constructor_body and not re.match(
                    r'^\s*_disableInitializers\s*\(\s*\)\s*;?\s*$',
                    constructor_body
                ):
                    # Find the constructor line
                    for i, line in enumerate(source.splitlines()):
                        if re.search(r'\bconstructor\s*\(', line):
                            findings.append(
                                Finding(
                                    title="Constructor-Initializer Conflict",
                                    description=(
                                        "Contract has both a non-trivial constructor and an "
                                        "`initialize()` function. In an upgradeable proxy "
                                        "pattern, constructor logic runs in the implementation "
                                        "context, not the proxy. State set in the constructor "
                                        "will not be available through the proxy.\n\n"
                                        "**Fix:** Move all setup logic to `initialize()` and "
                                        "only call `_disableInitializers()` in the constructor."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence=Confidence.MEDIUM,
                                    category=FindingCategory.INITIALIZATION,
                                    source=self.name,
                                    detector_name="constructor-initializer-conflict",
                                    locations=[
                                        SourceLocation(
                                            file=filename,
                                            start_line=i + 1,
                                            end_line=i + 1,
                                        )
                                    ],
                                )
                            )
                            break

        return findings

    def _check_missing_disable_initializers(
        self, filename: str, source: str, functions: list[dict[str, Any]]
    ) -> list[Finding]:
        """Detect upgradeable contracts missing _disableInitializers() in constructor."""
        findings: list[Finding] = []

        # Only check contracts that look upgradeable
        is_upgradeable = bool(re.search(
            r'\bUpgradeable\b|\bInitializable\b|\bUUPSUpgradeable\b|\bproxy\b',
            source, re.IGNORECASE
        ))
        if not is_upgradeable:
            return findings

        has_initialize = any(
            func['name'].lower() in ('initialize', 'init')
            for func in functions
        )
        if not has_initialize:
            return findings

        has_constructor = bool(re.search(r'\bconstructor\s*\(', source))

        if has_constructor:
            # Check if constructor calls _disableInitializers
            constructor_match = re.search(
                r'constructor\s*\([^)]*\)[^{]*\{(.*?)\}',
                source, re.DOTALL
            )
            if constructor_match:
                body = constructor_match.group(1)
                if '_disableInitializers' not in body:
                    for i, line in enumerate(source.splitlines()):
                        if re.search(r'\bconstructor\s*\(', line):
                            findings.append(
                                Finding(
                                    title="Missing _disableInitializers() in Constructor",
                                    description=(
                                        "Upgradeable contract has a constructor that does not "
                                        "call `_disableInitializers()`. The implementation "
                                        "contract can be initialized directly, allowing an "
                                        "attacker to take ownership and selfdestruct it.\n\n"
                                        "**Fix:** Add `_disableInitializers()` call in the "
                                        "constructor."
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.MEDIUM,
                                    category=FindingCategory.INITIALIZATION,
                                    source=self.name,
                                    detector_name="missing-disable-initializers",
                                    locations=[
                                        SourceLocation(
                                            file=filename,
                                            start_line=i + 1,
                                            end_line=i + 1,
                                        )
                                    ],
                                )
                            )
                            break
        else:
            # No constructor at all in upgradeable contract
            # Find the contract declaration line
            for i, line in enumerate(source.splitlines()):
                if re.search(r'\bcontract\s+\w+', line):
                    findings.append(
                        Finding(
                            title="Missing _disableInitializers() — No Constructor",
                            description=(
                                "Upgradeable contract has no constructor to call "
                                "`_disableInitializers()`. The implementation contract "
                                "can be initialized directly.\n\n"
                                "**Fix:** Add a constructor that calls "
                                "`_disableInitializers()`."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.INITIALIZATION,
                            source=self.name,
                            detector_name="missing-disable-initializers",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i + 1,
                                    end_line=i + 1,
                                )
                            ],
                        )
                    )
                    break

        return findings
