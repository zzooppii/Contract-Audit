"""Pragma and compiler version detector.

Detects floating pragma, outdated Solidity versions, and missing SPDX
license identifiers.
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


class PragmaDetector:
    """Detects pragma and compiler version issues."""

    name = "pragma_detector"
    category = "informational"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            lines = source.splitlines()

            findings.extend(self._check_floating_pragma(filename, lines))
            findings.extend(self._check_outdated_version(filename, lines))
            findings.extend(self._check_missing_spdx(filename, lines))

        logger.info(f"Pragma detector found {len(findings)} findings")
        return findings

    def _check_floating_pragma(
        self, filename: str, lines: list[str]
    ) -> list[Finding]:
        """Detect floating pragma versions (^, >=, >)."""
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('*'):
                continue

            pragma_match = re.search(
                r'pragma\s+solidity\s+([^;]+)',
                stripped
            )
            if not pragma_match:
                continue

            version_spec = pragma_match.group(1).strip()

            is_floating = bool(re.search(r'[\^~><]', version_spec))

            if is_floating:
                findings.append(
                    Finding(
                        title=f"Floating Pragma: {version_spec}",
                        description=(
                            f"Contract uses floating pragma `{version_spec}`. "
                            "Contracts should be deployed with a locked compiler "
                            "version to ensure consistent behavior.\n\n"
                            "**Fix:** Lock the pragma to a specific version, e.g., "
                            "`pragma solidity 0.8.20;`"
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.INFORMATIONAL,
                        source=self.name,
                        detector_name="floating-pragma",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=i + 1,
                                end_line=i + 1,
                            )
                        ],
                    )
                )

        return findings

    def _check_outdated_version(
        self, filename: str, lines: list[str]
    ) -> list[Finding]:
        """Detect Solidity versions below 0.8.0 (no overflow protection)."""
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue

            pragma_match = re.search(
                r'pragma\s+solidity\s+[^;]*?(\d+)\.(\d+)\.(\d+)',
                stripped
            )
            if not pragma_match:
                continue

            major = int(pragma_match.group(1))
            minor = int(pragma_match.group(2))

            if major == 0 and minor < 8:
                findings.append(
                    Finding(
                        title=f"Outdated Solidity Version: {major}.{minor}.x",
                        description=(
                            f"Contract uses Solidity {major}.{minor}.x which lacks "
                            "built-in overflow/underflow protection. Arithmetic "
                            "operations can silently wrap around.\n\n"
                            "**Fix:** Upgrade to Solidity 0.8.0+ for automatic "
                            "overflow checks, or use SafeMath library."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.INFORMATIONAL,
                        source=self.name,
                        detector_name="outdated-version",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=i + 1,
                                end_line=i + 1,
                            )
                        ],
                    )
                )

        return findings

    def _check_missing_spdx(
        self, filename: str, lines: list[str]
    ) -> list[Finding]:
        """Detect missing SPDX license identifier."""
        findings: list[Finding] = []

        has_spdx = any(
            'SPDX-License-Identifier' in line
            for line in lines[:10]  # Check first 10 lines
        )

        if not has_spdx:
            findings.append(
                Finding(
                    title="Missing SPDX License Identifier",
                    description=(
                        "Contract does not include an SPDX license identifier. "
                        "While not a security issue, it is best practice and "
                        "required by the Solidity compiler since 0.6.8.\n\n"
                        "**Fix:** Add `// SPDX-License-Identifier: MIT` (or "
                        "appropriate license) at the top of the file."
                    ),
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.INFORMATIONAL,
                    source=self.name,
                    detector_name="missing-spdx",
                    locations=[
                        SourceLocation(
                            file=filename,
                            start_line=1,
                            end_line=1,
                        )
                    ],
                )
            )

        return findings
