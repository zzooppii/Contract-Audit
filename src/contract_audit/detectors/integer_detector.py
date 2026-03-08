"""Integer/arithmetic vulnerability detector.

Detects unsafe downcasting, unchecked overflow in unchecked blocks,
division before multiplication, and potential zero division.
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
from .utils import extract_functions, strip_comments, strip_interfaces

logger = logging.getLogger(__name__)

# Downcast patterns: larger type to smaller type
DOWNCAST_PATTERNS = [
    # uint256 -> smaller uint
    (r'\buint128\s*\(\s*(\w+)', 'uint128', 256),
    (r'\buint96\s*\(\s*(\w+)', 'uint96', 256),
    (r'\buint64\s*\(\s*(\w+)', 'uint64', 256),
    (r'\buint32\s*\(\s*(\w+)', 'uint32', 256),
    (r'\buint16\s*\(\s*(\w+)', 'uint16', 256),
    (r'\buint8\s*\(\s*(\w+)', 'uint8', 256),
    # int256 -> smaller int
    (r'\bint128\s*\(\s*(\w+)', 'int128', 256),
    (r'\bint64\s*\(\s*(\w+)', 'int64', 256),
    (r'\bint32\s*\(\s*(\w+)', 'int32', 256),
]

# SafeCast patterns that indicate proper handling
SAFE_CAST_PATTERNS = [
    r'\bSafeCast\b',
    r'\btoUint128\b',
    r'\btoUint96\b',
    r'\btoUint64\b',
    r'\btoUint32\b',
    r'\btoUint16\b',
    r'\btoUint8\b',
    r'\btoInt128\b',
    r'\btoInt64\b',
]


class IntegerDetector:
    """Detects integer/arithmetic vulnerabilities."""

    name = "integer_detector"
    category = "arithmetic"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            clean = strip_interfaces(clean)
            lines = clean.splitlines()

            findings.extend(self._check_unsafe_downcast(filename, clean, lines))
            findings.extend(self._check_unchecked_overflow(filename, lines))
            findings.extend(self._check_division_before_multiplication(filename, lines))
            findings.extend(self._check_zero_division(filename, clean, lines))

        logger.info(f"Integer detector found {len(findings)} findings")
        return findings

    def _check_unsafe_downcast(
        self, filename: str, source: str, lines: list[str]
    ) -> list[Finding]:
        """Detect downcasting without bounds checking."""
        findings: list[Finding] = []

        # Check if SafeCast is used globally
        uses_safe_cast = any(re.search(pat, source) for pat in SAFE_CAST_PATTERNS)
        if uses_safe_cast:
            return findings

        for i, line in enumerate(lines):
            for pattern, target_type, _from_bits in DOWNCAST_PATTERNS:
                match = re.search(pattern, line)
                if not match:
                    continue

                var_name = match.group(1)

                # Check if there's a bounds check nearby (within 3 lines before)
                has_check = False
                for j in range(max(0, i - 3), i + 1):
                    if re.search(
                        rf'require\s*\(\s*{re.escape(var_name)}\s*(<|<=|==)',
                        lines[j]
                    ) or re.search(
                        rf'if\s*\(\s*{re.escape(var_name)}\s*(>|>=)',
                        lines[j]
                    ) or re.search(
                        rf'assert\s*\(\s*{re.escape(var_name)}\s*(<|<=)',
                        lines[j]
                    ):
                        has_check = True
                        break

                if not has_check:
                    findings.append(
                        Finding(
                            title=f"Unsafe Downcast to {target_type}",
                            description=(
                                f"Value `{var_name}` is cast to `{target_type}` without "
                                "bounds checking. If the value exceeds the target type's "
                                "maximum, it will silently truncate, potentially causing "
                                "incorrect calculations or fund loss.\n\n"
                                "**Fix:** Use OpenZeppelin's `SafeCast` library or add "
                                f"`require({var_name} <= type({target_type}).max)` before casting."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.ARITHMETIC,
                            source=self.name,
                            detector_name="unsafe-downcast",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=i + 1,
                                    end_line=i + 1,
                                )
                            ],
                            metadata={"variable": var_name, "target_type": target_type},
                        )
                    )

        return findings

    def _check_unchecked_overflow(
        self, filename: str, lines: list[str]
    ) -> list[Finding]:
        """Detect arithmetic operations inside unchecked blocks."""
        findings: list[Finding] = []
        in_unchecked = False
        unchecked_depth = 0
        for i, line in enumerate(lines):
            if re.search(r'\bunchecked\s*\{', line):
                in_unchecked = True
                unchecked_depth = 0

            if in_unchecked:
                unchecked_depth += line.count('{') - line.count('}')
                if unchecked_depth <= 0:
                    in_unchecked = False

                # Look for arithmetic operations that could overflow
                if re.search(r'(\+|\*|\*\*)\s*\w+', line) and \
                   not re.search(r'^[\s}]*$', line) and \
                   not re.search(r'\bunchecked\s*\{', line):
                    # Skip simple increment patterns (i++ in loops)
                    if re.search(r'\b\w+\s*\+\+|^\s*\+\+\w+', line):
                        continue
                    # Skip if it's clearly a loop counter
                    if re.search(r'\bi\s*\+=\s*1\b|\bi\s*\+\+', line):
                        continue

                    # Check for user-influenced values (not just constants)
                    has_variable_op = bool(re.search(
                        r'\b\w+\s*[\+\*]\s*\w+',
                        line
                    ))
                    if has_variable_op and not re.search(r'^\s*\d+\s*[\+\*]\s*\d+', line):
                        findings.append(
                            Finding(
                                title="Arithmetic in Unchecked Block",
                                description=(
                                    "Arithmetic operation inside `unchecked` block bypasses "
                                    "Solidity 0.8+ overflow protection. If values can be "
                                    "user-influenced, this may lead to overflow/underflow.\n\n"
                                    "**Fix:** Move user-influenced arithmetic outside "
                                    "`unchecked` blocks, or add explicit bounds checks."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.ARITHMETIC,
                                source=self.name,
                                detector_name="unchecked-overflow",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=i + 1,
                                        end_line=i + 1,
                                    )
                                ],
                            )
                        )
                        break  # One finding per unchecked block

        return findings

    def _check_division_before_multiplication(
        self, filename: str, lines: list[str]
    ) -> list[Finding]:
        """Detect (a / b) * c patterns that lose precision."""
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            # Pattern: (expr / expr) * expr  or  var / var * var
            if re.search(r'\([^)]*\/[^)]*\)\s*\*', line) or \
               re.search(r'\b\w+\s*\/\s*\w+\s*\*\s*\w+', line):

                # Skip if it looks like a comment or string
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue

                # Skip constants-only expressions
                if re.search(r'^\s*\d+\s*/\s*\d+\s*\*\s*\d+', stripped):
                    continue

                findings.append(
                    Finding(
                        title="Division Before Multiplication",
                        description=(
                            "Division is performed before multiplication, causing "
                            "precision loss due to integer truncation. In Solidity, "
                            "`(a / b) * c` may round down significantly.\n\n"
                            "**Fix:** Reorder to multiply before dividing: "
                            "`(a * c) / b`. Use care to avoid intermediate overflow."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.ARITHMETIC,
                        source=self.name,
                        detector_name="division-before-multiplication",
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

    def _check_zero_division(
        self, filename: str, source: str, lines: list[str]
    ) -> list[Finding]:
        """Detect division by variables that could be zero."""
        findings: list[Finding] = []
        functions = extract_functions(source)

        for func in functions:
            body_lines = func['body'].splitlines()

            for idx, line in enumerate(body_lines):
                # Find division operations
                div_match = re.search(r'\/\s*(\w+)', line)
                if not div_match:
                    continue

                divisor = div_match.group(1)

                # Skip constants and known safe values
                if divisor.isdigit() or divisor in ('1e18', '1e27', 'WAD', 'RAY', 'PRECISION'):
                    continue

                # Skip if it's a type (uint256, etc)
                if re.match(r'^(uint|int|bytes)', divisor):
                    continue

                # Check if divisor is validated before use
                has_zero_check = False
                for j in range(max(0, idx - 5), idx):
                    check_line = body_lines[j]
                    if re.search(
                        rf'require\s*\(\s*{re.escape(divisor)}\s*(>|!=)\s*0',
                        check_line
                    ) or re.search(
                        rf'if\s*\(\s*{re.escape(divisor)}\s*(==|<=)\s*0',
                        check_line
                    ) or re.search(
                        rf'assert\s*\(\s*{re.escape(divisor)}\s*>\s*0',
                        check_line
                    ):
                        has_zero_check = True
                        break

                if not has_zero_check:
                    # Check if the divisor is a parameter (more likely to be zero)
                    is_param = bool(re.search(
                        rf'\b(uint\d*|int\d*)\s+{re.escape(divisor)}\b',
                        func['signature']
                    ))

                    if is_param:
                        findings.append(
                            Finding(
                                title=f"Potential Division by Zero: {divisor}",
                                description=(
                                    f"Division by `{divisor}` in `{func['name']}()` without "
                                    "a preceding zero check. If `{divisor}` is zero, the "
                                    "transaction will revert with an opaque panic error.\n\n"
                                    "**Fix:** Add `require({divisor} > 0, \"division by zero\")` "
                                    "before the division."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                category=FindingCategory.ARITHMETIC,
                                source=self.name,
                                detector_name="zero-division",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=func['start'] + idx,
                                        end_line=func['start'] + idx,
                                        function=func['name'],
                                    )
                                ],
                                metadata={"divisor": divisor},
                            )
                        )

        return findings
