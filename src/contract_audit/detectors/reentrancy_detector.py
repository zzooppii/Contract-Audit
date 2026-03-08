"""Reentrancy vulnerability detector.

Detects CEI violations, cross-function reentrancy, missing reentrancy guards,
and read-only reentrancy patterns.
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

# Patterns indicating external calls that can trigger reentrancy
EXTERNAL_CALL_PATTERNS = [
    r'\.call\s*\{?\s*value\s*:',       # .call{value: ...}
    r'\.call\s*\(',                      # .call(...)
    r'\.transfer\s*\(',                  # .transfer(...)
    r'\.send\s*\(',                      # .send(...)
    r'\.safeTransfer\s*\(',             # safeTransfer
    r'\.safeTransferFrom\s*\(',         # safeTransferFrom
]

ETH_TRANSFER_PATTERNS = [
    r'\.call\s*\{?\s*value\s*:',
    r'\.transfer\s*\(',
    r'\.send\s*\(',
]

# State variable assignment patterns (after stripping comments)
STATE_UPDATE_PATTERN = re.compile(
    r'\b(\w+)\s*(?:\[.*?\])?\s*(?:=|\+=|-=|\*=|/=)\s*'
)

# Reentrancy guard modifiers
REENTRANCY_GUARD_PATTERNS = [
    r'\bnonReentrant\b',
    r'\bnoReentrant\b',
    r'\breentrancyGuard\b',
    r'\block\b',
    r'\b_locked\b',
    r'\b_notEntered\b',
]


def _strip_comments(source: str) -> str:
    """Remove single-line and multi-line comments."""
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    return source


def _strip_interfaces(source: str) -> str:
    """Remove interface declarations."""
    result = []
    in_interface = False
    depth = 0
    for line in source.splitlines():
        if re.search(r'\binterface\s+\w+', line):
            in_interface = True
            depth = 0
        if in_interface:
            depth += line.count('{') - line.count('}')
            if depth <= 0 and '}' in line:
                in_interface = False
            continue
        result.append(line)
    return '\n'.join(result)


class ReentrancyDetector:
    """Detects reentrancy vulnerabilities in Solidity contracts."""

    name = "reentrancy_detector"
    category = "reentrancy"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Run all reentrancy checks on contract sources."""
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = _strip_comments(source)
            clean = _strip_interfaces(clean)
            functions = self._extract_functions(clean)

            findings.extend(self._check_cei_violation(filename, functions))
            findings.extend(self._check_cross_function_reentrancy(filename, functions))
            findings.extend(self._check_missing_reentrancy_guard(filename, functions))
            findings.extend(self._check_read_only_reentrancy(filename, clean, functions))

        logger.info(f"Reentrancy detector found {len(findings)} findings")
        return findings

    def _check_cei_violation(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect Check-Effects-Interactions pattern violations.

        A CEI violation occurs when state variables are updated AFTER an external call.
        """
        findings: list[Finding] = []

        for func in functions:
            if func['is_view_pure']:
                continue

            body_lines = func['body'].splitlines()
            external_call_line = -1

            for idx, line in enumerate(body_lines):
                # Look for external calls
                if any(re.search(pat, line) for pat in EXTERNAL_CALL_PATTERNS):
                    external_call_line = idx

                # After an external call, check for state updates
                if external_call_line >= 0 and idx > external_call_line:
                    match = STATE_UPDATE_PATTERN.search(line)
                    if match:
                        var_name = match.group(1)
                        # Skip local variable declarations and common local names
                        if re.search(rf'\b(uint|int|bool|address|bytes|string|mapping)\b.*\b{re.escape(var_name)}\b', line):
                            continue
                        if var_name in ('success', 'result', 'ret', 'data', 'amount', 'i', 'j', 'k'):
                            # Check if declared locally in function
                            if re.search(rf'\b(uint|int|bool|address)\d*\s+{re.escape(var_name)}\b', func['body']):
                                continue

                        findings.append(
                            Finding(
                                title=f"CEI Violation in {func['name']}()",
                                description=(
                                    f"State variable `{var_name}` is updated after an external call "
                                    f"in `{func['name']}()`. This violates the Check-Effects-Interactions "
                                    "pattern and may allow reentrancy attacks.\n\n"
                                    "**Fix:** Move all state changes before external calls."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.REENTRANCY,
                                source=self.name,
                                detector_name="cei-violation",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=func['start'] + idx,
                                        end_line=func['start'] + idx,
                                        function=func['name'],
                                    )
                                ],
                                metadata={"variable": var_name},
                            )
                        )
                        break  # One finding per function

        return findings

    def _check_cross_function_reentrancy(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect cross-function reentrancy.

        Occurs when a function makes an external call, then another function
        reads a state variable that's modified after that call.
        """
        findings: list[Finding] = []

        # First, find functions with external calls and their post-call state writes
        post_call_writes: dict[str, set[str]] = {}
        for func in functions:
            if func['is_view_pure']:
                continue
            body_lines = func['body'].splitlines()
            after_call = False
            written_vars: set[str] = set()

            for line in body_lines:
                if any(re.search(pat, line) for pat in EXTERNAL_CALL_PATTERNS):
                    after_call = True
                if after_call:
                    match = STATE_UPDATE_PATTERN.search(line)
                    if match:
                        written_vars.add(match.group(1))

            if written_vars:
                post_call_writes[func['name']] = written_vars

        if not post_call_writes:
            return findings

        # Then find other functions that read those variables
        all_written = set()
        for vars_ in post_call_writes.values():
            all_written.update(vars_)

        for func in functions:
            if func['name'] in post_call_writes:
                continue
            for var in all_written:
                if re.search(rf'\b{re.escape(var)}\b', func['body']):
                    writer_funcs = [
                        fn for fn, vs in post_call_writes.items() if var in vs
                    ]
                    findings.append(
                        Finding(
                            title=f"Cross-function Reentrancy: {var}",
                            description=(
                                f"`{func['name']}()` reads `{var}` which is written after "
                                f"an external call in `{', '.join(writer_funcs)}()`. "
                                "An attacker could re-enter through this function during "
                                "the external call to exploit stale state.\n\n"
                                "**Fix:** Apply `nonReentrant` modifier to both functions "
                                "or update state before external calls."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.REENTRANCY,
                            source=self.name,
                            detector_name="cross-function-reentrancy",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=func['start'],
                                    end_line=func['start'],
                                    function=func['name'],
                                )
                            ],
                            metadata={"variable": var, "writer_functions": writer_funcs},
                        )
                    )
                    break  # One finding per reader function

        return findings

    def _check_missing_reentrancy_guard(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect functions with ETH transfers or external calls missing reentrancy guards."""
        findings: list[Finding] = []

        for func in functions:
            if func['is_view_pure']:
                continue
            if func['visibility'] not in ('external', 'public'):
                continue

            has_eth_transfer = any(
                re.search(pat, func['body']) for pat in ETH_TRANSFER_PATTERNS
            )
            has_external_call = any(
                re.search(pat, func['body']) for pat in EXTERNAL_CALL_PATTERNS
            )

            if not (has_eth_transfer or has_external_call):
                continue

            has_guard = any(
                re.search(pat, func['signature'] + func['body'])
                for pat in REENTRANCY_GUARD_PATTERNS
            )

            if not has_guard:
                findings.append(
                    Finding(
                        title=f"Missing Reentrancy Guard: {func['name']}()",
                        description=(
                            f"`{func['name']}()` performs external calls or ETH transfers "
                            "but lacks a reentrancy guard (e.g., `nonReentrant` modifier).\n\n"
                            "**Fix:** Add OpenZeppelin's `ReentrancyGuard` and apply "
                            "`nonReentrant` modifier."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.REENTRANCY,
                        source=self.name,
                        detector_name="missing-reentrancy-guard",
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

    def _check_read_only_reentrancy(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect read-only reentrancy.

        View functions reading state that can be stale during an external call
        in another function (e.g., price oracles based on pool balances).
        """
        findings: list[Finding] = []

        # Find state vars written after external calls
        post_call_state_vars: set[str] = set()
        for func in functions:
            if func['is_view_pure']:
                continue
            body_lines = func['body'].splitlines()
            after_call = False
            for line in body_lines:
                if any(re.search(pat, line) for pat in EXTERNAL_CALL_PATTERNS):
                    after_call = True
                if after_call:
                    match = STATE_UPDATE_PATTERN.search(line)
                    if match:
                        post_call_state_vars.add(match.group(1))

        if not post_call_state_vars:
            return findings

        # Find view functions that read those state vars
        for func in functions:
            if not func['is_view_pure']:
                continue
            for var in post_call_state_vars:
                if re.search(rf'\b{re.escape(var)}\b', func['body']):
                    findings.append(
                        Finding(
                            title=f"Read-only Reentrancy Risk: {func['name']}()",
                            description=(
                                f"View function `{func['name']}()` reads `{var}` which "
                                "is updated after an external call in another function. "
                                "During reentrancy, this view function may return stale "
                                "values, affecting contracts that depend on it.\n\n"
                                "**Fix:** Ensure state is updated before external calls "
                                "or document this known limitation."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=FindingCategory.REENTRANCY,
                            source=self.name,
                            detector_name="read-only-reentrancy",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=func['start'],
                                    end_line=func['start'],
                                    function=func['name'],
                                )
                            ],
                            metadata={"variable": var},
                        )
                    )
                    break

        return findings

    def _extract_functions(self, source: str) -> list[dict]:
        """Extract function declarations with bodies from cleaned source."""
        functions = []
        lines = source.splitlines()
        in_interface = False
        interface_depth = 0

        i = 0
        while i < len(lines):
            line = lines[i]

            if re.search(r'\binterface\s+\w+', line):
                in_interface = True
                interface_depth = 0

            if in_interface:
                interface_depth += line.count('{') - line.count('}')
                if interface_depth <= 0 and '}' in line:
                    in_interface = False
                i += 1
                continue

            func_match = re.search(r'\bfunction\s+(\w+)\s*\(', line)
            if func_match:
                func_name = func_match.group(1)

                # Collect full signature
                sig_lines = [line]
                j = i + 1
                brace_found = '{' in line
                while j < len(lines) and not brace_found:
                    sig_lines.append(lines[j])
                    if '{' in lines[j]:
                        brace_found = True
                    j += 1

                full_sig = ' '.join(sig_lines)

                visibility = 'internal'
                if 'external' in full_sig:
                    visibility = 'external'
                elif 'public' in full_sig:
                    visibility = 'public'
                elif 'private' in full_sig:
                    visibility = 'private'

                is_view_pure = bool(re.search(r'\b(view|pure)\b', full_sig))

                # Extract body
                depth = 0
                found_open = False
                body_lines = []
                for k in range(i, len(lines)):
                    body_lines.append(lines[k])
                    depth += lines[k].count('{') - lines[k].count('}')
                    if lines[k].count('{') > 0:
                        found_open = True
                    if found_open and depth <= 0:
                        break

                body = '\n'.join(body_lines)

                functions.append({
                    'name': func_name,
                    'start': i + 1,
                    'visibility': visibility,
                    'is_view_pure': is_view_pure,
                    'signature': full_sig,
                    'body': body,
                })

            i += 1

        return functions
