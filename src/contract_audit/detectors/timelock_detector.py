"""Timelock and vesting vulnerability detector.

Detects common vulnerabilities in timelock and vesting contracts:
- Zero or insufficient delay
- Execute without queue verification
- Unprotected cancel function
- Vesting cliff bypass
- Block.timestamp manipulation risk
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

_COMMENT_RE = re.compile(r'//.*$|/\*[\s\S]*?\*/', re.MULTILINE)

# Access control patterns
ACCESS_CONTROL_PATTERNS = [
    r'\bonlyOwner\b',
    r'\bonlyAdmin\b',
    r'\bonlyRole\b',
    r'\bonlyGovernance\b',
    r'\bonlyGuardian\b',
    r'\bonlyAuthorized\b',
    r'require\s*\(\s*msg\.sender\s*==',
    r'require\s*\(\s*_msgSender\(\)\s*==',
    r'require\s*\(\s*hasRole\s*\(',
    r'if\s*\(\s*msg\.sender\s*!=',
    r'_checkOwner\s*\(',
    r'_checkRole\s*\(',
]


def _strip_comments(source: str) -> str:
    return _COMMENT_RE.sub('', source)


class TimelockDetector:
    """Detects timelock and vesting vulnerabilities."""

    name = "timelock_detector"
    category = "timelock-bypass"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        min_delay = context.config.timelock_min_delay_seconds

        for filename, source in context.contract_sources.items():
            clean = _strip_comments(source)
            if not re.search(r'\b(timelock|delay|queue|vesting|cliff|unlock|schedule)\b', clean, re.IGNORECASE):
                continue
            findings.extend(self._check_zero_delay(filename, clean, min_delay))
            findings.extend(self._check_execute_without_queue(filename, clean))
            findings.extend(self._check_unprotected_cancel(filename, clean))
            findings.extend(self._check_vesting_cliff_bypass(filename, clean))
            findings.extend(self._check_timestamp_unlock(filename, clean))

        logger.info(f"Timelock detector found {len(findings)} findings")
        return findings

    def _check_zero_delay(self, filename: str, source: str, min_delay: int) -> list[Finding]:
        """CRITICAL/HIGH: delay set to zero or below minimum threshold."""
        findings: list[Finding] = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Check for delay = 0 or minDelay = 0 assignments
            if re.search(r'\b(delay|minDelay|timelockDelay)\s*=\s*0\s*;', line):
                findings.append(Finding(
                    title="Zero Timelock Delay",
                    description=(
                        "Timelock delay is set to zero, completely bypassing the time-delay "
                        "protection. Governance actions can be executed immediately without "
                        "giving users time to react. Set a minimum delay of at least 1 hour."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TIMELOCK_BYPASS,
                    source=self.name,
                    detector_name="zero-timelock-delay",
                    locations=[SourceLocation(file=filename, start_line=i, end_line=i)],
                ))

        # Check for setDelay/updateDelay without minimum check
        set_delay_funcs = self._find_functions(lines, r'\bfunction\s+(set\w*[Dd]elay\w*|updateDelay\w*)\s*\(')
        for func_name, line_num in set_delay_funcs:
            body = self._get_function_body(lines, line_num - 1)
            has_min_check = bool(re.search(
                r'require\s*\([^)]*>=\s*\d+'
                r'|require\s*\([^)]*>\s*0'
                r'|require\s*\([^)]*MIN_DELAY',
                body
            ))
            if not has_min_check:
                findings.append(Finding(
                    title=f"No Minimum Delay Check: {func_name}()",
                    description=(
                        f"`{func_name}()` does not enforce a minimum delay value. "
                        f"An authorized caller can set the delay to zero, bypassing "
                        f"the timelock. Add `require(newDelay >= MIN_DELAY)`."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TIMELOCK_BYPASS,
                    source=self.name,
                    detector_name="no-minimum-delay-check",
                    locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
                    metadata={"function": func_name},
                ))

        return findings

    def _check_execute_without_queue(self, filename: str, source: str) -> list[Finding]:
        """CRITICAL: execute() does not verify the transaction was queued."""
        findings: list[Finding] = []
        lines = source.splitlines()

        execute_funcs = self._find_functions(lines, r'\bfunction\s+(execute\w*)\s*\(')
        for func_name, line_num in execute_funcs:
            body = self._get_function_body(lines, line_num - 1)

            # Check for queue verification
            has_queue_check = bool(re.search(
                r'(require\s*\([^)]*queued|require\s*\([^)]*isQueued|require\s*\([^)]*queue\w*\[)'
                r'|(\bqueued\w*\[.*\]\s*)'
                r'|(isOperation\w*\()'
                r'|(_checkQueued\()',
                body, re.IGNORECASE
            ))

            # Check for timestamp verification (block.timestamp >= eta)
            has_timestamp_check = bool(re.search(
                r'require\s*\([^)]*block\.timestamp\s*>=',
                body
            ))

            if not has_queue_check and not has_timestamp_check:
                findings.append(Finding(
                    title=f"Execute Without Queue Verification: {func_name}()",
                    description=(
                        f"`{func_name}()` does not verify that the transaction was previously "
                        "queued. An attacker can directly execute arbitrary transactions, "
                        "bypassing the timelock entirely. Add a check that the transaction "
                        "hash exists in the queue mapping and that the delay has elapsed."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TIMELOCK_BYPASS,
                    source=self.name,
                    detector_name="execute-without-queue",
                    locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
                    metadata={"function": func_name},
                ))

        return findings

    def _check_unprotected_cancel(self, filename: str, source: str) -> list[Finding]:
        """HIGH: cancel() has no access control."""
        findings: list[Finding] = []
        lines = source.splitlines()

        cancel_funcs = self._find_functions(lines, r'\bfunction\s+(cancel\w*)\s*\(')
        for func_name, line_num in cancel_funcs:
            # Get full signature + body
            body = self._get_function_body(lines, line_num - 1)

            has_access_control = any(
                re.search(pat, body) for pat in ACCESS_CONTROL_PATTERNS
            )

            if not has_access_control:
                findings.append(Finding(
                    title=f"Unprotected Cancel: {func_name}()",
                    description=(
                        f"`{func_name}()` has no access control. Anyone can cancel "
                        "queued timelock transactions, enabling denial-of-service on "
                        "governance proposals. Add `onlyOwner` or role-based access control."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TIMELOCK_BYPASS,
                    source=self.name,
                    detector_name="unprotected-cancel",
                    locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
                    metadata={"function": func_name},
                ))

        return findings

    def _check_vesting_cliff_bypass(self, filename: str, source: str) -> list[Finding]:
        """HIGH: withdraw/release does not enforce cliff period."""
        findings: list[Finding] = []
        lines = source.splitlines()

        # Only check contracts mentioning vesting/cliff
        if not re.search(r'\b(vesting|cliff)\b', source, re.IGNORECASE):
            return findings

        withdraw_funcs = self._find_functions(
            lines,
            r'\bfunction\s+(withdraw\w*|release\w*|claim\w*)\s*\('
        )

        for func_name, line_num in withdraw_funcs:
            body = self._get_function_body(lines, line_num - 1)

            has_cliff_check = bool(re.search(
                r'(require\s*\([^)]*cliff)'
                r'|(require\s*\([^)]*block\.timestamp\s*>=?\s*\w*cliff)'
                r'|(\bcliff\b.*require)'
                r'|(if\s*\([^)]*cliff)',
                body, re.IGNORECASE
            ))

            if not has_cliff_check:
                findings.append(Finding(
                    title=f"Vesting Cliff Bypass: {func_name}()",
                    description=(
                        f"`{func_name}()` does not check the cliff period before allowing "
                        "withdrawal. Beneficiaries can withdraw tokens before the cliff ends. "
                        "Add `require(block.timestamp >= startTime + cliff)` check."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.TIMELOCK_BYPASS,
                    source=self.name,
                    detector_name="vesting-cliff-bypass",
                    locations=[SourceLocation(file=filename, start_line=line_num, end_line=line_num)],
                    metadata={"function": func_name},
                ))

        return findings

    def _check_timestamp_unlock(self, filename: str, source: str) -> list[Finding]:
        """LOW: block.timestamp used for unlock logic (miner manipulation)."""
        findings: list[Finding] = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if re.search(r'block\.timestamp\s*[<>=]+\s*\w*(unlock|release|end)\w*', line, re.IGNORECASE):
                findings.append(Finding(
                    title="Timestamp-Dependent Unlock",
                    description=(
                        "Unlock logic depends on `block.timestamp`, which can be slightly "
                        "manipulated by miners/validators (up to ~15 seconds). For high-value "
                        "time-sensitive operations, consider using block numbers or adding "
                        "a buffer period."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    category=FindingCategory.TIMELOCK_BYPASS,
                    source=self.name,
                    detector_name="timestamp-unlock",
                    locations=[SourceLocation(file=filename, start_line=i, end_line=i)],
                ))

        return findings

    def _find_functions(self, lines: list[str], pattern: str) -> list[tuple[str, int]]:
        results = []
        for i, line in enumerate(lines):
            m = re.search(pattern, line)
            if m:
                results.append((m.group(1), i + 1))
        return results

    def _get_function_body(self, lines: list[str], start_idx: int) -> str:
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
