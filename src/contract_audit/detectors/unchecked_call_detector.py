"""Unchecked call return value detector.

Detects unchecked low-level calls, unchecked ERC20 transfers,
delegatecall to untrusted targets, and selfdestruct via delegatecall.
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


class UncheckedCallDetector:
    """Detects unchecked call return values and dangerous delegatecall usage."""

    name = "unchecked_call_detector"
    category = "unchecked-return"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = strip_comments(source)
            clean = strip_interfaces(clean)
            lines = clean.splitlines()

            findings.extend(self._check_unchecked_low_level_call(filename, lines))
            findings.extend(self._check_unchecked_transfer(filename, clean, lines))
            findings.extend(self._check_delegatecall_to_untrusted(filename, clean, lines))
            findings.extend(self._check_selfdestruct_delegatecall(filename, clean, lines))

        logger.info(f"Unchecked call detector found {len(findings)} findings")
        return findings

    def _check_unchecked_low_level_call(
        self, filename: str, lines: list[str]
    ) -> list[Finding]:
        """Detect .call()/.delegatecall()/.staticcall() without return value check."""
        findings: list[Finding] = []

        for i, line in enumerate(lines):
            # Match low-level calls
            if not re.search(r'\.(call|delegatecall|staticcall)\s*[\({]', line):
                continue

            # Check if return value is captured
            # Good: (bool success, ) = addr.call(...)
            # Bad: addr.call(...)  (no assignment)
            if re.search(r'\(\s*bool\s+\w+', line):
                # Return is captured - check if it's actually checked
                # Look for require/if on next few lines
                checked = False
                for j in range(i, min(i + 3, len(lines))):
                    if re.search(r'require\s*\(\s*\w+', lines[j]) or \
                       re.search(r'if\s*\(\s*!\s*\w+', lines[j]) or \
                       re.search(r'if\s*\(\s*\w+\s*\)', lines[j]):
                        checked = True
                        break
                if checked:
                    continue

            # No return capture at all
            if not re.search(r'=\s*\S+\.(call|delegatecall|staticcall)', line) and \
               not re.search(r'\(\s*bool', line):
                call_type = re.search(r'\.(call|delegatecall|staticcall)', line)
                findings.append(
                    Finding(
                        title=(
                            "Unchecked Low-level "
                            f"{call_type.group(1) if call_type else 'call'}()"
                        ),
                        description=(
                            "Low-level "
                            f"`{call_type.group(1) if call_type else 'call'}"
                            "()` return value is not checked. "
                            "If the call fails silently, the contract will continue execution "
                            "with incorrect assumptions.\n\n"
                            "**Fix:** Capture and check the return value: "
                            "`(bool success, ) = target.call(...); require(success);`"
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.UNCHECKED_RETURN,
                        source=self.name,
                        detector_name="unchecked-low-level-call",
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

    def _check_unchecked_transfer(
        self, filename: str, source: str, lines: list[str]
    ) -> list[Finding]:
        """Detect ERC20 transfer/transferFrom without SafeERC20."""
        findings: list[Finding] = []

        # Check if SafeERC20 is used
        uses_safe_erc20 = bool(re.search(r'\bSafeERC20\b|using\s+SafeERC20', source))
        if uses_safe_erc20:
            return findings

        for i, line in enumerate(lines):
            # Look for .transfer() or .transferFrom() that look like ERC20 calls
            match = re.search(r'(\w+)\.(transfer|transferFrom)\s*\(', line)
            if not match:
                continue

            target = match.group(1)
            method = match.group(2)

            # Skip if it's ETH transfer (payable)
            if re.search(r'payable\s*\(\s*' + re.escape(target), source):
                continue

            # Skip if return value is checked
            if re.search(r'require\s*\(\s*' + re.escape(target) + r'\.' + method, line):
                continue
            if re.search(r'bool\s+\w+\s*=\s*' + re.escape(target) + r'\.' + method, line):
                continue

            # Check if target looks like a token (IERC20, token variable)
            is_token = bool(re.search(
                rf'\b(IERC20|ERC20|token|Token)\b.*\b{re.escape(target)}\b|'
                rf'\b{re.escape(target)}\b.*\b(IERC20|ERC20|token|Token)\b',
                source
            ))

            if is_token or method == 'transferFrom':
                findings.append(
                    Finding(
                        title=f"Unchecked ERC20 {method}()",
                        description=(
                            f"`{target}.{method}()` return value is not checked and "
                            "SafeERC20 is not used. Some ERC20 tokens (e.g., USDT) don't "
                            "return a bool, and others may return false on failure.\n\n"
                            "**Fix:** Use OpenZeppelin's `SafeERC20` library with "
                            f"`safeTransfer`/`safeTransferFrom`."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.UNCHECKED_RETURN,
                        source=self.name,
                        detector_name="unchecked-erc20-transfer",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=i + 1,
                                end_line=i + 1,
                            )
                        ],
                        metadata={"token": target, "method": method},
                    )
                )

        return findings

    def _check_delegatecall_to_untrusted(
        self, filename: str, source: str, lines: list[str]
    ) -> list[Finding]:
        """Detect delegatecall to user-supplied or parameter-provided addresses."""
        findings: list[Finding] = []

        functions = extract_functions(source)
        for func in functions:
            if not re.search(r'\.delegatecall\s*\(', func['body']):
                continue

            # Check if delegatecall target comes from a function parameter
            params = re.findall(r'address\s+(\w+)', func['signature'])
            for param in params:
                if re.search(rf'{re.escape(param)}\s*\.\s*delegatecall', func['body']):
                    findings.append(
                        Finding(
                            title=f"Delegatecall to Untrusted Target in {func['name']}()",
                            description=(
                                f"`{func['name']}()` performs `delegatecall` to address `{param}` "
                                "which comes from a function parameter. An attacker can pass "
                                "a malicious contract that modifies storage in the context of "
                                "this contract.\n\n"
                                "**Fix:** Use a whitelist of trusted implementation addresses "
                                "or remove the ability to delegatecall to arbitrary addresses."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.UNCHECKED_RETURN,
                            source=self.name,
                            detector_name="delegatecall-untrusted",
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

    def _check_selfdestruct_delegatecall(
        self, filename: str, source: str, lines: list[str]
    ) -> list[Finding]:
        """Detect contracts with both selfdestruct and delegatecall."""
        findings: list[Finding] = []

        has_selfdestruct = bool(re.search(r'\bselfdestruct\s*\(', source))
        has_delegatecall = bool(re.search(r'\.delegatecall\s*\(', source))

        if has_selfdestruct and has_delegatecall:
            # Find the selfdestruct line
            for i, line in enumerate(lines):
                if re.search(r'\bselfdestruct\s*\(', line):
                    findings.append(
                        Finding(
                            title="Selfdestruct Reachable via Delegatecall",
                            description=(
                                "This contract contains both `selfdestruct` and `delegatecall`. "
                                "If an attacker can control the delegatecall target, they can "
                                "execute selfdestruct in the context of the proxy/caller, "
                                "permanently destroying the contract.\n\n"
                                "**Fix:** Remove `selfdestruct` or ensure delegatecall targets "
                                "are strictly controlled."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.UNCHECKED_RETURN,
                            source=self.name,
                            detector_name="selfdestruct-delegatecall",
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
