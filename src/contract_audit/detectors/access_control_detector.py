"""Missing access control detector.

Detects external/public functions that modify state variables
but have no access control (no require(msg.sender), no onlyOwner, etc.).
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
from .utils import extract_functions

logger = logging.getLogger(__name__)

# Modifiers and patterns that indicate access control is present
ACCESS_CONTROL_PATTERNS = [
    r'\bonlyOwner\b',
    r'\bonlyAdmin\b',
    r'\bonlyRole\b',
    r'\bonlyRelayer\b',
    r'\bonlyGovernance\b',
    r'\bonlyGuardian\b',
    r'\bonlyMinter\b',
    r'\bonlyOperator\b',
    r'\bonlyAuthorized\b',
    r'\bwhenNotPaused\b',
    r'require\s*\(\s*msg\.sender\s*==',
    r'require\s*\(\s*_msgSender\(\)\s*==',
    r'require\s*\(\s*hasRole\s*\(',
    r'if\s*\(\s*msg\.sender\s*!=',
    r'_checkOwner\s*\(',
    r'_checkRole\s*\(',
]

# Function name patterns that indicate state-modifying admin functions
# These are the high-risk ones that MUST have access control
SENSITIVE_SETTER_PATTERNS = [
    r'^set[A-Z]\w*$',       # setFee, setFeeRecipient, setRelayer, etc.
    r'^update[A-Z]\w*$',    # updateConfig, updateOracle, etc.
    r'^change[A-Z]\w*$',    # changeOwner, changeAdmin, etc.
    r'^add[A-Z]\w*$',       # addPool, addSupportedToken, addMinter, etc.
    r'^remove[A-Z]\w*$',    # removePool, removeMinter, etc.
    r'^pause$',
    r'^unpause$',
    r'^setPaused$',
    r'^withdraw\w*$',       # withdrawFees, withdrawTokens, etc.
    r'^emergency\w*$',      # emergencyWithdraw, emergencyDelist, etc.
    r'^upgrade\w*$',        # upgradeAndCall, etc.
    r'^mint$',
    r'^burn$',
]

# Functions that are typically safe without access control
SAFE_FUNCTION_NAMES = {
    'deposit', 'stake', 'swap', 'addLiquidity', 'removeLiquidity',
    'buy', 'sell', 'claim', 'harvest', 'compound',
    'approve', 'transfer', 'transferFrom',
    'propose', 'castVote', 'execute', 'cancel',
    'createListing', 'placeBid', 'settleAuction',
    'flashLoan', 'onFlashLoan',
    'receive', 'fallback',
    'constructor',
    'burn', 'revokeConfirmation', 'confirmTransaction',
}


class AccessControlDetector:
    """Detects functions missing access control."""

    name = "access_control_detector"
    category = "access-control"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        """Detect missing access control vulnerabilities."""
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            findings.extend(self._check_missing_access_control(filename, source))

        logger.info(f"Access control detector found {len(findings)} findings")
        return findings

    def _check_missing_access_control(
        self, filename: str, source: str
    ) -> list[Finding]:
        """Find external/public functions that modify state without access control."""
        findings: list[Finding] = []
        # Skip interface blocks
        functions = extract_functions(source)

        for func in functions:
            name = func['name']
            start = func['start']
            body = func['body']
            visibility = func['visibility']

            # Only check external/public functions
            if visibility not in ('external', 'public'):
                continue

            # Skip view/pure functions
            if func['is_view_pure']:
                continue

            # Skip known safe function names
            if name in SAFE_FUNCTION_NAMES:
                continue

            # Check if function matches a sensitive setter pattern
            is_sensitive = any(
                re.match(pat, name) for pat in SENSITIVE_SETTER_PATTERNS
            )
            if not is_sensitive:
                continue

            # Check if function has any access control
            has_access_control = any(
                re.search(pat, body) for pat in ACCESS_CONTROL_PATTERNS
            )
            if has_access_control:
                continue

            # This is a sensitive function with no access control
            severity = self._assess_severity(name, body)
            findings.append(
                Finding(
                    title=f"Missing Access Control: {name}()",
                    description=(
                        f"`{name}()` is `{visibility}` and modifies contract state, "
                        "but has no access control. Any external address can call this "
                        "function.\n\n"
                        f"**Fix:** Add `onlyOwner` modifier or "
                        f"`require(msg.sender == owner)` check."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.ACCESS_CONTROL,
                    source=self.name,
                    detector_name="missing-access-control",
                    locations=[
                        SourceLocation(
                            file=filename,
                            start_line=start,
                            end_line=start,
                        )
                    ],
                    metadata={"function": name},
                )
            )

        return findings

    def _assess_severity(self, func_name: str, body: str) -> Severity:
        """Determine severity based on what the function does."""
        name_lower = func_name.lower()

        # Critical: functions that can drain funds, change ownership, or grant roles
        if any(kw in name_lower for kw in [
            'withdraw', 'emergency', 'upgrade', 'setowner', 'setadmin',
            'setrelayer', 'setguardian', 'setminter', 'setoperator',
            'addowner', 'removeowner', 'setrequired', 'rescue',
        ]):
            return Severity.CRITICAL

        # High: functions that control fees, recipients, or critical params
        if any(kw in name_lower for kw in [
            'fee', 'recipient', 'reward', 'oracle', 'price', 'pause',
            'mint', 'burn', 'token',
        ]):
            return Severity.HIGH

        # Medium: other setters
        return Severity.MEDIUM

