"""Parse Foundry JSON test output into unified findings."""

from __future__ import annotations

import logging
from typing import Any

from ...core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)


def parse_foundry_results(json_output: dict[str, Any]) -> list[Finding]:
    """Parse forge test --json output into findings."""
    findings = []

    for test_file, test_results in json_output.items():
        if not isinstance(test_results, dict):
            continue

        test_cases = test_results.get("test_results", {})

        for test_name, result in test_cases.items():
            if not isinstance(result, dict):
                continue

            status = result.get("status", "")

            if status == "Failure":
                finding = _failure_to_finding(test_name, result, test_file)
                if finding:
                    findings.append(finding)

    return findings


def _failure_to_finding(
    test_name: str, result: dict[str, Any], test_file: str
) -> Finding | None:
    """Convert a failing Foundry test to a Finding."""
    reason = result.get("reason", "")
    counterexample = result.get("counterexample", None)
    decoded_logs = result.get("decoded_logs", [])

    # Classify the failure type
    category, severity = _classify_failure(test_name, reason)

    description = f"Foundry test failed: `{test_name}`\n\n"

    if reason:
        description += f"**Reason:** {reason}\n\n"

    if counterexample:
        ce = _format_counterexample(counterexample)
        description += f"**Counterexample:**\n```\n{ce}\n```\n\n"

    if decoded_logs:
        description += "**Logs:**\n```\n" + "\n".join(decoded_logs[:10]) + "\n```\n"

    return Finding(
        title=f"Foundry Test Failure: {test_name}",
        description=description,
        severity=severity,
        confidence=Confidence.HIGH,
        category=category,
        source="foundry",
        detector_name="foundry-fuzz",
        locations=[
            SourceLocation(
                file=test_file,
                start_line=1,
                end_line=1,
                function=test_name,
            )
        ],
        metadata={
            "test_name": test_name,
            "reason": reason,
            "counterexample": counterexample,
        },
    )


def _classify_failure(test_name: str, reason: str) -> tuple[FindingCategory, Severity]:
    """Classify a failing test into a category and severity."""
    test_lower = test_name.lower()
    reason_lower = (reason or "").lower()

    if "invariant" in test_lower or "invariant" in reason_lower:
        return FindingCategory.OTHER, Severity.HIGH
    if "fuzz" in test_lower:
        return FindingCategory.OTHER, Severity.MEDIUM
    if "reentr" in test_lower or "reentr" in reason_lower:
        return FindingCategory.REENTRANCY, Severity.CRITICAL
    if "overflow" in test_lower or "underflow" in reason_lower:
        return FindingCategory.ARITHMETIC, Severity.HIGH
    if "oracle" in test_lower or "price" in reason_lower:
        return FindingCategory.ORACLE_MANIPULATION, Severity.HIGH
    if "flash" in test_lower:
        return FindingCategory.FLASH_LOAN, Severity.HIGH

    return FindingCategory.OTHER, Severity.MEDIUM


def _format_counterexample(counterexample: Any) -> str:
    """Format counterexample for display."""
    if isinstance(counterexample, dict):
        return "\n".join(f"{k}: {v}" for k, v in counterexample.items())
    return str(counterexample)
