"""LLM-based direct audit task.

Uses LLM to analyze contract source code for business logic vulnerabilities
that regex-based detectors cannot catch: economic incentive flaws, state
machine correctness, edge cases, and access control model issues.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from ...core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

if TYPE_CHECKING:
    from ..router import LLMRouter

logger = logging.getLogger(__name__)

AUDIT_SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in \
business logic vulnerabilities, economic attack vectors, and protocol-level flaws.

Analyze the provided Solidity contract for vulnerabilities that automated tools \
typically miss:

1. **Economic Incentives**: Flash loan attacks, MEV exploitation, price manipulation, \
   incentive misalignment
2. **Access Control Model**: Role hierarchy gaps, privilege escalation paths, \
   missing checks on state transitions
3. **State Machine Correctness**: Invalid state transitions, race conditions, \
   missing invariant enforcement
4. **Edge Cases**: Zero-amount operations, self-transfers, boundary conditions, \
   empty arrays/mappings

Respond ONLY with valid JSON in this exact format:
{
  "findings": [
    {
      "title": "Short descriptive title",
      "description": "Detailed description of the vulnerability and attack scenario",
      "severity": "Critical|High|Medium|Low|Informational",
      "category": "reentrancy|access-control|oracle-manipulation|flash-loan|arithmetic|front-running|other",
      "start_line": 42,
      "end_line": 50,
      "function_name": "vulnerableFunction"
    }
  ]
}

If no vulnerabilities found, respond with: {"findings": []}
Be precise and avoid false positives. Only report real vulnerabilities."""

# Map LLM category strings to FindingCategory
_CATEGORY_MAP: dict[str, FindingCategory] = {
    "reentrancy": FindingCategory.REENTRANCY,
    "access-control": FindingCategory.ACCESS_CONTROL,
    "oracle-manipulation": FindingCategory.ORACLE_MANIPULATION,
    "flash-loan": FindingCategory.FLASH_LOAN,
    "arithmetic": FindingCategory.ARITHMETIC,
    "front-running": FindingCategory.FRONT_RUNNING,
    "initialization": FindingCategory.INITIALIZATION,
    "governance": FindingCategory.GOVERNANCE_ATTACK,
    "other": FindingCategory.OTHER,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}


class LLMFinding(BaseModel):
    """Structured finding from LLM analysis."""
    title: str
    description: str
    severity: str
    category: str
    start_line: int = 1
    end_line: int = 1
    function_name: str | None = None


class LLMAuditResult(BaseModel):
    """Result of LLM audit analysis."""
    findings: list[LLMFinding] = []


class AuditTask:
    """Uses LLM to directly audit contract source for business logic vulnerabilities."""

    def __init__(self, router: "LLMRouter") -> None:
        self.router = router

    async def run(self, source: str, filename: str) -> list[Finding]:
        """Analyze contract source and return findings.

        Args:
            source: Solidity source code
            filename: Source file name

        Returns:
            List of Finding objects from LLM analysis
        """
        prompt = f"""Analyze this Solidity contract for security vulnerabilities:

File: {filename}

```solidity
{source}
```

Focus on business logic flaws, economic attacks, and protocol-level issues \
that automated regex detectors would miss."""

        try:
            response = await self.router.execute_task(
                task_type="audit",
                messages=[
                    {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
            )

            return self._parse_response(response.content, filename)

        except Exception as e:
            logger.warning(f"LLM audit failed for {filename}: {e}")
            return []

    def _parse_response(self, content: str, filename: str) -> list[Finding]:
        """Parse LLM response JSON into Finding objects."""
        findings: list[Finding] = []

        try:
            # Extract JSON from potential markdown code blocks
            json_str = content.strip()
            if "```json" in json_str:
                json_str = json_str.split("```json")[1].split("```")[0].strip()
            elif "```" in json_str:
                json_str = json_str.split("```")[1].split("```")[0].strip()

            data = json.loads(json_str)
            result = LLMAuditResult(**data)

            for llm_finding in result.findings:
                severity = _SEVERITY_MAP.get(
                    llm_finding.severity.lower(), Severity.MEDIUM
                )
                category = _CATEGORY_MAP.get(
                    llm_finding.category.lower(), FindingCategory.OTHER
                )

                findings.append(
                    Finding(
                        title=llm_finding.title,
                        description=llm_finding.description,
                        severity=severity,
                        confidence=Confidence.MEDIUM,  # LLM findings start as medium
                        category=category,
                        source="llm_audit",
                        detector_name="llm-business-logic",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=llm_finding.start_line,
                                end_line=llm_finding.end_line,
                                function=llm_finding.function_name,
                            )
                        ],
                    )
                )

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM audit response: {e}")

        return findings
