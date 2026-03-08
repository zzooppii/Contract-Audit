"""False-positive reduction using three-layer approach:

1. Annotation-based: // @audit-ok: <reason> in source code
2. Cross-tool correlation: demote single low-confidence findings
3. LLM triage (optional): Gemini Flash binary classification
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ..core.models import AuditContext, Confidence, Finding

if TYPE_CHECKING:
    from ..llm.router import LLMRouter

logger = logging.getLogger(__name__)

AUDIT_OK_PATTERN = re.compile(
    r'//\s*@audit-ok\s*(?::\s*(.+))?',
    re.IGNORECASE,
)

# @audit-fp: false positive with reason
AUDIT_FP_PATTERN = re.compile(
    r'//\s*@audit-fp\s*(?::\s*(.+))?',
    re.IGNORECASE,
)


class FalsePositiveReducer:
    """Applies three-layer FP reduction to findings."""

    def __init__(self, llm_router: "LLMRouter | None" = None) -> None:
        self.llm_router = llm_router

    def reduce(
        self,
        findings: list[Finding],
        context: AuditContext,
    ) -> list[Finding]:
        """Apply all FP reduction layers to findings."""
        findings = self._annotation_based(findings, context)
        findings = self._cross_tool_correlation(findings)
        return findings

    async def reduce_with_llm(
        self,
        findings: list[Finding],
        context: AuditContext,
    ) -> list[Finding]:
        """Apply FP reduction including LLM triage."""
        findings = self.reduce(findings, context)
        if self.llm_router:
            findings = await self._llm_triage(findings, context)
        return findings

    def _annotation_based(
        self, findings: list[Finding], context: AuditContext
    ) -> list[Finding]:
        """Suppress findings with @audit-ok annotations in source."""
        # Build a map of suppressed locations from source annotations
        suppressed_locations: dict[tuple[str, int], str] = {}

        for filename, source in context.contract_sources.items():
            lines = source.splitlines()
            for i, line in enumerate(lines, 1):
                match = AUDIT_OK_PATTERN.search(line) or AUDIT_FP_PATTERN.search(line)
                if match:
                    reason = match.group(1) or "Marked as false positive"
                    suppressed_locations[(filename, i)] = reason
                    suppressed_locations[(filename, i + 1)] = reason  # Also next line
                    suppressed_locations[(filename, i - 1)] = reason  # Also prev line

        # Apply suppressions
        for finding in findings:
            if finding.suppressed:
                continue
            for loc in finding.locations:
                key = (loc.file, loc.start_line)
                if key in suppressed_locations:
                    finding.suppressed = True
                    finding.suppression_reason = (
                        f"@audit-ok annotation: {suppressed_locations[key]}"
                    )
                    logger.debug(f"Suppressed finding '{finding.title}' via annotation")
                    break

        return findings

    def _cross_tool_correlation(self, findings: list[Finding]) -> list[Finding]:
        """Demote findings that only one low-confidence tool reports."""
        from collections import defaultdict

        # Group by fingerprint to check multi-tool coverage
        by_fingerprint: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_fingerprint[f.fingerprint].append(f)

        for fp, group in by_fingerprint.items():
            if len(group) == 1:
                f = group[0]
                # Single tool, low confidence -> suppress or demote
                if f.confidence == Confidence.LOW:
                    f.suppressed = True
                    f.suppression_reason = (
                        "Single low-confidence tool report (cross-tool correlation)"
                    )
                    logger.debug(
                        f"Suppressed '{f.title}' - single low-confidence source"
                    )

        return findings

    async def _llm_triage(
        self, findings: list[Finding], context: AuditContext
    ) -> list[Finding]:
        """Use LLM to classify borderline findings as true/false positives."""
        if not self.llm_router:
            return findings

        from ..llm.tasks.triage import TriageTask

        triage = TriageTask(self.llm_router)

        # Only triage medium-confidence findings to save budget
        borderline = [
            f for f in findings
            if not f.suppressed and f.confidence == Confidence.MEDIUM
        ]

        for finding in borderline:
            # Get relevant source snippet
            source_snippet = ""
            for loc in finding.locations[:1]:
                src = context.contract_sources.get(loc.file, "")
                if src:
                    lines = src.splitlines()
                    start = max(0, loc.start_line - 5)
                    end = min(len(lines), loc.end_line + 10)
                    source_snippet = "\n".join(lines[start:end])

            try:
                is_fp = await triage.classify(finding, source_snippet)
                if is_fp:
                    finding.suppressed = True
                    finding.suppression_reason = "LLM triage: classified as false positive"
                    logger.debug(f"LLM suppressed '{finding.title}'")
            except Exception as e:
                logger.warning(f"LLM triage failed for '{finding.title}': {e}")

        return findings
