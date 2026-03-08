"""Audit comparison tool.

Compares current audit results with previous results to identify
new, resolved, and persistent findings using fingerprints.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import BaseModel, Field

from ..core.models import AuditResult, Finding

logger = logging.getLogger(__name__)


class DeltaReport(BaseModel):
    """Result of comparing two audit runs."""

    new_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
    persistent_findings: list[Finding] = Field(default_factory=list)
    score_delta: float = 0.0

    @property
    def total_new(self) -> int:
        return len(self.new_findings)

    @property
    def total_resolved(self) -> int:
        return len(self.resolved_findings)

    @property
    def total_persistent(self) -> int:
        return len(self.persistent_findings)

    def summary_text(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "## Audit Comparison",
            "",
            f"- **New findings:** {self.total_new}",
            f"- **Resolved findings:** {self.total_resolved}",
            f"- **Persistent findings:** {self.total_persistent}",
            f"- **Score change:** {self.score_delta:+.2f}",
        ]

        if self.new_findings:
            lines.append("")
            lines.append("### New Findings")
            for f in self.new_findings:
                lines.append(f"- [{f.severity.value}] {f.title}")

        if self.resolved_findings:
            lines.append("")
            lines.append("### Resolved Findings")
            for f in self.resolved_findings:
                lines.append(f"- ~~[{f.severity.value}] {f.title}~~")

        return "\n".join(lines)


class AuditComparator:
    """Compares audit results across runs using fingerprints."""

    def compare(
        self, current: AuditResult, previous_json: Path
    ) -> DeltaReport:
        """Compare current results with previous JSON file.

        Args:
            current: Current audit result
            previous_json: Path to previous audit result JSON

        Returns:
            DeltaReport with new, resolved, and persistent findings
        """
        previous_findings = self._load_previous(previous_json)

        current_fps = {f.fingerprint: f for f in current.active_findings}
        previous_fps = {f.fingerprint: f for f in previous_findings}

        new_findings = [
            f for fp, f in current_fps.items()
            if fp not in previous_fps
        ]
        resolved_findings = [
            f for fp, f in previous_fps.items()
            if fp not in current_fps
        ]
        persistent_findings = [
            f for fp, f in current_fps.items()
            if fp in previous_fps
        ]

        # Calculate score delta
        current_score = current.summary.overall_risk_score
        previous_score = max(
            (f.risk_score for f in previous_findings if not f.suppressed),
            default=0.0,
        )
        score_delta = current_score - previous_score

        return DeltaReport(
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            score_delta=score_delta,
        )

    def _load_previous(self, json_path: Path) -> list[Finding]:
        """Load findings from a previous JSON report."""
        if not json_path.exists():
            logger.warning(f"Previous report not found: {json_path}")
            return []

        try:
            data = json.loads(json_path.read_text())
            findings_data = data.get("findings", [])

            findings = []
            for fd in findings_data:
                try:
                    findings.append(Finding(**fd))
                except Exception as e:
                    logger.debug(f"Skipping malformed finding: {e}")

            return findings

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse previous report: {e}")
            return []
