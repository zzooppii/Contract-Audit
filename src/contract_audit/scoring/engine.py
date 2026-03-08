"""Risk scoring engine for findings.

Composite score = severity_weight * confidence_multiplier * category_weight * context_modifier
"""

from __future__ import annotations

import logging

from ..core.models import AuditResult, Confidence, Finding, Severity
from .weights import (
    CATEGORY_MULTIPLIERS,
    CONFIDENCE_MULTIPLIERS,
    MULTI_TOOL_BONUS,
    SEVERITY_WEIGHTS,
    SINGLE_LOW_CONFIDENCE_PENALTY,
)

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Computes composite risk scores for findings."""

    def __init__(self, severity_overrides: dict[str, float] | None = None) -> None:
        self.severity_overrides = severity_overrides or {}

    def score_findings(self, findings: list[Finding]) -> list[Finding]:
        """Score all findings in place, returning scored list sorted by score."""
        # Count how many tools reported each fingerprint
        fingerprint_sources: dict[str, set[str]] = {}
        for f in findings:
            fingerprint_sources.setdefault(f.fingerprint, set()).add(f.source)

        for finding in findings:
            score = self._compute_score(
                finding,
                tool_count=len(fingerprint_sources.get(finding.fingerprint, set())),
            )
            finding.risk_score = round(score, 2)

        # Sort: suppressed last, then by risk score descending
        findings.sort(key=lambda f: (f.suppressed, -f.risk_score))
        logger.debug(f"Scored {len(findings)} findings")
        return findings

    def _compute_score(self, finding: Finding, tool_count: int = 1) -> float:
        """Compute composite risk score for a single finding."""
        # Base severity weight (allow config override)
        sev_key = finding.severity.value.lower()
        severity_weight = self.severity_overrides.get(
            sev_key, SEVERITY_WEIGHTS.get(finding.severity, 1.0)
        )

        # Confidence multiplier
        confidence_mult = CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0.7)

        # Category multiplier
        category_mult = CATEGORY_MULTIPLIERS.get(finding.category, 1.0)

        # Context modifier
        context_mod = 0.0
        if tool_count >= 2:
            context_mod += MULTI_TOOL_BONUS
        elif finding.confidence == Confidence.LOW and tool_count == 1:
            context_mod += SINGLE_LOW_CONFIDENCE_PENALTY

        base_score = severity_weight * confidence_mult * category_mult
        final_score = base_score + context_mod

        return max(0.0, final_score)

    def aggregate_score(self, findings: list[Finding]) -> float:
        """Compute overall audit risk score (0-10)."""
        active = [f for f in findings if not f.suppressed]
        if not active:
            return 0.0

        # Use max score of top findings (not average, to not dilute critical issues)
        scores = sorted([f.risk_score for f in active], reverse=True)

        # Weighted blend: top score + small contribution from others
        top_score = scores[0]
        if len(scores) > 1:
            # Add 10% of the sum of remaining scores, capped at 15.0 total
            rest = sum(scores[1:]) * 0.1
            total = min(top_score + rest, 15.0)
        else:
            total = top_score

        # Normalize to 0-10 scale (15.0 maps to 10.0)
        normalized = min(total / 15.0 * 10.0, 10.0)
        return round(normalized, 2)
