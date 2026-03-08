"""Unit tests for the risk scoring engine."""

from contract_audit.core.models import Confidence, Finding, FindingCategory, Severity
from contract_audit.scoring.engine import RiskScoringEngine


def make_finding(
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    category: FindingCategory = FindingCategory.OTHER,
    source: str = "test",
) -> Finding:
    return Finding(
        title="Test Finding",
        description="Test description",
        severity=severity,
        confidence=confidence,
        category=category,
        source=source,
        detector_name="test-detector",
    )


class TestRiskScoringEngine:
    def setup_method(self):
        self.engine = RiskScoringEngine()

    def test_critical_high_confidence_highest_score(self):
        f = make_finding(Severity.CRITICAL, Confidence.HIGH, FindingCategory.ORACLE_MANIPULATION)
        findings = self.engine.score_findings([f])
        # Critical * 1.0 * 1.5 = 15.0
        assert findings[0].risk_score == 15.0

    def test_low_confidence_reduces_score(self):
        high_conf = make_finding(Severity.HIGH, Confidence.HIGH)
        low_conf = make_finding(Severity.HIGH, Confidence.LOW)
        self.engine.score_findings([high_conf, low_conf])
        assert high_conf.risk_score > low_conf.risk_score

    def test_category_multiplier_applied(self):
        oracle_finding = make_finding(
            Severity.HIGH, Confidence.HIGH, FindingCategory.ORACLE_MANIPULATION
        )
        other_finding = make_finding(
            Severity.HIGH, Confidence.HIGH, FindingCategory.OTHER
        )
        self.engine.score_findings([oracle_finding, other_finding])
        # Oracle multiplier (1.5) > Other (0.8)
        assert oracle_finding.risk_score > other_finding.risk_score

    def test_multi_tool_bonus(self):
        f1 = make_finding(Severity.MEDIUM, Confidence.HIGH, source="slither")
        f2 = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.OTHER,
            source="aderyn",
            detector_name="test-detector",
            fingerprint=f1.fingerprint,  # Same fingerprint = same finding from 2 tools
        )
        results = self.engine.score_findings([f1, f2])
        # Medium * 1.0 (High conf) * 0.8 (OTHER) + 0.5 (multi-tool) = 4.5
        assert results[0].risk_score >= 4.0

    def test_sorted_by_score_descending(self):
        findings = [
            make_finding(Severity.LOW),
            make_finding(Severity.CRITICAL),
            make_finding(Severity.MEDIUM),
        ]
        results = self.engine.score_findings(findings)
        scores = [f.risk_score for f in results]
        assert scores == sorted(scores, reverse=True)

    def test_aggregate_score_zero_for_no_findings(self):
        assert self.engine.aggregate_score([]) == 0.0

    def test_aggregate_score_single_critical(self):
        f = make_finding(Severity.CRITICAL, Confidence.HIGH, FindingCategory.REENTRANCY)
        self.engine.score_findings([f])
        score = self.engine.aggregate_score([f])
        assert score > 0
        assert score <= 10.0


class TestFalsePositiveReducer:
    def test_annotation_suppression(self):
        from pathlib import Path

        from contract_audit.core.models import AuditContext, SourceLocation
        from contract_audit.scoring.false_positive import FalsePositiveReducer

        reducer = FalsePositiveReducer()

        # Source with @audit-ok annotation
        source = """
// @audit-ok: This is safe because we control the oracle
(, int256 price,,,) = oracle.latestRoundData();
"""
        finding = Finding(
            title="Oracle without staleness check",
            description="Missing staleness check",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.ORACLE_MANIPULATION,
            source="oracle_detector",
            detector_name="chainlink-staleness",
            locations=[SourceLocation(file="Oracle.sol", start_line=3, end_line=3)],
        )

        context = AuditContext(
            project_path=Path("/tmp/test"),
            contract_sources={"Oracle.sol": source},
        )

        findings = reducer.reduce([finding], context)
        assert findings[0].suppressed
        assert "@audit-ok" in findings[0].suppression_reason

    def test_single_low_confidence_suppressed(self):
        from pathlib import Path

        from contract_audit.core.models import AuditContext
        from contract_audit.scoring.false_positive import FalsePositiveReducer

        reducer = FalsePositiveReducer()

        finding = Finding(
            title="Low confidence finding",
            description="Desc",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            category=FindingCategory.OTHER,
            source="test",
            detector_name="test",
        )

        context = AuditContext(
            project_path=Path("/tmp/test"),
            contract_sources={},
        )

        findings = reducer.reduce([finding], context)
        assert findings[0].suppressed
        assert "single low-confidence" in findings[0].suppression_reason.lower()
