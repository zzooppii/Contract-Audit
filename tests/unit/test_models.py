"""Unit tests for core data models."""

import time

from contract_audit.core.models import (
    AuditSummary,
    Confidence,
    Finding,
    FindingCategory,
    OAuthToken,
    Severity,
    SourceLocation,
)


class TestFinding:
    def test_auto_id_generated(self):
        f = Finding(
            title="Test",
            description="Test desc",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.REENTRANCY,
            source="test",
            detector_name="test-detector",
        )
        assert f.id
        assert len(f.id) > 0

    def test_fingerprint_generated(self):
        loc = SourceLocation(file="test.sol", start_line=10, end_line=15)
        f = Finding(
            title="Test",
            description="Test desc",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.REENTRANCY,
            source="test",
            detector_name="test-detector",
            locations=[loc],
        )
        assert f.fingerprint
        assert len(f.fingerprint) == 16  # SHA256 hex truncated

    def test_fingerprint_stable(self):
        loc = SourceLocation(file="test.sol", start_line=10, end_line=15)

        f1 = Finding(
            title="Same Finding",
            description="Desc",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.REENTRANCY,
            source="slither",
            detector_name="reentrancy",
            locations=[loc],
        )
        f2 = Finding(
            title="Same Finding",
            description="Different desc",  # Different description
            severity=Severity.MEDIUM,  # Different severity
            confidence=Confidence.LOW,   # Different confidence
            category=FindingCategory.REENTRANCY,
            source="aderyn",  # Different source
            detector_name="reentrancy",
            locations=[loc],
        )

        # Same category + title + locations = same fingerprint
        assert f1.fingerprint == f2.fingerprint

    def test_primary_location(self):
        loc1 = SourceLocation(file="a.sol", start_line=1, end_line=5)
        loc2 = SourceLocation(file="b.sol", start_line=10, end_line=20)
        f = Finding(
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category=FindingCategory.OTHER,
            source="test",
            detector_name="test",
            locations=[loc1, loc2],
        )
        assert f.primary_location() == loc1

    def test_no_location_primary_returns_none(self):
        f = Finding(
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category=FindingCategory.OTHER,
            source="test",
            detector_name="test",
        )
        assert f.primary_location() is None


class TestAuditSummary:
    def test_from_findings(self):
        findings = [
            Finding(
                title=f"Finding {i}",
                description="Desc",
                severity=sev,
                confidence=Confidence.HIGH,
                category=FindingCategory.OTHER,
                source="test",
                detector_name="test",
                risk_score=score,
            )
            for i, (sev, score) in enumerate([
                (Severity.CRITICAL, 15.0),
                (Severity.HIGH, 10.0),
                (Severity.MEDIUM, 5.0),
                (Severity.LOW, 2.5),
            ])
        ]

        summary = AuditSummary.from_findings(findings)
        assert summary.critical_count == 1
        assert summary.high_count == 1
        assert summary.medium_count == 1
        assert summary.low_count == 1
        assert summary.total_findings == 4
        assert summary.suppressed_count == 0
        assert summary.overall_risk_score == 15.0  # Max score

    def test_suppressed_not_counted(self):
        findings = [
            Finding(
                title="Active",
                description="Desc",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=FindingCategory.OTHER,
                source="test",
                detector_name="test",
            ),
            Finding(
                title="Suppressed",
                description="Desc",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=FindingCategory.OTHER,
                source="test",
                detector_name="test",
                suppressed=True,
            ),
        ]

        summary = AuditSummary.from_findings(findings)
        assert summary.total_findings == 1  # Only active
        assert summary.critical_count == 0  # Suppressed critical not counted
        assert summary.suppressed_count == 1


class TestOAuthToken:
    def test_not_expired_when_no_expiry(self):
        token = OAuthToken(access_token="test")
        assert not token.is_expired()

    def test_expired_when_past_expiry(self):
        token = OAuthToken(
            access_token="test",
            expires_at=time.time() - 100,  # 100s in the past
        )
        assert token.is_expired()

    def test_not_expired_when_future(self):
        token = OAuthToken(
            access_token="test",
            expires_at=time.time() + 3600,  # 1 hour in future
        )
        assert not token.is_expired()

    def test_expired_within_buffer(self):
        # Expires in 30s (within 60s buffer)
        token = OAuthToken(
            access_token="test",
            expires_at=time.time() + 30,
        )
        assert token.is_expired()  # Should be considered expired due to 60s buffer
