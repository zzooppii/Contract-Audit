"""Unit tests for reporting modules."""

import json
import pytest
from pathlib import Path

from contract_audit.core.models import (
    AuditMetadata,
    AuditResult,
    AuditSummary,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)


def _make_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.HIGH,
    fingerprint: str = "",
) -> Finding:
    return Finding(
        title=title,
        description="Test description",
        severity=severity,
        confidence=Confidence.HIGH,
        category=FindingCategory.REENTRANCY,
        source="test",
        detector_name="test-detector",
        fingerprint=fingerprint or "",
        locations=[
            SourceLocation(file="Test.sol", start_line=10, end_line=20)
        ],
    )


def _make_result(findings: list[Finding] | None = None) -> AuditResult:
    if findings is None:
        findings = [_make_finding()]
    summary = AuditSummary.from_findings(findings)
    return AuditResult(
        findings=findings,
        summary=summary,
        metadata=AuditMetadata(),
    )


class TestPDFReport:
    def test_write_pdf_without_weasyprint(self, tmp_path):
        from contract_audit.reporting.formats.pdf import write_pdf

        result = _make_result()
        pdf_path = tmp_path / "test.pdf"

        write_pdf(result, pdf_path)

        # Without weasyprint, HTML fallback should be created
        html_fallback = pdf_path.with_suffix(".html")
        assert html_fallback.exists() or pdf_path.exists()


class TestAuditComparator:
    def test_compare_with_no_previous(self, tmp_path):
        from contract_audit.reporting.comparator import AuditComparator

        result = _make_result()
        nonexistent = tmp_path / "nonexistent.json"

        comparator = AuditComparator()
        delta = comparator.compare(result, nonexistent)

        assert delta.total_new == 1
        assert delta.total_resolved == 0
        assert delta.total_persistent == 0

    def test_compare_identifies_new_findings(self, tmp_path):
        from contract_audit.reporting.comparator import AuditComparator

        f1 = _make_finding("Old Finding", fingerprint="old123")
        f2 = _make_finding("New Finding", fingerprint="new456")

        # Save "previous" with just f1
        prev_json = tmp_path / "previous.json"
        prev_data = {
            "findings": [f1.model_dump(mode="json")],
        }
        prev_json.write_text(json.dumps(prev_data, default=str))

        # Current has both f1 and f2
        result = _make_result([f1, f2])

        comparator = AuditComparator()
        delta = comparator.compare(result, prev_json)

        assert delta.total_new == 1
        assert delta.total_persistent == 1
        assert delta.new_findings[0].fingerprint == "new456"

    def test_compare_identifies_resolved_findings(self, tmp_path):
        from contract_audit.reporting.comparator import AuditComparator

        f1 = _make_finding("Was Fixed", fingerprint="fixed123")
        f2 = _make_finding("Still There", fingerprint="persist456")

        # Previous had both
        prev_json = tmp_path / "previous.json"
        prev_data = {
            "findings": [
                f1.model_dump(mode="json"),
                f2.model_dump(mode="json"),
            ],
        }
        prev_json.write_text(json.dumps(prev_data, default=str))

        # Current only has f2
        result = _make_result([f2])

        comparator = AuditComparator()
        delta = comparator.compare(result, prev_json)

        assert delta.total_resolved == 1
        assert delta.total_persistent == 1
        assert delta.resolved_findings[0].fingerprint == "fixed123"

    def test_summary_text(self):
        from contract_audit.reporting.comparator import DeltaReport

        delta = DeltaReport(
            new_findings=[_make_finding("New Bug")],
            resolved_findings=[_make_finding("Old Bug")],
            persistent_findings=[],
            score_delta=-2.5,
        )

        text = delta.summary_text()
        assert "New findings:** 1" in text
        assert "Resolved findings:** 1" in text
        assert "-2.50" in text


class TestReportGenerator:
    def test_generate_all_formats(self, tmp_path):
        from contract_audit.core.models import AuditConfig
        from contract_audit.reporting.generator import ReportGenerator

        config = AuditConfig(
            report_formats=["sarif", "json", "markdown", "html"],
            output_dir=tmp_path,
        )

        result = _make_result()
        generator = ReportGenerator(config)
        paths = generator.generate_all(result)

        assert "sarif" in paths
        assert "json" in paths
        assert "markdown" in paths
        assert "html" in paths

        for p in paths.values():
            assert p.exists()

    def test_pdf_format_in_generate_all(self, tmp_path):
        from contract_audit.core.models import AuditConfig
        from contract_audit.reporting.generator import ReportGenerator

        config = AuditConfig(
            report_formats=["pdf"],
            output_dir=tmp_path,
        )

        result = _make_result()
        generator = ReportGenerator(config)
        paths = generator.generate_all(result)

        assert "pdf" in paths
