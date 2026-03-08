"""Structured JSON report format."""

from __future__ import annotations

import json
from pathlib import Path

from ...core.models import AuditResult


def generate_json_report(result: AuditResult) -> dict:
    """Generate structured JSON audit report."""
    return {
        "version": "1.0",
        "summary": result.summary.model_dump(),
        "metadata": {
            **result.metadata.model_dump(exclude={"start_time", "end_time"}),
            "start_time": result.metadata.start_time.isoformat(),
            "end_time": result.metadata.end_time.isoformat() if result.metadata.end_time else None,
        },
        "findings": [
            _finding_to_dict(f)
            for f in sorted(result.findings, key=lambda f: (-f.risk_score, f.severity.value))
        ],
        "statistics": {
            "by_severity": {
                sev.value: len(findings)
                for sev, findings in result.findings_by_severity().items()
                if findings
            },
            "by_source": _count_by_source(result),
            "llm_enriched": sum(
                1 for f in result.active_findings if f.llm_explanation
            ),
        },
    }


def _finding_to_dict(f: "Finding") -> dict:
    """Convert a Finding to a JSON-serializable dict."""
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "category": f.category.value,
        "source": f.source,
        "detector": f.detector_name,
        "risk_score": f.risk_score,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
        "locations": [
            {
                "file": loc.file,
                "start_line": loc.start_line,
                "end_line": loc.end_line,
                "function": loc.function,
                "contract": loc.contract,
            }
            for loc in f.locations
        ],
        "llm_explanation": f.llm_explanation,
        "llm_remediation": f.llm_remediation,
        "llm_poc": f.llm_poc,
        "related_findings": f.related_findings,
    }


def _count_by_source(result: AuditResult) -> dict[str, int]:
    """Count findings by analysis source."""
    counts: dict[str, int] = {}
    for f in result.active_findings:
        counts[f.source] = counts.get(f.source, 0) + 1
    return counts


def write_json_report(result: AuditResult, output_path: Path) -> None:
    """Write JSON report to file."""
    data = generate_json_report(result)
    output_path.write_text(json.dumps(data, indent=2))
