"""Markdown audit report generator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ...core.models import AuditResult, Finding, Severity

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFORMATIONAL: "⚪",
    Severity.GAS: "⛽",
}

SEVERITY_PREFIX: dict[Severity, str] = {
    Severity.CRITICAL: "C",
    Severity.HIGH: "H",
    Severity.MEDIUM: "M",
    Severity.LOW: "L",
    Severity.INFORMATIONAL: "I",
    Severity.GAS: "G",
}


def generate_markdown(result: AuditResult) -> str:
    """Generate a comprehensive Markdown audit report."""
    lines = []
    s = result.summary
    meta = result.metadata

    # Header
    lines.append(f"# Smart Contract Security Audit Report")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| **Date** | {datetime.utcnow().strftime('%Y-%m-%d')} |")
    lines.append(f"| **Engine** | contract-audit v{meta.engine_version} |")
    lines.append(f"| **Risk Score** | {s.overall_risk_score}/10 |")
    lines.append(f"| **Contracts Analyzed** | {meta.contract_count} |")
    lines.append(f"| **Lines Analyzed** | {meta.line_count:,} |")
    if meta.duration_seconds:
        lines.append(f"| **Duration** | {meta.duration_seconds:.1f}s |")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")

    # Check for LLM-generated summary
    exec_summary = None
    for f in result.findings:
        if "executive_summary" in f.metadata:
            exec_summary = f.metadata["executive_summary"]
            break

    if exec_summary:
        lines.append(exec_summary)
    else:
        lines.append(
            f"This audit identified **{s.total_findings} findings** across "
            f"**{meta.contract_count} contracts**: "
            f"{s.critical_count} critical, {s.high_count} high, "
            f"{s.medium_count} medium, {s.low_count} low, "
            f"and {s.informational_count} informational."
        )
    lines.append("")

    # Findings Summary Table
    lines.append("## Findings Overview")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in [
        (Severity.CRITICAL, s.critical_count),
        (Severity.HIGH, s.high_count),
        (Severity.MEDIUM, s.medium_count),
        (Severity.LOW, s.low_count),
        (Severity.INFORMATIONAL, s.informational_count),
        (Severity.GAS, s.gas_count),
    ]:
        if count > 0:
            emoji = SEVERITY_EMOJI[sev]
            lines.append(f"| {emoji} **{sev.value}** | {count} |")

    if s.suppressed_count > 0:
        lines.append(f"| ~~Suppressed (FP)~~ | {s.suppressed_count} |")
    lines.append("")

    # Tool Coverage
    lines.append("## Tool Coverage")
    lines.append("")
    sources: dict[str, int] = {}
    for f in result.active_findings:
        sources[f.source] = sources.get(f.source, 0) + 1
    if sources:
        lines.append("| Tool | Findings |")
        lines.append("|------|----------|")
        for src, count in sorted(sources.items(), key=lambda x: -x[1]):
            lines.append(f"| {src} | {count} |")
    lines.append("")

    # Findings by Severity
    findings_by_sev = result.findings_by_severity()

    counters: dict[Severity, int] = {s: 0 for s in Severity}

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        sev_findings = findings_by_sev.get(severity, [])
        if not sev_findings:
            continue

        lines.append(f"## {SEVERITY_EMOJI[severity]} {severity.value} Findings")
        lines.append("")

        for finding in sev_findings:
            counters[severity] += 1
            prefix = SEVERITY_PREFIX[severity]
            label = f"{prefix}-{counters[severity]:02d}"

            lines.append(f"### [{label}] {finding.title}")
            lines.append("")
            lines.append(
                f"| Field | Value |\n"
                f"|-------|-------|\n"
                f"| **Severity** | {SEVERITY_EMOJI[severity]} {severity.value} |\n"
                f"| **Confidence** | {finding.confidence.value} |\n"
                f"| **Risk Score** | {finding.risk_score} |\n"
                f"| **Category** | {finding.category.value} |\n"
                f"| **Detected by** | {finding.source} (`{finding.detector_name}`) |"
            )
            lines.append("")

            # Locations
            if finding.locations:
                lines.append("**Location(s):**")
                for loc in finding.locations[:5]:
                    fn_info = f" in `{loc.function}`" if loc.function else ""
                    lines.append(f"- `{loc.file}:{loc.start_line}`{fn_info}")
            lines.append("")

            # Source code snippet
            snippet = finding.metadata.get("source_snippet", "")
            if snippet:
                lines.append("**Vulnerable Code:**")
                lines.append("")
                lines.append("```solidity")
                lines.append(snippet)
                lines.append("```")
                lines.append("")

            # Description
            lines.append("**Description:**")
            lines.append("")
            lines.append(finding.description)
            lines.append("")

            # LLM Explanation
            if finding.llm_explanation:
                lines.append("**Analysis:**")
                lines.append("")
                lines.append(finding.llm_explanation)
                lines.append("")

            # Remediation
            if finding.llm_remediation:
                lines.append("**Remediation:**")
                lines.append("")
                lines.append(finding.llm_remediation)
                lines.append("")
            elif finding.description and "Fix:" in finding.description:
                pass  # Already in description

            # PoC
            if finding.llm_poc:
                lines.append("**Proof of Concept:**")
                lines.append("")
                lines.append("```solidity")
                lines.append(finding.llm_poc)
                lines.append("```")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Low / Info / Gas (condensed)
    for severity in [Severity.LOW, Severity.INFORMATIONAL, Severity.GAS]:
        sev_findings = findings_by_sev.get(severity, [])
        if not sev_findings:
            continue

        lines.append(f"## {SEVERITY_EMOJI[severity]} {severity.value} Findings (Summary)")
        lines.append("")
        lines.append("| # | Title | File | Line | Detector |")
        lines.append("|---|-------|------|------|----------|")

        for i, finding in enumerate(sev_findings, 1):
            prefix = SEVERITY_PREFIX[severity]
            label = f"{prefix}-{i:02d}"
            loc = finding.primary_location()
            file_str = f"`{loc.file}`" if loc else "-"
            line_str = str(loc.start_line) if loc else "-"
            lines.append(
                f"| {label} | {finding.title} | {file_str} | {line_str} | "
                f"`{finding.detector_name}` |"
            )

        lines.append("")

    # Appendix: Tool Versions
    if meta.tool_versions:
        lines.append("## Appendix: Tool Versions")
        lines.append("")
        for tool, version in meta.tool_versions.items():
            lines.append(f"- **{tool}**: {version}")
        lines.append("")

    return "\n".join(lines)


def write_markdown(result: AuditResult, output_path: Path) -> None:
    """Write Markdown report to file."""
    content = generate_markdown(result)
    output_path.write_text(content)
