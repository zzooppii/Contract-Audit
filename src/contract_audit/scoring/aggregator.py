"""Cross-finding aggregation utilities."""

from __future__ import annotations

import logging
from collections import defaultdict

from ..core.models import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


def aggregate_by_contract(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by contract file."""
    result: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for loc in finding.locations:
            result[loc.file].append(finding)
        if not finding.locations:
            result["(unknown)"].append(finding)
    return dict(result)


def aggregate_by_category(findings: list[Finding]) -> dict[FindingCategory, list[Finding]]:
    """Group findings by category."""
    result: dict[FindingCategory, list[Finding]] = defaultdict(list)
    for finding in findings:
        result[finding.category].append(finding)
    return dict(result)


def aggregate_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    """Group findings by severity."""
    result: dict[Severity, list[Finding]] = defaultdict(list)
    for finding in findings:
        result[finding.severity].append(finding)
    return dict(result)


def correlate_cross_tool(findings: list[Finding]) -> list[Finding]:
    """Mark findings that appear in multiple tools as corroborated."""
    # Group by fingerprint
    by_fingerprint: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_fingerprint[f.fingerprint].append(f)

    for fp, group in by_fingerprint.items():
        if len(group) > 1:
            sources = {f.source for f in group}
            for f in group:
                f.metadata["corroborated_by"] = list(sources - {f.source})
                f.metadata["tool_count"] = len(sources)

    return findings


def merge_related_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings from the same detector at the same location."""
    merged: dict[str, Finding] = {}

    for finding in findings:
        key = f"{finding.detector_name}:{finding.fingerprint}"
        if key not in merged:
            merged[key] = finding
        else:
            existing = merged[key]
            # Merge locations
            existing_locs = {(loc.file, loc.start_line) for loc in existing.locations}
            for loc in finding.locations:
                if (loc.file, loc.start_line) not in existing_locs:
                    existing.locations.append(loc)
                    existing_locs.add((loc.file, loc.start_line))

    return list(merged.values())
