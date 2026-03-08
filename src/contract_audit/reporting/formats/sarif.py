"""SARIF 2.1.0 format generator.

SARIF (Static Analysis Results Interchange Format) is a standard for
static analysis tool output, used by GitHub Code Scanning.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ...core.models import AuditResult, Finding, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
    Severity.GAS: "none",
}

SEVERITY_TO_RANK: dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 75.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFORMATIONAL: 10.0,
    Severity.GAS: 5.0,
}


def generate_sarif(result: AuditResult, tool_name: str = "contract-audit") -> dict[str, Any]:
    """Generate SARIF 2.1.0 output from audit result."""
    active_findings = result.active_findings

    # Build unique rules from findings
    rules = _build_rules(active_findings)

    # Build results
    sarif_results = []
    for finding in active_findings:
        sarif_results.extend(_finding_to_sarif(finding))

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": result.metadata.engine_version,
                        "informationUri": "https://github.com/crytic/contract-audit",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.metadata.start_time.isoformat() + "Z",
                        "endTimeUtc": (
                            result.metadata.end_time.isoformat() + "Z"
                            if result.metadata.end_time
                            else datetime.utcnow().isoformat() + "Z"
                        ),
                    }
                ],
            }
        ],
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build SARIF rule definitions from unique detector names."""
    seen: dict[str, dict[str, Any]] = {}

    for finding in findings:
        rule_id = finding.detector_name
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description[:1000]},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                    "rank": SEVERITY_TO_RANK.get(finding.severity, 50.0),
                },
                "help": {
                    "text": finding.description,
                    "markdown": finding.description,
                },
                "properties": {
                    "tags": [finding.category.value, finding.source],
                    "security-severity": str(SEVERITY_TO_RANK.get(finding.severity, 50.0) / 10.0),
                },
            }

    return list(seen.values())


def _finding_to_sarif(finding: Finding) -> list[dict[str, Any]]:
    """Convert a Finding to one or more SARIF results."""
    level = SEVERITY_TO_LEVEL.get(finding.severity, "warning")

    # Build locations
    sarif_locations = []
    for loc in finding.locations:
        sarif_locations.append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": loc.file,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": loc.start_line,
                    "endLine": loc.end_line,
                    **({"startColumn": 1} if loc.start_line == loc.end_line else {}),
                },
            },
            **(
                {
                    "logicalLocations": [
                        {
                            "name": loc.function,
                            "kind": "function",
                        }
                    ]
                }
                if loc.function
                else {}
            ),
        })

    if not sarif_locations:
        sarif_locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "(unknown)", "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                }
            }
        ]

    result: dict[str, Any] = {
        "ruleId": finding.detector_name,
        "level": level,
        "message": {
            "text": f"[{finding.severity.value}] {finding.title}: {finding.description[:500]}"
        },
        "locations": sarif_locations[:10],  # SARIF limit
        "fingerprints": {
            "contract-audit/v1": finding.fingerprint,
        },
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "category": finding.category.value,
            "riskScore": finding.risk_score,
            "source": finding.source,
        },
    }

    if finding.llm_remediation:
        result["fixes"] = [
            {
                "description": {"text": "Recommended fix"},
                "artifactChanges": [],
                "properties": {"remediation": finding.llm_remediation[:2000]},
            }
        ]

    return [result]


def write_sarif(result: AuditResult, output_path: Path) -> None:
    """Write SARIF output to file."""
    sarif_data = generate_sarif(result)
    output_path.write_text(json.dumps(sarif_data, indent=2))
