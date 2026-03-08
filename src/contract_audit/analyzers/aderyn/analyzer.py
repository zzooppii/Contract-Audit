"""Aderyn CLI subprocess wrapper."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path

from ...core.exceptions import AnalyzerError
from ...core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)

ADERYN_CMD = "aderyn"

SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Gas": Severity.GAS,
}


class AderynAnalyzer:
    """Runs Aderyn (Rust) static analysis via CLI subprocess."""

    name = "aderyn"

    def is_available(self) -> bool:
        return shutil.which(ADERYN_CMD) is not None

    async def analyze(self, context: AuditContext) -> list[Finding]:
        """Run Aderyn on the project directory."""
        if not self.is_available():
            logger.warning("aderyn not installed, skipping")
            return []

        try:
            return await self._run_aderyn(context)
        except Exception as e:
            logger.error(f"Aderyn analysis failed: {e}")
            raise AnalyzerError(self.name, str(e)) from e

    async def _run_aderyn(self, context: AuditContext) -> list[Finding]:
        """Execute aderyn and parse JSON output."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = Path(tmp.name)

        try:
            cmd = [
                ADERYN_CMD,
                str(context.project_path),
                "--output", str(output_file),
                "--format", "json",
            ]

            # Add exclusions
            for pattern in context.config.exclude_patterns:
                cmd.extend(["--exclude", pattern])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(context.project_path),
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=180
            )

            if proc.returncode not in (0, 1):  # aderyn exits 1 if findings found
                logger.warning(
                    f"aderyn exited {proc.returncode}: {stderr.decode()[:500]}"
                )

            if output_file.exists():
                return self._parse_output(output_file)
            return []

        except TimeoutError:
            logger.error("Aderyn timed out")
            return []
        finally:
            output_file.unlink(missing_ok=True)

    def _parse_output(self, output_file: Path) -> list[Finding]:
        """Parse Aderyn JSON output into unified findings."""
        findings = []
        try:
            data = json.loads(output_file.read_text())
        except Exception as e:
            logger.warning(f"Failed to parse Aderyn output: {e}")
            return []

        # Aderyn JSON schema: {"high": [...], "medium": [...], "low": [...], ...}
        for severity_key, issues in data.items():
            if not isinstance(issues, list):
                continue
            severity = SEVERITY_MAP.get(severity_key.title(), Severity.INFORMATIONAL)

            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                locations = []
                for loc in issue.get("instances", []):
                    file_path = loc.get("contract_path", loc.get("file", ""))
                    line = loc.get("line", 1)
                    locations.append(
                        SourceLocation(
                            file=file_path,
                            start_line=line,
                            end_line=line,
                            function=loc.get("function"),
                        )
                    )

                findings.append(
                    Finding(
                        title=issue.get("title", "Unknown"),
                        description=issue.get("description", ""),
                        severity=severity,
                        confidence=Confidence.HIGH,  # Aderyn has high precision
                        category=_map_category(issue.get("detector", "")),
                        source=self.name,
                        detector_name=issue.get("detector", "aderyn-unknown"),
                        locations=locations,
                        metadata={"aderyn_id": issue.get("id", "")},
                    )
                )

        logger.info(f"Aderyn found {len(findings)} findings")
        return findings


def _map_category(detector: str) -> FindingCategory:
    """Map Aderyn detector name to FindingCategory."""
    detector_lower = detector.lower()
    if "reentran" in detector_lower:
        return FindingCategory.REENTRANCY
    if "access" in detector_lower or "owner" in detector_lower:
        return FindingCategory.ACCESS_CONTROL
    if "oracle" in detector_lower:
        return FindingCategory.ORACLE_MANIPULATION
    if "flash" in detector_lower:
        return FindingCategory.FLASH_LOAN
    if "proxy" in detector_lower or "upgrade" in detector_lower:
        return FindingCategory.PROXY_VULNERABILITY
    if "storage" in detector_lower:
        return FindingCategory.STORAGE_COLLISION
    if "gas" in detector_lower:
        return FindingCategory.GAS_GRIEFING
    if "governance" in detector_lower or "vote" in detector_lower:
        return FindingCategory.GOVERNANCE_ATTACK
    if (
        "overflow" in detector_lower
        or "underflow" in detector_lower
        or "arithmetic" in detector_lower
    ):
        return FindingCategory.ARITHMETIC
    if "unchecked" in detector_lower or "return" in detector_lower:
        return FindingCategory.UNCHECKED_RETURN
    return FindingCategory.OTHER
