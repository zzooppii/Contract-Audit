"""Report generation orchestrator."""

from __future__ import annotations

import logging
from pathlib import Path

from ..core.models import AuditConfig, AuditResult
from .formats.sarif import write_sarif
from .formats.json_report import write_json_report
from .formats.markdown import write_markdown
from .formats.html import write_html

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Orchestrates report generation across all configured formats."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config

    def generate_all(self, result: AuditResult) -> dict[str, Path]:
        """Generate all configured report formats.

        Returns:
            Dict mapping format name to output file path
        """
        output_paths: dict[str, Path] = {}
        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in self.config.report_formats:
            fmt = fmt.strip().lower()
            try:
                if fmt == "sarif":
                    path = output_dir / "audit-results.sarif"
                    self.generate_sarif(result, path)
                    output_paths["sarif"] = path
                elif fmt == "json":
                    path = output_dir / "audit-results.json"
                    self.generate_json(result, path)
                    output_paths["json"] = path
                elif fmt in ("markdown", "md"):
                    path = output_dir / "audit-results.md"
                    self.generate_markdown(result, path)
                    output_paths["markdown"] = path
                elif fmt == "html":
                    path = output_dir / "audit-results.html"
                    self.generate_html(result, path)
                    output_paths["html"] = path
                else:
                    logger.warning(f"Unknown report format: {fmt}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {e}")

        return output_paths

    def generate_sarif(self, result: AuditResult, path: Path) -> None:
        """Generate SARIF report."""
        write_sarif(result, path)
        logger.info(f"SARIF report: {path}")

    def generate_json(self, result: AuditResult, path: Path) -> None:
        """Generate JSON report."""
        write_json_report(result, path)
        logger.info(f"JSON report: {path}")

    def generate_markdown(self, result: AuditResult, path: Path) -> None:
        """Generate Markdown report."""
        write_markdown(result, path)
        logger.info(f"Markdown report: {path}")

    def generate_html(self, result: AuditResult, path: Path) -> None:
        """Generate HTML report."""
        write_html(result, path)
        logger.info(f"HTML report: {path}")
