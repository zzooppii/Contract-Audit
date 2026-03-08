"""PDF audit report generator.

Uses the HTML template as a base and converts to PDF via weasyprint
(if available) or provides a fallback.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ...core.models import AuditResult

logger = logging.getLogger(__name__)


def generate_pdf(result: AuditResult, output_path: Path) -> bool:
    """Generate PDF audit report.

    Converts the HTML report to PDF using weasyprint.

    Args:
        result: Audit result to report on
        output_path: Path to write PDF

    Returns:
        True if PDF was generated, False if weasyprint not available
    """
    from .html import generate_html

    html_content = generate_html(result)

    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(output_path))
        logger.info(f"PDF report generated: {output_path}")
        return True
    except ImportError:
        logger.warning(
            "weasyprint not installed. Install with: "
            "pip install 'contract-audit[pdf]' or pip install weasyprint"
        )
        # Fallback: save HTML with .pdf extension note
        fallback_path = output_path.with_suffix(".html")
        fallback_path.write_text(html_content)
        logger.info(f"HTML fallback generated (weasyprint unavailable): {fallback_path}")
        return False
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return False


def write_pdf(result: AuditResult, output_path: Path) -> None:
    """Write PDF report to file (wrapper for generator.py interface)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generate_pdf(result, output_path)
