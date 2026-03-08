"""Report retrieval and download routes."""

from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from ...auth.middleware import require_google_auth
from ...core.models import AuditResult
from .audit import _audit_store

router = APIRouter(prefix="/reports", tags=["reports"])


def _get_audit_result(audit_id: str) -> AuditResult:
    """Get AuditResult from store or raise 404."""
    audit = _audit_store.get(audit_id)
    if not audit or audit["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not found")

    result_data = audit.get("result")
    if not result_data:
        raise HTTPException(status_code=500, detail="No result available")

    # Reconstruct AuditResult from stored JSON
    try:
        return AuditResult(**result_data)
    except Exception:
        # Fall back to returning raw data if reconstruction fails
        raise HTTPException(status_code=500, detail="Failed to reconstruct result")


@router.get("/{audit_id}/sarif")
async def get_sarif_report(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> Response:
    """Download SARIF report for a completed audit."""
    result = _get_audit_result(audit_id)

    from ...reporting.formats.sarif import generate_sarif
    sarif_content = json.dumps(generate_sarif(result), indent=2)

    return Response(
        content=sarif_content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.sarif"},
    )


@router.get("/{audit_id}/markdown")
async def get_markdown_report(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> Response:
    """Download Markdown report for a completed audit."""
    result = _get_audit_result(audit_id)

    from ...reporting.formats.markdown import generate_markdown
    md_content = generate_markdown(result)

    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.md"},
    )


@router.get("/{audit_id}/pdf")
async def get_pdf_report(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> Response:
    """Download PDF report for a completed audit."""
    result = _get_audit_result(audit_id)

    from ...reporting.formats.pdf import generate_pdf

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    success = generate_pdf(result, tmp_path)

    if success and tmp_path.exists():
        content = tmp_path.read_bytes()
        tmp_path.unlink()
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.pdf"},
        )
    else:
        # Fallback to HTML
        from ...reporting.formats.html import generate_html
        html_content = generate_html(result)
        if tmp_path.exists():
            tmp_path.unlink()
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.html"},
        )


@router.get("/{audit_id}/json")
async def get_json_report(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> Response:
    """Download JSON report for a completed audit."""
    audit = _audit_store.get(audit_id)
    if not audit or audit["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not found")

    result = audit.get("result", {})
    content = json.dumps(result, indent=2, default=str)

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.json"},
    )
