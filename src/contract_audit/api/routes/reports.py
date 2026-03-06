"""Report retrieval and download routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from ...auth.middleware import require_google_auth
from .audit import _audit_store

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{audit_id}/sarif")
async def get_sarif_report(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> Response:
    """Download SARIF report for a completed audit."""
    audit = _audit_store.get(audit_id)
    if not audit or audit["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not found")

    result_data = audit.get("result", {})

    # Generate SARIF from stored result (simplified - would need full AuditResult)
    import json
    sarif_content = json.dumps({"version": "2.1.0", "runs": []})

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
    audit = _audit_store.get(audit_id)
    if not audit or audit["status"] != "completed":
        raise HTTPException(status_code=404, detail="Report not found")

    # Simplified - return JSON as markdown in production
    return Response(
        content="# Audit Report\n\nSee JSON endpoint for full results.",
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.md"},
    )
