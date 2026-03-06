"""Audit submission and retrieval API routes."""

from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel

from ...auth.middleware import require_google_auth
from ...core.config import load_config
from ...core.models import AuditContext, AuditResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["audit"])

# In-memory audit store (production would use a database)
_audit_store: dict[str, dict[str, Any]] = {}


class AuditRequest(BaseModel):
    """Request body for starting an audit."""

    project_path: str
    config_path: str | None = None
    enable_llm: bool = True
    formats: list[str] = ["sarif", "json", "markdown"]


class AuditStatus(BaseModel):
    """Current audit status."""

    audit_id: str
    status: str  # "pending", "running", "completed", "failed"
    progress: str | None = None
    error: str | None = None


@router.post("", response_model=AuditStatus)
async def start_audit(
    request_body: AuditRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: dict = Depends(require_google_auth),
) -> AuditStatus:
    """Start a new audit in the background."""
    audit_id = str(uuid.uuid4())

    _audit_store[audit_id] = {
        "id": audit_id,
        "status": "pending",
        "user": user,
        "request": request_body.model_dump(),
        "result": None,
        "error": None,
    }

    background_tasks.add_task(_run_audit, audit_id, request_body, request.app.state)

    return AuditStatus(audit_id=audit_id, status="pending")


@router.get("/{audit_id}", response_model=AuditStatus)
async def get_audit_status(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> AuditStatus:
    """Get the status of an audit."""
    audit = _audit_store.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    return AuditStatus(
        audit_id=audit_id,
        status=audit["status"],
        progress=audit.get("progress"),
        error=audit.get("error"),
    )


@router.get("/{audit_id}/result")
async def get_audit_result(
    audit_id: str,
    user: dict = Depends(require_google_auth),
) -> dict:
    """Get the full result of a completed audit."""
    audit = _audit_store.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    if audit["status"] != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"Audit is {audit['status']}, not completed",
        )

    result = audit.get("result")
    if not result:
        raise HTTPException(status_code=500, detail="No result available")

    return result


async def _run_audit(
    audit_id: str, request_body: AuditRequest, app_state: Any
) -> None:
    """Background task to run the audit."""
    try:
        _audit_store[audit_id]["status"] = "running"
        _audit_store[audit_id]["progress"] = "Initializing..."

        project_path = Path(request_body.project_path)
        if not project_path.exists():
            raise ValueError(f"Project path not found: {project_path}")

        config_path = Path(request_body.config_path) if request_body.config_path else None
        full_config = load_config(config_path)

        if not request_body.enable_llm:
            full_config.audit.llm_enabled = False

        full_config.audit.report_formats = request_body.formats

        _audit_store[audit_id]["progress"] = "Building pipeline..."

        # Import pipeline builder from CLI
        from ...cli.main import _build_pipeline
        pipeline = _build_pipeline(full_config.audit, full_config.llm)

        context = AuditContext(
            project_path=project_path,
            config=full_config.audit,
        )

        _audit_store[audit_id]["progress"] = "Running analysis..."

        result = await pipeline.run(context)

        # Store serializable result
        from ...reporting.formats.json_report import generate_json_report
        _audit_store[audit_id]["result"] = generate_json_report(result)
        _audit_store[audit_id]["status"] = "completed"
        _audit_store[audit_id]["progress"] = "Done"

        logger.info(f"Audit {audit_id} completed successfully")

    except Exception as e:
        logger.error(f"Audit {audit_id} failed: {e}")
        _audit_store[audit_id]["status"] = "failed"
        _audit_store[audit_id]["error"] = str(e)
