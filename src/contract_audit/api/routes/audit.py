"""Audit submission and retrieval API routes."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel

from ...auth.middleware import require_google_auth
from ...core.config import load_config
from ...core.models import AuditContext

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


@router.get("", response_model=list[AuditStatus])
async def list_audits(
    user: dict[str, Any] = Depends(require_google_auth),
) -> list[AuditStatus]:
    """List all audits."""
    return [
        AuditStatus(
            audit_id=audit["id"],
            status=audit["status"],
            progress=audit.get("progress"),
            error=audit.get("error"),
        )
        for audit in _audit_store.values()
    ]


@router.post("/start", response_model=AuditStatus)
async def start_audit(
    request_body: AuditRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: dict[str, Any] = Depends(require_google_auth),
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
    user: dict[str, Any] = Depends(require_google_auth),
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
    user: dict[str, Any] = Depends(require_google_auth),
) -> dict[str, Any]:
    """Get the full result of a completed audit."""
    audit = _audit_store.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    if audit["status"] != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"Audit is {audit['status']}, not completed",
        )

    result: dict[str, Any] | None = audit.get("result")
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


# ----------------------------------------------------
# LIVE WATCH MODE API & SSE STREAMING
# ----------------------------------------------------
from fastapi.responses import StreamingResponse
from ...watcher.file_watcher import SolidityFileWatcher

_watch_sessions: dict[str, dict[str, Any]] = {}


class WatchRequest(BaseModel):
    """Request body for starting Live Watch mode."""
    project_path: str
    config_path: str | None = None
    enable_llm: bool = True
    formats: list[str] = ["sarif", "json", "markdown"]


@router.post("/watch/start")
async def start_watch_session(
    request_body: WatchRequest,
    request: Request,
    user: dict[str, Any] = Depends(require_google_auth),
) -> dict[str, Any]:
    """Start Live Watch Mode for a project path."""
    project_path = Path(request_body.project_path).resolve()
    if not project_path.exists():
        raise HTTPException(status_code=404, detail=f"Project path not found: {project_path}")

    session_id = str(uuid.uuid4())
    event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    watcher = SolidityFileWatcher(debounce_delay=0.5)

    async def on_files_changed(changed_files: list[Path]) -> None:
        logger.info(f"Live Watcher detected changes in {len(changed_files)} files. Re-running audit...")
        audit_id = str(uuid.uuid4())
        audit_req = AuditRequest(
            project_path=str(project_path),
            config_path=request_body.config_path,
            enable_llm=request_body.enable_llm,
            formats=request_body.formats,
        )
        _audit_store[audit_id] = {
            "id": audit_id,
            "status": "pending",
            "user": user,
            "request": audit_req.model_dump(),
            "result": None,
            "error": None,
        }
        await _run_audit(audit_id, audit_req, request.app.state)
        res_data = _audit_store[audit_id].get("result", {})
        await event_queue.put({
            "type": "live_update",
            "audit_id": audit_id,
            "result": res_data,
            "changed_files": [str(f) for f in changed_files],
        })

    watcher.start(project_path, on_files_changed)

    _watch_sessions[session_id] = {
        "session_id": session_id,
        "project_path": str(project_path),
        "watcher": watcher,
        "event_queue": event_queue,
        "user": user,
    }

    return {
        "session_id": session_id,
        "status": "active",
        "project_path": str(project_path),
    }


@router.post("/watch/stop")
async def stop_watch_session(
    session_id: str,
    user: dict[str, Any] = Depends(require_google_auth),
) -> dict[str, str]:
    """Stop Live Watch Mode for a session."""
    session = _watch_sessions.pop(session_id, None)
    if not session:
        raise HTTPException(status_code=404, detail="Watch session not found")

    watcher: SolidityFileWatcher = session["watcher"]
    watcher.stop()

    return {"status": "stopped", "session_id": session_id}


@router.get("/watch/stream/{session_id}")
async def stream_watch_events(
    session_id: str,
    user: dict[str, Any] = Depends(require_google_auth),
) -> StreamingResponse:
    """Server-Sent Events (SSE) streaming endpoint for live audit updates."""
    session = _watch_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Watch session not found")

    event_queue: asyncio.Queue[dict[str, Any]] = session["event_queue"]

    async def event_generator():
        import json
        # Send initial connected message
        yield f"event: connected\ndata: {json.dumps({'session_id': session_id, 'status': 'connected'})}\n\n"

        while session_id in _watch_sessions:
            try:
                event_data = await asyncio.wait_for(event_queue.get(), timeout=15.0)
                json_str = json.dumps(event_data)
                yield f"event: live_update\ndata: {json_str}\n\n"
            except asyncio.TimeoutError:
                # Send keep-alive ping
                yield ": keep-alive\n\n"
            except Exception as e:
                logger.warning(f"Error in SSE stream event generator: {e}")
                break

    return StreamingResponse(event_generator(), media_type="text/event-stream")
