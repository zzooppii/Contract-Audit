"""FastAPI application for the web dashboard."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..auth.token_store import TokenStore
from .routes import audit, auth, reports

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: setup and teardown."""
    # Initialize shared state
    app.state.token_store = TokenStore()
    logger.info("contract-audit web API started")
    yield
    logger.info("contract-audit web API shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="contract-audit API",
        description="AI-assisted Smart Contract Audit Engine",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS for frontend
    allowed_origins = os.environ.get(
        "ALLOWED_ORIGINS", "http://localhost:3000"
    ).split(",")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Session middleware for OAuth state
    try:
        from starlette.middleware.sessions import SessionMiddleware
        secret_key = os.environ.get("SESSION_SECRET", "change-me-in-production")
        app.add_middleware(SessionMiddleware, secret_key=secret_key)
    except ImportError:
        logger.warning("starlette sessions not available")

    # Register routes
    app.include_router(auth.router)
    app.include_router(audit.router)
    app.include_router(reports.router)

    # Mock login for developer local testing (bypasses Google OAuth)
    @app.get("/auth/dev-login")
    async def dev_login(request: Request) -> RedirectResponse:
        """Inject a dev user into the session for local testing."""
        request.session["user"] = {
            "email": "dev@contractaudit.local",
            "name": "Dev User",
            "picture": "https://lh3.googleusercontent.com/a/default-user=s96-c",
        }
        logger.info("Developer local login session established")
        return RedirectResponse(url="/")

    # Serve index.html at root
    @app.get("/")
    async def dashboard() -> FileResponse:
        """Serve the main dashboard Single Page Application."""
        index_path = STATIC_DIR / "index.html"
        if not index_path.exists():
            # If assets haven't been created yet, return simple placeholder
            from fastapi.responses import HTMLResponse
            return HTMLResponse(
                """
                <!DOCTYPE html>
                <html>
                <head><title>contract-audit Dashboard</title></head>
                <body style="font-family: sans-serif; text-align: center; padding-top: 100px;">
                    <h1>contract-audit Web Dashboard</h1>
                    <p>Static files are mounting, but index.html is missing.</p>
                    <p><a href="/auth/dev-login">Dev Login (Bypass Auth)</a></p>
                </body>
                </html>
                """
            )
        return FileResponse(index_path)

    # Mount static directory for CSS/JS
    if not STATIC_DIR.exists():
        STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/health")
    async def health() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "version": "1.0.0"}

    return app


# App instance
app = create_app()


def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Start the uvicorn server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
