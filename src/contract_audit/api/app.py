"""FastAPI application for the web dashboard."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from ..auth.token_store import TokenStore
from .routes import audit, auth, reports

logger = logging.getLogger(__name__)


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

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> str:
        """Simple dashboard homepage."""
        return """
        <!DOCTYPE html>
        <html>
        <head><title>contract-audit Dashboard</title></head>
        <body>
            <h1>contract-audit Web Dashboard</h1>
            <p><a href="/auth/login">Login with Google</a></p>
            <p><a href="/docs">API Documentation</a></p>
        </body>
        </html>
        """

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
