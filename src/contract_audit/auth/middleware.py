"""FastAPI authentication middleware using Google OAuth."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

from .google_oauth import GOOGLE_AUTH_URL, GOOGLE_CLIENT_ID, GOOGLE_SCOPES
from .token_store import TokenStore

logger = logging.getLogger(__name__)


async def require_google_auth(request: Request) -> dict[str, Any]:
    """FastAPI dependency that requires valid Google OAuth session.

    Returns user info dict if authenticated, raises 401 otherwise.
    """
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_google_auth_url(redirect_uri: str, state: str = "") -> str:
    """Generate Google OAuth authorization URL for web flow."""
    from urllib.parse import urlencode
    params = {
        "response_type": "code",
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": " ".join(GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
