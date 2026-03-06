"""Google OAuth callback routes for web dashboard."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from ...auth.google_oauth import GoogleOAuth
from ...auth.token_store import TokenStore
from ...auth.middleware import get_google_auth_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _get_oauth(request: Request) -> GoogleOAuth:
    token_store = request.app.state.token_store
    return GoogleOAuth(token_store=token_store)


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    """Redirect to Google OAuth login."""
    redirect_uri = str(request.url_for("callback"))
    import secrets
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state
    auth_url = get_google_auth_url(redirect_uri, state)
    return RedirectResponse(url=auth_url)


@router.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    error: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    """Handle Google OAuth callback."""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    oauth = _get_oauth(request)
    redirect_uri = str(request.url_for("callback"))

    try:
        token = oauth.exchange_code(code, redirect_uri)
        user_info = oauth.get_user_info()

        if user_info:
            request.session["user"] = {
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "picture": user_info.get("picture"),
            }

        return RedirectResponse(url="/")
    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")


@router.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Log out the current user."""
    request.session.clear()
    oauth = _get_oauth(request)
    oauth.logout()
    return RedirectResponse(url="/")


@router.get("/me")
async def me(request: Request) -> dict[str, Any]:
    """Get current user info."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
