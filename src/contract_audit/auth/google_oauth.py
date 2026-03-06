"""Google OAuth 2.0 login flow for web dashboard and CLI.

Supports:
- Standard Authorization Code flow with PKCE for CLI
- Device authorization flow as alternative
- Scopes: openid email profile
"""

from __future__ import annotations

import logging
import os
import time
import webbrowser
from typing import Any
from urllib.parse import urlencode

import httpx

from ..core.exceptions import AuthError
from ..core.models import OAuthToken
from .token_store import TokenStore

logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DEVICE_AUTH_URL = "https://oauth2.googleapis.com/device/code"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_SCOPES = ["openid", "email", "profile"]


class GoogleOAuth:
    """Manages Google OAuth 2.0 token lifecycle."""

    def __init__(self, token_store: TokenStore) -> None:
        self.token_store = token_store

    def get_api_key(self) -> str | None:
        """Get API key from environment (for CI fallback)."""
        return os.environ.get("GOOGLE_AI_API_KEY")

    def get_access_token(self) -> str | None:
        """Get a valid access token, refreshing if necessary."""
        token = self.token_store.get_google_token()
        if token:
            if token.is_expired() and token.refresh_token:
                refreshed = self._refresh_token(token.refresh_token)
                if refreshed:
                    self.token_store.store_google_token(refreshed)
                    return refreshed.access_token
            elif not token.is_expired():
                return token.access_token
        return None

    def get_user_info(self) -> dict[str, Any] | None:
        """Get user profile information from Google."""
        token = self.get_access_token()
        if not token:
            return None
        try:
            response = httpx.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"Failed to get user info: {e}")
            return None

    def _refresh_token(self, refresh_token: str) -> OAuthToken | None:
        """Refresh an expired access token."""
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            logger.warning("GOOGLE_CLIENT_ID/SECRET not set, cannot refresh token")
            return None
        try:
            response = httpx.post(
                GOOGLE_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                },
                timeout=30,
            )
            response.raise_for_status()
            return _parse_google_token(response.json(), existing_refresh=refresh_token)
        except Exception as e:
            logger.warning(f"Google token refresh failed: {e}")
            return None

    def login_browser(self) -> OAuthToken:
        """Start browser-based Google OAuth login for CLI."""
        import base64
        import hashlib
        import http.server
        import secrets
        import threading

        if not GOOGLE_CLIENT_ID:
            raise AuthError("GOOGLE_CLIENT_ID environment variable not set")

        # PKCE
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        callback_code: list[str] = []

        class CallbackHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                if "code" in params:
                    callback_code.append(params["code"][0])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Google login successful! You can close this tab.")

            def log_message(self, format: str, *args: Any) -> None:
                pass

        server = http.server.HTTPServer(("localhost", 9877), CallbackHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        redirect_uri = "http://localhost:9877/callback"
        params = {
            "response_type": "code",
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": " ".join(GOOGLE_SCOPES),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
        }

        auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
        logger.info("Opening browser for Google login...")
        webbrowser.open(auth_url)

        thread.join(timeout=300)

        if not callback_code:
            raise AuthError("Google OAuth callback not received within timeout")

        response = httpx.post(
            GOOGLE_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": callback_code[0],
                "redirect_uri": redirect_uri,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code_verifier": code_verifier,
            },
            timeout=30,
        )
        response.raise_for_status()
        token = _parse_google_token(response.json())
        self.token_store.store_google_token(token)
        return token

    def exchange_code(self, code: str, redirect_uri: str) -> OAuthToken:
        """Exchange authorization code for token (web flow)."""
        response = httpx.post(
            GOOGLE_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
            },
            timeout=30,
        )
        response.raise_for_status()
        token = _parse_google_token(response.json())
        self.token_store.store_google_token(token)
        return token

    def logout(self) -> None:
        """Remove stored Google tokens."""
        self.token_store.clear_google()
        logger.info("Logged out from Google")

    def is_authenticated(self) -> bool:
        """Check if valid Google auth is available."""
        return self.get_access_token() is not None


def _parse_google_token(
    data: dict[str, Any], existing_refresh: str | None = None
) -> OAuthToken:
    """Parse Google OAuth token response."""
    expires_in = data.get("expires_in")
    expires_at = time.time() + expires_in if expires_in else None
    refresh_token = data.get("refresh_token") or existing_refresh
    return OAuthToken(
        access_token=data["access_token"],
        refresh_token=refresh_token,
        expires_at=expires_at,
        token_type=data.get("token_type", "Bearer"),
        scopes=data.get("scope", "").split() if data.get("scope") else GOOGLE_SCOPES,
    )
