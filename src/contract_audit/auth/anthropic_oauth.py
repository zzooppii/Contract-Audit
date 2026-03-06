"""Anthropic OAuth token management.

Supports:
- Browser-based OAuth 2.0 flow for CLI login
- Automatic token refresh
- Fallback to ANTHROPIC_API_KEY env var for CI
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

# Anthropic OAuth endpoints
ANTHROPIC_AUTH_URL = "https://claude.ai/oauth/authorize"
ANTHROPIC_TOKEN_URL = "https://api.anthropic.com/oauth/token"
ANTHROPIC_CLIENT_ID = "contract-audit-cli"
ANTHROPIC_SCOPES = ["completions:read"]

# Device auth flow
ANTHROPIC_DEVICE_AUTH_URL = "https://api.anthropic.com/oauth/device/authorize"


class AnthropicOAuth:
    """Manages Anthropic OAuth 2.0 token lifecycle."""

    def __init__(self, token_store: TokenStore) -> None:
        self.token_store = token_store

    def get_api_key(self) -> str | None:
        """Get API key from environment (for CI fallback)."""
        return os.environ.get("ANTHROPIC_API_KEY")

    def get_access_token(self) -> str | None:
        """Get a valid access token, refreshing if necessary."""
        token = self.token_store.get_anthropic_token()
        if token:
            if token.is_expired() and token.refresh_token:
                refreshed = self._refresh_token(token.refresh_token)
                if refreshed:
                    self.token_store.store_anthropic_token(refreshed)
                    return refreshed.access_token
            elif not token.is_expired():
                return token.access_token

        # Fall back to env var
        return self.get_api_key()

    def _refresh_token(self, refresh_token: str) -> OAuthToken | None:
        """Refresh an expired access token."""
        try:
            response = httpx.post(
                ANTHROPIC_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": ANTHROPIC_CLIENT_ID,
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            return _parse_token_response(data)
        except Exception as e:
            logger.warning(f"Token refresh failed: {e}")
            return None

    def login_browser(self) -> OAuthToken:
        """Initiate browser-based OAuth flow for CLI login.

        Uses PKCE for security (no client secret needed).
        """
        import base64
        import hashlib
        import secrets

        # Generate PKCE verifier/challenge
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        # Start local HTTP server to receive callback
        import http.server
        import threading

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
                self.wfile.write(b"Login successful! You can close this tab.")

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress default HTTP log output

        server = http.server.HTTPServer(("localhost", 9876), CallbackHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        redirect_uri = "http://localhost:9876/callback"
        params = {
            "response_type": "code",
            "client_id": ANTHROPIC_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": " ".join(ANTHROPIC_SCOPES),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{ANTHROPIC_AUTH_URL}?{urlencode(params)}"
        logger.info(f"Opening browser for Anthropic login: {auth_url}")
        webbrowser.open(auth_url)

        thread.join(timeout=300)

        if not callback_code:
            raise AuthError("OAuth callback not received within timeout")

        # Exchange code for token
        response = httpx.post(
            ANTHROPIC_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": callback_code[0],
                "redirect_uri": redirect_uri,
                "client_id": ANTHROPIC_CLIENT_ID,
                "code_verifier": code_verifier,
            },
            timeout=30,
        )
        response.raise_for_status()
        token = _parse_token_response(response.json())
        self.token_store.store_anthropic_token(token)
        return token

    def logout(self) -> None:
        """Remove stored Anthropic tokens."""
        self.token_store.clear_anthropic()
        logger.info("Logged out from Anthropic")

    def is_authenticated(self) -> bool:
        """Check if valid authentication is available."""
        return self.get_access_token() is not None


def _parse_token_response(data: dict[str, Any]) -> OAuthToken:
    """Parse OAuth token response into OAuthToken model."""
    expires_in = data.get("expires_in")
    expires_at = time.time() + expires_in if expires_in else None
    return OAuthToken(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        expires_at=expires_at,
        token_type=data.get("token_type", "Bearer"),
        scopes=data.get("scope", "").split() if data.get("scope") else [],
    )
