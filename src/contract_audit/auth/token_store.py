"""Secure OAuth token storage using system keychain via keyring."""

from __future__ import annotations

import json
import logging

from ..core.models import OAuthToken

logger = logging.getLogger(__name__)

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    logger.warning("keyring not installed; tokens stored in memory only")


class TokenStore:
    """Stores OAuth tokens in the system keychain via keyring.

    Falls back to in-memory storage if keyring is unavailable.
    """

    ANTHROPIC_SERVICE = "contract-audit-anthropic"
    GOOGLE_SERVICE = "contract-audit-google"
    TOKEN_KEY = "oauth-token"

    def __init__(self) -> None:
        self._memory: dict[str, str] = {}

    def _store(self, service: str, value: str) -> None:
        if KEYRING_AVAILABLE:
            keyring.set_password(service, self.TOKEN_KEY, value)
        else:
            self._memory[service] = value

    def _load(self, service: str) -> str | None:
        if KEYRING_AVAILABLE:
            return keyring.get_password(service, self.TOKEN_KEY)
        return self._memory.get(service)

    def _delete(self, service: str) -> None:
        if KEYRING_AVAILABLE:
            try:
                keyring.delete_password(service, self.TOKEN_KEY)
            except Exception:
                pass
        else:
            self._memory.pop(service, None)

    def store_anthropic_token(self, token: OAuthToken) -> None:
        """Store Anthropic OAuth token securely."""
        self._store(self.ANTHROPIC_SERVICE, token.model_dump_json())
        logger.debug("Stored Anthropic token")

    def get_anthropic_token(self) -> OAuthToken | None:
        """Retrieve stored Anthropic OAuth token."""
        data = self._load(self.ANTHROPIC_SERVICE)
        if data:
            try:
                return OAuthToken.model_validate_json(data)
            except Exception as e:
                logger.warning(f"Failed to parse Anthropic token: {e}")
        return None

    def store_google_token(self, token: OAuthToken) -> None:
        """Store Google OAuth token securely."""
        self._store(self.GOOGLE_SERVICE, token.model_dump_json())
        logger.debug("Stored Google token")

    def get_google_token(self) -> OAuthToken | None:
        """Retrieve stored Google OAuth token."""
        data = self._load(self.GOOGLE_SERVICE)
        if data:
            try:
                return OAuthToken.model_validate_json(data)
            except Exception as e:
                logger.warning(f"Failed to parse Google token: {e}")
        return None

    def clear_all(self) -> None:
        """Remove all stored tokens."""
        self._delete(self.ANTHROPIC_SERVICE)
        self._delete(self.GOOGLE_SERVICE)
        self._memory.clear()
        logger.info("Cleared all stored tokens")

    def clear_anthropic(self) -> None:
        """Remove stored Anthropic token."""
        self._delete(self.ANTHROPIC_SERVICE)

    def clear_google(self) -> None:
        """Remove stored Google token."""
        self._delete(self.GOOGLE_SERVICE)
