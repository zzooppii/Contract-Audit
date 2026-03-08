"""Anthropic Claude provider via Anthropic SDK."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from pydantic import BaseModel

from ...auth.token_store import TokenStore
from ...core.models import LLMResponse

logger = logging.getLogger(__name__)

# Cost per 1M tokens in USD (Claude Opus 4)
COST_PER_1M: dict[str, dict[str, float]] = {
    "claude-opus-4": {"input": 15.0, "output": 75.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
}

DEFAULT_MODEL = "claude-opus-4-6"


class AnthropicProvider:
    """Claude provider using the Anthropic Python SDK."""

    name = "anthropic"
    available_models = list(COST_PER_1M.keys())

    def __init__(
        self,
        token_store: TokenStore | None = None,
        fallback_api_key_env: str = "ANTHROPIC_API_KEY",
    ) -> None:
        self.token_store = token_store
        self.fallback_api_key_env = fallback_api_key_env
        self._client: Any = None

    def _get_api_key(self) -> str | None:
        """Get API key from OAuth token or env var."""
        if self.token_store:
            token = self.token_store.get_anthropic_token()
            if token and not token.is_expired():
                return token.access_token

        return os.environ.get(self.fallback_api_key_env)

    def _get_client(self) -> Any:
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                api_key = self._get_api_key()
                if api_key:
                    self._client = anthropic.AsyncAnthropic(api_key=api_key)
                else:
                    self._client = anthropic.AsyncAnthropic()  # Uses ANTHROPIC_API_KEY
            except ImportError:
                raise RuntimeError("anthropic package not installed")
        return self._client

    def is_available(self) -> bool:
        """Check if Anthropic credentials are available."""
        return bool(self._get_api_key() or os.environ.get("ANTHROPIC_API_KEY"))

    async def complete(
        self,
        messages: list[dict[str, str]],
        model: str = DEFAULT_MODEL,
        response_schema: type[BaseModel] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Get a completion from Claude."""
        client = self._get_client()

        # Separate system message if present
        system = None
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                user_messages.append(msg)

        # Add structured output instruction if schema provided
        if response_schema and user_messages:
            schema_json = response_schema.model_json_schema()
            last_msg = user_messages[-1].copy()
            last_msg["content"] += (
                f"\n\nRespond with valid JSON matching this schema:\n"
                f"```json\n{json.dumps(schema_json, indent=2)}\n```"
            )
            user_messages[-1] = last_msg

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            kwargs["system"] = system

        response = await client.messages.create(**kwargs)

        content = response.content[0].text if response.content else ""
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

        structured: dict[str, Any] | None = None
        if response_schema:
            try:
                # Parse JSON from response
                import re
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    parsed = response_schema.model_validate_json(json_match.group())
                    structured = parsed.model_dump()
            except Exception as e:
                logger.warning(f"Failed to parse structured response: {e}")

        return LLMResponse(
            content=content,
            model=model,
            provider=self.name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=self.estimate_cost(input_tokens, output_tokens, model),
            structured_data=structured,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """Estimate cost in USD."""
        costs = COST_PER_1M.get(model, {"input": 15.0, "output": 75.0})
        return (input_tokens * costs["input"] + output_tokens * costs["output"]) / 1_000_000
