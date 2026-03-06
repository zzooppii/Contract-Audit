"""Google Gemini provider via google-genai SDK."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from pydantic import BaseModel

from ...core.models import LLMResponse
from ...auth.token_store import TokenStore

logger = logging.getLogger(__name__)

# Cost per 1M tokens in USD (Gemini models)
COST_PER_1M: dict[str, dict[str, float]] = {
    "gemini-3-flash": {"input": 0.075, "output": 0.30},
    "gemini-3.1-pro": {"input": 1.25, "output": 5.0},
    "gemini-2.0-flash": {"input": 0.075, "output": 0.30},
    "gemini-2.0-pro": {"input": 1.25, "output": 5.0},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.0},
}

DEFAULT_MODEL = "gemini-2.0-flash"

# Model name mappings (plan name -> actual API name)
MODEL_ALIASES: dict[str, str] = {
    "gemini-3-flash": "gemini-2.0-flash",
    "gemini-3.1-pro": "gemini-2.0-pro-exp-02-05",
    "gemini-3-pro": "gemini-2.0-pro-exp-02-05",
}


class GoogleProvider:
    """Gemini provider using the google-genai SDK."""

    name = "google"
    available_models = list(COST_PER_1M.keys())

    def __init__(
        self,
        token_store: TokenStore | None = None,
        fallback_api_key_env: str = "GOOGLE_AI_API_KEY",
    ) -> None:
        self.token_store = token_store
        self.fallback_api_key_env = fallback_api_key_env
        self._client: Any = None

    def _get_api_key(self) -> str | None:
        """Get API key from OAuth token or env var."""
        if self.token_store:
            token = self.token_store.get_google_token()
            if token and not token.is_expired():
                return token.access_token

        return os.environ.get(self.fallback_api_key_env)

    def _get_client(self) -> Any:
        """Get or create Google GenAI client."""
        if self._client is None:
            try:
                from google import genai
                api_key = self._get_api_key()
                if api_key:
                    self._client = genai.Client(api_key=api_key)
                else:
                    self._client = genai.Client()
            except ImportError:
                raise RuntimeError("google-genai package not installed")
        return self._client

    def is_available(self) -> bool:
        """Check if Google AI credentials are available."""
        return bool(self._get_api_key() or os.environ.get("GOOGLE_AI_API_KEY"))

    def _resolve_model(self, model: str) -> str:
        """Resolve model alias to actual API name."""
        return MODEL_ALIASES.get(model, model)

    async def complete(
        self,
        messages: list[dict[str, str]],
        model: str = DEFAULT_MODEL,
        response_schema: type[BaseModel] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Get a completion from Gemini."""
        import asyncio
        client = self._get_client()
        actual_model = self._resolve_model(model)

        # Build the prompt from messages
        prompt_parts = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if role == "system":
                prompt_parts.insert(0, f"Instructions: {content}\n\n")
            elif role == "user":
                prompt_parts.append(f"User: {content}")
            elif role == "assistant":
                prompt_parts.append(f"Assistant: {content}")

        full_prompt = "\n".join(prompt_parts)

        # Add structured output instruction
        if response_schema:
            schema_json = response_schema.model_json_schema()
            full_prompt += (
                f"\n\nRespond ONLY with valid JSON matching this schema:\n"
                f"```json\n{json.dumps(schema_json, indent=2)}\n```"
            )

        try:
            from google.genai import types

            config = types.GenerateContentConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )

            # Run in executor to avoid blocking event loop
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=actual_model,
                    contents=full_prompt,
                    config=config,
                )
            )

            content = response.text or ""
            input_tokens = getattr(response.usage_metadata, "prompt_token_count", 0)
            output_tokens = getattr(response.usage_metadata, "candidates_token_count", 0)

        except Exception as e:
            logger.error(f"Google AI completion failed: {e}")
            raise

        structured = None
        if response_schema:
            try:
                import re
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    structured = response_schema.model_validate_json(json_match.group())
                    structured = structured.model_dump()
            except Exception as e:
                logger.warning(f"Failed to parse structured Google response: {e}")

        return LLMResponse(
            content=content,
            model=actual_model,
            provider=self.name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=self.estimate_cost(input_tokens, output_tokens, model),
            structured_data=structured,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """Estimate cost in USD."""
        costs = COST_PER_1M.get(model, {"input": 1.25, "output": 5.0})
        return (input_tokens * costs["input"] + output_tokens * costs["output"]) / 1_000_000
