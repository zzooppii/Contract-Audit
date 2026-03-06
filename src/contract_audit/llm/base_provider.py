"""LLM provider protocol definition."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from ..core.models import LLMResponse


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol that all LLM providers must implement."""

    @property
    def name(self) -> str:
        """Provider identifier (e.g., 'anthropic', 'google')."""
        ...

    @property
    def available_models(self) -> list[str]:
        """List of models available from this provider."""
        ...

    async def complete(
        self,
        messages: list[dict[str, str]],
        model: str,
        response_schema: type[BaseModel] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send messages and get a completion response.

        Args:
            messages: List of {role, content} message dicts
            model: Model identifier
            response_schema: Optional Pydantic model for structured output
            temperature: Sampling temperature (0.0 = deterministic)
            max_tokens: Maximum response tokens

        Returns:
            LLMResponse with content and token usage
        """
        ...

    def estimate_cost(
        self, input_tokens: int, output_tokens: int, model: str
    ) -> float:
        """Estimate cost in USD for a completion."""
        ...

    def is_available(self) -> bool:
        """Check if this provider has valid credentials."""
        ...
