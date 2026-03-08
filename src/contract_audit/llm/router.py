"""Multi-provider LLM router with budget tracking."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

from ..core.config import LLMConfig, TaskRoute
from ..core.exceptions import BudgetExhaustedError
from ..core.models import LLMResponse
from ..auth.token_store import TokenStore
from .cost import BudgetTracker
from .providers.anthropic_provider import AnthropicProvider
from .providers.google_provider import GoogleProvider

logger = logging.getLogger(__name__)


class LLMRouter:
    """Routes LLM tasks to the appropriate provider/model based on config."""

    def __init__(self, config: LLMConfig, token_store: TokenStore) -> None:
        self.providers: dict[str, Any] = {}
        self.task_routing: dict[str, TaskRoute] = config.task_routing
        self.budget_tracker = BudgetTracker(max_usd=config.max_budget_usd)

        # Initialize providers based on available auth
        if "anthropic" in config.providers:
            pcfg = config.providers["anthropic"]
            provider = AnthropicProvider(
                token_store=token_store,
                fallback_api_key_env=pcfg.api_key_env or "ANTHROPIC_API_KEY",
            )
            if provider.is_available():
                self.providers["anthropic"] = provider
                logger.info("Anthropic provider initialized")
            else:
                logger.warning("Anthropic provider: no credentials found")

        if "google" in config.providers:
            pcfg = config.providers["google"]
            provider = GoogleProvider(
                token_store=token_store,
                fallback_api_key_env=pcfg.api_key_env or "GOOGLE_AI_API_KEY",
            )
            if provider.is_available():
                self.providers["google"] = provider
                logger.info("Google provider initialized")
            else:
                logger.warning("Google provider: no credentials found")

        if not self.providers:
            logger.warning(
                "No LLM providers available. Set ANTHROPIC_API_KEY or GOOGLE_AI_API_KEY."
            )

    async def execute_task(
        self,
        task_type: str,
        messages: list[dict[str, str]],
        response_schema: type[BaseModel] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Route and execute an LLM task.

        Args:
            task_type: Task identifier ("triage", "explain", "remediate", "poc_generate", "summarize")
            messages: Conversation messages
            response_schema: Optional Pydantic model for structured output
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLMResponse from the routed provider

        Raises:
            BudgetExhaustedError: If budget is exhausted
            RuntimeError: If no providers are available
        """
        if self.budget_tracker.is_exhausted:
            raise BudgetExhaustedError(self.budget_tracker.spent_usd)

        route = self.task_routing.get(task_type)
        if not route:
            logger.warning(f"No route configured for task '{task_type}', using defaults")
            route = TaskRoute(provider="anthropic", model="claude-opus-4-6")

        provider_name = route.provider
        model = route.model

        # Try primary provider, fall back to other
        provider = self.providers.get(provider_name)
        if not provider:
            # Try any available provider
            for name, p in self.providers.items():
                provider = p
                provider_name = name
                logger.warning(
                    f"Provider '{route.provider}' not available, using '{name}'"
                )
                # Use default model for this provider
                if name == "anthropic":
                    model = "claude-opus-4-6"
                else:
                    model = "gemini-2.0-flash"
                break

        if not provider:
            raise RuntimeError(
                "No LLM providers available. Set ANTHROPIC_API_KEY or GOOGLE_AI_API_KEY."
            )

        logger.debug(f"Routing task '{task_type}' to {provider_name}:{model}")

        response = await provider.complete(
            messages=messages,
            model=model,
            response_schema=response_schema,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        self.budget_tracker.record(response.cost_usd)
        logger.debug(
            f"Task '{task_type}' completed. Cost: ${response.cost_usd:.4f}. "
            f"Budget remaining: ${self.budget_tracker.remaining_usd:.4f}"
        )

        return response

    def get_budget_summary(self) -> dict:
        """Get current budget usage summary."""
        return self.budget_tracker.summary()

    @property
    def is_available(self) -> bool:
        return bool(self.providers)
