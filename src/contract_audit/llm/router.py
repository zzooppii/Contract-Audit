"""Multi-provider LLM router with budget tracking."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

from ..auth.token_store import TokenStore
from ..core.config import LLMConfig, TaskRoute
from ..core.exceptions import BudgetExhaustedError
from ..core.models import LLMResponse
from .cost import BudgetTracker
from .providers.anthropic_provider import AnthropicProvider
from .providers.google_provider import GoogleProvider

logger = logging.getLogger(__name__)


# Intelligent default routes based on task complexity
INTELLIGENT_DEFAULTS: dict[str, dict[str, str]] = {
    "triage": {"google": "gemini-2.0-flash", "anthropic": "claude-haiku-4-5-20251001"},
    "explain": {"google": "gemini-2.0-flash", "anthropic": "claude-haiku-4-5-20251001"},
    "remediate": {"google": "gemini-2.0-pro", "anthropic": "claude-sonnet-4-6"},
    "poc": {"google": "gemini-2.0-pro", "anthropic": "claude-sonnet-4-6"},
    "audit": {"google": "gemini-2.0-pro", "anthropic": "claude-sonnet-4-6"},
}


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
            google_provider = GoogleProvider(
                token_store=token_store,
                fallback_api_key_env=pcfg.api_key_env or "GOOGLE_AI_API_KEY",
            )
            if google_provider.is_available():
                self.providers["google"] = google_provider
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
            task_type: Task identifier
                ("triage", "explain", "remediate", etc.)
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

        # 1. Budget Preservation Mode Check
        max_usd = self.budget_tracker.max_usd
        spent_usd = self.budget_tracker.spent_usd
        remaining_usd = max_usd - spent_usd

        budget_preservation_mode = False
        if max_usd > 0 and (remaining_usd / max_usd) < 0.2:
            if task_type != "poc":
                budget_preservation_mode = True
                logger.info(
                    f"LLM Budget Preservation Mode active. Remaining: ${remaining_usd:.4f} "
                    f"({(remaining_usd/max_usd)*100:.1f}%). Downgrading model for '{task_type}'."
                )

        # 2. Determine base route
        route = self.task_routing.get(task_type)
        provider_name = None
        model = None

        if route:
            provider_name = route.provider
            model = route.model

        # Fallback to defaults if provider not configured or not active
        if not provider_name or provider_name not in self.providers:
            if self.providers:
                provider_name = next(iter(self.providers.keys()))
            else:
                raise RuntimeError("No LLM providers configured or available.")

        # Resolve model from defaults if not set
        if not model:
            provider_defaults = INTELLIGENT_DEFAULTS.get(task_type, {})
            model = provider_defaults.get(provider_name)
            if not model:
                model = "claude-haiku-4-5-20251001" if provider_name == "anthropic" else "gemini-2.0-flash"

        # 3. Apply Budget Preservation Downgrade
        if budget_preservation_mode:
            if provider_name == "anthropic":
                model = "claude-haiku-4-5-20251001"
            elif provider_name == "google":
                model = "gemini-2.0-flash"

        provider = self.providers.get(provider_name)
        if not provider:
            raise RuntimeError(f"Routed provider '{provider_name}' is not initialized.")

        logger.debug(f"Routing task '{task_type}' to {provider_name}:{model}")

        response: LLMResponse = await provider.complete(
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

    def get_budget_summary(self) -> dict[str, Any]:
        """Get current budget usage summary."""
        return self.budget_tracker.summary()

    @property
    def is_available(self) -> bool:
        return bool(self.providers)
