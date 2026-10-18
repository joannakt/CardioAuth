"""Provider-agnostic LLM boundary (§4.1). Providers arrive in M4 for extraction, M5 for
criteria evaluation, M6 for generation/verification.

Kept import-light deliberately: it imports nothing but ``Protocol`` at module scope, so
services can depend on the interface long before any vendor SDK is chosen. Every provider
must return a *validated* schema instance (``extra="forbid"``), never free text.
"""

from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)

PROVIDER_REGISTRY: dict[str, str] = {
    "mock": "MockLLMProvider (dev/CI only; refused under CARDIOAUTH_ENV=production)",
    "openai_compatible": "OpenAICompatibleProvider (Ollama/vLLM or any OpenAI-shaped vendor API)",
    "bedrock": "BedrockProvider (production candidate, BAA-eligible)",
    "azure_openai": "AzureOpenAIProvider (production candidate, BAA-covered subscription)",
    "recording": "RecordingProvider decorator (CARDIOAUTH_PHI_LOGGING=dev only)",
}


class LLMError(RuntimeError):
    """Base class for provider errors, so services never catch vendor-specific types."""


class LLMTransportError(LLMError): ...


class LLMSchemaError(LLMError): ...


class LLMRefusalError(LLMError): ...


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str

    def complete_structured(
        self,
        schema: type[ModelT],
        *,
        system: str,
        user: str,
        cache_key: str,
        purpose: str,
        log_body: bool = False,
        **kwargs: Any,
    ) -> ModelT: ...


def get_provider(provider: str | None = None, model: str | None = None) -> LLMProvider:  # pragma: no cover - M4
    """Resolve a provider. Deliberately unimplemented until M4: a stub that returned a
    plausible object would let the pipeline 'work' with no provider behind it."""
    from cardioauth.settings import get_settings

    settings = get_settings()
    name = provider or settings.llm_provider
    raise NotImplementedError(
        f"LLM provider '{name}' is implemented in M4 (mock, openai_compatible) and M6 "
        "(bedrock, azure_openai). Registered provider names: "
        f"{', '.join(sorted(PROVIDER_REGISTRY))}. Model requested: {model or settings.llm_model}."
    )
