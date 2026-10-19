"""Provider discovery, credential readiness and model selection."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

import httpx

from agent_bom.ai_components.call_state import DEFAULT_MODEL, HF_DEFAULT_MODEL, OLLAMA_MODEL_PREFERENCE
from agent_bom.config import OLLAMA_BASE_URL
from agent_bom.core.settings import env_first, env_is_set, env_str


@dataclass(frozen=True, slots=True)
class AIProviderDescriptor:
    """Public, non-secret provider contract for AI enrichment."""

    name: str
    display_name: str
    local: bool
    requires_network: bool
    required_env: tuple[str, ...] = ()
    optional_extra: str = ""
    supports_structured_output: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "local": self.local,
            "requires_network": self.requires_network,
            "required_env": list(self.required_env),
            "optional_extra": self.optional_extra,
            "supports_structured_output": self.supports_structured_output,
        }


@dataclass(frozen=True, slots=True)
class AIProviderStatus:
    """Availability status without leaking configured token values."""

    descriptor: AIProviderDescriptor
    installed: bool
    configured: bool
    available: bool
    reason: str
    selected_model_ready: bool | None = None

    def to_dict(self) -> dict[str, object]:
        payload = self.descriptor.to_dict()
        payload.update(
            {
                "installed": self.installed,
                "configured": self.configured,
                "available": self.available,
                "reason": self.reason,
                "selected_model_ready": self.selected_model_ready,
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class AIProviderResolution:
    """Resolved provider/model decision for one enrichment run."""

    requested_model: str
    model: str
    provider: AIProviderDescriptor | None
    available: bool
    status: str
    reason: str = ""
    fallback_from: str | None = None

    def to_metadata(self) -> dict[str, object]:
        return {
            "schema_version": "1",
            "requested_model": self.requested_model,
            "model": self.model,
            "provider": self.provider.name if self.provider else None,
            "provider_display_name": self.provider.display_name if self.provider else None,
            "local": self.provider.local if self.provider else False,
            "requires_network": self.provider.requires_network if self.provider else False,
            "status": self.status,
            "reason": self.reason,
            "fallback_from": self.fallback_from,
        }


AI_PROVIDER_DESCRIPTORS: dict[str, AIProviderDescriptor] = {
    "ollama": AIProviderDescriptor(
        name="ollama",
        display_name="Ollama",
        local=True,
        requires_network=False,
        optional_extra="core",
        supports_structured_output=True,
    ),
    "huggingface": AIProviderDescriptor(
        name="huggingface",
        display_name="HuggingFace Inference API",
        local=False,
        requires_network=True,
        required_env=("HF_TOKEN",),
        optional_extra="huggingface",
    ),
    "litellm": AIProviderDescriptor(
        name="litellm",
        display_name="litellm",
        local=False,
        requires_network=True,
        optional_extra="ai-enrich",
    ),
}


def _check_litellm() -> bool:
    """Check if litellm is installed."""
    try:
        import litellm  # noqa: F401

        return True
    except ImportError:
        return False


def _check_huggingface() -> bool:
    """Check if huggingface-hub is installed with InferenceClient."""
    try:
        from huggingface_hub import InferenceClient  # noqa: F401

        return True
    except ImportError:
        return False


def _detect_ollama() -> bool:
    """Check if Ollama is running locally."""
    try:
        resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2.0)
        return resp.status_code == 200
    except (httpx.ConnectError, httpx.TimeoutException, Exception):
        return False


def _get_ollama_models() -> list[str]:
    """Get list of locally available Ollama models."""
    try:
        resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    return []


def _provider_name_for_model(model: str) -> str:
    if model.startswith("ollama/"):
        return "ollama"
    if model.startswith("huggingface/"):
        return "huggingface"
    return "litellm"


def _ollama_endpoint_is_loopback() -> bool:
    """Return whether the configured Ollama endpoint stays on this host.

    Raw skill/instruction content is eligible only for a loopback Ollama
    endpoint. Hostnames are not resolved here: treating a DNS name as local
    would make the trust decision vulnerable to DNS changes and would add a
    blocking lookup to provider metadata.
    """
    try:
        hostname = (urlsplit(OLLAMA_BASE_URL).hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _url_is_loopback(value: str) -> bool:
    """Treat only explicit loopback HTTP(S) endpoints as keyless-local."""
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


_LITELLM_MODEL_CREDENTIALS: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "azure": ("AZURE_API_KEY", "AZURE_OPENAI_API_KEY"),
    "bedrock": ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_WEB_IDENTITY_TOKEN_FILE"),
    "cohere": ("COHERE_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "google": ("GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"),
    "groq": ("GROQ_API_KEY",),
    "mistral": ("MISTRAL_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
    "vertex_ai": ("GOOGLE_APPLICATION_CREDENTIALS",),
}


def _litellm_readiness(model: str) -> tuple[bool, str]:
    """Return model-specific credential or explicit local-endpoint readiness."""
    proxy_url = env_str("LITELLM_PROXY_URL")
    if proxy_url:
        if _url_is_loopback(proxy_url):
            return True, "keyless loopback LiteLLM proxy configured"
        if env_is_set("LITELLM_API_KEY"):
            return True, "authenticated LiteLLM proxy configured"
        return False, "LITELLM_API_KEY is required for the configured remote LiteLLM proxy"

    prefix = model.partition("/")[0].lower()
    if prefix in {"bedrock", "vertex_ai"}:
        return True, f"{prefix} ambient workload identity chain supported"
    if prefix == "openai":
        api_base = env_first("OPENAI_API_BASE", "OPENAI_BASE_URL")
        if api_base and _url_is_loopback(api_base):
            return True, "keyless loopback OpenAI-compatible endpoint configured"

    credential_names = _LITELLM_MODEL_CREDENTIALS.get(prefix, ("LITELLM_API_KEY",))
    if any(env_is_set(name) for name in credential_names):
        return True, "model credentials configured"
    return False, f"selected {prefix or 'litellm'} model requires one of: {', '.join(credential_names)}"


def _provider_status(provider_name: str, model: str | None = None) -> AIProviderStatus:
    descriptor = AI_PROVIDER_DESCRIPTORS[provider_name]
    if provider_name == "ollama":
        endpoint_local = _ollama_endpoint_is_loopback()
        descriptor = replace(descriptor, local=endpoint_local, requires_network=not endpoint_local)
        available = _detect_ollama()
        return AIProviderStatus(
            descriptor=descriptor,
            installed=True,
            configured=available,
            available=available,
            reason="available" if available else "ollama is not reachable at the configured local endpoint",
            selected_model_ready=available,
        )
    if provider_name == "huggingface":
        installed = _check_huggingface()
        configured = env_is_set("HF_TOKEN")
        return AIProviderStatus(
            descriptor=descriptor,
            installed=installed,
            configured=configured,
            available=installed and configured,
            reason="available" if installed and configured else "huggingface-hub and HF_TOKEN are required for HuggingFace enrichment",
            selected_model_ready=installed and configured,
        )
    installed = _check_litellm()
    if model is None:
        capability_reason = "adapter installed; selected-model readiness is evaluated during resolution"
        if not installed:
            capability_reason = "litellm is not installed"
        return AIProviderStatus(
            descriptor=descriptor,
            installed=installed,
            configured=installed,
            available=installed,
            reason=capability_reason,
            selected_model_ready=None,
        )
    configured, readiness_reason = _litellm_readiness(model)
    return AIProviderStatus(
        descriptor=descriptor,
        installed=installed,
        configured=configured,
        available=installed and configured,
        reason="available" if installed and configured else ("litellm is not installed" if not installed else readiness_reason),
        selected_model_ready=installed and configured,
    )


def describe_ai_providers() -> list[dict[str, object]]:
    """Return non-secret provider capability and availability metadata."""
    return [_provider_status(name).to_dict() for name in ("ollama", "huggingface", "litellm")]


def _resolve_ai_provider(model: str = DEFAULT_MODEL) -> AIProviderResolution:
    """Resolve the provider/model used by AI enrichment with explicit fallback metadata."""
    requested_model = model
    resolved_model = _resolve_model(model) if model == DEFAULT_MODEL else model
    preferred_name = _provider_name_for_model(resolved_model)
    preferred_status = _provider_status(preferred_name, resolved_model)
    if preferred_status.available:
        return AIProviderResolution(
            requested_model=requested_model,
            model=resolved_model,
            provider=preferred_status.descriptor,
            available=True,
            status="active",
        )

    return AIProviderResolution(
        requested_model=requested_model,
        model=resolved_model,
        provider=preferred_status.descriptor,
        available=False,
        status="unavailable",
        reason=preferred_status.reason,
    )


def _resolve_model(model: str = DEFAULT_MODEL) -> str:
    """Auto-detect the best available model.

    Priority:
    1. If Ollama is running → pick best installed model from preference list
    2. If HF_TOKEN set + huggingface-hub installed → HuggingFace Inference API
    3. If OPENAI_API_KEY is set → ``openai/gpt-4o-mini``
    4. Fallback to default (will fail gracefully at call time)
    """
    if _detect_ollama():
        installed = _get_ollama_models()
        if installed:
            # Check preference list first
            for preferred in OLLAMA_MODEL_PREFERENCE:
                if preferred in installed:
                    return f"ollama/{preferred}"
                # Also match without tag (e.g. "llama3.2" matches "llama3.2:latest")
                base = preferred.split(":")[0]
                for inst in installed:
                    if inst.startswith(base):
                        return f"ollama/{inst}"
            # None from preference list — use first available
            return f"ollama/{installed[0]}"
        # Ollama running but no models pulled — fall through
    if _check_huggingface() and env_is_set("HF_TOKEN"):
        return f"huggingface/{HF_DEFAULT_MODEL}"
    if env_is_set("OPENAI_API_KEY"):
        return DEFAULT_MODEL
    return model


def _has_any_provider(model: str) -> bool:
    """Check if any LLM provider is available for the given model."""
    return _resolve_ai_provider(model).available
