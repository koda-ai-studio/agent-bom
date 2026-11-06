"""Who may use AI, and where prompts may go. Everything starts closed."""

from __future__ import annotations

from dataclasses import dataclass

from agent_bom.ai_components import provider_discovery
from agent_bom.core.settings import env_bool, env_first, env_str

ALLOW_REMOTE_ENV = "AGENT_BOM_AI_ALLOW_REMOTE"
CONTROL_PLANE_ENV = "AGENT_BOM_AI_CONTROL_PLANE_ENABLED"
CONTROL_PLANE_TENANTS_ENV = "AGENT_BOM_AI_CONTROL_PLANE_TENANTS"
CONTROL_PLANE_MODEL_ENV = "AGENT_BOM_AI_CONTROL_PLANE_MODEL"
_LITELLM_OLLAMA_DEFAULT_BASE = "http://localhost:11434"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    enabled: bool
    reason: str = ""


def control_plane_decision(tenant_id: str) -> PolicyDecision:
    """Whether hosted use is on for this tenant. A request can never turn it on."""
    if not env_bool(CONTROL_PLANE_ENV, False, on_invalid="default"):
        return PolicyDecision(False, f"AI advice is off: the operator has not set {CONTROL_PLANE_ENV}.")
    allowed = {item.strip() for item in env_str(CONTROL_PLANE_TENANTS_ENV).split(",") if item.strip()}
    if allowed and tenant_id not in allowed:
        return PolicyDecision(False, f"AI advice is off for this tenant: it is not listed in {CONTROL_PLANE_TENANTS_ENV}.")
    return PolicyDecision(True)


def control_plane_model(requested: str) -> str:
    """The operator's model when one is set; a tenant user cannot redirect prompts elsewhere."""
    return env_str(CONTROL_PLANE_MODEL_ENV) or requested


def endpoint_is_local(model: str) -> bool:
    """Whether prompts for this model stay on this host. Hostnames other than localhost never count."""
    if model.startswith("ollama/"):
        return provider_discovery._ollama_endpoint_is_loopback()
    if model.startswith("huggingface/"):
        return False
    proxy = env_str("LITELLM_PROXY_URL")
    if proxy:
        return provider_discovery._url_is_loopback(proxy)
    if model.startswith("ollama_chat/"):
        return provider_discovery._url_is_loopback(env_str("OLLAMA_API_BASE") or _LITELLM_OLLAMA_DEFAULT_BASE)
    if model.partition("/")[0].lower() == "openai":
        base = env_first("OPENAI_API_BASE", "OPENAI_BASE_URL")
        return bool(base) and provider_discovery._url_is_loopback(base)
    return False


def remote_allowed() -> bool:
    return env_bool(ALLOW_REMOTE_ENV, False, on_invalid="default")


def egress_refusal(model: str) -> str:
    """Why this model may not be called; empty when it may."""
    if endpoint_is_local(model) or remote_allowed():
        return ""
    return f"{model} sends prompts off this host. Set {ALLOW_REMOTE_ENV}=1 to allow it."
