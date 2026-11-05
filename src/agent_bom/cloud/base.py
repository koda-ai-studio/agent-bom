"""Shared base types for cloud provider discovery modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from agent_bom.extensions import ExtensionCapabilities, RegistryEntry
from agent_bom.models import Agent


class CloudDiscoveryError(Exception):
    """Raised when a cloud provider SDK is missing or an API call fails."""


def missing_scope_hint(provider: str) -> str:
    """Name the correct scope flag for both CLI entrypoints."""
    label, scope, envvar = {
        "azure": ("Azure", "subscription", "AZURE_SUBSCRIPTION_ID"),
        "gcp": ("GCP", "project", "GOOGLE_CLOUD_PROJECT"),
    }[provider]
    return (
        f"No {label} {scope} resolved. Pass --{scope} to `agent-bom cloud {provider}` "
        f"(or --{provider}-{scope} to `agent-bom scan`), or set {envvar}."
    )


@dataclass(frozen=True)
class CloudProviderRegistration(RegistryEntry):
    """Registry metadata for a cloud provider discovery implementation."""


class CloudProvider(Protocol):
    """Protocol implemented by cloud provider discovery extensions."""

    name: str
    capabilities: ExtensionCapabilities

    def discover(self, **kwargs: Any) -> tuple[list[Agent], list[str]]:
        """Discover cloud inventory and return user-safe warnings."""
