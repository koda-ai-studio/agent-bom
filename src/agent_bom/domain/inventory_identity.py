"""Identity scope for inventory agents that declare no location of their own.

The inventory's declared ``source_id`` (else ``source``) scopes the agent's
name, so the same name means the same agent only within one inventory source.
The inventory file path never enters identity: a moved inventory keeps its
ids. Without a declared source the id stays location-free (``""``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

INVENTORY_SOURCE_SCOPE_PREFIX = "inventory-source:"


def inventory_identity_scope(document: Mapping[str, Any]) -> str:
    """The identity location an inventory document gives its location-less agents."""
    declared = str(document.get("source_id") or document.get("source") or "").strip()
    return f"{INVENTORY_SOURCE_SCOPE_PREFIX}{declared}" if declared else ""


def is_inventory_identity(identity_config_path: Any) -> bool:
    """True for an inventory agent's identity location: location-free or source-scoped."""
    return identity_config_path == "" or (
        isinstance(identity_config_path, str) and identity_config_path.startswith(INVENTORY_SOURCE_SCOPE_PREFIX)
    )
