"""Repository-local graph identities, retaining legacy report compatibility."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from agent_bom.core.repository_identity import relative_path, repository_id


def repository_scope(inventory: object) -> str:
    context = inventory.get("repository_context") if isinstance(inventory, Mapping) else None
    scope = context.get("scope_id") if isinstance(context, Mapping) and context.get("version") == 1 else None
    return scope if isinstance(scope, str) and re.fullmatch(r"[a-f0-9]{64}", scope) else ""


def scoped_node_id(kind: str, path: str, scope: str = "") -> str:
    return repository_id(scope, kind, path or ".") if scope else f"{kind}:{path or '.'}"


def scoped_file_path(raw: Any, inventory: Any) -> str | None:
    """Only join findings inside the recorded repository; no filesystem reads."""
    if not isinstance(raw, str):
        return None
    root = inventory.get("root") if isinstance(inventory, Mapping) else None
    if raw.startswith("/") and isinstance(root, str) and root.startswith("/"):
        prefix = root.rstrip("/") + "/"
        if not raw.startswith(prefix):
            return None
        raw = raw[len(prefix) :]
    return relative_path(raw)
