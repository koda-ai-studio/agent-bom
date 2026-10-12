"""Tenant-bound trace credentials resolved through the control-plane secret source.

Operators configure connection scope and secret references; browser users only
select an opaque connection ID. Missing, disabled, expired or mismatched bindings
fail closed without an ambient-credential or caller-supplied endpoint fallback.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.audit_log import log_action
from agent_bom.api.secret_source import resolve_secret


class TraceConnection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_id: str = Field(min_length=1)
    provider: Literal["langfuse", "langsmith"]
    display_name: str = Field(min_length=1, max_length=120)
    endpoint: str = Field(min_length=1)
    credentials_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    project: str = ""
    cloud_provider: str = Field(default="", max_length=80)
    account_id: str = Field(default="", max_length=256)
    environment: str = Field(default="", max_length=256)
    enabled: bool = True
    expires_at: str

    def available(self, tenant_id: str) -> bool:
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return bool(self.enabled and self.tenant_id == tenant_id and expires.tzinfo and expires > datetime.now(timezone.utc))


def _connections() -> dict[str, TraceConnection]:
    try:
        raw = resolve_secret("AGENT_BOM_TRACE_CONNECTIONS")
        if not raw:
            return {}
        if len(raw) > 1_048_576:
            raise ValueError("oversize configuration")
        data = json.loads(raw)
        if not isinstance(data, dict) or len(data) > 1000 or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", key) for key in data):
            raise ValueError("invalid configuration")
        return {key: TraceConnection.model_validate(value) for key, value in data.items()}
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=503, detail="Managed trace connections are unavailable. Contact the control-plane operator."
        ) from exc


def public_connections(tenant_id: str) -> list[dict[str, str]]:
    try:
        return [
            {"id": key, "provider": binding.provider, "display_name": binding.display_name}
            for key, binding in _connections().items()
            if binding.available(tenant_id)
        ]
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=503, detail="Managed trace connections are unavailable. Contact the control-plane operator."
        ) from exc


def pull_credentials(tenant_id: str, provider: str, body: dict, *, actor: str) -> dict[str, str]:
    if "connection_id" not in body:
        credentials = body.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            raise HTTPException(status_code=400, detail="Select a managed connection or supply connector credentials.")
        return credentials
    ref = body["connection_id"]
    if not isinstance(ref, str) or set(body) - {
        "connection_id",
        "limit",
        "screen_content",
        "import_id",
        "window_start",
        "window_end",
        "max_pages",
    }:
        raise HTTPException(status_code=400, detail="Managed connections do not accept credential or endpoint overrides.")
    binding = _connections().get(ref)
    try:
        available = binding is not None and binding.provider == provider and binding.available(tenant_id)
    except ValueError:
        available = False
    if not available or binding is None:
        raise HTTPException(status_code=404, detail="Managed trace connection is unavailable.")
    try:
        raw = resolve_secret(binding.credentials_env, required=True)
        if len(raw) > 65_536:
            raise ValueError("oversize credentials")
        credentials = json.loads(raw)
        expected = {"public_key", "secret_key"} if provider == "langfuse" else {"api_key"}
        if (
            not isinstance(credentials, dict)
            or set(credentials) != expected
            or any(not isinstance(value, str) or not value.strip() for value in credentials.values())
        ):
            raise ValueError("invalid credentials")
        if provider == "langsmith" and not binding.project.strip():
            raise ValueError("missing project scope")
        log_action("trace_connection.use", actor=actor, tenant_id=tenant_id, resource=f"trace_connection/{ref}", provider=provider)
        scope = {f"scope_{key}": getattr(binding, key) for key in ("cloud_provider", "account_id", "environment") if getattr(binding, key)}
        if provider == "langfuse":
            return {"host": binding.endpoint, "project": binding.project, **scope, **credentials}
        return {"api_url": binding.endpoint, "project": binding.project, **scope, **credentials}
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=503, detail="Managed trace credentials are unavailable. Contact the control-plane operator."
        ) from exc
