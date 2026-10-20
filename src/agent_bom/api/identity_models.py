"""Managed identity records and storage protocol."""

from __future__ import annotations

import builtins
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.identity_grants import AgentJITGrant
from agent_bom.api.identity_policies import ConditionalAccessPolicy


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AgentIdentity:
    """A managed agent identity and its lifecycle state."""

    identity_id: str
    agent_id: str
    tenant_id: str
    token_hash: str
    token_prefix: str
    role: str
    blueprint_id: str
    status: str  # active | rotating | revoked | expired
    issued_at: str
    expires_at: str
    # Per-tool scope allowlist. Empty = the identity may call any tool the
    # policy permits; non-empty = the identity is bounded to these tool names
    # ("*" allows all). Enforced at the gateway/proxy decision point so the
    # identity itself constrains authorization, not just the policy.
    allowed_tools: list[str] = field(default_factory=list)
    # Accountable owner of this ISSUED identity — the human / team / service that
    # provisioned it and is answerable for it. New identities are always
    # owner-bound at issue time (the issuing actor when no explicit owner is
    # given), so an agent-bom-issued identity carries the same attribution as a
    # discovered cloud NHI. Empty only for rows persisted before owner-binding
    # existed; ``owner_type`` is advisory (user | team | service).
    #
    # Migration: persisted JSON rows written before this field existed simply
    # lack the key and deserialize back to "" (no schema change needed — the
    # SQLite/Postgres stores keep the full dataclass as JSON ``data``).
    owner: str = ""
    owner_type: str = ""
    rotated_to_id: str = ""
    revoked_at: str = ""
    revoked_reason: str = ""
    # Last observed authentication time for this identity (ISO-8601, injected by
    # the runtime verifier). Drives dormant auto-deprovision; empty means the
    # identity has never been observed authenticating.
    last_used_at: str = ""
    # Advisory rotation flag. The cleanup loop sets this True when the token's
    # age exceeds the configured rotation window; the secret is never rotated
    # silently — an operator/automation rotates it explicitly via rotate_identity.
    rotation_due: bool = False
    rotation_due_at: str = ""
    # Per-identity quota DATA. These are surfaced via ``quota_state`` for the
    # gateway to enforce in a later PR; this store records them but does not
    # itself meter requests. 0 / unset means "no limit".
    max_requests_per_window: int = 0
    max_cost_usd_per_window: float = 0.0
    quota_window_seconds: int = 0

    def tool_allowed(self, tool_name: str) -> bool:
        """True when this identity may call ``tool_name`` (empty allowlist = any)."""
        if not self.allowed_tools:
            return True
        return "*" in self.allowed_tools or tool_name in self.allowed_tools

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize without the token hash."""
        d = asdict(self)
        d.pop("token_hash", None)
        return d

    def is_live(self, *, at: datetime | None = None) -> bool:
        """True when the identity may still authenticate (active or in rotation
        overlap, and not past expiry)."""
        if self.status in ("revoked", "expired"):
            return False
        now = at or _now()
        try:
            if self.expires_at and now > datetime.fromisoformat(self.expires_at):
                return False
        except ValueError:
            return False
        return self.status in ("active", "rotating")


class AgentIdentityStore(Protocol):
    def put(self, identity: AgentIdentity) -> None: ...

    def get(self, identity_id: str, *, tenant_id: str) -> AgentIdentity | None: ...

    def get_by_token_hash(self, token_hash: str) -> AgentIdentity | None: ...

    def list(self, tenant_id: str, *, include_inactive: bool = False, limit: int = 200) -> list[AgentIdentity]: ...

    def count(self, tenant_id: str, *, include_inactive: bool = False) -> int: ...

    def list_by_agent(self, tenant_id: str, agent_id: str, *, limit: int = 200) -> builtins.list[AgentIdentity]: ...

    def put_jit_grant(self, grant: AgentJITGrant, *, tenant_id: str) -> None: ...

    def get_jit_grant(self, grant_id: str, *, tenant_id: str) -> AgentJITGrant | None: ...

    def list_jit_grants(
        self,
        tenant_id: str,
        *,
        identity_id: str | None = None,
        include_inactive: bool = False,
        limit: int = 200,
    ) -> builtins.list[AgentJITGrant]: ...

    def active_jit_grant(
        self,
        tenant_id: str,
        identity_id: str,
        tool_name: str,
        *,
        at: datetime | None = None,
    ) -> AgentJITGrant | None: ...

    def iter_all_identities(self, *, limit: int = 10000) -> builtins.list[AgentIdentity]: ...

    def iter_all_jit_grants(self, *, limit: int = 10000) -> builtins.list[AgentJITGrant]: ...

    def put_conditional_policy(self, policy: ConditionalAccessPolicy, *, tenant_id: str) -> None: ...

    def get_conditional_policy(self, policy_id: str, *, tenant_id: str) -> ConditionalAccessPolicy | None: ...

    def list_conditional_policies(
        self,
        tenant_id: str,
        *,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> builtins.list[ConditionalAccessPolicy]: ...
