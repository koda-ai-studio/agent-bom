"""Showcase identities shared by demo bootstrap and graph projections."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.agent_identity_store import AgentIdentity, AgentJITGrant, InMemoryAgentIdentityStore
from agent_bom.demo_estate.showcase_constants import SHOWCASE_TENANT
from agent_bom.graph.container import UnifiedGraph

# Deterministic non-human-identity estate for the demo. Identity ids are stable
# across restarts so the persisted MANAGED_IDENTITY graph nodes and the live
# identity store agree — the governance overlay re-runs at request time and must
# not inject a *second*, duplicate set of identities. Each row is shaped to tell
# one clear NHI-governance story:
#   * an over-granted but owned + active identity (standing tool scopes it never
#     uses → right-size),
#   * a dormant + orphaned admin identity that reaches an exposed resource (the
#     textbook worst case → deprovision), and
#   * clean, owned, least-privilege identities for contrast.
_DEMO_IDENTITIES: tuple[dict[str, Any], ...] = (
    {
        "slug": "cursor",
        "agent_label": "Cursor IDE Agent",
        "role": "prod-admin",
        "owner": "platform-team@corp",
        "owner_type": "team",
        "allowed_tools": ["run_shell", "exec_command", "read_file", "execute_sql", "query_vectors"],
        "last_used_days": 1,
    },
    {
        "slug": "support-copilot",
        "agent_label": "Support Copilot",
        "role": "support-admin",
        "owner": "",  # orphaned — no accountable owner
        "owner_type": "",
        "allowed_tools": ["send_email", "create_ticket", "search_tickets"],
        "last_used_days": None,  # never observed → dormant
        "privileged": True,
        "internet_exposed": True,
    },
    {
        "slug": "data-pipeline",
        "agent_label": "Data Pipeline Agent",
        "role": "data-pipeline",
        "owner": "data-eng@corp",
        "owner_type": "team",
        "allowed_tools": [],  # least privilege — access is JIT-granted
        "last_used_days": 2,
    },
    {
        "slug": "langchain-service",
        "agent_label": "LangChain Service Agent",
        "role": "service",
        "owner": "ml-platform@corp",
        "owner_type": "team",
        "allowed_tools": [],
        "last_used_days": 3,
    },
    {
        "slug": "claude-desktop",
        "agent_label": "Claude Desktop Agent",
        "role": "agent",
        "owner": "",  # orphaned
        "owner_type": "",
        "allowed_tools": [],
        "last_used_days": None,  # dormant
    },
)


# JIT grants that light up ACCESS_GRANT nodes for the least-privilege identities.
_DEMO_JIT_GRANTS: tuple[tuple[str, str], ...] = (
    ("cursor", "run_shell"),
    ("data-pipeline", "execute_sql"),
    ("langchain-service", "eval_expression"),
)


def _demo_identity_id(slug: str) -> str:
    return f"demo-nhi-{slug}"


def demo_identity_records(tenant_id: str = SHOWCASE_TENANT) -> tuple[list[AgentIdentity], list[AgentJITGrant]]:
    """Return the deterministic enriched demo identities + JIT grants.

    Single source of truth shared by the persisted graph seed and the live
    identity-store seed so both carry identical ids and attributes.
    """
    now = datetime.now(timezone.utc)
    issued_at = (now - timedelta(days=120)).isoformat()
    expires_at = (now + timedelta(days=90)).isoformat()

    identities: list[AgentIdentity] = []
    by_slug: dict[str, str] = {}
    for spec in _DEMO_IDENTITIES:
        slug = str(spec["slug"])
        identity_id = _demo_identity_id(slug)
        by_slug[slug] = identity_id
        last_used_days = spec.get("last_used_days")
        last_used_at = "" if last_used_days is None else (now - timedelta(days=int(last_used_days))).isoformat()
        identities.append(
            AgentIdentity(
                identity_id=identity_id,
                agent_id=str(spec["agent_label"]),
                tenant_id=tenant_id,
                token_hash=f"demo-nhi-hash-{slug}",
                token_prefix="demo",
                role=str(spec.get("role") or "agent"),
                blueprint_id=str(spec["agent_label"]),
                status="active",
                issued_at=issued_at,
                expires_at=expires_at,
                allowed_tools=list(spec.get("allowed_tools") or []),
                owner=str(spec.get("owner") or ""),
                owner_type=str(spec.get("owner_type") or ""),
                last_used_at=last_used_at,
            )
        )

    grants: list[AgentJITGrant] = []
    approved_at = (now - timedelta(hours=2)).isoformat()
    grant_expiry = (now + timedelta(hours=1)).isoformat()
    for slug, tool_name in _DEMO_JIT_GRANTS:
        grant_identity_id = by_slug.get(slug)
        if not grant_identity_id:
            continue
        grants.append(
            AgentJITGrant(
                grant_id=f"demo-jit-{slug}-{tool_name}",
                identity_id=grant_identity_id,
                agent_id=next(str(s["agent_label"]) for s in _DEMO_IDENTITIES if s["slug"] == slug),
                tenant_id=tenant_id,
                tool_name=tool_name,
                status="active",
                requested_at=approved_at,
                requested_by="oncall@corp",
                approved_at=approved_at,
                approved_by="oncall@corp",
                starts_at=approved_at,
                expires_at=grant_expiry,
                ticket_id=f"OPS-{slug.upper()}",
            )
        )
    return identities, grants


def build_demo_identity_store(tenant_id: str = SHOWCASE_TENANT) -> InMemoryAgentIdentityStore:
    """A throwaway identity store pre-loaded with the demo NHI estate."""
    store = InMemoryAgentIdentityStore()
    identities, grants = demo_identity_records(tenant_id)
    for identity in identities:
        store.put(identity)
    for grant in grants:
        store.put_jit_grant(grant, tenant_id=grant.tenant_id)
    return store


def seed_showcase_identities(tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Populate the LIVE agent-identity store with the demo NHI estate.

    Idempotent and independent of the graph seed so the NHI/Identity overview
    tile and the ``/v1/*/nhi/governance`` posture survive a restart even when the
    graph snapshot already exists. Only ever runs under demo-estate mode.
    """
    from agent_bom.api.agent_identity_store import get_agent_identity_store

    store = get_agent_identity_store()
    existing = {i.identity_id for i in store.list(tenant_id, include_inactive=True, limit=1000)}
    if any(iid.startswith("demo-nhi-") for iid in existing):
        return {"seeded": False, "reason": "identities_present", "count": len(existing)}

    identities, grants = demo_identity_records(tenant_id)
    for identity in identities:
        store.put(identity)
    for grant in grants:
        store.put_jit_grant(grant, tenant_id=grant.tenant_id)
    return {"seeded": True, "identities": len(identities), "jit_grants": len(grants)}


def _annotate_demo_identity_risk(graph: UnifiedGraph) -> None:
    """Pin privilege / exposure signals the identity record cannot carry.

    ``AgentIdentity`` has no privilege or internet-exposure field, so the
    governance evaluator would otherwise only see dormancy/ownership. Stamp the
    curated signals directly onto the persisted MANAGED_IDENTITY node so the demo
    surfaces at least one clearly high/critical NHI (a dormant, orphaned, admin
    identity). Node ids are deterministic; safe to call on any showcase snapshot.
    """
    for spec in _DEMO_IDENTITIES:
        node = graph.nodes.get(f"managed_identity:{_demo_identity_id(str(spec['slug']))}")
        if node is None:
            continue
        if spec.get("privileged"):
            node.attributes["privilege_level"] = "admin"
            node.attributes["is_admin"] = True
        if spec.get("internet_exposed"):
            node.attributes["internet_exposed"] = True
