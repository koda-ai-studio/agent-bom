"""Managed identities are keyed by (tenant_id, identity_id): two tenants may hold the same id and never see each other's rows."""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL not set")

TENANTS = ("identity-key-a", "identity-key-b")


@pytest.fixture
def store():
    from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore
    from agent_bom.api.postgres_common import _maintenance_connection, bypass_tenant_rls, reset_pool

    reset_pool()
    identity_store = PostgresAgentIdentityStore()

    def purge() -> None:
        with bypass_tenant_rls(), _maintenance_connection() as conn:
            conn.execute("DELETE FROM agent_identity_jit_grants WHERE tenant_id = ANY(%s)", (list(TENANTS),))
            conn.execute("DELETE FROM agent_identities WHERE tenant_id = ANY(%s)", (list(TENANTS),))
            conn.commit()

    purge()
    yield identity_store
    purge()
    reset_pool()


def _identity(tenant_id: str, *, identity_id: str = "shared-identity", agent: str = "agent"):
    from agent_bom.api.agent_identity_store import AgentIdentity

    return AgentIdentity(
        identity_id=identity_id,
        agent_id=f"{agent}-{tenant_id}",
        tenant_id=tenant_id,
        token_hash=f"hash-{tenant_id}-{identity_id}",
        token_prefix="abid",
        role="agent",
        blueprint_id="",
        status="active",
        issued_at="2026-10-24T00:00:00+00:00",
        expires_at="2027-10-24T00:00:00+00:00",
    )


def _as(tenant_id: str):
    from agent_bom.api.tenant_worker import postgres_tenant_scope

    return postgres_tenant_scope(tenant_id)


def test_two_tenants_hold_the_same_identity_id_without_seeing_each_other(store):
    a, b = TENANTS
    with _as(a):
        store.put(_identity(a))
    with _as(b):
        store.put(_identity(b))
        store.put(replace(_identity(b), status="revoked"))

    with _as(a):
        mine = store.get("shared-identity", tenant_id=a)
        assert mine is not None and mine.tenant_id == a and mine.status == "active"
        assert [identity.tenant_id for identity in store.list(a, include_inactive=True)] == [a]
        assert store.get("shared-identity", tenant_id=b) is None
        assert store.list(b, include_inactive=True) == []
        assert store.get_by_token_hash(f"hash-{b}-shared-identity") is None
    with _as(b):
        theirs = store.get("shared-identity", tenant_id=b)
        assert theirs is not None and theirs.tenant_id == b and theirs.status == "revoked"
        assert store.count(b, include_inactive=True) == 1


def test_a_second_tenant_demo_seed_lands_beside_the_first(store, monkeypatch):
    from agent_bom.api import agent_identity_store
    from agent_bom.demo_estate.showcase_identities import seed_showcase_identities

    monkeypatch.setattr(agent_identity_store, "get_agent_identity_store", lambda: store)
    a, b = TENANTS
    for tenant in TENANTS:
        with _as(tenant):
            assert seed_showcase_identities(tenant)["seeded"] is True
    with _as(a):
        ids_a = {identity.identity_id for identity in store.list(a, include_inactive=True, limit=1000)}
    with _as(b):
        ids_b = {identity.identity_id for identity in store.list(b, include_inactive=True, limit=1000)}
        grants_b = store.list_jit_grants(b, include_inactive=True)
    assert ids_a == ids_b and ids_a
    assert grants_b and {grant.tenant_id for grant in grants_b} == {b}
