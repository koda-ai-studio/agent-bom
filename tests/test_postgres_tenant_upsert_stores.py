"""Real Postgres: every store keyed by a global id rejects another tenant's id the same way.

A write whose id already belongs to another tenant raises ``ValueError`` and
leaves that tenant's row as it was, instead of surfacing a database error or
moving the row across tenants.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")


@pytest.fixture(autouse=True)
def _fresh_pool() -> Iterator[None]:
    from agent_bom.api import postgres_common

    postgres_common.reset_pool()
    yield
    if postgres_common._pool is not None:
        postgres_common._pool.close()
    postgres_common.reset_pool()


@contextmanager
def _as_tenant(tenant: str) -> Iterator[None]:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def _tenants(label: str) -> tuple[str, str]:
    suffix = uuid4().hex[:12]
    return f"{label}-a-{suffix}", f"{label}-b-{suffix}"


def test_gateway_policy_id_of_another_tenant_is_rejected_and_not_moved() -> None:
    from agent_bom.api.policy_store import GatewayPolicy
    from agent_bom.api.postgres_policy import PostgresPolicyStore

    store = PostgresPolicyStore()
    tenant_a, tenant_b = _tenants("policy")
    policy_id = f"policy-{uuid4().hex}"
    with _as_tenant(tenant_a):
        store.put_policy(GatewayPolicy(policy_id=policy_id, name="owned by a", tenant_id=tenant_a))
        store.put_policy(GatewayPolicy(policy_id=policy_id, name="renamed by a", tenant_id=tenant_a))
    with _as_tenant(tenant_b):
        with pytest.raises(ValueError, match="different tenant"):
            store.put_policy(GatewayPolicy(policy_id=policy_id, name="claimed by b", tenant_id=tenant_b))
        assert store.get_policy(policy_id, tenant_id=tenant_b) is None
    with _as_tenant(tenant_a):
        kept = store.get_policy(policy_id, tenant_id=tenant_a)
        assert kept is not None and (kept.name, kept.tenant_id) == ("renamed by a", tenant_a)
        assert store.delete_policy(policy_id, tenant_id=tenant_a)


def test_model_provider_and_virtual_key_ids_of_another_tenant_are_rejected() -> None:
    from agent_bom.api.model_key_broker import ModelProviderKey, VirtualModelKey
    from agent_bom.api.postgres_model_key_broker import PostgresModelKeyBrokerStore

    store = PostgresModelKeyBrokerStore()
    tenant_a, tenant_b = _tenants("broker")
    provider = ModelProviderKey(
        provider_key_id=f"pk-{uuid4().hex}",
        tenant_id=tenant_a,
        provider="openai",
        display_name="a",
        secret_encrypted="ciphertext",
        created_at="2026-11-12T00:00:00Z",
    )
    virtual = VirtualModelKey(
        virtual_key_id=f"vk-{uuid4().hex}",
        tenant_id=tenant_a,
        provider_key_id=provider.provider_key_id,
        provider="openai",
        token_hash=uuid4().hex,
        token_prefix="abvk_test",
        holder_id="holder",
        issued_at="2026-11-12T00:00:00Z",
    )
    with _as_tenant(tenant_a):
        store.put_provider_key(provider)
        store.put_provider_key(replace(provider, status="revoked"))
        store.put_virtual_key(virtual)
        store.put_virtual_key(replace(virtual, status="revoked"))
    with _as_tenant(tenant_b):
        with pytest.raises(ValueError, match="different tenant"):
            store.put_provider_key(replace(provider, tenant_id=tenant_b, display_name="b"))
        with pytest.raises(ValueError, match="different tenant"):
            store.put_virtual_key(replace(virtual, tenant_id=tenant_b, token_hash=uuid4().hex))
        assert store.get_provider_key(provider.provider_key_id, tenant_id=tenant_b) is None
        assert store.get_virtual_key(virtual.virtual_key_id, tenant_id=tenant_b) is None
    with _as_tenant(tenant_a):
        kept_provider = store.get_provider_key(provider.provider_key_id, tenant_id=tenant_a)
        kept_virtual = store.get_virtual_key(virtual.virtual_key_id, tenant_id=tenant_a)
        assert kept_provider is not None and (kept_provider.display_name, kept_provider.status) == ("a", "revoked")
        assert kept_virtual is not None and kept_virtual.status == "revoked"
        assert store.delete_provider_key(provider.provider_key_id, tenant_id=tenant_a)


def test_api_key_id_of_another_tenant_is_rejected_and_not_moved() -> None:
    from agent_bom.api.auth import Role, create_api_key
    from agent_bom.api.postgres_access import PostgresKeyStore

    store = PostgresKeyStore()
    tenant_a, tenant_b = _tenants("apikey")
    _, key_a = create_api_key("owner-a", Role.ADMIN, tenant_id=tenant_a)
    _, key_b = create_api_key("owner-b", Role.ADMIN, tenant_id=tenant_b)
    store.provision_tenant_key(key_a, team_name="Tenant A")
    store.provision_tenant_key(key_b, team_name="Tenant B")
    with _as_tenant(tenant_a):
        store.add(replace(key_a, name="renamed by a"))
    with _as_tenant(tenant_b):
        _, other = create_api_key("owner-b", Role.ADMIN, tenant_id=tenant_b)
        with pytest.raises(ValueError, match="different tenant"):
            store.add(replace(other, key_id=key_a.key_id))
        assert store.get(key_a.key_id) is None
    with _as_tenant(tenant_a):
        kept = store.get(key_a.key_id)
        assert kept is not None and (kept.name, kept.tenant_id) == ("renamed by a", tenant_a)
