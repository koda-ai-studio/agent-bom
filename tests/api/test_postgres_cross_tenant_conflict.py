"""An upsert onto another tenant's row is reported as the store's own refusal.

Postgres may enforce the tenant boundary itself, raising an RLS ``USING`` error
for the existing row before the ``ON CONFLICT ... WHERE`` guard filters it. The
stores must report that the same way as a filtered update: a ``ValueError``
naming the different tenant, never a raw database error.
"""

from __future__ import annotations

import pytest

from agent_bom.api.postgres_tenant_conflict import cross_tenant_conflict_as

errors = pytest.importorskip("psycopg.errors")


_RLS_USING = 'new row violates row-level security policy (USING expression) for table "credential_refs"'


def test_rls_using_violation_becomes_the_tenant_refusal() -> None:
    with pytest.raises(ValueError, match="different tenant") as raised:
        with cross_tenant_conflict_as("Credential identity belongs to a different tenant"):
            raise errors.InsufficientPrivilege(_RLS_USING)
    assert raised.value.__cause__ is None


def test_other_privilege_errors_are_not_masked() -> None:
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with cross_tenant_conflict_as("x belongs to a different tenant"):
            raise errors.InsufficientPrivilege("permission denied for table credential_refs")


def test_with_check_violations_are_not_masked() -> None:
    message = 'new row violates row-level security policy for table "credential_refs"'
    with pytest.raises(errors.InsufficientPrivilege):
        with cross_tenant_conflict_as("x belongs to a different tenant"):
            raise errors.InsufficientPrivilege(message)


def test_other_errors_pass_through() -> None:
    with pytest.raises(errors.UniqueViolation):
        with cross_tenant_conflict_as("x belongs to a different tenant"):
            raise errors.UniqueViolation(_RLS_USING)


@pytest.mark.parametrize(
    ("module", "marker"),
    [
        ("agent_bom.api.postgres_policy", "scan_schedules.tenant_id = EXCLUDED.tenant_id"),
        ("agent_bom.api.postgres_policy", "credential_refs.tenant_id = EXCLUDED.tenant_id"),
        ("agent_bom.api.source_postgres", "control_plane_sources.tenant_id = EXCLUDED.tenant_id"),
        ("agent_bom.api.postgres_agent_identity", "agent_identity_jit_grants.tenant_id = EXCLUDED.tenant_id"),
        ("agent_bom.api.postgres_agent_identity", "agent_conditional_access_policies.tenant_id = EXCLUDED.tenant_id"),
    ],
)
def test_every_tenant_guarded_upsert_translates_the_rls_refusal(module: str, marker: str) -> None:
    import importlib
    import inspect

    source = inspect.getsource(importlib.import_module(module))
    upsert_at = source.index(marker)
    statement_start = source.rfind("conn.execute(", 0, upsert_at)
    preceding = source[source.rfind("\n    def ", 0, statement_start) : statement_start]
    assert "with cross_tenant_conflict_as(" in preceding, f"{module}: {marker} is not wrapped"
