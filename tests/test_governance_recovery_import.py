"""Recovery preserves disabled policies, quarantine, and historical waiver decisions."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.exception_store import ExceptionStatus, SQLiteExceptionStore, VulnException
from agent_bom.api.fleet_store import FleetAgent, FleetEndpoint, FleetLifecycleState, SQLiteFleetStore
from agent_bom.api.policy_store import GatewayPolicy, SQLitePolicyStore
from agent_bom.api.storage.registry_import import import_registries, read_source
from tests.sqlite_snapshot import checkpointed_bytes

TABLES = ["fleet_agents", "fleet_endpoints", "gateway_policies", "exceptions"]


@pytest.mark.parametrize("resource", [{}, {"kind": "Pod", "namespace": "dev", "labels": {"env": "dev"}}])
def test_recovery_decodes_iac_scope_without_changing_the_decision(tmp_path, resource):
    path = tmp_path / "iac.db"
    waiver = VulnException(
        tenant_id="source",
        iac_rule_id="K8S-001",
        iac_path="dev/**",
        iac_resource=resource,
        status=ExceptionStatus.REVOKED,
        approved_by="reviewer",
        revoked_at="2026-10-02T00:00:00Z",
    )
    SQLiteExceptionStore(str(path)).put(waiver, tenant_id="source")
    before = checkpointed_bytes(path)
    [(table, record, payload)] = read_source(path, {"source": "target"}, ["exceptions"])
    assert table == "exceptions"
    assert record.iac_resource == resource
    assert payload["iac_resource"] == resource
    assert record.iac_rule_id == "K8S-001" and record.iac_path == "dev/**"
    assert record.tenant_id == "target" and record.status == ExceptionStatus.REVOKED
    assert record.approved_by == "reviewer" and record.revoked_at == waiver.revoked_at
    assert path.read_bytes() == before


@pytest.mark.parametrize("raw", ["not-json", "[]", "null", '"Pod"'])
def test_recovery_rejects_malformed_iac_resource(raw):
    from agent_bom.api.storage.canonical_import import CONTROL_TABLES

    with pytest.raises(ValueError):
        CONTROL_TABLES["exceptions"].decode({"status": "revoked", "iac_resource": raw})


def seed(path, *, iac=False):
    suffix = uuid4().hex
    fleet = SQLiteFleetStore(str(path))
    agent = FleetAgent(
        agent_id=suffix,
        name="Retired agent",
        agent_type="custom",
        tenant_id="source",
        lifecycle_state=FleetLifecycleState.DECOMMISSIONED,
        created_at="2026-10-01T00:00:00Z",
    )
    endpoint = FleetEndpoint(endpoint_id=suffix, tenant_id="source", completeness="partial", observed_at="2026-10-01T00:00:00Z")
    fleet.put(agent)
    fleet.put_endpoint(endpoint)
    policy = GatewayPolicy(policy_id=suffix, name="Disabled policy", tenant_id="source", enabled=False)
    SQLitePolicyStore(str(path)).put_policy(policy)
    waiver = VulnException(
        exception_id=suffix,
        tenant_id="source",
        vuln_id="" if iac else "CVE-2026-0001",
        package_name="" if iac else "fixture",
        iac_rule_id="K8S-001" if iac else "",
        iac_path="dev/**" if iac else "",
        iac_resource={"kind": "Pod", "labels": {"env": "dev"}} if iac else {},
        status=ExceptionStatus.REVOKED,
        approved_by="reviewer",
        approved_at="2026-10-01T00:00:00Z",
        revoked_at="2026-10-02T00:00:00Z",
        expires_at="2026-10-03T00:00:00Z",
        approval_version=1,
    )
    SQLiteExceptionStore(str(path)).put(waiver, tenant_id="source")
    return agent, endpoint, policy, waiver


def test_governance_recovery_reads_without_reactivating_or_mutating_source(tmp_path):
    path = tmp_path / "governance.db"
    seed(path)
    before = checkpointed_bytes(path)
    records = read_source(path, {"source": "target"}, TABLES)
    by_table = {t: payload for t, _, payload in records}
    assert by_table["fleet_agents"]["lifecycle_state"] == "decommissioned"
    assert by_table["gateway_policies"]["enabled"] is False
    assert by_table["exceptions"]["status"] == "revoked"
    assert by_table["exceptions"]["approved_by"] == "reviewer"
    assert path.read_bytes() == before


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
@pytest.mark.parametrize("iac", [False, True])
def test_governance_recovery_dry_run_repeat_conflict_and_tenant_isolation(tmp_path, iac):
    from agent_bom.api.postgres_access import PostgresExceptionStore
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_fleet_store import PostgresFleetStore
    from agent_bom.api.postgres_policy import PostgresPolicyStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "governance.db"
    agent, endpoint, policy, waiver = seed(path, iac=iac)
    target = "recovery-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        from agent_bom.api.auth import Role, create_api_key
        from agent_bom.api.postgres_access import PostgresKeyStore

        _, key = create_api_key(name="Recovery fixture", role=Role.ADMIN, tenant_id=target)
        PostgresKeyStore(pool=pool).provision_tenant_key(key, team_name="Recovery fixture")
        assert import_registries(path, {"source": target}, TABLES, pool=pool)["inserted"] == 4
        with tenant_scope(target):
            assert PostgresFleetStore(pool=pool).get(agent.agent_id, tenant_id=target) is None
        receipt = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert receipt["committed"] and receipt["inserted"] == 4
        assert import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)["unchanged"] == 4
        with tenant_scope(target):
            assert PostgresFleetStore(pool=pool).get(agent.agent_id, tenant_id=target).lifecycle_state == FleetLifecycleState.DECOMMISSIONED
            assert not PostgresPolicyStore(pool=pool).get_policy(policy.policy_id, tenant_id=target).enabled
            restored = PostgresExceptionStore(pool=pool).get(waiver.exception_id, tenant_id=target)
            assert restored.status == ExceptionStatus.REVOKED and not restored.matches(waiver.vuln_id, waiver.package_name)
            assert (restored.iac_rule_id, restored.iac_path, restored.iac_resource) == (
                waiver.iac_rule_id,
                waiver.iac_path,
                waiver.iac_resource,
            )
        with tenant_scope("other"):
            assert PostgresExceptionStore(pool=pool).get(waiver.exception_id, tenant_id=target) is None
        waiver.reason = "Changed historical decision"
        SQLiteExceptionStore(str(path)).put(waiver, tenant_id="source")
        assert not import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)["committed"]
    finally:
        pool.close()
