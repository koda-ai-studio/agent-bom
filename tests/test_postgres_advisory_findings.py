"""Advisory findings persisted on Postgres: same logical key in two tenants, both kept, none leaked, retire scoped."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADVISORY = json.loads((ROOT / "tests/fixtures/php2shell/operator-advisory.json").read_text())
REPORTS = json.loads((ROOT / "tests/fixtures/php2shell/affected-reports.json").read_text())


def _require_postgres() -> None:
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres (AGENT_BOM_POSTGRES_URL)")


def _open_rows(store, tenant: str) -> dict[str, dict]:
    rows, _total, _cursor = store.list_current_page(tenant, limit=100, status="open")
    payloads = [row.get("payload") if isinstance(row.get("payload"), dict) else row for row in rows]
    return {payload["package"]: payload for payload in payloads if payload.get("cve_id") == "CVE-2026-109618"}


def test_advisory_findings_are_tenant_isolated_and_retire_per_tenant_on_postgres() -> None:
    _require_postgres()
    from agent_bom.api import compliance_hub_store
    from agent_bom.api.advisory_affected_read import persist_affected_answer, retire_advisory_findings
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore
    from agent_bom.api.storage.hub_contract import ComplianceHubStore
    from agent_bom.scanners.advisory_affected import affected_answer
    from agent_bom.scanners.operator_advisory import OperatorAdvisory

    answer = affected_answer(OperatorAdvisory.model_validate(ADVISORY), REPORTS)
    tenant_a, tenant_b = f"adv-{uuid.uuid4().hex}", f"adv-{uuid.uuid4().hex}"
    store: ComplianceHubStore = PostgresComplianceHubStore()
    compliance_hub_store.set_compliance_hub_store(store)
    try:
        for tenant in (tenant_a, tenant_b):
            token = set_current_tenant(tenant)
            try:
                assert persist_affected_answer(tenant, answer)["persisted"] == 2
            finally:
                reset_current_tenant(token)
        for tenant in (tenant_a, tenant_b):
            token = set_current_tenant(tenant)
            try:
                rows = _open_rows(store, tenant)
                assert set(rows) == {"php", "php8.2-cli"}
                assert rows["php8.2-cli"]["severity"] == "unknown"
            finally:
                reset_current_tenant(token)

        token = set_current_tenant(tenant_a)
        try:
            assert retire_advisory_findings(tenant_a, "CVE-2026-109618") == 2
            assert _open_rows(store, tenant_a) == {}
        finally:
            reset_current_tenant(token)
        token = set_current_tenant(tenant_b)
        try:
            assert set(_open_rows(store, tenant_b)) == {"php", "php8.2-cli"}
        finally:
            reset_current_tenant(token)
    finally:
        compliance_hub_store.reset_compliance_hub_store()
