"""Fix availability splits the queue into "upgrade" and "mitigate".

The findings facet already counted fixable and unfixable findings, but the list
could not be narrowed to either: a reader saw "120 without a fix" and had no way
to ask for those 120, the findings that need a compensating control instead of
an upgrade. ``fix=available`` and ``fix=none`` use the facet's own definition (a
recorded fixed version or remediation version), through the predicate shared by
scan rows and hub rows, so the facet and the filter cannot disagree.
"""

from __future__ import annotations

import pytest

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.finding_scope import row_matches_scope
from agent_bom.finding_signal_filters import row_has_fix
from tests.api.test_scan_job_sla_history import get_rows, job
from tests.api.test_scan_job_sla_history import scan_store as history_store  # noqa: F401


@pytest.fixture
def scan_store(history_store):  # noqa: F811 - imported parametrized fixture
    return history_store


def _finding(cve: str, package: str, **extra: object) -> Finding:
    return Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name=package, asset_type="package", identifier=f"pkg:pypi/{package}@1.0.0"),
        severity="critical",
        cve_id=cve,
        title=f"{cve}: {package}@1.0.0",
        evidence={"package_name": package, "package_version": "1.0.0"},
        **extra,  # type: ignore[arg-type]
    )


def test_a_recorded_fixed_or_remediation_version_is_a_fix() -> None:
    assert row_has_fix({"fixed_version": "2.0.1"}) is True
    assert row_has_fix({"remediation_versions": ["", "3.1.0"]}) is True
    assert row_has_fix({"fixed_version": "  ", "remediation_versions": [" "]}) is False
    assert row_has_fix({}) is False


def test_fix_filter_selects_each_side_and_absent_means_unfiltered() -> None:
    fixable, unfixable = {"id": "a", "fixed_version": "2.0.1"}, {"id": "b"}
    assert row_matches_scope(fixable, {"fix": "available"}) and not row_matches_scope(unfixable, {"fix": "available"})
    assert row_matches_scope(unfixable, {"fix": "none"}) and not row_matches_scope(fixable, {"fix": "none"})
    assert row_matches_scope(fixable, {}) and row_matches_scope(unfixable, {})


def test_fix_composes_with_kev() -> None:
    row = {"id": "a", "is_kev": True}
    assert row_matches_scope(row, {"fix": "none", "kev": "true"}) is True
    assert row_matches_scope({**row, "fixed_version": "1.2"}, {"fix": "none", "kev": "true"}) is False


def test_the_list_filter_agrees_with_the_fixability_facet(scan_store) -> None:
    fixable, unfixable = _finding("CVE-2026-1111", "left-pad", fixed_version="1.0.1"), _finding("CVE-2026-2222", "right-pad")

    scan_store.put(job(9, findings=[fixable, unfixable]))
    everything = get_rows()
    assert len(everything) == 2
    available = get_rows(fix="available")
    none = get_rows(fix="none")
    assert [row["cve_id"] for row in available] == ["CVE-2026-1111"]
    assert [row["cve_id"] for row in none] == ["CVE-2026-2222"]


# SQLite and PostgreSQL share the scoped keyset walk (``scoped_page``) that applies the predicate.
@pytest.mark.parametrize("hub_kind", ["memory", "sqlite"])
def test_bulk_ingested_hub_rows_filter_by_fix_through_the_store(scan_store, hub_kind, tmp_path) -> None:
    from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore, get_compliance_hub_store, set_compliance_hub_store
    from tests._clock_helpers import recent

    if hub_kind == "sqlite":
        set_compliance_hub_store(SQLiteComplianceHubStore(str(tmp_path / "hub.db")))

    rows = [
        {"id": f"bulk:{cve}", "title": cve, "cve_id": cve, "severity": "high", "origin": "bulk_ingest", "source": "fix-test", **extra}
        for cve, extra in (("CVE-2026-3333", {"fixed_version": "4.0.0"}), ("CVE-2026-4444", {}))
    ]
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    hub = get_compliance_hub_store()
    # Row-level security binds writes to the request tenant, as the API middleware does.
    token = set_current_tenant("history-tenant")
    try:
        hub.add("history-tenant", rows)
        hub.upsert_current_batch("history-tenant", rows, observed_at=recent("2026-09-01T00:00:00Z"), batch_id="b1", source="fix-test")
    finally:
        reset_current_tenant(token)
    assert {row["cve_id"] for row in get_rows(fix="available")} == {"CVE-2026-3333"}
    assert {row["cve_id"] for row in get_rows(fix="none")} == {"CVE-2026-4444"}
