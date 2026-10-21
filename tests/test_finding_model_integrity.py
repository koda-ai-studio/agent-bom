"""Identity, source preservation and event-time finding lifecycle contracts."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore
from agent_bom.domain.finding_merge import merge_external_code_findings
from agent_bom.finding import Asset, Finding, FindingSource, FindingType


def test_account_local_asset_ids_do_not_collapse():
    findings = [
        Finding(
            FindingType.CIS_FAIL,
            FindingSource.EXTERNAL,
            Asset("warehouse", "cloud_resource", identifier="warehouse-01", provider="snowflake", account_ref=f"snowflake:{account}"),
            "high",
            title="Public resource",
        )
        for account in ("account-a", "account-b")
    ]
    assert findings[0].id != findings[1].id


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="Postgres application DSN required")
        ),
    ]
)
def store(request, tmp_path):
    if request.param == "postgres":
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
        from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

        backend = PostgresComplianceHubStore()
        prefix = uuid4().hex

        class ScopedStore:
            """Bind each real database call to an isolated test tenant."""

            def __getattr__(self, name):
                def call(tenant, *args, **kwargs):
                    tenant = prefix + tenant
                    token = set_current_tenant(tenant)
                    try:
                        return getattr(backend, name)(tenant, *args, **kwargs)
                    finally:
                        reset_current_tenant(token)

                return call

        return ScopedStore()
    return InMemoryComplianceHubStore() if request.param == "memory" else SQLiteComplianceHubStore(str(tmp_path / "audit.db"))


def test_late_observation_does_not_replace_current_severity(store):
    store.upsert_current_batch("audit", [{"id": "issue-1", "severity": "critical"}], observed_at="2026-10-21T10:00:00Z", batch_id="new")
    store.upsert_current_batch("audit", [{"id": "issue-1", "severity": "low"}], observed_at="2026-10-20T10:00:00Z", batch_id="late-old")
    assert store.get_current("audit", "issue-1")["severity"] == "critical"


def test_old_absence_does_not_resolve_new_observation(store):
    store.upsert_current_batch("audit", [{"id": "issue-1", "severity": "critical"}], observed_at="2026-10-21T10:00:00Z", batch_id="new")
    store.reconcile_current_absent("audit", present_canonical_ids=set(), observed_at="2026-10-20T10:00:00Z")
    assert store.get_current("audit", "issue-1")["status"] == "open"


def test_pre_resolution_observation_does_not_reopen(store):
    store.upsert_current_batch("audit", [{"id": "issue-1", "severity": "critical"}], observed_at="2026-10-19T10:00:00Z", batch_id="first")
    store.reconcile_current_absent("audit", present_canonical_ids=set(), observed_at="2026-10-21T10:00:00Z")
    store.upsert_current_batch("audit", [{"id": "issue-1", "severity": "critical"}], observed_at="2026-10-20T10:00:00Z", batch_id="late")
    assert store.get_current("audit", "issue-1")["status"] == "resolved"


def test_different_repositories_do_not_merge_by_path_suffix_and_cwe():
    native = Finding(
        FindingType.SAST,
        FindingSource.SAST,
        Asset("auth.py", "source_file", identifier="repo-a:src/auth.py", location="/repo-a/src/auth.py"),
        "low",
        cwe_ids=["CWE-89"],
        evidence={"file": "/repo-a/src/auth.py", "line": 10, "rule_id": "rule-a", "repository": "repo-a"},
    )
    external = Finding(
        FindingType.SAST,
        FindingSource.EXTERNAL,
        Asset("auth.py", "source_file", identifier="repo-b:src/auth.py", location="src/auth.py"),
        "critical",
        cwe_ids=["CWE-89"],
        evidence={
            "file": "src/auth.py",
            "line": 10,
            "rule_id": "rule-b",
            "repository": "repo-b",
            "external_tool": "scanner-b",
            "vendor_detail": "specific proof",
        },
    )
    assert len(merge_external_code_findings([native, external])) == 2


def _ingest(store, payload, at, batch):
    return store.ingest_batch_atomic(
        "audit",
        [payload],
        observed_at=at,
        batch_id=batch,
        source="test",
        reconcile_absent=False,
        present_canonical_ids={payload["id"]},
    )


@pytest.mark.parametrize("late_at,batch", [("2026-10-20T10:00:00Z", "older"), ("2026-10-22T10:00:00Z", "latest")])
def test_atomic_late_or_replayed_batch_preserves_current_payload(store, late_at, batch):
    latest = {"id": "one", "source": "test", "title": "Current", "severity": "critical", "description": "current proof"}
    older = {**latest, "title": "Old", "severity": "low", "description": "old proof"}
    _ingest(store, latest, "2026-10-21T10:00:00Z", "latest")
    _ingest(store, older, late_at, batch)
    row = store.get_current("audit", "one")
    assert row["severity"] == "critical"
    assert row["payload"]["title"] == "Current"
    assert store.list("audit")[0]["title"] == "Current"
    assert row["scan_count"] == (2 if batch == "older" else 1)


def test_equal_file_line_cwe_retains_both_vendor_observations():
    native = Finding(
        FindingType.SAST,
        FindingSource.SAST,
        Asset("auth.py", "source_file", identifier="auth.py"),
        "low",
        title="Native issue",
        cwe_ids=["CWE-89"],
        evidence={"file": "auth.py", "line": 10, "rule_id": "native"},
    )
    external = Finding(
        FindingType.SAST,
        FindingSource.EXTERNAL,
        Asset("auth.py", "source_file", identifier="auth.py"),
        "critical",
        title="Vendor issue",
        cwe_ids=["CWE-89"],
        evidence={"file": "auth.py", "line": 10, "rule_id": "vendor", "proof": "vendor proof"},
    )
    result = merge_external_code_findings([native, external])
    assert len(result) == 2
    assert external.evidence["proof"] == "vendor proof"
    assert external.severity == "critical"
    assert native.related_findings == [external.id]
    assert external.related_findings == [native.id]
    merge_external_code_findings(result)
    assert len(native.evidence["correlation_candidates"]) == 1


@pytest.mark.parametrize("other", ["account-b", "snowflake:account-b"])
def test_scoped_id_is_shared_by_model_and_ingest_fallback(other):
    from agent_bom.api.finding_lifecycle import resolve_canonical_id
    from agent_bom.domain.asset_identity import canonical_asset_id

    left = Asset("warehouse", "cloud_resource", identifier="local", provider="snowflake", account_ref="account-a")
    right = Asset("warehouse", "cloud_resource", identifier="local", provider="snowflake", account_ref=other)
    assert left.stable_id != right.stable_id
    assert left.stable_id == canonical_asset_id("cloud_resource", "local", provider="Snowflake", account_ref="snowflake:account-a")
    a, b = (
        {
            "asset": {
                "name": x.name,
                "asset_type": x.asset_type,
                "identifier": x.identifier,
                "provider": x.provider,
                "account_ref": x.account_ref,
            },
            "title": "issue",
        }
        for x in (left, right)
    )
    assert resolve_canonical_id(a) != resolve_canonical_id(b)


def test_qualified_and_non_cloud_asset_ids_keep_compatibility():
    from agent_bom.canonical_ids import canonical_id

    for identifier in ["pkg:pypi/requests@2.0", "arn:aws:iam::123456789012:role/test"]:
        asset = Asset("asset", "cloud_resource", identifier=identifier, provider="aws", account_ref="aws:123456789012")
        assert asset.stable_id == canonical_id("cloud_resource", identifier)
    assert Asset("file", "source_file", identifier="a.py").stable_id == canonical_id("source_file", "a.py")


def test_rehydration_preserves_recorded_identity_and_scope():
    from agent_bom.domain.finding_rehydrate import finding_from_dict

    finding = Finding(
        FindingType.CIS_FAIL,
        FindingSource.CLOUD_CIS,
        Asset("warehouse", "cloud_resource", identifier="local", provider="snowflake", account_ref="account-a"),
        "high",
        title="issue",
    )
    payload = finding.to_dict()
    payload["id"] = "historical-finding"
    payload["asset"]["canonical_id"] = "historical-asset"
    restored = finding_from_dict(payload)
    assert restored.id == "historical-finding"
    assert restored.asset.canonical_id == "historical-asset"
    assert restored.account_ref == "account-a"
    assert restored.to_dict()["asset"]["account_ref"] == "account-a"


def test_environment_reclassification_does_not_rename_asset():
    asset = Asset("warehouse", "cloud_resource", identifier="local", provider="snowflake", account_ref="account-a", environment="dev")
    original = asset.stable_id
    asset.environment = "prod"
    assert asset.stable_id == original


@pytest.mark.parametrize(
    "newer,older",
    [
        ("2026-10-21T10:00:00Z", "2026-10-21T11:00:00+02:00"),
        ("2026-10-21T10:00:00.000001Z", "2026-10-21T10:00:00Z"),
    ],
)
def test_temporal_order_uses_instants_not_timestamp_strings(store, newer, older):
    _ingest(store, {"id": "one", "source": "test", "title": "Current", "severity": "critical"}, newer, "new")
    _ingest(store, {"id": "one", "source": "test", "title": "Old", "severity": "low"}, older, "old")
    row = store.get_current("audit", "one")
    assert row["severity"] == "critical"
    assert row["payload"]["title"] == "Current"
    assert row["last_seen"] == newer
    assert row["first_seen"] == older
    store.reconcile_current_absent("audit", present_canonical_ids=set(), observed_at=older)
    assert store.get_current("audit", "one")["status"] == "open"


def test_new_observation_can_reopen_and_other_tenant_is_independent(store):
    _ingest(store, {"id": "one", "source": "test", "title": "First", "severity": "critical"}, "2026-10-19T10:00:00Z", "first")
    store.reconcile_current_absent("audit", present_canonical_ids=set(), observed_at="2026-10-20T10:00:00Z")
    _ingest(store, {"id": "one", "source": "test", "title": "Reopened", "severity": "high"}, "2026-10-21T10:00:00Z", "second")
    row = store.get_current("audit", "one")
    assert row["status"] == "reopened"
    assert row["payload"]["title"] == "Reopened"
    assert row["reopened_at"] == "2026-10-21T10:00:00Z"
    store.ingest_batch_atomic(
        "other",
        [{"id": "one", "title": "Other tenant", "severity": "low"}],
        observed_at="2026-10-18T10:00:00Z",
        batch_id="first",
        source="test",
        reconcile_absent=False,
        present_canonical_ids={"one"},
    )
    assert store.get_current("other", "one")["severity"] == "low"
    assert store.get_current("audit", "one")["severity"] == "high"


@pytest.mark.parametrize("scope", [{"repository": "other"}, {"repository_commit": "other"}])
def test_same_path_different_repository_or_revision_does_not_link(scope):
    findings = [
        Finding(
            FindingType.SAST,
            source,
            Asset("file", "source_file", identifier=str(index)),
            "high",
            title=str(index),
            cwe_ids=["CWE-89"],
            evidence={
                "file": "src/file.py",
                "line": 1,
                "rule_id": "same",
                **(
                    {"repository": "repo", "repository_commit": "rev"}
                    if index == 0
                    else {"repository": "repo", "repository_commit": "rev", **scope}
                ),
            },
        )
        for index, source in enumerate((FindingSource.SAST, FindingSource.EXTERNAL))
    ]
    assert len(merge_external_code_findings(findings)) == 2
    assert not any(f.related_findings for f in findings)


def test_source_native_scanner_and_repository_namespaces_keep_distinct_occurrences():
    def finding(**evidence):
        return Finding(
            FindingType.SAST,
            FindingSource.EXTERNAL,
            Asset("a.py", "source_file", identifier="a.py"),
            "high",
            title="same rule",
            evidence={"file": "a.py", "line": 1, "rule_id": "rule", **evidence},
        )

    findings = [
        finding(external_tool="scanner-a", repository="repo-a"),
        finding(external_tool="scanner-b", repository="repo-a"),
        finding(external_tool="scanner-a", repository="repo-b"),
    ]
    assert len({f.id for f in findings}) == 3
    assert finding(external_tool="scanner-a", repository="repo-a").id == findings[0].id
    assert finding(external_tool="scanner-a", repository="repo-a", repository_commit="new-revision").id == findings[0].id
    assert finding(external_tool="scanner-a", repository="repo-a", commit_sha="new-revision").id == findings[0].id


def test_ingest_normalization_preserves_subseconds_and_negative_offsets():
    from agent_bom.api.finding_lifecycle import normalize_observed_at

    assert normalize_observed_at("2026-10-21T12:00:00.000001+02:00") == "2026-10-21T10:00:00.000001Z"
    assert normalize_observed_at("2026-10-21T06:00:00-04:00") == "2026-10-21T10:00:00Z"


def test_missing_scanner_evidence_cannot_create_a_correlation():
    finding = Finding(FindingType.SAST, FindingSource.EXTERNAL, Asset("file", "source_file"), "high")
    finding.evidence = None
    assert merge_external_code_findings([finding]) == [finding]
    assert finding.related_findings == []


@pytest.mark.parametrize(
    "field,values",
    [("account_ref", ("aws:111111111111", "aws:222222222222")), ("provider", ("aws", "gcp")), ("region", ("us-east-1", "eu-west-1"))],
)
def test_bulk_fallback_ids_preserve_recorded_asset_scope(store, field, values):
    from agent_bom.api.bulk_findings_ingest import _normalized_bulk_finding

    rows = []
    for ordinal, value in enumerate(values):
        row = {
            "rule_id": "public-resource",
            "severity": "high",
            "provider": "aws",
            "account_ref": "aws:111111111111",
            "region": "us-east-1",
            "asset": {"asset_type": "cloud_resource", "identifier": "resource-01", "name": "resource"},
        }
        row[field] = value
        rows.append(_normalized_bulk_finding(row, source="vendor-a", batch_id="scope", ordinal=ordinal))
    assert rows[0]["id"] != rows[1]["id"]
    store.ingest_batch_atomic(
        "scoped-bulk",
        rows,
        observed_at="2026-10-21T12:00:00Z",
        batch_id="scope",
        source="vendor-a",
        reconcile_absent=False,
        present_canonical_ids={row["id"] for row in rows},
    )
    page, total, _ = store.list_current_page("scoped-bulk", limit=10)
    assert total == 2
    # Tier-A persistence may redact location fields; it must retain both
    # occurrence IDs after that projection rather than collapse the accounts.
    assert {row["id"] for row in page} == {row["id"] for row in rows}


def test_bulk_fallback_ids_preserve_explicit_asset_identity():
    from agent_bom.api.bulk_findings_ingest import _normalized_bulk_finding

    ids = []
    for identity in ("asset-a", "asset-b"):
        row = {"rule_id": "rule", "asset": {"name": "same label", "canonical_id": identity}}
        ids.append(_normalized_bulk_finding(row, source="vendor-a", batch_id="scope", ordinal=0)["id"])
    assert len(set(ids)) == 2


@pytest.mark.parametrize("field", ["provider", "account_ref", "region"])
def test_bulk_fallback_rejects_malformed_scope_without_server_error(field):
    from fastapi import HTTPException

    from agent_bom.api.bulk_findings_ingest import _normalized_bulk_finding

    with pytest.raises(HTTPException) as error:
        _normalized_bulk_finding({"rule_id": "rule", field: {"unexpected": "value"}}, source="vendor", batch_id="batch", ordinal=0)
    assert error.value.status_code == 422


def test_bulk_fallback_replays_and_mutable_environment_do_not_rename_identity():
    from agent_bom.api.bulk_findings_ingest import _normalized_bulk_finding

    row = {
        "rule_id": "rule",
        "provider": "aws",
        "account_ref": "aws:111111111111",
        "asset": {"asset_type": "cloud_resource", "identifier": "local-resource"},
    }
    first = _normalized_bulk_finding(row, source="vendor-a", batch_id="first", ordinal=0)
    second = _normalized_bulk_finding(
        {**row, "environment": "production", "severity": "critical"}, source="vendor-a", batch_id="second", ordinal=1
    )
    assert first["id"] == second["id"]
    other_vendor = _normalized_bulk_finding(row, source="vendor-b", batch_id="first", ordinal=0)
    assert other_vendor["id"] != first["id"]
    explicit = _normalized_bulk_finding({**row, "id": "caller-owned"}, source="vendor-a", batch_id="first", ordinal=0)
    assert explicit["id"] == "caller-owned"


def test_bulk_fallback_asset_display_name_is_not_identity():
    from agent_bom.api.bulk_findings_ingest import _normalized_bulk_finding

    ids = []
    for label in ("before rename", "after rename"):
        row = {"rule_id": "rule", "provider": "aws", "asset": {"identifier": "local-resource", "name": label}}
        ids.append(_normalized_bulk_finding(row, source="vendor", batch_id="batch", ordinal=0)["id"])
    assert len(set(ids)) == 1
