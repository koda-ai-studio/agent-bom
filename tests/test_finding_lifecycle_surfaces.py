"""Lifecycle contract outside the routes: public projection, deltas, CLI and client wiring."""

from __future__ import annotations

from typing import Any

from click.testing import CliRunner

from agent_bom.api.bulk_findings_ingest import BulkScanRun, reconcile_skip_reasons
from agent_bom.api.finding_lifecycle import enriched_finding_payload, ingest_asset_key, ingest_asset_scope, lifecycle_fields
from agent_bom.delta_stream import FindingSnapshot, resolved_canonical_ids
from agent_bom.finding_scope import safe_finding_response_payload


def test_resolved_at_only_describes_a_resolution_in_force() -> None:
    fields = lifecycle_fields("reopened", first_seen="T1", resolved_at="T2", reopened_at="T3")
    assert fields == {"status": "reopened", "resolved_at": None, "last_resolved_at": "T2", "reopened_at": "T3", "status_updated_at": "T3"}
    assert lifecycle_fields("resolved", first_seen="T1", resolved_at="T2", reopened_at=None)["status_updated_at"] == "T2"
    assert lifecycle_fields("open", first_seen="T1", resolved_at=None, reopened_at=None)["status_updated_at"] == "T1"


def test_hub_row_projects_the_same_public_fields() -> None:
    payload = enriched_finding_payload(
        {
            "status": "reopened",
            "first_seen": "2026-10-01T00:00:00Z",
            "last_seen": "2026-10-03T00:00:00Z",
            "resolved_at": "2026-10-02T00:00:00Z",
            "reopened_at": "2026-10-03T00:00:00Z",
            "payload": {"id": "f-1", "severity": "high"},
        }
    )
    public = safe_finding_response_payload(payload)
    assert public["resolved_at"] is None
    assert public["last_resolved_at"] == "2026-10-02T00:00:00Z"
    assert public["status_updated_at"] == "2026-10-03T00:00:00Z"


def test_asset_scope_is_opaque_and_never_public() -> None:
    row = {"asset": {"identifier": "arn:aws:s3:::private-bucket"}}
    key = ingest_asset_key(row)
    assert "private-bucket" not in key
    assert key == ingest_asset_scope("arn:aws:s3:::private-bucket")
    assert ingest_asset_key({}) == ""
    assert "ingest_asset" not in safe_finding_response_payload({"id": "f-1", "severity": "low", "ingest_asset": key})


def test_resolved_delta_covers_only_scanned_assets() -> None:
    def snapshot(name: str, asset: str) -> FindingSnapshot:
        return FindingSnapshot.from_finding({"canonical_id": name, "severity": "high", "ingest_asset": asset})

    prior = {"a": snapshot("a", "asset-a"), "b": snapshot("b", "asset-b"), "kept": snapshot("kept", "asset-a")}
    assert resolved_canonical_ids(prior, {"kept"}, {"asset-a"}) == {"a"}
    assert resolved_canonical_ids(prior, {"kept"}) == {"a", "b"}


def test_incomplete_receipts_skip_reconciliation() -> None:
    assert reconcile_skip_reasons(None) == []
    assert reconcile_skip_reasons(BulkScanRun(outcome="complete")) == []
    assert reconcile_skip_reasons(BulkScanRun(outcome="failed")) == ["scan_failed"]
    outage = {"code": "scanner_warning", "source": "vulnerability-data", "affects_coverage": True}
    assert reconcile_skip_reasons(BulkScanRun(outcome="partial", issues=[outage])) == ["advisory_data_degraded"]
    accepted = {**outage, "affects_coverage": False}
    assert reconcile_skip_reasons(BulkScanRun(outcome="complete", issues=[accepted])) == []


def test_cli_push_sends_the_declared_reconcile_scope(tmp_path: Any, monkeypatch: Any) -> None:
    from agent_bom.cli import _findings_group

    calls: dict[str, Any] = {}

    class Client:
        def __init__(self, **_: Any) -> None:
            pass

        def close(self) -> None:
            pass

        def ingest_findings(self, findings: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
            calls.update(kwargs)
            return {"ingested": len(findings)}

    monkeypatch.setattr(_findings_group, "AgentBomClient", Client, raising=False)
    monkeypatch.setattr(_findings_group, "_make_client", lambda *args, **kwargs: Client())
    report = tmp_path / "findings.json"
    report.write_text('[{"id": "f-1", "severity": "low"}]', encoding="utf-8")
    result = CliRunner().invoke(
        _findings_group.findings_cmd,
        ["push", str(report), "--api-url", "http://127.0.0.1:1", "--reconcile", "--scanned-asset", "host-a", "--scanned-asset", "host-b"],
    )
    assert result.exit_code == 0, result.output
    assert calls["reconcile_absent"] is True
    assert calls["reconcile_options"] == {"reconcile_scope": "assets", "scanned_assets": ["host-a", "host-b"]}


def test_client_omits_scope_fields_when_not_declared() -> None:
    from agent_bom.client import AgentBomClient

    sent: dict[str, Any] = {}
    client = AgentBomClient.__new__(AgentBomClient)
    client.tenant_id = None  # type: ignore[assignment]
    client._request = lambda method, path, **kwargs: sent.update(kwargs) or {}  # type: ignore[method-assign]
    client.ingest_findings([{"id": "f-1"}], source="ci")
    assert "reconcile_scope" not in sent["json"]
    assert "scanned_assets" not in sent["json"]
    options = {"reconcile_scope": "source", "scanned_assets": ["host-a"]}
    client.ingest_findings([{"id": "f-1"}], source="ci", reconcile_absent=True, reconcile_options=options)
    assert sent["json"]["reconcile_scope"] == "source"
    assert sent["json"]["scanned_assets"] == ["host-a"]
