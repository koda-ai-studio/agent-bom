"""Execution completeness derived from native cloud collection receipts.

Failed controls describe posture, not collection quality. Denied reads,
warnings and unevaluated checks keep a snapshot partial so reconciliation
cannot treat its missing resources as deletions.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from agent_bom.evidence.scan_run import ScanRun, ScanScope, ScanScopeStatus

_BENCHMARKS = {"aws": "cis_benchmark_data", "azure": "azure_cis_benchmark_data", "gcp": "gcp_cis_benchmark_data"}
_DENIED = {"denied", "permission_denied", "access_denied"}
_UNAVAILABLE = {"disabled", "sdk_missing", "boto3_missing", "no_credentials", "no_subscription", "no_project", "unavailable"}


def _status(payload: dict[str, Any], *, inventory: bool = False) -> ScanScopeStatus:
    status = str(payload.get("status") or ("unknown" if inventory else "ok"))
    if payload.get("missing_permissions") or status in _DENIED:
        return ScanScopeStatus.PERMISSION_DENIED
    if status in _UNAVAILABLE:
        return ScanScopeStatus.UNAVAILABLE
    if (
        status not in {"ok", "complete"}
        or payload.get("warnings")
        or payload.get("errored")
        or payload.get("no_data")
        or str(payload.get("completeness")) in {"partial", "incomplete", "unknown"}
    ):
        return ScanScopeStatus.PARTIAL
    return ScanScopeStatus.COMPLETE


def cloud_scan_scopes(report: Any) -> list[ScanScope]:
    """Aggregate all accounts per provider, retaining any incomplete member.

    Only explicitly present evidence contributes a scope. Scope names and messages
    contain no account identifiers, provider exception strings or credential data.
    """
    inventory = getattr(report, "cloud_inventory_data", None)
    payloads = inventory if isinstance(inventory, list) else [inventory]
    scopes: list[ScanScope] = []
    for provider, field in _BENCHMARKS.items():
        members = [p for p in payloads if isinstance(p, dict) and p.get("provider") == provider]
        if members:
            statuses = {_status(member, inventory=True) for member in members}
            status = next(
                candidate
                for candidate in (
                    ScanScopeStatus.PERMISSION_DENIED,
                    ScanScopeStatus.UNAVAILABLE,
                    ScanScopeStatus.PARTIAL,
                    ScanScopeStatus.COMPLETE,
                )
                if candidate in statuses
            )
            scopes.append(ScanScope(name=f"cloud:{provider}:inventory", status=status))
        benchmark = getattr(report, field, None)
        if isinstance(benchmark, dict) and benchmark:
            scopes.append(ScanScope(name=f"cloud:{provider}:posture", status=_status(benchmark)))
    return scopes


def inventory_artifact(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Attach execution coverage to the native CLI inventory artifact."""
    run = ScanRun(scopes=cloud_scan_scopes(SimpleNamespace(cloud_inventory_data=reports)))
    return {"providers": reports, "scan_run": run.to_dict()}
