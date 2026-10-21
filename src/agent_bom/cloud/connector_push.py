"""Shape Vercel/Supabase connector reports for the control-plane push path.

Each payload names one explicit connector target (a Vercel team or a Supabase
project) through ``source_id`` plus a versioned ``target_scope``. The server
then gives it its own replacement scope, so a later push for the same target
replaces only that target's evidence in the current estate. Incomplete
collection is declared in ``scan_run`` so the estate retains prior evidence for
that target and reports partial coverage instead of treating it as complete.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

from agent_bom.evidence.scan_run import ScanOutcome, ScanScopeStatus

_DENIED_STATES = frozenset({"denied", "unauthenticated"})
_UNAVAILABLE_STATES = frozenset({"rate_limited", "unavailable", "paused"})


def _target_scope(provider: str, target: str) -> str:
    canonical = json.dumps({"connector": provider, "target": target}, sort_keys=True, separators=(",", ":"))
    return "v1:" + hashlib.sha256(canonical.encode()).hexdigest()


def _scope_status(receipt: dict[str, Any]) -> ScanScopeStatus:
    if receipt.get("complete") is True:
        return ScanScopeStatus.COMPLETE
    state = str(receipt.get("state") or "")
    if state in _DENIED_STATES:
        return ScanScopeStatus.PERMISSION_DENIED
    if state in _UNAVAILABLE_STATES:
        return ScanScopeStatus.UNAVAILABLE
    if state == "not_attempted":
        return ScanScopeStatus.SKIPPED
    return ScanScopeStatus.PARTIAL


def _scan_run(coverage: list[dict[str, Any]]) -> dict[str, Any]:
    scopes = [
        {
            "name": str(receipt.get("capability") or "unknown"),
            "status": _scope_status(receipt).value,
            "requested": True,
            "message": str(receipt.get("state") or ""),
        }
        for receipt in coverage
    ]
    complete = bool(coverage) and all(scope["status"] == ScanScopeStatus.COMPLETE.value for scope in scopes)
    return {"outcome": (ScanOutcome.COMPLETE if complete else ScanOutcome.PARTIAL).value, "scopes": scopes}


def _payload(report: dict[str, Any], provider: str, target: str, **evidence: Any) -> dict[str, Any]:
    # Each target is its own server-assigned scan: one shared local scan_id
    # would make per-project pushes overwrite each other's graph snapshot.
    excluded = {"persistence", "evidence_sha256", "scan_id", *evidence}
    payload = {key: deepcopy(value) for key, value in report.items() if key not in excluded}
    payload.update(deepcopy(evidence))
    payload["source_id"] = f"connector:{provider}:{target}"
    payload["target_scope"] = _target_scope(provider, target)
    payload["scan_run"] = _scan_run(payload["coverage"])
    # Replacement order follows when the provider was read, not arrival order.
    payload["generated_at"] = payload["observed_at"]
    payload["status"] = "ok" if payload["scan_run"]["outcome"] == ScanOutcome.COMPLETE.value else "partial"
    return payload


def _supabase_payloads(report: dict[str, Any]) -> list[dict[str, Any]]:
    refs = list(dict.fromkeys(str(receipt["project_ref"]) for receipt in report["coverage"] if "project_ref" in receipt))
    projects = [
        _payload(
            report,
            "supabase",
            ref,
            cloud_inventory=[
                inventory for inventory in report["cloud_inventory"] if any(project["ref"] == ref for project in inventory["projects"])
            ],
            coverage=[receipt for receipt in report["coverage"] if receipt.get("project_ref") == ref],
            findings=[finding for finding in report["findings"] if finding["evidence"]["project_ref"] == ref],
        )
        for ref in refs
    ]

    directories = [
        _payload(
            report,
            "supabase",
            "organization:" + inventory["account_id"],
            cloud_inventory=[inventory],
            coverage=inventory["coverage"],
            findings=[],
        )
        for inventory in report["cloud_inventory"]
        if "directory" in inventory
    ]
    return directories + projects


def connector_push_payloads(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one push payload per explicit connector target in ``report``."""
    schema = report.get("schema_version")
    if schema == "vercel.inventory.v1":
        team = str(report["cloud_inventory"][0]["account_id"])
        return [_payload(report, "vercel", team)]
    if schema == "supabase.inventory.v1":
        return _supabase_payloads(report)
    raise ValueError("Unsupported connector report")
