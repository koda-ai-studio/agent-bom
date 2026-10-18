"""Explicit-project, metadata-only Supabase Management API collection.

Only GET project and GET security advisors are exercised. No SQL, database
contents, keys, project resume, or advisor execution endpoints are called.
The experimental advisor contract is validated before any findings are emitted.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from agent_bom.cloud.management_http import read_json
from agent_bom.cloud.resource_model import supabase_project_node_id as project_node_id
from agent_bom.finding import Asset, Finding, FindingSource, FindingType, stable_id
from agent_bom.security import sanitize_text

API_ROOT = "https://api.supabase.com/v1/projects"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PROJECTS = 50
MAX_ADVISORS = 5000


def _text(value: Any, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("Invalid Supabase response field")
    return sanitize_text(value, max_len=limit)


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    text = _text(value, 64)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Supabase observation time lacks timezone")
    return parsed.isoformat().replace("+00:00", "Z")


def _read(client: httpx.Client, path: str, token: str) -> tuple[Any, str]:
    return read_json(client, API_ROOT + path, token, max_bytes=MAX_RESPONSE_BYTES)


def _project(payload: Any, ref: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("ref") != ref:
        raise ValueError("Supabase project scope mismatch")
    account = _text(payload.get("organization_id"))
    result = {
        "id": ref,
        "ref": ref,
        "organization_id": account,
        "name": _text(payload.get("name")),
        "region": _text(payload.get("region")),
        "status": _text(payload.get("status")),
        "node_id": project_node_id(account, ref),
    }
    database = payload.get("database")
    if isinstance(database, dict):
        for key in ("version", "postgres_engine", "release_channel"):
            if database.get(key) is not None:
                result["database_" + key] = _text(database[key])
    return result


def _findings(payload: Any, project: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("lints"), list):
        raise ValueError("Invalid Supabase advisors response")
    if len(payload["lints"]) > MAX_ADVISORS:
        raise ValueError("Supabase advisors limit exceeded")
    findings: dict[str, dict[str, Any]] = {}
    for row in payload["lints"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid Supabase advisor")
        native_id = _text(row.get("cache_key"), 2048)
        rule = _text(row.get("name"))
        level = _text(row.get("level"))
        title = _text(row.get("title"), 1000)
        categories = row.get("categories")
        if not isinstance(categories, list) or not all(isinstance(c, str) for c in categories) or "SECURITY" not in categories:
            raise ValueError("Unsupported Supabase advisor category")
        metadata = row.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Invalid Supabase advisor metadata")
        # No detail, description, arbitrary metadata, SQL or sample values.
        target = {key: _text(metadata[key]) for key in ("schema", "name", "type", "entity") if metadata.get(key) is not None}
        native_time = _timestamp(row.get("observed_at"))
        evidence = {
            "provider": "supabase",
            "native_id": native_id,
            "rule_id": rule,
            "rule_version": None,
            "native_severity": level,
            "source_observed_at": native_time,
            "collected_at": observed_at,
            "target": target,
            "project_ref": project["ref"],
            "project_status": project["status"],
            "source": "supabase-security-advisors",
            "contract": "v1-experimental",
            "severity_mapping": "ERROR=high,WARN=medium,INFO=info;otherwise=unknown",
        }
        fid = stable_id("supabase-security-advisors", project["organization_id"], project["ref"], native_id)
        finding = Finding(
            id=fid,
            finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
            source=FindingSource.CLOUD_SECURITY,
            asset=Asset(
                name=project["name"],
                asset_type="cloud_resource",
                identifier=f"supabase://{project['organization_id']}/projects/{project['ref']}",
                provider="supabase",
                account_ref="supabase:" + project["organization_id"],
                region=project["region"],
            ),
            title=title,
            severity={"ERROR": "high", "WARN": "medium", "INFO": "info"}.get(level, "unknown"),
            vendor_severity={"ERROR": "high", "WARN": "medium", "INFO": "info"}.get(level, "unknown"),
            evidence=evidence,
            node_id=project["node_id"],
            finding_node_id="misconfig:supabase:" + fid,
            remediation_guidance=(
                "Review this native advisor in the Supabase project Security Advisor; verify configuration before applying a fix."
            ),
        ).to_dict()
        if fid in findings and findings[fid] != finding:
            raise ValueError("Conflicting duplicate Supabase advisor")
        findings[fid] = finding
    return list(findings.values())


def _new_receipt(ref: str, capability: str, observed_at: str) -> dict[str, Any]:
    """Start each capability independently; authentication never implies ingestion."""
    return {
        "provider": "supabase",
        "project_ref": ref,
        "capability": capability,
        "observed_at": observed_at,
        "state": "not_attempted",
        "authenticated": False,
        "read": False,
        "ingested": False,
        "persisted": False,
        "evaluated": False,
        "correlated": False,
        "complete": False,
        "clean_posture_assertion": False,
    }


def collect_report(*, project_refs: list[str], token: str, client: httpx.Client | None = None) -> dict[str, Any]:
    """Collect a report with independent capability receipts; errors never mean clean.

    Scope is required and bounded before networking. Partial reads retain validated
    inventory but never enable absent-finding reconciliation. Rate limits are
    recorded so an operator can retry without a hidden unbounded request loop.
    """
    if (
        not project_refs
        or len(project_refs) > MAX_PROJECTS
        or any(not isinstance(r, str) or not re.fullmatch(r"[a-z]{20}", r) for r in project_refs)
    ):
        raise ValueError("Provide 1-50 explicit Supabase project refs (20 lowercase letters each)")
    if not isinstance(token, str) or not token.strip() or "\n" in token or "\r" in token:
        raise ValueError("A Supabase management token is required")
    if client is None:
        with httpx.Client(trust_env=False) as owned:
            return collect_report(project_refs=project_refs, token=token, client=owned)
    observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report: dict[str, Any] = {
        "schema_version": "supabase.inventory.v1",
        "status": "ok",
        "observed_at": observed_at,
        "scan_sources": ["supabase-management"],
        "cloud_inventory": [],
        "findings": [],
        "coverage": [],
        "reconcile_absent": False,
    }
    for ref in dict.fromkeys(project_refs):
        project: dict[str, Any] | None = None
        inventory: dict[str, Any] | None = None
        for capability, suffix in (("project", ""), ("security_advisors", "/advisors/security")):
            receipt = _new_receipt(ref, capability, observed_at)
            report["coverage"].append(receipt)
            if inventory is not None:
                inventory["coverage"].append(receipt)
            if capability == "security_advisors" and project is None:
                continue
            payload, state = _read(client, "/" + ref + suffix, token)
            receipt["state"] = state
            receipt["authenticated"] = state == "read"
            if state != "read":
                report["status"] = "partial"
                continue
            receipt["read"] = True
            try:
                if capability == "project":
                    project = _project(payload, ref)
                    inventory = {
                        "provider": "supabase",
                        "status": "ok",
                        "account_id": project["organization_id"],
                        "projects": [project],
                        "coverage": [receipt],
                        "findings": [],
                    }
                    report["cloud_inventory"].append(inventory)
                    receipt["state"] = "collected"
                else:
                    assert project is not None and inventory is not None
                    findings = _findings(payload, project, observed_at)
                    inventory["findings"] = findings
                    report["findings"].extend(findings)
                    receipt["state"] = "collected" if findings else "empty"
                    receipt["evaluated"] = project["status"] == "ACTIVE_HEALTHY"
                    if not receipt["evaluated"]:
                        receipt["state"] = "paused" if project["status"] == "INACTIVE" else "unavailable"
                        report["status"] = "partial"
                receipt["complete"] = True
                receipt["ingested"] = True
            except (ValueError, TypeError):
                receipt["state"] = "invalid_response"
                report["status"] = "partial"
    # Content hash covers normalized evidence, not secrets or a provider-signed attestation.
    report["evidence_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report
