"""Explicit-team Vercel inventory with bounded, complete pagination receipts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from agent_bom.cloud.management_http import read_json
from agent_bom.cloud.vercel_model import deployment, evaluate, native_id, project

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PAGES = 20
MAX_RECORDS = 2000


def _collect(
    client: httpx.Client, token: str, team: str, capability: str, normalizer: Callable[[Any], dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    receipt: dict[str, Any] = {
        "provider": "vercel",
        "team_id": team,
        "capability": capability,
        "state": "not_attempted",
        "authenticated": False,
        "read": False,
        "ingested": False,
        "persisted": False,
        "evaluated": False,
        "correlated": False,
        "complete": False,
        "clean_posture_assertion": False,
        "pages_read": 0,
    }
    rows: dict[str, dict[str, Any]] = {}
    cursor: int | None = None
    version = "v10" if capability == "projects" else "v7"
    for _ in range(MAX_PAGES):
        params: dict[str, Any] = {"teamId": team, "limit": 100}
        if cursor is not None:
            params["until"] = cursor
        payload, state = read_json(
            client, f"https://api.vercel.com/{version}/{capability}", token, max_bytes=MAX_RESPONSE_BYTES, params=params
        )
        receipt["state"] = state
        if state != "read":
            return list(rows.values()), receipt
        receipt["authenticated"] = True
        receipt["read"] = True
        receipt["pages_read"] += 1
        try:
            if not isinstance(payload, dict) or not isinstance(payload.get(capability), list):
                raise ValueError("Invalid Vercel page")
            pagination = payload.get("pagination")
            if not isinstance(pagination, dict) or "next" not in pagination:
                raise ValueError("Missing Vercel continuation state")
            next_cursor = pagination["next"]
            if next_cursor is not None and (
                type(next_cursor) is not int or next_cursor < 0 or (cursor is not None and next_cursor >= cursor)
            ):
                raise ValueError("Invalid Vercel continuation state")
            page = [normalizer(item) for item in payload[capability]]
            if len(rows) + len(page) > MAX_RECORDS:
                receipt["state"] = "record_limit"
                return list(rows.values()), receipt
            updated = dict(rows)
            for item in page:
                if item["id"] in updated and updated[item["id"]] != item:
                    raise ValueError("Conflicting Vercel resource identity")
                updated[item["id"]] = item
            rows = updated
            receipt["ingested"] = True
            if next_cursor is None:
                receipt.update(state="collected" if rows else "empty", complete=True)
                return list(rows.values()), receipt
            if not page:
                raise ValueError("Empty continued Vercel page")
            cursor = next_cursor
        except (ValueError, TypeError):
            receipt["state"] = "invalid_response"
            return list(rows.values()), receipt
    receipt["state"] = "page_limit"
    return list(rows.values()), receipt


def collect_report(*, team_id: str, token: str, client: httpx.Client | None = None) -> dict[str, Any]:
    """Collect metadata, with unknown coverage distinct from an empty inventory."""
    native_id(team_id, "team_")
    if not isinstance(token, str) or not token.strip() or "\n" in token or "\r" in token:
        raise ValueError("A Vercel token is required")
    if client is None:
        with httpx.Client(trust_env=False) as owned:
            return collect_report(team_id=team_id, token=token, client=owned)
    observed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    projects, project_receipt = _collect(client, token, team_id, "projects", lambda row: project(row, team_id))
    coverage = [project_receipt]
    deployments: list[dict[str, Any]] = []
    if project_receipt["complete"]:
        project_ids = {item["id"] for item in projects}
        deployments, deployment_receipt = _collect(client, token, team_id, "deployments", lambda row: deployment(row, team_id, project_ids))
        coverage.append(deployment_receipt)
    else:
        coverage.append(
            {
                **project_receipt,
                "capability": "deployments",
                "state": "not_attempted",
                "read": False,
                "authenticated": False,
                "ingested": False,
                "pages_read": 0,
            }
        )
    checks, findings = evaluate(projects, team_id, observed)
    for receipt in coverage:
        receipt["observed_at"] = observed
    inventory = {
        "provider": "vercel",
        "account_id": team_id,
        "projects": projects,
        "deployments": deployments,
        "findings": findings,
        "coverage": coverage,
    }
    report = {
        "schema_version": "vercel.inventory.v1",
        "status": "ok" if all(c["complete"] for c in coverage) else "partial",
        "observed_at": observed,
        "scan_sources": ["vercel-management"],
        "cloud_inventory": [inventory],
        "coverage": coverage,
        "findings": findings,
        "configuration_checks": checks,
        "reconcile_absent": False,
        "limitations": [
            "Configuration checks do not prove deployment reachability, runtime behavior, or exploitation.",
            "Package vulnerabilities, deployed contents, effective access, and firewall rules are not evaluated.",
        ],
    }
    report["evidence_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report
