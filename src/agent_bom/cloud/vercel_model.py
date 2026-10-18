"""Allowlisted Vercel metadata and deterministic configuration checks."""

from __future__ import annotations

import re
from typing import Any

from agent_bom.canonical_ids import canonical_id
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.security import sanitize_text


def text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("Invalid Vercel metadata field")
    return sanitize_text(value, max_len=512)


def native_id(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(prefix + r"[A-Za-z0-9]{1,100}", value):
        raise ValueError("Invalid Vercel resource identifier")
    return value


def node_id(team: str, kind: str, identifier: str) -> str:
    return "resource:vercel:" + canonical_id("vercel", team, kind, identifier)


def project(row: Any, team: str) -> dict[str, Any]:
    if not isinstance(row, dict) or row.get("accountId") != team:
        raise ValueError("Vercel project scope mismatch")
    identifier = native_id(row.get("id"), "prj_")
    result: dict[str, Any] = {
        "id": identifier,
        "account_id": team,
        "name": text(row.get("name")),
        "node_id": node_id(team, "project", identifier),
    }
    for source, target in (("framework", "framework"), ("nodeVersion", "node_version")):
        result[target] = text(row[source]) if row.get(source) is not None else None
    for source, target in (("gitForkProtection", "git_fork_protection"), ("publicSource", "public_source")):
        value = row.get(source)
        if value is not None and not isinstance(value, bool):
            raise ValueError("Invalid Vercel configuration flag")
        result[target] = value
    link = row.get("link")
    if "link" not in row:
        result["git_connected"] = None
    elif link is None:
        result["git_connected"] = False
    elif isinstance(link, dict) and isinstance(link.get("type"), str):
        result["git_connected"] = True
        result["git_provider"] = text(link["type"])
    else:
        raise ValueError("Invalid Vercel Git configuration")
    protection = row.get("ssoProtection")
    if protection is not None and not isinstance(protection, dict):
        raise ValueError("Invalid Vercel deployment protection")
    result["sso_protection"] = text(protection["deploymentType"]) if protection and protection.get("deploymentType") else None
    # Never retain env, build commands, repository identifiers, passwords, bypass
    # keys, arbitrary metadata, or embedded deployment payloads.
    return result


def deployment(row: Any, team: str, project_ids: set[str]) -> dict[str, Any]:
    if not isinstance(row, dict) or row.get("projectId") not in project_ids:
        raise ValueError("Vercel deployment project mismatch")
    if row.get("teamId", team) != team:
        raise ValueError("Vercel deployment team mismatch")
    identifier = native_id(row.get("uid"), "dpl_")
    return {
        "id": identifier,
        "account_id": team,
        "project_id": row["projectId"],
        "name": text(row.get("name")),
        "state": text(row.get("state")),
        "target": text(row["target"]) if row.get("target") is not None else None,
        "node_id": node_id(team, "deployment", identifier),
    }


def evaluate(projects: list[dict[str, Any]], team: str, observed_at: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks, findings = [], []
    for item in projects:
        connected, protected = item["git_connected"], item["git_fork_protection"]
        state = (
            "not_applicable"
            if connected is False
            else "unknown"
            if connected is None or protected is None
            else "pass"
            if protected
            else "fail"
        )
        evidence = {
            "rule_id": "vercel.git_fork_protection",
            "rule_version": "1",
            "basis": "configuration",
            "source": "vercel-management",
            "collected_at": observed_at,
            "source_observed_at": None,
            "project_id": item["id"],
            "team_id": team,
            "git_connected": connected,
            "git_fork_protection": protected,
        }
        checks.append({**evidence, "state": state})
        if state != "fail":
            continue
        identifier = canonical_id("vercel", team, item["id"], evidence["rule_id"])
        findings.append(
            Finding(
                id=identifier,
                finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
                source=FindingSource.CLOUD_SECURITY,
                asset=Asset(
                    name=item["name"],
                    asset_type="cloud_resource",
                    identifier=f"vercel://{team}/projects/{item['id']}",
                    provider="vercel",
                    account_ref=team,
                ),
                title="Git fork deployment approval is disabled",
                severity="medium",
                evidence=evidence,
                node_id=item["node_id"],
                finding_node_id="misconfig:vercel:" + identifier,
                remediation_guidance=(
                    "Review Git fork protection for this project before allowing deployments from untrusted forks. "
                    "This configuration observation does not establish exploitation."
                ),
            ).to_dict()
        )
    return checks, findings
