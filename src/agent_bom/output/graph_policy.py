"""Graph-derived policy finding elements and small label helpers for graph exports."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.evidence.finding_node_ids import finding_row_node_id
from agent_bom.graph import SEVERITY_BADGE as _SEVERITY_BADGE
from agent_bom.graph import SEVERITY_RANK as _SEVERITY_RANK

if TYPE_CHECKING:
    from agent_bom.finding import Finding
    from agent_bom.models import AIBOMReport


def _graph_policy_findings(report: "AIBOMReport") -> list["Finding"]:
    """Unified-stream findings the CVE-centric builders never surface
    (COMBINATION, PROMPT_SECURITY, NHI, CIEM, CIS, ...)."""
    from agent_bom.output.finding_views import _MACHINE_EXPORT_TYPES

    return [finding for finding in report.to_findings() if finding.finding_type not in _MACHINE_EXPORT_TYPES]


def _graph_policy_finding_elements(report: "AIBOMReport") -> list[dict]:
    """Cytoscape elements for graph-derived / policy finding categories.

    The unified findings stream (the one JSON/API/MCP report) carries
    COMBINATION and other non-CVE categories; emit one ``finding`` node per
    entry — linked to its agent asset node when present — so graph exports
    reconcile with every other scan surface.
    """
    findings = _graph_policy_findings(report)
    if not findings:
        return []

    agent_ids_by_name: dict[str, set[str]] = {}
    for agent in report.agents:
        agent_ids_by_name.setdefault(agent.name, set()).add(agent_graph_id_for(agent))
    elements: list[dict] = []
    for finding in findings:
        severity = str(finding.effective_severity() or "unknown").lower()
        category = finding.finding_type.value
        row = finding.to_dict()
        node_id = str(row.get("finding_node_id") or finding_row_node_id(row) or f"finding:{finding.id}")
        description = " ".join((finding.description or "").split())
        elements.append(
            {
                "data": {
                    "id": node_id,
                    "label": f"{category}\n{severity.upper()}",
                    "type": "finding",
                    "category": category,
                    "severity": severity,
                    "title": finding.title,
                    "tip": (f"{finding.title}\nCategory: {category}\nSeverity: {severity}\n{description[:220]}"),
                    "searchText": f"{finding.title} {category} {severity}".lower(),
                }
            }
        )
        asset = getattr(finding, "asset", None)
        if getattr(asset, "asset_type", "") == "agent":
            # A name shared by several agents does not identify one of them.
            owners = agent_ids_by_name.get(str(getattr(asset, "name", "")), set())
            if len(owners) == 1:
                elements.append({"data": {"source": next(iter(owners)), "target": node_id, "type": "has_finding"}})
    return elements


def _norm_repo_dir(raw: object) -> str:
    """Normalise a repo-relative directory path; root (``""``/``"."``) → ``""``."""
    if not isinstance(raw, str):
        return ""
    text = raw.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.strip("/")
    return "" if text == "." else text


def _provider_label(source: str) -> str:
    """Human-readable label for a provider source string."""
    labels = {
        "local": "Local",
        "aws-bedrock": "AWS Bedrock",
        "aws-ecs": "AWS ECS",
        "aws-sagemaker": "AWS SageMaker",
        "azure-container-apps": "Azure Container Apps",
        "azure-ai-foundry": "Azure AI Foundry",
        "gcp-vertex-ai": "GCP Vertex AI",
        "gcp-cloud-run": "GCP Cloud Run",
        "databricks": "Databricks",
        "snowflake-cortex": "Snowflake Cortex",
        "snowflake-streamlit": "Snowflake Streamlit",
        "snowflake": "Snowflake",
        "mcp-registry": "MCP Registry",
        "smithery": "Smithery",
        "snyk": "Snyk",
        "huggingface": "Hugging Face",
        "openai": "OpenAI",
        "mlflow": "MLflow",
        "wandb": "W&B",
        "nebius": "Nebius",
    }
    return labels.get(source, source.upper())


class _PackageVulnSummary(TypedDict):
    counts: dict[str, int]
    maxSeverity: str
    vulnCount: int
    summaryText: str
    vulnIds: list[str]


def _summarize_package_vulns(vulns: list[dict]) -> _PackageVulnSummary:
    """Aggregate vulnerability counts and labels for a package."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    max_severity = "unknown"
    max_rank = -1
    unique_ids: list[str] = []
    seen_ids: set[str] = set()

    for vuln in vulns:
        severity = str(vuln.get("severity") or "unknown")
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
        rank = _SEVERITY_RANK[severity]
        if rank > max_rank:
            max_rank = rank
            max_severity = severity
        vuln_id = str(vuln.get("id") or "")
        if vuln_id and vuln_id not in seen_ids:
            seen_ids.add(vuln_id)
            unique_ids.append(vuln_id)

    badge_parts = []
    for severity in ("critical", "high", "medium", "low"):
        count = counts[severity]
        if count:
            badge_parts.append(f"{_SEVERITY_BADGE[severity]}{count}")
    if counts["unknown"]:
        badge_parts.append(f"?{counts['unknown']}")

    summary_text = " ".join(badge_parts) if badge_parts else "No CVEs"
    return {
        "counts": counts,
        "maxSeverity": max_severity,
        "vulnCount": len(unique_ids),
        "summaryText": summary_text,
        "vulnIds": unique_ids,
    }
