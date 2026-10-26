"""KSPM cluster-posture MCP tool implementation (issue #4134 stage 3).

Exposes live Kubernetes security posture to headless agents as the SAME evidence
envelope the REST route and CLI evidence dict emit — benchmark provenance,
per-collector executed/skipped/unevaluable/failed state, the canonical ScanRun
outcome, and a findings summary — all derived from one
:class:`~agent_bom.k8s.K8sPostureResult`, so API/MCP/CLI reconcile 1:1. A denied
read is 'unevaluable' and 'partial', never a clean pass. Read-only.
"""

from __future__ import annotations

import json
import logging

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = "kspm.cluster.posture.v1"


def _collect_posture(
    *,
    namespace: str,
    all_namespaces: bool,
    context: str | None,
    enable_nodes_configz: bool,
):
    """Run the live posture collection (isolated seam for testing)."""
    from agent_bom.k8s import scan_live_cluster_posture_with_evidence

    return scan_live_cluster_posture_with_evidence(
        namespace=namespace,
        all_namespaces=all_namespaces,
        context=context,
        enable_nodes_configz=enable_nodes_configz,
    )


async def kspm_cluster_posture_impl(
    *,
    namespace: str = "default",
    all_namespaces: bool = False,
    context: str | None = None,
    enable_nodes_configz: bool = False,
    _truncate_response,
) -> str:
    """Implementation of the kspm_cluster_posture tool."""
    try:
        result = _collect_posture(
            namespace=namespace,
            all_namespaces=all_namespaces,
            context=context,
            enable_nodes_configz=enable_nodes_configz,
        )
        evidence = result.to_evidence_dict()
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "resource": "cluster_posture",
            "status": evidence["status"],
            "transport": evidence["transport"],
            "benchmark": evidence["benchmark"],
            "collectors": evidence["collectors"],
            "finding_count": evidence["finding_count"],
            "severity_summary": result.severity_summary(),
            "scan_run": result.to_scan_run().to_dict(),
            "note": (
                "Live, read-only Kubernetes posture. Per-collector execution state is explicit: "
                "a denied/absent read is 'unevaluable' and a failed read is 'failed' — never a clean "
                "pass. This tool returns security posture, not container-image inventory."
            ),
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


_INVENTORY_SCHEMA_VERSION = "kspm.workload.inventory.v1"


def _collect_inventory(*, namespace: str, all_namespaces: bool, context: str | None) -> dict:
    """Run the live workload inventory collection (isolated seam for testing)."""
    from agent_bom.k8s_inventory_live import cluster_label, collect_live_k8s_inventory
    from agent_bom.k8s_transport import select_k8s_transport

    transport = select_k8s_transport(context=context)
    try:
        cluster = cluster_label(context, transport.name)
        return collect_live_k8s_inventory(transport, namespace=namespace, all_namespaces=all_namespaces, cluster=cluster)
    finally:
        transport.close()


def _bounded(items: list, limit: int) -> dict:
    return {"items": items[:limit], "total": len(items), "truncated": len(items) > limit}


async def kspm_workload_inventory_impl(
    *,
    namespace: str = "default",
    all_namespaces: bool = False,
    context: str | None = None,
    max_items: int = 200,
    _truncate_response,
) -> str:
    """Implementation of the kspm_workload_inventory tool."""
    try:
        limit = max(1, min(int(max_items), 1000))
        inventory = _collect_inventory(namespace=namespace, all_namespaces=all_namespaces, context=context)
        payload = {
            "schema_version": _INVENTORY_SCHEMA_VERSION,
            "resource": "workload_inventory",
            "status": inventory["collection"]["status"],
            "cluster": inventory["cluster"],
            "collectors": inventory["collection"]["collectors"],
            "summary": inventory["summary"],
            "namespaces": _bounded(inventory["namespaces"], limit),
            "workloads": _bounded(inventory["workloads"], limit),
            "service_accounts": _bounded(inventory["service_accounts"], limit),
            "rbac_grants": _bounded(inventory["rbac_grants"], limit),
            "note": (
                "Live, read-only workload inventory: workloads, containers and images (pinned to the running "
                "digest when the pod recorded one), service accounts, RBAC grants and the Secret names workloads "
                "reference. Secret values are never read. Image CVEs come from a scan (agent-bom scan --k8s, or "
                "POST /v1/scans with k8s=true); query the resulting graph for workload attack paths."
            ),
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
