"""The ``kubernetes_inventory`` report section: inventories plus per-image scan results.

Each container records whether its image was scanned in this run and, if so,
its package and vulnerability counts, taken from the same image-carrier agents
the graph projects. An image that was not scanned (for example a manifest-only
scan) says so instead of reading as clean.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any

from agent_bom.core.image_ref import image_key

_SEVERITIES = ("critical", "high", "medium", "low")


def _image_results(agents: Iterable[Any]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for agent in agents:
        metadata = getattr(agent, "metadata", None) or {}
        if metadata.get("inventory_role") != "container_image":
            continue
        packages = [pkg for server in getattr(agent, "mcp_servers", []) or [] for pkg in server.packages]
        vulns = [vuln for pkg in packages for vuln in getattr(pkg, "vulnerabilities", []) or []]
        counts = {sev: 0 for sev in _SEVERITIES}
        for vuln in vulns:
            severity = str(getattr(getattr(vuln, "severity", ""), "value", getattr(vuln, "severity", "")) or "").lower()
            if severity in counts:
                counts[severity] += 1
        key = image_key(str(metadata.get("image_ref") or ""), str(metadata.get("image_digest") or ""))
        results[key] = {"scanned": True, "packages": len(packages), "vulnerabilities": len(vulns), **counts}
    return results


def kubernetes_inventory_section(inventories: list[dict[str, Any]], agents: Iterable[Any]) -> dict[str, Any]:
    results = _image_results(agents)
    annotated = copy.deepcopy(inventories)
    scanned, vulnerable_workloads = set(), 0
    for inventory in annotated:
        for workload in inventory.get("workloads") or []:
            workload_vulns = 0
            for container in workload.get("containers") or []:
                key = image_key(str(container.get("image") or ""), str(container.get("image_digest") or ""))
                container["scan"] = results.get(key, {"scanned": False})
                if container["scan"]["scanned"]:
                    scanned.add(key)
                    workload_vulns += container["scan"]["vulnerabilities"]
            vulnerable_workloads += 1 if workload_vulns else 0
    totals = {
        key: sum(int(inv.get("summary", {}).get(key, 0)) for inv in annotated)
        for key in ("namespaces", "workloads", "images", "service_accounts", "rbac_grants", "secret_refs")
    }
    return {
        "inventories": annotated,
        "summary": {**totals, "images_scanned": len(scanned), "workloads_with_vulnerabilities": vulnerable_workloads},
    }
