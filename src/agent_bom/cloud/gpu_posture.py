"""Read-only GPU posture checks over inventoried GPU pools and workloads.

Every check is provider-aware: it runs only where the provider exposes the
setting and its default makes the condition meaningful (GKE taints GPU node
pools automatically, so the missing-taint check is AWS/Azure only; SSH from
the internet is an EKS node-group setting; node public IPs an AKS one).

Outdated drivers / Container Toolkit releases are not re-judged here: the
detected versions become packages with NVD CPE identity and go through the
same advisory matching (NVD, NVIDIA CSAF, KEV enrichment) as every other
package, so there is one judgement per CVE.

Raw findings are plain dicts; :func:`gpu_posture_finding_to_finding` turns
them into unified findings and :func:`gpu_finding_id` is shared with the graph
projection so the finding and its misconfiguration node carry one id.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_bom.cloud.gpu_node_pools import gpu_pool_node_id
from agent_bom.domain.finding_model import Asset, Finding
from agent_bom.domain.finding_types import FindingSource, FindingType, stable_id
from agent_bom.finding_scope import normalize_account_ref
from agent_bom.security import sanitize_text

_HOST_FLAGS = {"host_pid": "hostPID", "host_ipc": "hostIPC", "host_network": "hostNetwork"}
_NO_SCHEDULE = {"noschedule", "no_schedule", "noexecute", "no_execute"}
_SHARED_STRATEGIES = {"time-slicing", "mps"}
_DRIVER_OWNER = {
    "aws": "a CUSTOM AMI or a non-accelerated AMI type",
    "gcp": "gpu_driver_version=INSTALLATION_DISABLED",
    "azure": "gpuProfile.driver=None",
}


def gpu_finding_id(check_id: str, asset_ref: str) -> str:
    return stable_id("gpu-posture", check_id, asset_ref)


def _finding(check_id: str, severity: str, title: str, detail: str, remediation: str, asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "severity": severity,
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "category": "gpu_posture",
        **asset,
        "id": gpu_finding_id(check_id, asset["asset_ref"]),
    }


def _pool_asset(pool: dict[str, Any], account_id: str) -> dict[str, Any]:
    provider = str(pool.get("provider") or "")
    return {
        "provider": provider,
        "account_id": account_id,
        "asset_ref": gpu_pool_node_id(provider, str(pool.get("cluster_key") or ""), str(pool.get("name") or "")),
        "asset_name": f"{pool.get('cluster_name') or ''}/{pool.get('name') or ''}",
        "asset_kind": str(pool.get("pool_kind") or "gpu-node-pool"),
    }


def _has_gpu_taint(pool: dict[str, Any]) -> bool:
    return any(str(t.get("effect") or "").casefold() in _NO_SCHEDULE for t in pool.get("taints") or [])


def _gke_default_sa(identity: str) -> bool:
    return identity in {"", "default"} or identity.endswith("-compute@developer.gserviceaccount.com")


def pool_findings(pool: dict[str, Any], *, account_id: str = "") -> list[dict[str, Any]]:
    """Posture findings for one managed Kubernetes GPU node pool."""
    if not pool.get("gpu"):
        return []
    provider = str(pool.get("provider") or "")
    asset = _pool_asset(pool, account_id)
    name = asset["asset_name"]
    out: list[dict[str, Any]] = []
    if provider == "aws" and pool.get("ssh_open_to_internet"):
        out.append(
            _finding(
                "GPU-001",
                "high",
                "GPU node group allows SSH from the internet",
                f"EKS node group {name} sets an SSH key without source security groups, so port 22 is open to 0.0.0.0/0 on GPU nodes.",
                "Restrict remoteAccess.sourceSecurityGroups or remove the SSH key and use SSM Session Manager.",
                asset,
            )
        )
    if provider == "azure" and pool.get("node_public_ip"):
        out.append(
            _finding(
                "GPU-002",
                "medium",
                "GPU node pool assigns public IPs to nodes",
                f"AKS agent pool {name} has enableNodePublicIP set; each GPU node is directly addressable from the internet.",
                "Disable node public IPs and reach nodes through the cluster's private network.",
                asset,
            )
        )
    if provider == "gcp" and _gke_default_sa(str(pool.get("node_identity") or "")):
        out.append(
            _finding(
                "GPU-003",
                "medium",
                "GPU node pool runs as the Compute Engine default service account",
                f"GKE node pool {name} uses the project's default compute service account, which is commonly granted Editor.",
                "Create a least-privilege node service account and use Workload Identity for pods.",
                asset,
            )
        )
    if provider in {"aws", "azure"} and not _has_gpu_taint(pool):
        out.append(
            _finding(
                "GPU-004",
                "low",
                "GPU node pool is not tainted",
                f"{name} has no NoSchedule taint, so non-GPU pods can be scheduled next to GPU workloads on GPU nodes.",
                "Taint GPU node pools (for example nvidia.com/gpu=present:NoSchedule) and tolerate it only in GPU workloads.",
                asset,
            )
        )
    if (pool.get("gpu_driver") or {}).get("management") == "user-managed":
        out.append(
            _finding(
                "GPU-005",
                "low",
                "GPU driver is installed and patched by the operator",
                f"{name} uses {_DRIVER_OWNER.get(provider, 'an operator-managed driver')}; NVIDIA driver and Container Toolkit "
                "security updates are not applied by the provider.",
                "Track NVIDIA security bulletins for the driver branch and Container Toolkit, or use the provider-managed driver.",
                asset,
            )
        )
    out.extend(_sharing_findings(pool, asset))
    return out


def _sharing_findings(pool: dict[str, Any], asset: dict[str, Any]) -> list[dict[str, Any]]:
    strategy = str((pool.get("gpu_sharing") or {}).get("strategy") or "")
    if strategy not in _SHARED_STRATEGIES:
        return []
    clients = (pool.get("gpu_sharing") or {}).get("max_shared_clients")
    return [
        _finding(
            "GPU-006",
            "low",
            "GPU node pool shares each GPU between containers",
            f"{asset['asset_name']} uses {strategy} (up to {clients or 'several'} containers per GPU); time-slicing and MPS do "
            "not isolate GPU memory or faults between the containers that share a GPU.",
            "Schedule only mutually trusted workloads on shared GPUs, or use MIG partitions for hardware isolation.",
            asset,
        )
    ]


def _workload_asset(workload: dict[str, Any]) -> dict[str, Any]:
    ident = f"{workload.get('namespace')}/{workload.get('pod')}"
    return {
        "provider": str(workload.get("provider") or "kubernetes"),
        "account_id": "",
        "asset_ref": f"k8s://{workload.get('cluster_key')}/{ident}",
        "asset_name": ident,
        "asset_kind": "gpu-workload",
    }


def workload_findings(workload: dict[str, Any]) -> list[dict[str, Any]]:
    """Posture findings for one Kubernetes GPU workload (``GpuWorkload.to_dict()``)."""
    asset = _workload_asset(workload)
    out: list[dict[str, Any]] = []
    privileged = [c["name"] for c in workload.get("containers") or [] if c.get("privileged")]
    if privileged:
        out.append(
            _finding(
                "GPU-010",
                "high",
                "GPU workload runs a privileged container",
                f"{asset['asset_name']} runs {', '.join(privileged)} privileged: it sees every GPU and host device on the node, "
                "bypassing device-plugin allocation.",
                "Drop privileged; request GPUs through the device plugin resource (nvidia.com/gpu) only.",
                asset,
            )
        )
    if workload.get("host_paths"):
        out.append(
            _finding(
                "GPU-011",
                "high",
                "GPU workload mounts host GPU or runtime paths",
                f"{asset['asset_name']} mounts {', '.join(workload['host_paths'])} from the host (device nodes, device-plugin "
                "socket or container runtime), enough to take over GPU allocation or the node.",
                "Remove the hostPath volumes; GPU access comes from the device plugin.",
                asset,
            )
        )
    shared = [name for flag, name in _HOST_FLAGS.items() if workload.get(flag)]
    if shared:
        out.append(
            _finding(
                "GPU-012",
                "medium",
                "GPU workload shares host namespaces",
                f"{asset['asset_name']} sets {', '.join(shared)}; processes on "
                "the GPU node (including other tenants' GPU jobs) become visible or reachable.",
                "Unset hostPID/hostIPC/hostNetwork; CUDA MPS through the device plugin does not need hostIPC.",
                asset,
            )
        )
    return out


def shared_gpu_tenancy_findings(workloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Context: namespaces that share time-sliced / MPS GPUs in the same node pool."""
    groups: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    strategies: dict[tuple[str, str, str], str] = {}
    for workload in workloads:
        strategy = str((workload.get("gpu_sharing") or {}).get("strategy") or "")
        if strategy not in _SHARED_STRATEGIES or not workload.get("pool_name"):
            continue
        key = (str(workload.get("provider") or ""), str(workload.get("cluster_key") or ""), str(workload["pool_name"]))
        groups[key].add(str(workload.get("namespace") or ""))
        strategies[key] = strategy
    out: list[dict[str, Any]] = []
    for (provider, cluster_key, pool_name), namespaces in sorted(groups.items()):
        if len(namespaces) < 2:
            continue
        asset = {
            "provider": provider,
            "account_id": "",
            "asset_ref": gpu_pool_node_id(provider, cluster_key, pool_name),
            "asset_name": pool_name,
            "asset_kind": "gpu-node-pool",
        }
        out.append(
            _finding(
                "GPU-013",
                "low",
                "Namespaces share GPUs without memory isolation",
                f"Workloads from {len(namespaces)} namespaces ({', '.join(sorted(namespaces))}) run on "
                f"{strategies[(provider, cluster_key, pool_name)]} GPUs in pool {pool_name}; a tenant can observe or "
                "disrupt another tenant's GPU memory.",
                "Separate tenants onto dedicated GPU pools or MIG partitions.",
                asset,
            )
        )
    return out


def managed_compute_findings(record: dict[str, Any], *, account_id: str = "") -> list[dict[str, Any]]:
    """Posture findings for Snowflake SPCS GPU pools and Databricks GPU clusters."""
    if not record.get("gpu"):
        return []
    kind = record.get("pool_kind")
    if kind == "databricks-cluster" and record.get("data_security_mode") == "NONE":
        asset = {
            "provider": "databricks",
            "account_id": account_id,
            "asset_ref": f"cloud_resource:databricks:clusters:cluster:{record.get('pool_id')}",
            "asset_name": str(record.get("name") or record.get("pool_id") or ""),
            "asset_kind": "databricks-cluster",
        }
        return [
            _finding(
                "GPU-020",
                "medium",
                "Shared GPU cluster runs without user isolation",
                f"Databricks GPU cluster {asset['asset_name']} uses the No Isolation Shared access mode: every attached user runs "
                "code as the same identity on the same GPUs.",
                "Use Dedicated (single user) access mode for GPU clusters.",
                asset,
            )
        ]
    if kind == "spcs-compute-pool" and int(record.get("num_services") or 0) > 1 and not record.get("is_exclusive"):
        asset = {
            "provider": "snowflake",
            "account_id": account_id,
            "asset_ref": spcs_pool_node_id(account_id, str(record.get("name") or "")),
            "asset_name": str(record.get("name") or ""),
            "asset_kind": "spcs-compute-pool",
        }
        return [
            _finding(
                "GPU-021",
                "low",
                "GPU compute pool is shared by several services",
                f"Snowpark Container Services pool {asset['asset_name']} runs {record.get('num_services')} services on the same GPU nodes.",
                "Give services with different owners or data access their own GPU compute pool.",
                asset,
            )
        ]
    return []


def spcs_pool_node_id(account: str, name: str) -> str:
    return f"cloud_resource:snowflake:compute_pool:{account}/{name}" if account else f"cloud_resource:snowflake:compute_pool:{name}"


def gpu_posture_finding_to_finding(raw: dict[str, Any]) -> Finding:
    """Unified finding for one raw GPU posture finding."""
    provider = sanitize_text(str(raw.get("provider") or "kubernetes"), max_len=40).lower()
    account_ref = normalize_account_ref(provider, str(raw.get("account_id") or "")) if raw.get("account_id") else None
    asset_ref = sanitize_text(str(raw.get("asset_ref") or ""), max_len=500)
    workload = raw.get("asset_kind") == "gpu-workload"
    return Finding(
        finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
        source=FindingSource.CLOUD_SECURITY,
        asset=Asset(
            name=sanitize_text(str(raw.get("asset_name") or asset_ref), max_len=300),
            asset_type="agent" if workload else "cloud_resource",
            identifier=str(raw.get("identifier") or asset_ref),
            location=provider,
            provider=provider,
            account_ref=account_ref,
        ),
        severity=str(raw.get("severity") or "medium").lower(),
        provider=provider,
        account_ref=account_ref,
        title=sanitize_text(str(raw.get("title") or raw.get("check_id") or "GPU posture"), max_len=300),
        description=sanitize_text(str(raw.get("detail") or ""), max_len=800),
        remediation_guidance=sanitize_text(str(raw.get("remediation") or ""), max_len=500) or None,
        compliance_tags=[f"GPU-POSTURE-{raw.get('check_id')}"],
        evidence={
            "check_id": raw.get("check_id"),
            "category": "gpu_posture",
            "asset_ref": asset_ref,
            "asset_kind": raw.get("asset_kind"),
            "provider": provider,
        },
        node_id=None if workload else asset_ref,
        is_actionable=True,
        impact_category="gpu_infrastructure",
        id=str(raw.get("id") or gpu_finding_id(str(raw.get("check_id")), asset_ref)),
    )


CLUSTER_COLLECTIONS = {"aws": "eks_clusters", "gcp": "gke_clusters", "azure": "container_clusters"}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value] if isinstance(value, dict) else []


def inventory_account(inventory: dict[str, Any]) -> str:
    return str(inventory.get("account_id") or inventory.get("subscription_id") or inventory.get("project_id") or "")


def cloud_gpu_pools(cloud_inventory: Any) -> list[tuple[dict[str, Any], dict[str, Any], str]]:
    """``(inventory, pool, account)`` for every GPU pool on an inventoried cluster."""
    out: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    for inventory in _as_list(cloud_inventory):
        if not isinstance(inventory, dict) or inventory.get("status", "ok") != "ok":
            continue
        collection = CLUSTER_COLLECTIONS.get(str(inventory.get("provider") or ""), "")
        clusters = (inventory.get(collection) or []) if collection else []
        for cluster in clusters:
            for pool in (cluster.get("node_pools") if isinstance(cluster, dict) else None) or []:
                if isinstance(pool, dict) and pool.get("gpu"):
                    out.append((inventory, pool, inventory_account(inventory)))
    return out


def _workload_agent_ids(agents: list[Any]) -> dict[tuple[str, str], str]:
    """``(agent name, cluster) -> agent stable id``, so a workload finding binds to its agent node."""
    out: dict[tuple[str, str], str] = {}
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        scope = (((agent.get("metadata") or {}).get("cloud_origin") or {}).get("scope")) or {}
        if agent.get("stable_id") and scope.get("cluster"):
            out[(str(agent.get("name") or ""), str(scope["cluster"]))] = str(agent["stable_id"])
    return out


def gpu_posture_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every raw GPU posture finding for a JSON-shaped report: one judgement for all surfaces."""
    findings: list[dict[str, Any]] = []
    for _inventory, pool, account in cloud_gpu_pools(report.get("cloud_inventory")):
        findings.extend(pool_findings(pool, account_id=account))
    workloads = [w for w in ((report.get("gpu_infra") or {}).get("k8s") or {}).get("workloads") or [] if isinstance(w, dict)]
    agent_ids = _workload_agent_ids(report.get("agents") or [])
    for workload in workloads:
        identifier = agent_ids.get(
            (f"gpu-workload:{workload.get('namespace')}/{workload.get('pod')}", str(workload.get("cluster_key") or ""))
        )
        findings.extend({**f, "identifier": identifier} if identifier else f for f in workload_findings(workload))
    findings.extend(shared_gpu_tenancy_findings(workloads))
    services = report.get("snowflake_services")
    if isinstance(services, dict):
        for pool in services.get("compute_pools") or []:
            if isinstance(pool, dict):
                findings.extend(managed_compute_findings(pool, account_id=str(services.get("account") or "")))
    for agent in report.get("agents") or []:
        record = ((agent.get("metadata") if isinstance(agent, dict) else None) or {}).get("gpu_compute")
        if isinstance(record, dict):
            findings.extend(managed_compute_findings(record, account_id=str(record.get("workspace_host") or "")))
    unique = {f["id"]: f for f in findings}
    return [unique[key] for key in sorted(unique)]
