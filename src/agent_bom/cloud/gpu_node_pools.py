"""Normalize managed Kubernetes node pools into one GPU-aware record shape.

Each provider's read-only API response is mapped by its own function; nothing
here calls a cloud API. The record keeps every pool (GPU or not) so the
cluster's capacity is complete, and marks GPU pools with ``gpu=True``.

Record keys: ``name``, ``pool_id`` (native id), ``pool_kind``, ``provider``,
``cluster_name``, ``cluster_key``, ``machine_types``, ``gpu``, ``gpu_vendor``,
``accelerator_type``, ``accelerators_per_node``, ``min_nodes``, ``max_nodes``,
``node_count``, ``gpu_driver`` (``management`` + provider ``setting``),
``gpu_sharing`` (``strategy`` + detail), ``taints``, ``labels``,
``node_identity``, ``image``, ``node_public_ip``, ``ssh_open_to_internet``.

``gpu_driver.management`` is ``provider-managed`` when the provider installs
and patches the NVIDIA driver (EKS accelerated AMIs, GKE ``DEFAULT``/``LATEST``,
AKS default install), ``user-managed`` when the operator does (EKS ``CUSTOM``
AMI or a standard AMI on GPU hardware, GKE ``INSTALLATION_DISABLED``, AKS
``gpuProfile.driver=None``), else ``unknown``.
"""

from __future__ import annotations

import re
from typing import Any

from agent_bom.cloud.gpu_accelerators import Accelerator, aws_instance_accelerator, azure_vm_accelerator, gcp_machine_accelerator
from agent_bom.cloud.gpu_accelerators import gke_accelerator_vendor as _gke_vendor

_EKS_ACCELERATED_AMIS = re.compile(r".*_(GPU|NVIDIA|NVIDIA_FIPS|NEURON)$")
_GKE_LINK_PREFIX = re.compile(r"^https://container\.googleapis\.com/v[0-9a-z]+/")


def gpu_pool_node_id(provider: str, cluster_key: str, pool_name: str) -> str:
    """Graph id of a GPU node pool, derivable from cloud inventory and from kubectl alike."""
    key = cluster_key.casefold() if provider == "azure" else cluster_key
    return f"cloud_resource:{provider}:gpu_node_pool:{key}/{pool_name}"


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value) or "").strip()


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None and str(value) != "" else None
    except (TypeError, ValueError):
        return None


def _accelerator_fields(acc: Accelerator | None, *, count: int | None = None, accelerator_type: str = "") -> dict[str, Any]:
    if acc is None and not accelerator_type:
        return {"gpu": False, "gpu_vendor": "", "accelerator_type": "", "accelerators_per_node": None}
    return {
        "gpu": True,
        "gpu_vendor": acc.vendor if acc else "",
        "accelerator_type": accelerator_type or (acc.model if acc else ""),
        "accelerators_per_node": count if count is not None else (acc.count if acc else None),
    }


# ── AWS EKS managed node groups (eks:DescribeNodegroup) ──────────────────────


def _eks_driver(ami_type: str, gpu: bool) -> dict[str, str]:
    if not gpu:
        return {"management": "not-applicable", "setting": ami_type}
    if _EKS_ACCELERATED_AMIS.fullmatch(ami_type):
        return {"management": "provider-managed", "setting": ami_type}
    return {"management": "user-managed", "setting": ami_type}


def eks_node_group_pool(nodegroup: dict[str, Any], *, cluster_arn: str) -> dict[str, Any]:
    """Normalize one ``describe_nodegroup()["nodegroup"]`` response."""
    instance_types = [str(t) for t in nodegroup.get("instanceTypes") or [] if t]
    accelerators = [acc for t in instance_types if (acc := aws_instance_accelerator(t))]
    ami_type = str(nodegroup.get("amiType") or "")
    acc = accelerators[0] if accelerators else None
    if acc is None and _EKS_ACCELERATED_AMIS.fullmatch(ami_type):
        acc = Accelerator("aws-neuron" if ami_type.endswith("NEURON") else "nvidia", "")
    fields = _accelerator_fields(acc)
    scaling = nodegroup.get("scalingConfig") or {}
    remote = nodegroup.get("remoteAccess") or {}
    return {
        "name": str(nodegroup.get("nodegroupName") or ""),
        "pool_id": str(nodegroup.get("nodegroupArn") or ""),
        "pool_kind": "eks-node-group",
        "provider": "aws",
        "cluster_name": str(nodegroup.get("clusterName") or ""),
        "cluster_key": cluster_arn,
        "machine_types": instance_types,
        **fields,
        "min_nodes": _int_or_none(scaling.get("minSize")),
        "max_nodes": _int_or_none(scaling.get("maxSize")),
        "node_count": _int_or_none(scaling.get("desiredSize")),
        "gpu_driver": _eks_driver(ami_type, fields["gpu"]),
        "gpu_sharing": {"strategy": "not-reported"},
        "taints": [
            {"key": str(t.get("key") or ""), "value": str(t.get("value") or ""), "effect": str(t.get("effect") or "")}
            for t in nodegroup.get("taints") or []
            if isinstance(t, dict)
        ],
        "labels": {str(k): str(v) for k, v in (nodegroup.get("labels") or {}).items()},
        "node_identity": str(nodegroup.get("nodeRole") or ""),
        "image": ami_type,
        "release_version": str(nodegroup.get("releaseVersion") or ""),
        "node_public_ip": None,
        # EKS opens port 22 to 0.0.0.0/0 when an SSH key is set without source security groups.
        "ssh_open_to_internet": bool(remote.get("ec2SshKey")) and not remote.get("sourceSecurityGroups"),
        "status": str(nodegroup.get("status") or ""),
    }


# ── GCP GKE node pools (container.clusters.list) ─────────────────────────────


def gke_cluster_key(cluster_self_link: str, project_id: str, location: str, name: str) -> str:
    link = _GKE_LINK_PREFIX.sub("", str(cluster_self_link or ""))
    return link or f"projects/{project_id}/locations/{location}/clusters/{name}"


def _gke_sharing(acc: Any) -> dict[str, Any]:
    partition = str(_attr(acc, "gpu_partition_size", "") or "")
    sharing = _attr(acc, "gpu_sharing_config")
    strategy = _enum_name(_attr(sharing, "gpu_sharing_strategy", "")) if sharing else ""
    if strategy and strategy != "GPU_SHARING_STRATEGY_UNSPECIFIED":
        clients = _int_or_none(_attr(sharing, "max_shared_clients_per_gpu"))
        return {
            "strategy": "time-slicing" if strategy == "TIME_SHARING" else strategy.lower(),
            "max_shared_clients": clients,
            **({"mig_partition": partition} if partition else {}),
        }
    if partition:
        return {"strategy": "mig", "mig_partition": partition}
    return {"strategy": "none"}


def _gke_driver(acc: Any) -> dict[str, str]:
    config = _attr(acc, "gpu_driver_installation_config")
    setting = _enum_name(_attr(config, "gpu_driver_version", "")) if config else ""
    if setting in {"DEFAULT", "LATEST"}:
        return {"management": "provider-managed", "setting": setting}
    if setting == "INSTALLATION_DISABLED":
        return {"management": "user-managed", "setting": setting}
    return {"management": "unknown", "setting": setting or "unspecified"}


def gke_node_pool(pool: Any, *, cluster_key: str, cluster_name: str) -> dict[str, Any]:
    """Normalize one GKE ``NodePool`` (SDK object or its dict form)."""
    config = _attr(pool, "config") or {}
    machine = str(_attr(config, "machine_type", "") or "")
    accelerators = [a for a in _attr(config, "accelerators", None) or [] if _gke_vendor(str(_attr(a, "accelerator_type", "") or ""))]
    first = accelerators[0] if accelerators else None
    if first is not None:
        acc_type = str(_attr(first, "accelerator_type", "") or "")
        fields = _accelerator_fields(
            Accelerator("nvidia", acc_type), count=_int_or_none(_attr(first, "accelerator_count")), accelerator_type=acc_type
        )
    else:
        fields = _accelerator_fields(gcp_machine_accelerator(machine))
    autoscaling = _attr(pool, "autoscaling")
    autoscaled = bool(_attr(autoscaling, "enabled", False)) if autoscaling else False
    name = str(_attr(pool, "name", "") or "")
    return {
        "name": name,
        "pool_id": _GKE_LINK_PREFIX.sub("", str(_attr(pool, "self_link", "") or "")) or f"{cluster_key}/nodePools/{name}",
        "pool_kind": "gke-node-pool",
        "provider": "gcp",
        "cluster_name": cluster_name,
        "cluster_key": cluster_key,
        "machine_types": [machine] if machine else [],
        **fields,
        "min_nodes": _int_or_none(_attr(autoscaling, "min_node_count")) if autoscaled else None,
        "max_nodes": _int_or_none(_attr(autoscaling, "max_node_count")) if autoscaled else None,
        "node_count": _int_or_none(_attr(pool, "initial_node_count")),
        "gpu_driver": _gke_driver(first)
        if first is not None
        else {"management": "unknown" if fields["gpu"] else "not-applicable", "setting": ""},
        "gpu_sharing": _gke_sharing(first) if first is not None else {"strategy": "none"},
        "taints": [
            {"key": str(_attr(t, "key", "") or ""), "value": str(_attr(t, "value", "") or ""), "effect": _enum_name(_attr(t, "effect", ""))}
            for t in _attr(config, "taints", None) or []
        ],
        "labels": {str(k): str(v) for k, v in dict(_attr(config, "labels", None) or {}).items()},
        "node_identity": str(_attr(config, "service_account", "") or ""),
        "image": str(_attr(config, "image_type", "") or ""),
        "node_public_ip": None,
        "ssh_open_to_internet": False,
        "status": _enum_name(_attr(pool, "status", "")),
    }


# ── Azure AKS agent pools (managedClusters agentPoolProfiles) ────────────────


def _aks_taint(raw: str) -> dict[str, str]:
    key_value, _, effect = str(raw).partition(":")
    key, _, value = key_value.partition("=")
    return {"key": key, "value": value, "effect": effect}


def _aks_driver(profile: Any, gpu: bool) -> dict[str, str]:
    if not gpu:
        return {"management": "not-applicable", "setting": ""}
    setting = _enum_name(_attr(_attr(profile, "gpu_profile"), "driver", "")) if _attr(profile, "gpu_profile") else ""
    if setting.casefold() == "none":
        return {"management": "user-managed", "setting": "None"}
    return {"management": "provider-managed", "setting": setting or "Install (default)"}


def aks_agent_pool(profile: Any, *, cluster_id: str, cluster_name: str) -> dict[str, Any]:
    """Normalize one ``ManagedClusterAgentPoolProfile`` (SDK object or dict form)."""
    vm_size = str(_attr(profile, "vm_size", "") or "")
    fields = _accelerator_fields(azure_vm_accelerator(vm_size))
    mig = _enum_name(_attr(profile, "gpu_instance_profile", ""))
    name = str(_attr(profile, "name", "") or "")
    autoscaled = bool(_attr(profile, "enable_auto_scaling", False))
    return {
        "name": name,
        "pool_id": f"{cluster_id}/agentPools/{name}" if cluster_id else name,
        "pool_kind": "aks-agent-pool",
        "provider": "azure",
        "cluster_name": cluster_name,
        "cluster_key": cluster_id,
        "machine_types": [vm_size] if vm_size else [],
        **fields,
        "min_nodes": _int_or_none(_attr(profile, "min_count")) if autoscaled else None,
        "max_nodes": _int_or_none(_attr(profile, "max_count")) if autoscaled else None,
        "node_count": _int_or_none(_attr(profile, "count")),
        "gpu_driver": _aks_driver(profile, fields["gpu"]),
        "gpu_sharing": {"strategy": "mig", "mig_partition": mig} if mig else {"strategy": "none"},
        "taints": [_aks_taint(t) for t in _attr(profile, "node_taints", None) or [] if t],
        "labels": {str(k): str(v) for k, v in dict(_attr(profile, "node_labels", None) or {}).items()},
        "node_identity": "",
        "image": str(_attr(profile, "os_sku", "") or ""),
        "mode": _enum_name(_attr(profile, "mode", "")),
        "node_public_ip": bool(_attr(profile, "enable_node_public_ip", False)),
        "ssh_open_to_internet": False,
        "status": _enum_name(_attr(_attr(profile, "power_state"), "code", "")) if _attr(profile, "power_state") else "",
    }


def gpu_pools(clusters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every GPU pool recorded on a cluster collection."""
    return [pool for cluster in clusters or [] if isinstance(cluster, dict) for pool in cluster.get("node_pools") or [] if pool.get("gpu")]
