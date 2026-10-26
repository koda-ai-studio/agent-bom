"""Kubernetes GPU workloads, the node pools they run on, and the node GPU stack.

Pure functions over read-only ``kubectl get ... -o json`` payloads:

- nodes: pool membership from the managed-provider node labels
  (``eks.amazonaws.com/nodegroup``, ``cloud.google.com/gke-nodepool``,
  ``kubernetes.azure.com/agentpool``) and the driver version / sharing
  replicas published by NVIDIA GPU Feature Discovery labels;
- pods: containers requesting a GPU extended resource, with the security
  context, host namespaces, hostPath mounts, service account and the IRSA role
  the EKS pod-identity webhook injects (``AWS_ROLE_ARN``);
- the NVIDIA GPU Operator ``ClusterPolicy``: declared driver and Container
  Toolkit versions.

Env values are never kept except ``AWS_ROLE_ARN``, which is an identifier.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from agent_bom.constants import is_credential_key
from agent_bom.models import Package
from agent_bom.parsers.gpu_stack import CONTAINER_TOOLKIT, DRIVER

_POOL_LABELS = (
    ("eks.amazonaws.com/nodegroup", "aws"),
    ("cloud.google.com/gke-nodepool", "gcp"),
    ("kubernetes.azure.com/agentpool", "azure"),
    ("agentpool", "azure"),
)
_PROVIDER_IDS = (("aws://", "aws"), ("gce://", "gcp"), ("azure://", "azure"))
_GPU_RESOURCE = re.compile(r"^(?:nvidia\.com/(?:gpu|mig-[0-9a-z.]+)|amd\.com/gpu|gpu\.intel\.com/[a-z0-9]+)$")
_EKS_CLUSTER_ARN = re.compile(r"^arn:aws[a-z-]*:eks:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_.-]+$")
_GKE_CONTEXT = re.compile(r"^gke_(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])_(?P<location>[a-z0-9-]+)_(?P<name>[a-z0-9-]+)$")
_SENSITIVE_HOST_PATHS = (
    "/dev",
    "/var/lib/kubelet/device-plugins",
    "/var/lib/kubelet/pod-resources",
    "/run/nvidia",
    "/var/run/docker.sock",
    "/run/containerd",
    "/var/run/containerd",
    "/var/run/cri-dockerd.sock",
    "/",
)
_VERSION = re.compile(r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)")


@dataclass
class GpuNodeContext:
    name: str
    provider: str
    pool_name: str
    gpu_capacity: int
    gpu_product: str = ""
    driver_version: str = ""
    sharing: dict[str, Any] = field(default_factory=dict)


@dataclass
class GpuWorkload:
    namespace: str
    pod: str
    phase: str
    node_name: str
    pool_name: str
    provider: str
    cluster_key: str
    service_account: str
    containers: list[dict[str, Any]]
    host_paths: list[str]
    host_pid: bool = False
    host_ipc: bool = False
    host_network: bool = False
    aws_role_arn: str = ""
    credential_env: list[str] = field(default_factory=list)
    gpu_sharing: dict[str, Any] = field(default_factory=dict)
    driver_version: str = ""

    @property
    def gpu_count(self) -> int:
        return sum(int(c.get("gpus") or 0) for c in self.containers)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "gpu_count": self.gpu_count}


@dataclass
class GpuStack:
    driver_version: str = ""
    toolkit_version: str = ""
    source: str = ""
    driver_by_node: dict[str, str] = field(default_factory=dict)


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    return {str(k): str(v) for k, v in ((obj.get("metadata") or {}).get("labels") or {}).items()}


def _node_provider(node: dict[str, Any]) -> str:
    provider_id = str((node.get("spec") or {}).get("providerID") or "")
    return next((name for prefix, name in _PROVIDER_IDS if provider_id.startswith(prefix)), "")


def _pool_from_labels(labels: dict[str, str]) -> tuple[str, str]:
    for key, provider in _POOL_LABELS:
        if labels.get(key):
            return labels[key], provider
    return "", ""


def _gpu_capacity(node: dict[str, Any]) -> int:
    capacity = (node.get("status") or {}).get("capacity") or {}
    total = 0
    for key, value in capacity.items():
        if _GPU_RESOURCE.match(str(key)):
            try:
                total += int(str(value))
            except ValueError:
                continue
    return total


def gfd_driver_version(labels: dict[str, str]) -> str:
    full = labels.get("nvidia.com/cuda.driver-version.full", "")
    if full:
        return full
    for prefix, rev in (("nvidia.com/cuda.driver-version", "revision"), ("nvidia.com/cuda.driver", "rev")):
        parts = [labels.get(f"{prefix}.{p}", "") for p in ("major", "minor", rev)]
        if parts[0] and parts[1]:
            return ".".join(p for p in parts if p)
    return ""


def _node_sharing(labels: dict[str, str]) -> dict[str, Any]:
    gke_strategy = labels.get("cloud.google.com/gke-gpu-sharing-strategy", "")
    if gke_strategy:
        clients = labels.get("cloud.google.com/gke-max-shared-clients-per-gpu", "")
        return {
            "strategy": "time-slicing" if gke_strategy == "time-sharing" else gke_strategy,
            "max_shared_clients": int(clients) if clients.isdigit() else None,
        }
    replicas = labels.get("nvidia.com/gpu.replicas", "")
    if replicas.isdigit() and int(replicas) > 1:
        strategy = labels.get("nvidia.com/gpu.sharing-strategy", "time-slicing")
        return {"strategy": strategy, "max_shared_clients": int(replicas)}
    mig = labels.get("nvidia.com/mig.strategy") or labels.get("cloud.google.com/gke-gpu-partition-size")
    if mig:
        return {"strategy": "mig", "mig_partition": mig}
    return {"strategy": "none"}


def node_contexts(node_list: dict[str, Any] | None) -> dict[str, GpuNodeContext]:
    """Pool, GPU capacity and GFD facts for every node in ``kubectl get nodes``."""
    contexts: dict[str, GpuNodeContext] = {}
    for node in (node_list or {}).get("items") or []:
        name = str((node.get("metadata") or {}).get("name") or "")
        if not name:
            continue
        labels = _labels(node)
        pool, label_provider = _pool_from_labels(labels)
        contexts[name] = GpuNodeContext(
            name=name,
            provider=_node_provider(node) or label_provider,
            pool_name=pool,
            gpu_capacity=_gpu_capacity(node),
            gpu_product=labels.get("nvidia.com/gpu.product", "") or labels.get("cloud.google.com/gke-accelerator", ""),
            driver_version=gfd_driver_version(labels),
            sharing=_node_sharing(labels),
        )
    return contexts


def cluster_identity(kubeconfig: dict[str, Any] | None, nodes: dict[str, GpuNodeContext]) -> tuple[str, str]:
    """``(provider, cluster_key)`` matching the cloud inventory's cluster key when provable.

    ``aws eks update-kubeconfig`` names the context and cluster after the EKS
    cluster ARN, and ``gcloud container clusters get-credentials`` names them
    ``gke_<project>_<location>_<cluster>``. Anything else stays keyed by its
    kube context so it is never merged with an unrelated cloud cluster.
    """
    config = kubeconfig or {}
    context_name = str(config.get("current-context") or "")
    contexts = [c for c in config.get("contexts") or [] if isinstance(c, dict)]
    cluster_name = next((str((c.get("context") or {}).get("cluster") or "") for c in contexts if c.get("name") == context_name), "")
    for candidate in (cluster_name, context_name):
        if _EKS_CLUSTER_ARN.match(candidate):
            return "aws", candidate
        if match := _GKE_CONTEXT.match(candidate):
            return "gcp", f"projects/{match['project']}/locations/{match['location']}/clusters/{match['name']}"
    providers = {n.provider for n in nodes.values() if n.provider}
    provider = providers.pop() if len(providers) == 1 else "kubernetes"
    return provider, f"kube-context:{context_name or 'current'}"


def _gpus(resources: dict[str, Any]) -> int:
    total = 0
    for bucket in ("limits", "requests"):
        counts = [int(str(v)) for k, v in (resources.get(bucket) or {}).items() if _GPU_RESOURCE.match(str(k)) and str(v).isdigit()]
        total = max(total, sum(counts))
    return total


def _env_facts(containers: list[dict[str, Any]]) -> tuple[str, list[str]]:
    role, names = "", []
    for container in containers:
        for env in container.get("env") or []:
            name = str(env.get("name") or "")
            literal = str(env.get("value") or "")
            if name == "AWS_ROLE_ARN" and literal.startswith("arn:"):
                role = literal
            elif literal.startswith("/"):
                continue  # a mounted-file path (e.g. the projected IRSA token), not a secret value
            elif name and (is_credential_key(name) or "secretKeyRef" in (env.get("valueFrom") or {})):
                names.append(name)
    return role, sorted(set(names))


def _host_paths(spec: dict[str, Any]) -> list[str]:
    paths = []
    for volume in spec.get("volumes") or []:
        path = str((volume.get("hostPath") or {}).get("path") or "")
        if path and any(
            path == p or (p != "/" and path.startswith(p + "/")) or path.startswith("/dev/nvidia") for p in _SENSITIVE_HOST_PATHS
        ):
            paths.append(path)
    return sorted(set(paths))


def _container_facts(container: dict[str, Any]) -> dict[str, Any]:
    ctx = container.get("securityContext") or {}
    return {
        "name": str(container.get("name") or ""),
        "image": str(container.get("image") or "").strip(),
        "gpus": _gpus(container.get("resources") or {}),
        "privileged": bool(ctx.get("privileged")),
        "allow_privilege_escalation": ctx.get("allowPrivilegeEscalation"),
        "added_capabilities": sorted(str(c) for c in (ctx.get("capabilities") or {}).get("add") or []),
    }


def _scheduled_pool(spec: dict[str, Any], node: GpuNodeContext | None) -> str:
    if node is not None and node.pool_name:
        return node.pool_name
    pool, _ = _pool_from_labels({str(k): str(v) for k, v in (spec.get("nodeSelector") or {}).items()})
    return pool or (f"node/{node.name}" if node is not None else "")


def gpu_workloads(
    pod_list: dict[str, Any] | None, nodes: dict[str, GpuNodeContext], *, provider: str, cluster_key: str
) -> list[GpuWorkload]:
    """Pods with at least one container requesting a GPU extended resource."""
    workloads: list[GpuWorkload] = []
    for pod in (pod_list or {}).get("items") or []:
        spec = pod.get("spec") or {}
        containers = [_container_facts(c) for c in [*(spec.get("containers") or []), *(spec.get("initContainers") or [])]]
        if not any(c["gpus"] for c in containers):
            continue
        meta = pod.get("metadata") or {}
        node = nodes.get(str(spec.get("nodeName") or ""))
        role, credential_env = _env_facts(spec.get("containers") or [])
        workloads.append(
            GpuWorkload(
                namespace=str(meta.get("namespace") or "default"),
                pod=str(meta.get("name") or ""),
                phase=str((pod.get("status") or {}).get("phase") or ""),
                node_name=node.name if node else "",
                pool_name=_scheduled_pool(spec, node),
                provider=provider,
                cluster_key=cluster_key,
                service_account=str(spec.get("serviceAccountName") or "default"),
                containers=containers,
                host_paths=_host_paths(spec),
                host_pid=bool(spec.get("hostPID")),
                host_ipc=bool(spec.get("hostIPC")),
                host_network=bool(spec.get("hostNetwork")),
                aws_role_arn=role,
                credential_env=credential_env,
                gpu_sharing=dict(node.sharing) if node else {},
                driver_version=node.driver_version if node else "",
            )
        )
    return workloads


def _version(raw: Any) -> str:
    match = _VERSION.match(str(raw or "").strip())
    return match[1] if match else ""


def cluster_policy_stack(policies: dict[str, Any] | None) -> GpuStack:
    """Driver and Container Toolkit versions declared by the GPU Operator ClusterPolicy."""
    for policy in (policies or {}).get("items") or []:
        spec = policy.get("spec") or {}
        driver = spec.get("driver") or {}
        toolkit = spec.get("toolkit") or {}
        return GpuStack(
            driver_version=_version(driver.get("version")) if driver.get("enabled", True) else "",
            toolkit_version=_version(toolkit.get("version")) if toolkit.get("enabled", True) else "",
            source="gpu-operator-clusterpolicy",
        )
    return GpuStack()


def stack_packages(*, driver_version: str, toolkit_version: str, driver_source: str, toolkit_source: str) -> list[Package]:
    """Driver / Container Toolkit packages carrying NVD CPE identity, for CVE matching."""
    packages: list[Package] = []
    for product, version, source in ((DRIVER, driver_version, driver_source), (CONTAINER_TOOLKIT, toolkit_version, toolkit_source)):
        cpe = product.cpe(version) if version else None
        if cpe is None:
            continue
        packages.append(
            Package(
                name=product.name,
                version=version,
                ecosystem="generic",
                purl=product.purl(version),
                cpe=cpe,
                is_direct=False,
                resolved_from_registry=False,
                version_evidence=[{"type": source}],
                discovery_provenance={"source_type": "kubernetes", "source": source, "confidence": "medium"},
            )
        )
    return packages
