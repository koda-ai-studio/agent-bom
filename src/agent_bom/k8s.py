"""Kubernetes live-cluster helpers.

Runs ``kubectl get pods`` to list running containers, then returns their image
references so the caller can pass them to ``image.scan_image()`` for package
extraction.

Usage from cli.py::

    from agent_bom.k8s import discover_images, K8sDiscoveryError
    images = discover_images(namespace="default", context="my-cluster")
    for image_ref, pod_name, container_name in images:
        packages, strategy = scan_image(image_ref)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from math import ceil
from time import monotonic
from typing import Optional

from agent_bom.iac.models import IaCFinding
from agent_bom.k8s_transport import K8sReadTransport, K8sTransportError, select_k8s_transport, validate_kubelet_endpoint
from agent_bom.kubernetes.admission_checks import ADMISSION_RESOURCES, evaluate_admission_posture
from agent_bom.kubernetes.posture_checks import evaluate_kubelet_config, evaluate_pod_security, evaluate_rbac
from agent_bom.kubernetes.posture_models import CollectorState, K8sCollectorEvidence, K8sPostureResult, K8sPostureStatus

__all__ = [
    "CollectorState",
    "K8sCollectorEvidence",
    "K8sDiscoveryError",
    "K8sPostureResult",
    "K8sPostureStatus",
    "discover_images",
    "evaluate_kubelet_config",
    "evaluate_pod_security",
    "evaluate_rbac",
    "list_namespaces",
    "scan_live_cluster_posture",
    "scan_live_cluster_posture_with_evidence",
]


class K8sDiscoveryError(Exception):
    """Raised when kubectl discovery fails."""


def _kubectl_available() -> bool:
    return shutil.which("kubectl") is not None


ImageRecord = tuple[str, str, str]  # (image_ref, pod_name, container_name)


def _run_kubectl_json(args: list[str], *, context: Optional[str] = None, timeout: int = 60) -> dict:
    """Run kubectl and parse JSON output."""
    if not _kubectl_available():
        raise K8sDiscoveryError(
            "'kubectl' not found on PATH. Install kubectl and ensure it is configured with access to the target cluster."
        )

    cmd = ["kubectl", *args]
    if context:
        cmd += ["--context", context]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise K8sDiscoveryError("kubectl not found")
    except subprocess.TimeoutExpired:
        raise K8sDiscoveryError("kubectl timed out — check cluster connectivity")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise K8sDiscoveryError(f"kubectl exited {result.returncode}: {stderr[:300]}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise K8sDiscoveryError(f"kubectl produced invalid JSON: {exc}")


def discover_images(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
    label_selector: Optional[str] = None,
) -> list[ImageRecord]:
    """Discover container images running in a Kubernetes cluster.

    Uses ``kubectl get pods`` with ``-o json`` output.

    Args:
        namespace: Kubernetes namespace to query (ignored when ``all_namespaces=True``).
        all_namespaces: Query all namespaces (``kubectl get pods -A``).
        context: kubectl context to use (uses current context if ``None``).
        label_selector: Label selector string, e.g. ``"app=myapp"``.

    Returns:
        List of ``(image_ref, pod_name, container_name)`` tuples.
        Deduplication is applied — the same image reference is only returned once,
        attributed to the first pod/container where it was seen.

    Raises:
        K8sDiscoveryError: If kubectl is not available or the API call fails.
    """
    cmd = ["get", "pods", "-o", "json"]

    if all_namespaces:
        cmd.append("-A")
    else:
        cmd += ["-n", namespace]

    if label_selector:
        cmd += ["-l", label_selector]

    data = _run_kubectl_json(cmd, context=context, timeout=60)

    records: list[ImageRecord] = []
    seen_images: set[str] = set()

    for pod in data.get("items", []):
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", namespace)
        qualified_pod = f"{pod_ns}/{pod_name}" if all_namespaces else pod_name

        # Prefer spec.containers; also check initContainers and ephemeralContainers
        container_lists = [
            pod.get("spec", {}).get("containers", []),
            pod.get("spec", {}).get("initContainers", []),
            pod.get("spec", {}).get("ephemeralContainers", []),
        ]

        for container_list in container_lists:
            for container in container_list:
                image_ref = container.get("image", "").strip()
                container_name = container.get("name", "unknown")
                if image_ref and image_ref not in seen_images:
                    seen_images.add(image_ref)
                    records.append((image_ref, qualified_pod, container_name))

    return records


def list_namespaces(context: Optional[str] = None) -> list[str]:
    """Return the list of namespaces in the cluster.

    Useful for ``--k8s --all-namespaces`` mode UI feedback.

    Raises:
        K8sDiscoveryError: If kubectl is not available or the call fails.
    """
    try:
        data = _run_kubectl_json(["get", "namespaces", "-o", "json"], context=context, timeout=30)
        return [item["metadata"]["name"] for item in data.get("items", [])]
    except K8sDiscoveryError as exc:
        if "invalid JSON" in str(exc):
            return []
        raise
    except KeyError:
        return []


_POSTURE_RESOURCES = (
    "pods",
    "networkpolicies",
    "clusterrolebindings",
    "clusterroles",
    "roles",
    "nodes",
)
MAX_CONFIGZ_NODES = 100
MAX_CONFIGZ_BUDGET_SECONDS = 60
MAX_CONFIGZ_REQUEST_SECONDS = 30


def _collector_state_for_error(exc: K8sTransportError) -> CollectorState:
    if exc.status_code in {401, 403, 404}:
        return CollectorState.UNEVALUABLE
    return CollectorState.FAILED


def _kubelet_endpoint(node: dict) -> tuple[str, int] | None:
    """Return a node-advertised kubelet HTTPS endpoint, if present."""
    status = node.get("status", {}) or {}
    raw_addresses = status.get("addresses", []) or []
    by_type = {
        item.get("type"): item.get("address")
        for item in raw_addresses
        if isinstance(item, dict) and isinstance(item.get("address"), str) and item.get("address")
    }
    host = by_type.get("InternalIP")
    endpoint = (status.get("daemonEndpoints", {}) or {}).get("kubeletEndpoint", {}) or {}
    port = endpoint.get("Port", endpoint.get("port"))
    if not host or not isinstance(port, int) or isinstance(port, bool):
        return None
    try:
        return validate_kubelet_endpoint(str(host), port)
    except K8sTransportError:
        return None


def _posture_status(collectors: list[K8sCollectorEvidence]) -> K8sPostureStatus:
    primary = [collector for collector in collectors if collector.collector_id in _POSTURE_RESOURCES]
    if primary and all(collector.state is not CollectorState.EXECUTED for collector in primary):
        return K8sPostureStatus.FAILED
    if any(collector.state in {CollectorState.UNEVALUABLE, CollectorState.FAILED} or collector.truncated for collector in collectors):
        return K8sPostureStatus.PARTIAL
    return K8sPostureStatus.COMPLETE


def _live_finding(rule_id: str, severity: str, title: str, message: str, file_path: str, compliance: list[str]) -> IaCFinding:
    return IaCFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        file_path=file_path,
        line_number=1,
        category="kubernetes-live",
        compliance=compliance,
    )


def _transport_unavailable_result(exc: K8sTransportError) -> K8sPostureResult:
    """Stage 1 failure: no read transport, so every collector is recorded as not run."""
    collectors = [
        K8sCollectorEvidence(collector_id=resource, state=CollectorState.FAILED, message=str(exc)) for resource in _POSTURE_RESOURCES
    ]
    collectors.append(
        K8sCollectorEvidence(
            collector_id="kubelet_configz",
            state=CollectorState.SKIPPED,
            message="nodes/configz collection was not started",
        )
    )
    return K8sPostureResult(findings=[], collectors=collectors, status=K8sPostureStatus.FAILED, transport="unavailable")


def _collect_posture_resources(
    transport: K8sReadTransport,
    transport_name: str,
    namespace: str,
    all_namespaces: bool,
    collectors: list[K8sCollectorEvidence],
    resources: tuple[str, ...] = _POSTURE_RESOURCES,
) -> dict[str, dict]:
    """Stage 2: GET each posture resource kind, recording per-kind collector evidence."""
    payloads: dict[str, dict] = {}
    for resource in resources:
        resource_namespace = namespace if resource in {"pods", "networkpolicies", "roles"} else None
        try:
            read = transport.list_resource(resource, namespace=resource_namespace, all_namespaces=all_namespaces)
        except K8sTransportError as exc:
            collectors.append(
                K8sCollectorEvidence(
                    collector_id=resource, state=_collector_state_for_error(exc), message=str(exc), transport=transport_name
                )
            )
            continue
        payloads[resource] = read.data
        collectors.append(
            K8sCollectorEvidence(
                collector_id=resource,
                state=CollectorState.EXECUTED,
                object_count=read.object_count,
                pages=read.pages,
                truncated=read.truncated,
                message="collection reached its configured bound" if read.truncated else "",
                transport=transport_name,
            )
        )
    return payloads


def _live_pod_findings(pod_ns: str, pod_name: str, spec: dict, status: dict) -> list[IaCFinding]:
    """Stage 3a: runtime health and service-account token checks for one live pod."""
    findings: list[IaCFinding] = []
    pod_ref = f"k8s://{pod_ns}/{pod_name}"
    phase = status.get("phase", "Unknown")
    if phase != "Running":
        message = (
            f"Pod '{pod_ns}/{pod_name}' is currently in phase '{phase}'. "
            "Investigate runtime drift, crash loops, or image/config rollout health."
        )
        findings.append(_live_finding("K8S-LIVE-001", "medium", "Live pod not running", message, pod_ref, ["CIS-K8s-5.7.4", "NIST-SI-4"]))

    container_statuses = status.get("containerStatuses", []) or []
    for container_status in container_statuses:
        waiting = (container_status.get("state", {}) or {}).get("waiting", {}) or {}
        if waiting.get("reason") == "CrashLoopBackOff":
            message = (
                f"Pod '{pod_ns}/{pod_name}' container "
                f"'{container_status.get('name', 'unknown')}' is in CrashLoopBackOff. "
                "Runtime drift or bad rollout is already impacting availability."
            )
            findings.append(
                _live_finding("K8S-LIVE-002", "high", "Live pod is crash looping", message, pod_ref, ["CIS-K8s-5.7.4", "NIST-SI-4"])
            )
        if not container_status.get("ready", False):
            message = (
                f"Pod '{pod_ns}/{pod_name}' container "
                f"'{container_status.get('name', 'unknown')}' is not ready. "
                "Live readiness drift may bypass assumptions in static manifests."
            )
            findings.append(
                _live_finding("K8S-LIVE-003", "medium", "Live pod container not ready", message, pod_ref, ["CIS-K8s-5.7.4", "NIST-SI-4"])
            )

    automount = spec.get("automountServiceAccountToken")
    if automount is not False:
        explicit = automount is True
        detail = (
            "service-account token auto-mount explicitly enabled."
            if explicit
            else "service-account token auto-mount left at the Kubernetes default (enabled)."
        )
        message = (
            f"Pod '{pod_ns}/{pod_name}' is running with {detail} "
            "Set automountServiceAccountToken: false unless the workload needs Kubernetes API access."
        )
        severity = "medium" if explicit else "low"
        findings.append(
            _live_finding(
                "K8S-LIVE-004", severity, "Live pod mounts service-account token", message, pod_ref, ["CIS-K8s-5.1.6", "NIST-AC-6"]
            )
        )
    return findings


def _evaluate_live_pods(pods: dict, namespace: str, findings: list[IaCFinding]) -> set[str]:
    """Stage 3b: evaluate every live pod and return the namespaces that run pods."""
    namespaces_with_pods: set[str] = set()
    for pod in pods.get("items", []):
        if not isinstance(pod, dict):
            continue
        metadata = pod.get("metadata", {})
        pod_name = metadata.get("name", "unknown")
        pod_ns = metadata.get("namespace", namespace)
        namespaces_with_pods.add(pod_ns)
        findings.extend(_live_pod_findings(pod_ns, pod_name, pod.get("spec", {}) or {}, pod.get("status", {}) or {}))
    findings.extend(evaluate_pod_security(pods, default_namespace=namespace))
    return namespaces_with_pods


def _network_policy_gaps(namespaces_with_pods: set[str], policy_namespaces: set[str]) -> list[IaCFinding]:
    """Stage 3c: namespaces running pods without any live NetworkPolicy object."""
    findings: list[IaCFinding] = []
    for ns in sorted(namespaces_with_pods):
        if ns not in policy_namespaces:
            message = (
                f"Namespace '{ns}' has running pods but no live NetworkPolicy objects. "
                "This is a runtime posture gap even if manifests exist elsewhere in Git."
            )
            title = "Namespace lacks live NetworkPolicy coverage"
            findings.append(_live_finding("K8S-LIVE-005", "high", title, message, f"k8s://namespace/{ns}", ["CIS-K8s-5.3.2", "NIST-SC-7"]))
    return findings


def _read_node_configz(transport: K8sReadTransport, node: dict, remaining_seconds: float) -> dict:
    """GET one node's kubelet ``/configz``; raises K8sTransportError when not evaluable."""
    endpoint = _kubelet_endpoint(node)
    if endpoint is None:
        raise K8sTransportError("Node does not advertise an evaluable kubelet HTTPS endpoint", status_code=404, reason="unavailable")
    kubelet_host, kubelet_port = endpoint
    data = transport.get_kubelet_json(
        kubelet_host,
        kubelet_port,
        "/configz",
        timeout=max(1, min(MAX_CONFIGZ_REQUEST_SECONDS, ceil(remaining_seconds))),
    )
    config = data.get("kubeletconfig", data)
    if not isinstance(config, dict) or not config:
        raise K8sTransportError("nodes/configz returned no evaluable configuration", reason="invalid_json")
    return config


def _configz_evidence(
    config_errors: list[K8sTransportError], config_truncated: bool, config_count: int, transport_name: str
) -> K8sCollectorEvidence:
    if config_errors:
        config_state = (
            CollectorState.FAILED
            if any(_collector_state_for_error(error) is CollectorState.FAILED for error in config_errors)
            else CollectorState.UNEVALUABLE
        )
        message = f"{len(config_errors)} node config read(s) were not evaluable"
    elif config_truncated and config_count == 0:
        config_state = CollectorState.UNEVALUABLE
        message = "nodes/configz collection reached its configured bound before any node was evaluated"
    else:
        config_state = CollectorState.EXECUTED
        message = "nodes/configz collection reached its configured bound" if config_truncated else ""
    return K8sCollectorEvidence(
        collector_id="kubelet_configz",
        state=config_state,
        object_count=config_count,
        pages=config_count,
        truncated=config_truncated,
        message=message,
        transport=transport_name,
    )


def _collect_kubelet_configz(
    transport: K8sReadTransport, transport_name: str, nodes: dict, findings: list[IaCFinding]
) -> K8sCollectorEvidence:
    """Bounded per-node kubelet config reads and CIS kubelet checks."""
    config_count = 0
    config_errors: list[K8sTransportError] = []
    node_items = nodes.get("items", []) or []
    config_truncated = len(node_items) > MAX_CONFIGZ_NODES
    config_deadline = monotonic() + MAX_CONFIGZ_BUDGET_SECONDS
    for node in node_items[:MAX_CONFIGZ_NODES]:
        remaining_seconds = config_deadline - monotonic()
        if remaining_seconds <= 0:
            config_truncated = True
            break
        if not isinstance(node, dict):
            continue
        node_name = (node.get("metadata", {}) or {}).get("name")
        if not node_name:
            continue
        try:
            config = _read_node_configz(transport, node, remaining_seconds)
        except K8sTransportError as exc:
            config_errors.append(exc)
            continue
        config_count += 1
        findings.extend(evaluate_kubelet_config(str(node_name), config))
    return _configz_evidence(config_errors, config_truncated, config_count, transport_name)


def _kubelet_configz_collector(
    transport: K8sReadTransport, transport_name: str, payloads: dict[str, dict], enable_nodes_configz: bool, findings: list[IaCFinding]
) -> K8sCollectorEvidence:
    """Stage 4: kubelet ``/configz`` evidence; opt-in and gated on node inventory."""
    if not enable_nodes_configz:
        state, message = CollectorState.SKIPPED, "nodes/configz collection is opt-in and disabled"
    elif "nodes" not in payloads:
        state, message = CollectorState.UNEVALUABLE, "nodes/configz requires successful node inventory"
    else:
        return _collect_kubelet_configz(transport, transport_name, payloads["nodes"], findings)
    return K8sCollectorEvidence(collector_id="kubelet_configz", state=state, message=message, transport=transport_name)


def scan_live_cluster_posture_with_evidence(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
    *,
    enable_nodes_configz: bool = False,
    transport: K8sReadTransport | None = None,
) -> K8sPostureResult:
    """Inspect live Kubernetes posture with explicit collection evidence.

    This complements manifest scanning. It does not attempt full policy
    evaluation across the cluster; it inspects live workload, RBAC, namespace,
    and optional node/kubelet state that static manifests cannot prove. The
    in-cluster path uses the mounted service-account token and CA directly;
    kubectl is retained only as a workstation fallback. All access is GET-only.

    Direct kubelet ``/configz`` is separately opt-in because older clusters do
    not map it to the fine-grained ``nodes/configz`` authorization subresource.
    The collector never falls back to ``nodes/proxy``; unavailable config is
    recorded as unevaluable.
    """
    findings: list[IaCFinding] = []
    collectors: list[K8sCollectorEvidence] = []
    owns_transport = transport is None

    if transport is None:
        try:
            transport = select_k8s_transport(
                context=context,
            )
        except K8sTransportError as exc:
            return _transport_unavailable_result(exc)

    transport_name = transport.name
    try:
        payloads = _collect_posture_resources(transport, transport_name, namespace, all_namespaces, collectors)
        network_policies = payloads.get("networkpolicies", {"items": []})
        policy_namespaces = {
            item.get("metadata", {}).get("namespace", namespace)
            for item in network_policies.get("items", [])
            if isinstance(item, dict) and item.get("metadata", {}).get("namespace")
        }
        namespaces_with_pods: set[str] = set()
        if "pods" in payloads:
            namespaces_with_pods = _evaluate_live_pods(payloads["pods"], namespace, findings)
        # NetworkPolicy absence is only evaluable when both inputs completed.
        if "pods" in payloads and "networkpolicies" in payloads:
            findings.extend(_network_policy_gaps(namespaces_with_pods, policy_namespaces))
        # Each RBAC input remains independently useful when another read is denied.
        findings.extend(
            evaluate_rbac(
                payloads.get("clusterroles", {"items": []}),
                payloads.get("roles", {"items": []}),
                payloads.get("clusterrolebindings", {"items": []}),
                default_namespace=namespace,
            )
        )
        admission = _collect_posture_resources(transport, transport_name, namespace, all_namespaces, collectors, ADMISSION_RESOURCES)
        findings.extend(
            evaluate_admission_posture(
                namespaces=admission.get("namespaces"),
                workload_namespaces=namespaces_with_pods,
                validating_policies=admission.get("validatingadmissionpolicies"),
                validating_policy_bindings=admission.get("validatingadmissionpolicybindings"),
                validating_webhooks=admission.get("validatingwebhookconfigurations"),
                admission_evaluated="pods" in payloads and all(resource in admission for resource in ADMISSION_RESOURCES),
            )
        )
        collectors.append(_kubelet_configz_collector(transport, transport_name, payloads, enable_nodes_configz, findings))
    finally:
        if owns_transport:
            transport.close()

    return K8sPostureResult(
        findings=findings,
        collectors=collectors,
        status=_posture_status(collectors),
        transport=transport_name,
    )


def scan_live_cluster_posture(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
    *,
    enable_nodes_configz: bool = False,
) -> list[IaCFinding]:
    """Compatibility wrapper returning findings while failing on total outage.

    Call :func:`scan_live_cluster_posture_with_evidence` when partial and
    unevaluable collector states must be rendered or persisted.
    """
    result = scan_live_cluster_posture_with_evidence(
        namespace=namespace,
        all_namespaces=all_namespaces,
        context=context,
        enable_nodes_configz=enable_nodes_configz,
    )
    if result.status is not K8sPostureStatus.COMPLETE:
        details = next(
            (
                collector.message
                for collector in result.collectors
                if collector.state in {CollectorState.UNEVALUABLE, CollectorState.FAILED} and collector.message
            ),
            "collection incomplete",
        )
        raise K8sDiscoveryError(details)
    return result.findings
