"""Shared Kubernetes pod-scanning helpers for GPU cloud providers.

CoreWeave and Nebius both read ``kubectl get pods -o json`` payloads to find
GPU containers and InfiniBand (``rdma/ib``) training pods. This module owns
the read-only ``kubectl`` invocation, its fixed failure classification, and
the per-record parsing of that payload.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterable, Iterator
from typing import NamedTuple, TypeVar

from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

from .collection_errors import COLLECTION_ERRORS, CollectionError, CollectionStatus
from .k8s_errors import kubectl_failure_code
from .normalization import build_cloud_origin, build_package_purl, parse_container_image_package

_T = TypeVar("_T")
_INVALID_KUBECTL_LIST = "Invalid inventory response from kubectl. Assessment incomplete."
_KUBECTL_STATUS = {
    "permission_denied": CollectionStatus.DENIED,
    "invalid_credentials": CollectionStatus.DENIED,
    "throttled": CollectionStatus.THROTTLED,
}


class KubectlError(CollectionError):
    """Classified kubectl failure whose text never includes stderr or stdout."""

    def __init__(self, status: CollectionStatus, message: str):
        super().__init__(status)
        self.args = (message,)


def kubectl_command(args: list[str], context: str | None = None) -> list[str]:
    return ["kubectl", *(["--context", context] if context else []), *args, "-o", "json"]


def parse_kubectl_list(result: subprocess.CompletedProcess[str] | object) -> list:
    """Return the ``items`` list of a kubectl list response or raise a classified error.

    A malformed envelope fails the whole read; individual items are validated
    by the record iterators so one bad element cannot erase its neighbours.
    """
    if getattr(result, "returncode", 1) != 0:
        code = kubectl_failure_code(str(getattr(result, "stderr", "") or ""))
        raise KubectlError(_KUBECTL_STATUS.get(code, CollectionStatus.UNAVAILABLE), f"kubectl: {code}")
    try:
        data = json.loads(getattr(result, "stdout", ""))
    except (TypeError, ValueError):
        raise KubectlError(CollectionStatus.UNAVAILABLE, _INVALID_KUBECTL_LIST) from None
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise KubectlError(CollectionStatus.UNAVAILABLE, _INVALID_KUBECTL_LIST)
    return data["items"]


def run_kubectl_list(args: list[str], context: str | None = None, timeout: int = 60) -> list:
    """Run a read-only ``kubectl get ... -o json`` and return its items."""
    result = subprocess.run(kubectl_command(args, context), capture_output=True, text=True, timeout=timeout)
    return parse_kubectl_list(result)


def read_once(fetch: Callable[[], _T]) -> Callable[[], _T]:
    """Share one read between collection passes, including its failure."""
    state: dict[str, object] = {}

    def get() -> _T:
        if not state:
            try:
                state["value"] = fetch()
            except Exception as exc:  # noqa: BLE001 - re-raised to every caller unchanged
                state["error"] = exc
        if "error" in state:
            raise state["error"]  # type: ignore[misc]
        return state["value"]  # type: ignore[return-value]

    return get


def container_image_packages(image_ref: str) -> list[Package]:
    """Return the ``container-image`` package for an image reference, if parseable."""
    image_parts = parse_container_image_package(image_ref)
    if not image_parts:
        return []
    return [
        Package(
            name=image_parts[0],
            version=image_parts[1],
            ecosystem="container-image",
            purl=build_package_purl(ecosystem="container-image", name=image_parts[0], version=image_parts[1]),
        )
    ]


class GpuContainer(NamedTuple):
    namespace: str
    pod: str
    container: str
    image: str
    gpus: int


_QUANTITY = re.compile(r"(\d{1,18})(m|k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?")
_MULTIPLIERS = {
    **{suffix: 1000**power for power, suffix in enumerate(("", "k", "M", "G", "T", "P", "E"))},
    **{suffix: 1024 ** (power + 1) for power, suffix in enumerate(("Ki", "Mi", "Gi", "Ti", "Pi", "Ei"))},
}


def parse_quantity(value: object) -> int:
    """Whole-unit Kubernetes quantity of an extended resource (GPUs, ``rdma/ib``)."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if not isinstance(value, str):
        raise TypeError("Invalid resource quantity")
    match = _QUANTITY.fullmatch(value.strip())
    if not match:
        raise ValueError("Invalid resource quantity")
    number, suffix = int(match.group(1)), match.group(2) or ""
    if suffix == "m":
        if number % 1000:
            raise ValueError("Fractional extended resource quantity")
        return number // 1000
    return number * _MULTIPLIERS[suffix]


class InvalidPodRecordError(ValueError):
    """The pod envelope or identity is malformed; skip the whole pod."""


def _mapping(value: object, default: dict | None = None) -> dict:
    if value is None and default is not None:
        return default
    if not isinstance(value, dict):
        raise TypeError("Invalid Kubernetes record")
    return value


def _pod_identity(pod: dict) -> tuple[str, str]:
    """Return ``(namespace, name)``; a pod without a name is a malformed record."""
    meta = pod.get("metadata")
    if not isinstance(meta, dict):
        raise InvalidPodRecordError("Invalid pod metadata")
    name, namespace = meta.get("name"), meta.get("namespace", "default")
    if not isinstance(name, str) or not name or not isinstance(namespace, str) or not namespace:
        raise InvalidPodRecordError("Invalid pod identity")
    return namespace, name


def _pod_containers(pod: object, keys: tuple[str, ...]) -> tuple[dict, list[tuple[int, object]]]:
    if not isinstance(pod, dict) or not isinstance(pod.get("metadata"), dict):
        raise InvalidPodRecordError("Invalid pod record")
    spec = pod.get("spec", {})
    if not isinstance(spec, dict):
        raise InvalidPodRecordError("Invalid pod spec")
    indexed: list[tuple[int, object]] = []
    for key in keys:
        listed = spec.get(key, [])
        if not isinstance(listed, list):
            raise InvalidPodRecordError("Invalid pod container list")
        indexed.extend(enumerate(listed))
    return pod, indexed


def _container_resources(container: object) -> tuple[dict, dict, dict]:
    if not isinstance(container, dict):
        raise TypeError("Invalid container record")
    resources = _mapping(container.get("resources"), {})
    return container, _mapping(resources.get("limits"), {}), _mapping(resources.get("requests"), {})


def _image(container: dict) -> str:
    image = container.get("image", "")
    if not isinstance(image, str):
        raise TypeError("Invalid container image")
    return image.strip()


def _report(errors: list[Exception] | None, exc: Exception) -> None:
    if errors is None:
        raise exc
    errors.append(exc)


def iter_gpu_containers(
    pods: Iterable[object],
    *,
    include_init_containers: bool = False,
    errors: list[Exception] | None = None,
) -> Iterator[GpuContainer]:
    """Yield each container requesting ``nvidia.com/gpu``.

    A shared image is a shared dependency, not a workload identity. Preserve
    each pod/container observation so inventory and graph projection retain
    every affected workload when multiple replicas use the same image.

    Each pod and each container is isolated: with an ``errors`` sink a
    malformed record is reported there and later records still yield; without
    one the first malformed record raises.
    """
    keys = ("containers", "initContainers") if include_init_containers else ("containers",)
    for item in pods:
        try:
            pod, containers = _pod_containers(item, keys)
        except COLLECTION_ERRORS as exc:
            _report(errors, exc)
            continue
        for index, entry in containers:
            try:
                container, limits, requested = _container_resources(entry)
                gpus = parse_quantity(limits.get("nvidia.com/gpu", "0")) or parse_quantity(requested.get("nvidia.com/gpu", "0"))
                image_ref = _image(container) if gpus else ""
                if not image_ref:
                    continue
                name = container.get("name") or f"container-{index}"
                if not isinstance(name, str):
                    raise TypeError("Invalid container name")
                namespace, pod_name = _pod_identity(pod)
            except InvalidPodRecordError as exc:
                _report(errors, exc)
                break
            except COLLECTION_ERRORS as exc:
                _report(errors, exc)
                continue
            yield GpuContainer(namespace, pod_name, name, image_ref, gpus)


def iter_infiniband_pods(pods: Iterable[object], *, errors: list[Exception] | None = None) -> Iterator[tuple[str, str, str, int]]:
    """Yield pods with a container requesting ``rdma/ib``, once per pod.

    Yields ``(namespace, pod_name, image_ref, gpu_count)`` from the first valid
    InfiniBand container of each pod. Malformed pods and containers are
    isolated like :func:`iter_gpu_containers`; a pod is only marked seen once
    it has been yielded.
    """
    seen_jobs: set[tuple[str, str]] = set()
    for item in pods:
        try:
            pod, containers = _pod_containers(item, ("containers",))
        except COLLECTION_ERRORS as exc:
            _report(errors, exc)
            continue
        for _index, entry in containers:
            try:
                container, limits, requested = _container_resources(entry)
                if not (parse_quantity(limits.get("rdma/ib", "0")) or parse_quantity(requested.get("rdma/ib", "0"))):
                    continue
                job_key = _pod_identity(pod)
                if job_key in seen_jobs:
                    break
                image_ref = _image(container)
                gpu_count = parse_quantity(limits.get("nvidia.com/gpu", "0"))
            except InvalidPodRecordError as exc:
                _report(errors, exc)
                break
            except COLLECTION_ERRORS as exc:
                _report(errors, exc)
                continue
            seen_jobs.add(job_key)
            yield job_key[0], job_key[1], image_ref, gpu_count
            break


def build_training_agent(
    *,
    provider: str,
    pod_ns: str,
    pod_name: str,
    image_ref: str,
    gpu_count: int,
    config_path: str,
    project_id: str | None = None,
    cluster: str | None = None,
    previous_config_paths: list[str] | None = None,
) -> Agent:
    """Build the ``<provider>-training`` agent for an InfiniBand training pod."""
    label = f"{provider}-training"
    server = MCPServer(
        name=f"{label}:{pod_ns}/{pod_name}",
        transport=TransportType.UNKNOWN,
        packages=container_image_packages(image_ref),
    )
    return Agent(
        name=f"{label}:{pod_ns}/{pod_name}",
        agent_type=AgentType.CUSTOM,
        config_path=config_path,
        source=label,
        version=f"infiniband+gpu:{gpu_count}" if gpu_count else "infiniband",
        mcp_servers=[server],
        metadata={
            "training_job": True,
            "infiniband": True,
            "gpu_count": gpu_count,
            "image": image_ref,
            "kind": "Pod",
            "cloud_origin": build_cloud_origin(
                provider=provider,
                service="kubernetes",
                resource_type="training-pod",
                resource_id=f"{pod_ns}/{pod_name}",
                resource_name=pod_name,
                project_id=project_id,
                cluster=cluster,
                raw_identity={"namespace": pod_ns, "pod": pod_name, "image": image_ref, **({"context": cluster} if cluster else {})},
            ),
            **({"previous_config_paths": previous_config_paths} if previous_config_paths else {}),
        },
    )
