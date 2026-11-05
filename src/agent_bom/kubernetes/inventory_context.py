"""Allowlisted runtime and routing context; no pod environment or secret values."""

from collections.abc import Callable, Mapping
from typing import Any


def object_ref(obj: Mapping[str, Any]) -> dict[str, str]:
    meta = obj.get("metadata") or {}
    return {
        "kind": str(obj.get("kind") or ""),
        "namespace": str(meta.get("namespace") or "default"),
        "name": str(meta.get("name") or ""),
        "uid": str(meta.get("uid") or ""),
    }


def recorded_owner(obj: Mapping[str, Any], by_ref: dict[tuple[str, str, str], Mapping[str, Any]]) -> dict[str, str] | None:
    ref = object_ref(obj)
    for owner in (obj.get("metadata") or {}).get("ownerReferences") or []:
        if not isinstance(owner, Mapping) or owner.get("controller") is not True or not owner.get("uid"):
            continue
        parent = by_ref.get((str(owner.get("kind")), ref["namespace"], str(owner.get("name"))))
        if parent and object_ref(parent)["uid"] == owner["uid"]:
            return object_ref(parent)
    return None


def investigation_context(items: list[Mapping[str, Any]], containers: Callable[..., list[dict[str, Any]]]) -> dict[str, Any]:
    by_ref = {(r["kind"], r["namespace"], r["name"]): obj for obj in items if (r := object_ref(obj))["name"]}
    pods, controllers, services, routes = [], [], [], []
    for obj in items:
        ref = object_ref(obj)
        kind = ref["kind"]
        if kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}:
            record: dict[str, Any] = {**ref, "owner": recorded_owner(obj, by_ref)}
            if kind == "Pod":
                record["containers"] = containers(obj.get("spec") or {}, [obj])
                pods.append(record)
            else:
                controllers.append(record)
        elif kind == "Service":
            spec = obj.get("spec") or {}
            services.append(
                {
                    **ref,
                    "type": str(spec.get("type") or "ClusterIP"),
                    "ports": [
                        {k: p[k] for k in ("name", "port", "targetPort", "protocol") if k in p}
                        for p in spec.get("ports") or []
                        if isinstance(p, Mapping)
                    ],
                }
            )
        elif kind == "EndpointSlice":
            service_name = ((obj.get("metadata") or {}).get("labels") or {}).get("kubernetes.io/service-name")
            service = by_ref.get(("Service", ref["namespace"], str(service_name)))
            if not service or not object_ref(service)["uid"]:
                continue
            owners = (obj.get("metadata") or {}).get("ownerReferences") or []
            if not any(
                isinstance(o, Mapping)
                and o.get("kind") == "Service"
                and o.get("name") == service_name
                and o.get("uid") == object_ref(service)["uid"]
                for o in owners
            ):
                continue
            for endpoint in obj.get("endpoints") or []:
                target = endpoint.get("targetRef") or {}
                pod = by_ref.get(("Pod", str(target.get("namespace") or ""), str(target.get("name") or "")))
                if (
                    target.get("kind") != "Pod"
                    or not pod
                    or not target.get("uid")
                    or target.get("uid") != object_ref(pod)["uid"]
                    or target.get("namespace") != ref["namespace"]
                    or (endpoint.get("conditions") or {}).get("ready") is not True
                ):
                    continue
                routes.append(
                    {
                        "service": object_ref(service),
                        "pod": object_ref(pod),
                        "slice": ref,
                        "ports": [
                            {k: p[k] for k in ("name", "port", "protocol") if k in p}
                            for p in obj.get("ports") or []
                            if isinstance(p, Mapping)
                        ],
                    }
                )
    return {
        "pod_context": pods,
        "controller_context": controllers,
        "services": services,
        "endpoint_routes": routes,
        "ingresses": _ingresses(items, by_ref),
    }


def _ingresses(items: list[Mapping[str, Any]], by_ref: dict[tuple[str, str, str], Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for obj in items:
        ref = object_ref(obj)
        if ref["kind"] != "Ingress":
            continue
        spec = obj.get("spec") or {}
        candidates = [spec.get("defaultBackend") or {}]
        candidates.extend(
            path.get("backend") or {} for rule in spec.get("rules") or [] for path in (rule.get("http") or {}).get("paths") or []
        )
        backends = []
        for backend in candidates:
            service = backend.get("service") or {}
            target = by_ref.get(("Service", ref["namespace"], str(service.get("name") or "")))
            if target:
                backends.append(
                    {
                        "service": object_ref(target),
                        "port": {k: service["port"][k] for k in ("name", "number") if k in (service.get("port") or {})},
                    }
                )
        result.append({**ref, "backends": backends})
    return result
