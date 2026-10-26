"""Normalized Kubernetes workload inventory, the same model from a live cluster or manifests.

Input is a flat list of Kubernetes objects (``kubectl get -o json`` items, or
parsed manifest / rendered Helm documents). Output is one JSON-safe inventory:
namespaces, workloads with their containers, images (by digest when the source
recorded one), referenced Secret names, service accounts and service-account
RBAC grants. Secrets are only ever named, never read: no Secret object is
collected, so no secret value can enter the inventory.

Live pods collapse into the top-level controller that owns them (Pod →
ReplicaSet → Deployment, Pod → Job → CronJob) when that controller was
collected; a pod whose owner was not collected stays its own workload.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.core.image_ref import DIGEST_PREFIX, digest_in_ref
from agent_bom.kubernetes.inventory_rbac import binding_record, resolve_grants, role_record

WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod")
_PSA_LABEL_PREFIX = "pod-security.kubernetes.io/"


def image_digest_from_status(image_id: str) -> str:
    """The registry digest in a container status ``imageID``; a bare local image id is not one."""
    value = (image_id or "").strip()
    for scheme in ("docker-pullable://", "docker://"):
        value = value.removeprefix(scheme)
    if "@" not in value:
        return ""
    digest = value.rsplit("@", 1)[1]
    return digest if digest.startswith(DIGEST_PREFIX) else ""


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _meta(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(obj.get("metadata"))


def pod_spec(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    """The pod spec a workload object runs (``spec`` for a Pod, its template otherwise)."""
    spec = _mapping(obj.get("spec"))
    if obj.get("kind") == "Pod":
        return spec
    if obj.get("kind") == "CronJob":
        spec = _mapping(_mapping(spec.get("jobTemplate")).get("spec"))
    return _mapping(_mapping(spec.get("template")).get("spec"))


def _owner(obj: Mapping[str, Any]) -> tuple[str, str] | None:
    for ref in _meta(obj).get("ownerReferences") or []:
        if isinstance(ref, Mapping) and ref.get("kind") and ref.get("name"):
            return str(ref["kind"]), str(ref["name"])
    return None


def _secret_refs(spec: Mapping[str, Any]) -> list[dict[str, str]]:
    refs: set[tuple[str, str]] = set()
    for volume in spec.get("volumes") or []:
        if isinstance(volume, Mapping) and isinstance(volume.get("secret"), Mapping) and volume["secret"].get("secretName"):
            refs.add((str(volume["secret"]["secretName"]), "volume"))
    for container in _all_containers(spec):
        for env in container.get("env") or []:
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef") or {}) if isinstance(env, Mapping) else {}
            if isinstance(ref, Mapping) and ref.get("name"):
                refs.add((str(ref["name"]), "env"))
        for env_from in container.get("envFrom") or []:
            ref = (env_from.get("secretRef") or {}) if isinstance(env_from, Mapping) else {}
            if isinstance(ref, Mapping) and ref.get("name"):
                refs.add((str(ref["name"]), "envFrom"))
    for pull in spec.get("imagePullSecrets") or []:
        if isinstance(pull, Mapping) and pull.get("name"):
            refs.add((str(pull["name"]), "imagePullSecret"))
    return [{"name": name, "via": via} for name, via in sorted(refs)]


def _all_containers(spec: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    found: list[Mapping[str, Any]] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        found.extend(c for c in spec.get(key) or [] if isinstance(c, Mapping))
    return found


def _status_digests(pods: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    digests: dict[str, set[str]] = {}
    for pod in pods:
        status = _mapping(pod.get("status"))
        for key in ("initContainerStatuses", "containerStatuses"):
            for entry in status.get(key) or []:
                if isinstance(entry, Mapping) and (digest := image_digest_from_status(str(entry.get("imageID") or ""))):
                    digests.setdefault(str(entry.get("name") or ""), set()).add(digest)
    return digests


def _containers(spec: Mapping[str, Any], pods: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    running = _status_digests(pods)
    init_names = {str(c.get("name") or "") for c in spec.get("initContainers") or [] if isinstance(c, Mapping)}
    records: list[dict[str, Any]] = []
    for container in _all_containers(spec):
        name, image = str(container.get("name") or ""), str(container.get("image") or "").strip()
        if not image:
            continue
        digests = sorted(running.get(name) or {digest_in_ref(image)})
        for digest in digests:
            records.append({"name": name, "image": image, "image_digest": digest, "init": name in init_names})
    return records


def _token_mounted(spec: Mapping[str, Any], sa_automount: bool | None) -> bool:
    for volume in spec.get("volumes") or []:
        sources = ((volume.get("projected") or {}).get("sources") or []) if isinstance(volume, Mapping) else []
        if any(isinstance(src, Mapping) and "serviceAccountToken" in src for src in sources):
            return True
    pod_setting = spec.get("automountServiceAccountToken")
    if isinstance(pod_setting, bool):
        return pod_setting
    return sa_automount is not False


def _top_owner(obj: Mapping[str, Any], by_key: dict[tuple[str, str, str], Mapping[str, Any]]) -> Mapping[str, Any]:
    current, namespace = obj, str(_meta(obj).get("namespace") or "")
    for _ in range(4):
        owner = _owner(current)
        parent = by_key.get((owner[0], namespace, owner[1])) if owner else None
        if parent is None:
            return current
        current = parent
    return current


def _workload_key(obj: Mapping[str, Any]) -> tuple[str, str, str]:
    meta = _meta(obj)
    return str(obj.get("kind") or ""), str(meta.get("namespace") or "default"), str(meta.get("name") or "")


def _group_workloads(objects: list[Mapping[str, Any]]) -> dict[tuple[str, str, str], list[Mapping[str, Any]]]:
    """Top-level workload key → the pods it owns (empty for manifests)."""
    by_key = {_workload_key(obj): obj for obj in objects if obj.get("kind") in WORKLOAD_KINDS}
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for key, obj in by_key.items():
        top = _top_owner(obj, by_key)
        top_key = _workload_key(top)
        groups.setdefault(top_key, [])
        if obj.get("kind") == "Pod":
            groups[top_key].append(obj)
    return {key: pods for key, pods in groups.items() if key in by_key}


def _workload_record(obj: Mapping[str, Any], pods: list[Mapping[str, Any]], sa_automount: dict[tuple[str, str], bool | None]) -> dict:
    kind, namespace, name = _workload_key(obj)
    spec = pod_spec(obj)
    service_account = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
    return {
        "kind": kind,
        "namespace": namespace,
        "name": name,
        "uid": str(_meta(obj).get("uid") or ""),
        "service_account": service_account,
        "token_mounted": _token_mounted(spec, sa_automount.get((namespace, service_account))),
        "containers": _containers(spec, pods),
        "secret_refs": _secret_refs(spec),
        "host_network": spec.get("hostNetwork") is True,
        "privileged": any(((c.get("securityContext") or {}).get("privileged") is True) for c in _all_containers(spec)),
        "pod_uids": sorted(str(_meta(pod).get("uid") or "") for pod in pods if _meta(pod).get("uid")),
    }


def _service_accounts(objects: list[Mapping[str, Any]], workloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    accounts: dict[tuple[str, str], dict[str, Any]] = {}
    for obj in objects:
        if obj.get("kind") == "ServiceAccount":
            meta = _meta(obj)
            key = (str(meta.get("namespace") or "default"), str(meta.get("name") or ""))
            automount = obj.get("automountServiceAccountToken")
            accounts[key] = {
                "namespace": key[0],
                "name": key[1],
                "automount_token": automount if isinstance(automount, bool) else None,
                "declared": True,
            }
    for workload in workloads:
        key = (workload["namespace"], workload["service_account"])
        accounts.setdefault(key, {"namespace": key[0], "name": key[1], "automount_token": None, "declared": False})
    return [accounts[key] for key in sorted(accounts)]


def _namespaces(objects: list[Mapping[str, Any]], workloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("kind") == "Namespace" and _meta(obj).get("name"):
            labels = _mapping(_meta(obj).get("labels"))
            psa = {str(k): str(v) for k, v in sorted(labels.items()) if str(k).startswith(_PSA_LABEL_PREFIX)}
            name = str(_meta(obj)["name"])
            found[name] = {"name": name, "labels": psa, "declared": True}
    for workload in workloads:
        found.setdefault(workload["namespace"], {"name": workload["namespace"], "labels": {}, "declared": False})
    return [found[name] for name in sorted(found)]


def _summary(inventory: dict[str, Any]) -> dict[str, int]:
    containers = [c for w in inventory["workloads"] for c in w["containers"]]
    images = {(c["image"], c["image_digest"]) for c in containers}
    return {
        "namespaces": len(inventory["namespaces"]),
        "workloads": len(inventory["workloads"]),
        "containers": len(containers),
        "images": len(images),
        "images_with_digest": sum(1 for _image, digest in images if digest),
        "service_accounts": len(inventory["service_accounts"]),
        "rbac_grants": len(inventory["rbac_grants"]),
        "secret_refs": len({(w["namespace"], ref["name"]) for w in inventory["workloads"] for ref in w["secret_refs"]}),
    }


def build_k8s_inventory(objects: Iterable[Any], *, source: str, cluster: str = "") -> dict[str, Any]:
    """Normalize Kubernetes objects into the workload inventory (see module docstring)."""
    items = [obj for obj in objects if isinstance(obj, Mapping) and isinstance(obj.get("kind"), str)]
    sa_automount = {
        (str(_meta(o).get("namespace") or "default"), str(_meta(o).get("name") or "")): o.get("automountServiceAccountToken")
        if isinstance(o.get("automountServiceAccountToken"), bool)
        else None
        for o in items
        if o.get("kind") == "ServiceAccount"
    }
    by_key = {_workload_key(obj): obj for obj in items if obj.get("kind") in WORKLOAD_KINDS}
    workloads = [_workload_record(by_key[key], pods, sa_automount) for key, pods in sorted(_group_workloads(items).items())]
    roles = [role_record(obj) for obj in items if obj.get("kind") in {"Role", "ClusterRole"}]
    bindings = [binding_record(obj) for obj in items if obj.get("kind") in {"RoleBinding", "ClusterRoleBinding"}]
    inventory: dict[str, Any] = {
        "source": source,
        "cluster": cluster,
        "namespaces": _namespaces(items, workloads),
        "workloads": workloads,
        "service_accounts": _service_accounts(items, workloads),
        "rbac_grants": resolve_grants(roles, bindings),
        "non_service_account_subjects": sum(1 for b in bindings for s in b["subjects"] if s["kind"] != "ServiceAccount"),
    }
    inventory["summary"] = _summary(inventory)
    return inventory
