#!/usr/bin/env python3
"""Generate UI graph fixtures by running the real Kubernetes projection.

Investigation-flow tests must see what the collector and projection emit, not a
hand-written approximation of it. Each scenario below is raw Kubernetes API
objects; everything in the fixture comes from ``build_k8s_inventory`` and
``build_unified_graph_from_report``.

Usage:
    python scripts/generate_k8s_graph_fixture.py            # regenerate
    python scripts/generate_k8s_graph_fixture.py --check    # drift guard
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.graph.builder import build_unified_graph_from_report  # noqa: E402
from agent_bom.kubernetes.inventory import build_k8s_inventory  # noqa: E402
from agent_bom.kubernetes.inventory_report import kubernetes_inventory_section  # noqa: E402

FIXTURE = ROOT / "ui" / "e2e" / "fixtures" / "k8s-projection.json"
NS = "prod"
SCAN_ID = "k8s-fixture"
# The projection stamps these with the wall clock at build time.
VOLATILE_FIELDS = {"first_seen", "last_seen", "valid_from", "valid_to", "created_at", "updated_at"}
Obj = dict[str, Any]


def _object(kind: str, name: str, uid: str, *, meta: Obj | None = None, **fields: Any) -> Obj:
    return {"kind": kind, "metadata": {"name": name, "namespace": NS, "uid": uid, **(meta or {})}, **fields}


def _owner(kind: str, name: str, uid: str) -> Obj:
    return {"ownerReferences": [{"kind": kind, "name": name, "uid": uid, "controller": True}]}


def _pod_spec(account: str, image: str, *, token: bool, secret: str = "") -> Obj:
    spec: Obj = {"serviceAccountName": account, "automountServiceAccountToken": token, "containers": [{"name": "app", "image": image}]}
    if secret:
        spec["volumes"] = [{"name": "credentials", "secret": {"secretName": secret}}]
    return spec


def _deployment(name: str, spec: Obj, pods: list[str]) -> list[Obj]:
    """A Deployment, its ReplicaSet and pods, joined by owner references as the API reports them."""
    replicaset = f"{name}-7c9f"
    objects = [
        _object("Deployment", name, f"{name}-deploy-uid", spec={"template": {"spec": spec}}),
        _object(
            "ReplicaSet",
            replicaset,
            f"{name}-rs-uid",
            meta=_owner("Deployment", name, f"{name}-deploy-uid"),
            spec={"template": {"spec": spec}},
        ),
    ]
    objects += [_object("Pod", pod, f"{pod}-uid", meta=_owner("ReplicaSet", replicaset, f"{name}-rs-uid"), spec=spec) for pod in pods]
    return objects


def _service(name: str, service_type: str, port: int = 443) -> Obj:
    return _object("Service", name, f"{name}-svc-uid", spec={"type": service_type, "ports": [{"port": port, "protocol": "TCP"}]})


def _routes(service: str, pods: list[str], port: int = 8080) -> Obj:
    return _object(
        "EndpointSlice",
        f"{service}-slice",
        f"{service}-slice-uid",
        meta={
            "labels": {"kubernetes.io/service-name": service},
            "ownerReferences": [{"kind": "Service", "name": service, "uid": f"{service}-svc-uid"}],
        },
        ports=[{"port": port}],
        endpoints=[
            {"targetRef": {"kind": "Pod", "name": pod, "namespace": NS, "uid": f"{pod}-uid"}, "conditions": {"ready": True}} for pod in pods
        ],
    )


def _ingress(name: str, service: str, port: int = 443) -> Obj:
    backend = {"service": {"name": service, "port": {"number": port}}}
    return _object("Ingress", name, f"{name}-ing-uid", spec={"rules": [{"http": {"paths": [{"backend": backend}]}}]})


def _account(name: str, *, token: bool) -> Obj:
    return _object("ServiceAccount", name, f"{name}-sa-uid", automountServiceAccountToken=token)


def _reader_role(account: str) -> list[Obj]:
    role = f"{account}-reader"
    return [
        _object("Role", role, f"{role}-uid", rules=[{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]),
        _object(
            "RoleBinding",
            f"{role}-binding",
            f"{role}-binding-uid",
            roleRef={"kind": "Role", "name": role},
            subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}],
        ),
    ]


def _namespace() -> Obj:
    return {"kind": "Namespace", "metadata": {"name": NS, "uid": "ns-uid"}}


def snapshot_token_unmounted() -> list[Obj]:
    """Twenty nodes: an Ingress route, internal Services on the same pod and a separate worker, and an unmounted token."""
    spec = _pod_spec("web-sa", "nginx:1.19.0", token=False, secret="db-pass")
    worker = _pod_spec("worker-sa", "registry.example.test/worker:3.1", token=True)
    return [
        _namespace(),
        _account("web-sa", token=False),
        _account("worker-sa", token=True),
        *_deployment("web", spec, ["web-7c9f-1"]),
        *_deployment("worker", worker, ["worker-7c9f-1"]),
        _service("worker", "ClusterIP", 8081),
        _routes("worker", ["worker-7c9f-1"], 8081),
        _service("web", "ClusterIP"),
        _service("internal-only", "ClusterIP", 9090),
        _ingress("web", "web"),
        _routes("web", ["web-7c9f-1"]),
        _routes("internal-only", ["web-7c9f-1"], 9090),
        *_reader_role("web-sa"),
    ]


def snapshot_token_mounted() -> list[Obj]:
    """The same routes with a mounted token, so identity continues the exposure path."""
    spec = _pod_spec("web-sa", "nginx:1.19.0", token=True, secret="db-pass")
    return [
        _namespace(),
        _account("web-sa", token=True),
        *_deployment("web", spec, ["web-7c9f-1"]),
        _service("web", "ClusterIP"),
        _ingress("web", "web"),
        _routes("web", ["web-7c9f-1"]),
        *_reader_role("web-sa"),
    ]


def internal_only() -> list[Obj]:
    """Only ClusterIP Services: reachable inside the cluster, with no recorded exposure entry."""
    spec = _pod_spec("api-sa", "registry.example.test/api:2.4", token=True)
    return [
        _namespace(),
        _account("api-sa", token=True),
        *_deployment("api", spec, ["api-7c9f-1"]),
        _service("api", "ClusterIP"),
        _routes("api", ["api-7c9f-1"]),
    ]


def two_services() -> list[Obj]:
    """A LoadBalancer reaches the pod in one hop while the Ingress route takes two."""
    spec = _pod_spec("web-sa", "nginx:1.25.3", token=True)
    return [
        _namespace(),
        _account("web-sa", token=True),
        *_deployment("web", spec, ["web-7c9f-1"]),
        _service("web", "ClusterIP"),
        _service("web-public", "LoadBalancer"),
        _ingress("web", "web"),
        _routes("web", ["web-7c9f-1"]),
        _routes("web-public", ["web-7c9f-1"]),
    ]


def cluster_estate(deployments: int = 10, pods_per_deployment: int = 3) -> list[Obj]:
    """Thirty pods across ten deployments: a typical cluster, above the former flow limit."""
    objects = [_namespace()]
    for index in range(deployments):
        name = f"app-{index:02d}"
        account = f"{name}-sa"
        pods = [f"{name}-7c9f-{replica}" for replica in range(pods_per_deployment)]
        objects += [
            _account(account, token=True),
            *_deployment(name, _pod_spec(account, f"registry.example.test/{name}:1", token=True), pods),
        ]
        objects += [_service(name, "ClusterIP"), _routes(name, pods)]
        if index < 3:
            objects.append(_ingress(name, name))
    return objects


def image_scan_report() -> Obj:
    """A scanned image, as ``agent-bom image`` reports it, carrying a finding the workload's image reaches."""
    return {
        "agents": [
            {
                "name": "image:nginx:1.19.0",
                "source": "image",
                "metadata": {"inventory_role": "container_image", "image_ref": "nginx:1.19.0"},
                "mcp_servers": [
                    {
                        "name": "nginx:1.19.0",
                        "surface": "container-image",
                        "packages": [
                            {
                                "name": "openssl",
                                "version": "1.1.1k",
                                "ecosystem": "deb",
                                "vulnerabilities": [{"id": "CVE-2021-3711", "severity": "critical", "cvss_score": 9.8}],
                            }
                        ],
                    }
                ],
            }
        ]
    }


SCENARIOS = {
    "snapshot": snapshot_token_unmounted,
    "tokenMounted": snapshot_token_mounted,
    "internalOnly": internal_only,
    "twoServices": two_services,
    "clusterEstate": cluster_estate,
    "withFindings": snapshot_token_mounted,
}
EXTRA_REPORT = {"withFindings": image_scan_report}


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _stable(item) for key, item in value.items() if key not in VOLATILE_FIELDS}
    return [_stable(item) for item in value] if isinstance(value, list) else value


def project(objects: list[Obj], extra: Obj | None = None) -> Obj:
    inventory = build_k8s_inventory(objects, source="live", cluster="prod-eks")
    report = {"scan_id": SCAN_ID, "kubernetes_inventory": kubernetes_inventory_section([inventory], []), **(extra or {})}
    graph = build_unified_graph_from_report(report).to_dict()
    return {"nodes": _stable(graph["nodes"]), "edges": _stable(graph["edges"])}


def _records(records: list[Obj]) -> str:
    return ",\n".join(json.dumps(record, sort_keys=True, default=str) for record in records)


def render() -> str:
    """One record per line keeps regenerated diffs reviewable."""
    scenarios = {name: project(build(), EXTRA_REPORT[name]() if name in EXTRA_REPORT else None) for name, build in SCENARIOS.items()}
    body = ",\n".join(
        f'"{name}": {{"nodes": [\n{_records(graph["nodes"])}\n], "edges": [\n{_records(graph["edges"])}\n]}}'
        for name, graph in scenarios.items()
    )
    return f"{{\n{body}\n}}\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed fixture differs from the projection")
    args = parser.parse_args()
    content = render()
    if args.check:
        if not FIXTURE.exists() or FIXTURE.read_text(encoding="utf-8") != content:
            print(f"{FIXTURE.relative_to(ROOT)} is stale. Run: python scripts/generate_k8s_graph_fixture.py")
            return 1
        print(f"{FIXTURE.relative_to(ROOT)} matches the projection.")
        return 0
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(content, encoding="utf-8")
    print(f"Wrote {FIXTURE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
