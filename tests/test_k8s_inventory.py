"""Kubernetes workload inventory: one normalized model from live objects and manifests."""

from __future__ import annotations

from agent_bom.kubernetes.inventory import build_k8s_inventory, image_digest_from_status

_DIGEST = "sha256:" + "a" * 64


def _deployment(name: str = "web", ns: str = "shop", sa: str | None = "web-sa", **pod_spec: object) -> dict:
    spec: dict = {
        "containers": [
            {
                "name": "app",
                "image": "registry.example.test/shop/web:1.4",
                "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "password"}}}],
                "envFrom": [{"secretRef": {"name": "api-keys"}}],
            }
        ],
        "initContainers": [{"name": "migrate", "image": "registry.example.test/shop/migrate@" + _DIGEST}],
        "volumes": [{"name": "tls", "secret": {"secretName": "web-tls"}}],
        **pod_spec,
    }
    if sa:
        spec["serviceAccountName"] = sa
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns, "uid": "dep-uid-1"},
        "spec": {"template": {"spec": spec}},
    }


def _replicaset(name: str, owner: str, ns: str = "shop") -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {"name": name, "namespace": ns, "uid": f"rs-{name}", "ownerReferences": [{"kind": "Deployment", "name": owner}]},
        "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "registry.example.test/shop/web:1.4"}]}}},
    }


def _pod(name: str, owner_kind: str | None, owner: str | None, ns: str = "shop", image_id: str = "") -> dict:
    meta: dict = {"name": name, "namespace": ns, "uid": f"pod-{name}"}
    if owner_kind:
        meta["ownerReferences"] = [{"kind": owner_kind, "name": owner}]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta,
        "spec": {"serviceAccountName": "web-sa", "containers": [{"name": "app", "image": "registry.example.test/shop/web:1.4"}]},
        "status": {"phase": "Running", "containerStatuses": [{"name": "app", "imageID": image_id}]},
    }


def test_manifest_deployment_normalizes_containers_images_secrets_and_service_account() -> None:
    inventory = build_k8s_inventory([_deployment()], source="manifest")

    assert inventory["source"] == "manifest"
    [workload] = inventory["workloads"]
    assert (workload["kind"], workload["namespace"], workload["name"]) == ("Deployment", "shop", "web")
    assert workload["service_account"] == "web-sa"
    assert workload["token_mounted"] is True
    containers = {c["name"]: c for c in workload["containers"]}
    assert containers["app"]["image"] == "registry.example.test/shop/web:1.4"
    assert containers["app"]["image_digest"] == ""
    assert containers["migrate"]["init"] is True
    assert containers["migrate"]["image_digest"] == _DIGEST
    assert workload["secret_refs"] == [
        {"name": "api-keys", "via": "envFrom"},
        {"name": "db-creds", "via": "env"},
        {"name": "web-tls", "via": "volume"},
    ]
    # The referenced service account is recorded even though no manifest declares it.
    assert inventory["service_accounts"] == [{"namespace": "shop", "name": "web-sa", "automount_token": None, "declared": False}]
    assert inventory["namespaces"] == [{"name": "shop", "labels": {}, "declared": False}]


def test_service_account_defaults_to_default_and_automount_false_unmounts_token() -> None:
    inventory = build_k8s_inventory([_deployment(sa=None, automountServiceAccountToken=False)], source="manifest")
    [workload] = inventory["workloads"]
    assert workload["service_account"] == "default"
    assert workload["token_mounted"] is False


def test_projected_service_account_token_volume_counts_as_mounted() -> None:
    projected = {"name": "tok", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}
    deployment = _deployment(automountServiceAccountToken=False, volumes=[projected])
    [workload] = build_k8s_inventory([deployment], source="manifest")["workloads"]
    assert workload["token_mounted"] is True


def test_service_account_automount_false_applies_when_pod_does_not_set_it() -> None:
    sa = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "web-sa", "namespace": "shop"},
        "automountServiceAccountToken": False,
    }
    inventory = build_k8s_inventory([_deployment(), sa], source="manifest")
    [workload] = inventory["workloads"]
    assert workload["token_mounted"] is False
    assert inventory["service_accounts"] == [{"namespace": "shop", "name": "web-sa", "automount_token": False, "declared": True}]


def test_live_pods_collapse_to_their_top_owner_and_carry_running_digest() -> None:
    objects = [
        _deployment(),
        _replicaset("web-7d9", "web"),
        _pod("web-7d9-a", "ReplicaSet", "web-7d9", image_id="docker-pullable://registry.example.test/shop/web@" + _DIGEST),
        _pod("web-7d9-b", "ReplicaSet", "web-7d9", image_id="registry.example.test/shop/web@" + _DIGEST),
        _pod("debug", None, None),
    ]
    inventory = build_k8s_inventory(objects, source="live", cluster="prod-east")

    by_kind = {w["kind"]: w for w in inventory["workloads"]}
    assert set(by_kind) == {"Deployment", "Pod"}, "an owned ReplicaSet and its pods collapse into the Deployment"
    deployment = by_kind["Deployment"]
    assert deployment["pod_uids"] == ["pod-web-7d9-a", "pod-web-7d9-b"]
    app = next(c for c in deployment["containers"] if c["name"] == "app")
    assert app["image_digest"] == _DIGEST
    assert by_kind["Pod"]["pod_uids"] == ["pod-debug"]
    assert inventory["cluster"] == "prod-east"


def test_local_image_id_is_not_a_registry_digest() -> None:
    assert image_digest_from_status("sha256:" + "b" * 64) == ""
    assert image_digest_from_status("docker://registry.example.test/x@" + _DIGEST) == _DIGEST
    assert image_digest_from_status("") == ""


def test_cronjob_pod_template_is_read_from_job_template() -> None:
    cronjob = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "nightly", "namespace": "ops"},
        "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "run", "image": "busybox:1.36"}]}}}}},
    }
    [workload] = build_k8s_inventory([cronjob], source="manifest")["workloads"]
    assert workload["kind"] == "CronJob"
    assert workload["containers"][0]["image"] == "busybox:1.36"


def test_rbac_grants_resolve_service_account_permissions_and_secret_access() -> None:
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "secret-reader", "namespace": "shop"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "web-reads-secrets", "namespace": "shop"},
        "roleRef": {"kind": "Role", "name": "secret-reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}],
    }
    crb = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "web-admin"},
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}, {"kind": "Group", "name": "ops"}],
    }
    inventory = build_k8s_inventory([_deployment(), role, binding, crb], source="manifest")

    grants = {g["binding"]["name"]: g for g in inventory["rbac_grants"]}
    assert set(grants) == {"web-reads-secrets", "web-admin"}, "only service-account subjects become grants"
    reads = grants["web-reads-secrets"]
    assert reads["service_account"] == {"namespace": "shop", "name": "web-sa"}
    assert reads["scope"] == "shop"
    assert reads["role_resolved"] is True
    assert reads["secrets"] == {"access": "all", "names": []}
    admin = grants["web-admin"]
    assert admin["scope"] == "cluster"
    assert admin["role_source"] == "builtin_default"
    assert admin["wildcard"] is True
    assert admin["secrets"] == {"access": "all", "names": []}


def test_resource_names_restrict_secret_access_and_view_role_cannot_read_secrets() -> None:
    role = {
        "kind": "Role",
        "metadata": {"name": "one-secret", "namespace": "shop"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["db-creds"], "verbs": ["get"]}],
    }
    named = {
        "kind": "RoleBinding",
        "metadata": {"name": "named", "namespace": "shop"},
        "roleRef": {"kind": "Role", "name": "one-secret"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-sa"}],
    }
    view = {
        "kind": "RoleBinding",
        "metadata": {"name": "viewer", "namespace": "shop"},
        "roleRef": {"kind": "ClusterRole", "name": "view"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}],
    }
    grants = {g["binding"]["name"]: g for g in build_k8s_inventory([role, named, view], source="manifest")["rbac_grants"]}
    assert grants["named"]["secrets"] == {"access": "named", "names": ["db-creds"]}
    assert grants["named"]["service_account"] == {"namespace": "shop", "name": "web-sa"}, "a RoleBinding subject defaults to its namespace"
    assert grants["viewer"]["secrets"] == {"access": "none", "names": []}
    assert grants["viewer"]["scope"] == "shop", "a ClusterRole bound by a RoleBinding grants only in that namespace"


def test_unresolved_role_is_recorded_not_guessed() -> None:
    binding = {
        "kind": "RoleBinding",
        "metadata": {"name": "custom", "namespace": "shop"},
        "roleRef": {"kind": "ClusterRole", "name": "vendor-operator"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}],
    }
    [grant] = build_k8s_inventory([binding], source="manifest")["rbac_grants"]
    assert grant["role_resolved"] is False
    assert grant["secrets"] == {"access": "unknown", "names": []}


def test_namespace_labels_and_summary_counts() -> None:
    namespace = {
        "kind": "Namespace",
        "metadata": {"name": "shop", "labels": {"pod-security.kubernetes.io/enforce": "restricted", "team": "x"}},
    }
    inventory = build_k8s_inventory([namespace, _deployment()], source="manifest")
    assert inventory["namespaces"] == [{"name": "shop", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}, "declared": True}]
    assert inventory["summary"] == {
        "namespaces": 1,
        "workloads": 1,
        "containers": 2,
        "images": 2,
        "images_with_digest": 1,
        "service_accounts": 1,
        "rbac_grants": 0,
        "secret_refs": 3,
    }


def test_non_mapping_and_unknown_kinds_are_ignored() -> None:
    inventory = build_k8s_inventory([None, "x", {"kind": "ConfigMap", "metadata": {"name": "c"}}], source="manifest")  # type: ignore[list-item]
    assert inventory["workloads"] == []
    assert inventory["summary"]["workloads"] == 0
