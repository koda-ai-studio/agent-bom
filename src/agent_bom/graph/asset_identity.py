"""Strong and weak identity keys for one real-world asset seen by many sources.

A *strong* key is a provider-native identifier that names exactly one asset
inside its scope: a qualified ARN, an AWS instance id bound to its account and
region, an Azure ARM id, a GCP self link, a Kubernetes uid, an image digest, a
principal id or a warehouse object's account-qualified name. Two observations
that share a strong key are the same asset and merge.

A *weak* key (host name, private address, MAC, name within an account) is a
hint. Weak keys never merge; they only propose a reviewable candidate.

Keys merge only within one family, so a bucket never merges with the data-store
node that describes its contents and an image never merges with a container
running it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

E = EntityType

_FAMILIES: dict[EntityType, str] = {
    E.CLOUD_RESOURCE: "resource",
    E.CLUSTER: "resource",
    E.DATA_STORE: "data",
    E.CONTAINER: "workload",
    E.USER: "identity",
    E.ROLE: "identity",
    E.SERVICE_ACCOUNT: "identity",
    E.SERVICE_PRINCIPAL: "identity",
    E.MANAGED_IDENTITY: "identity",
}
FAMILY_TYPES: dict[str, tuple[EntityType, ...]] = {}
for _entity, _family in _FAMILIES.items():
    FAMILY_TYPES.setdefault(_family, ())
    FAMILY_TYPES[_family] = (*FAMILY_TYPES[_family], _entity)

_NATIVE_ID_KEYS = ("arn", "resource_arn", "instance_arn", "resource_id", "identifier", "native_id", "provider_id", "id_native")
_INSTANCE_ID = re.compile(r"^i-[0-9a-f]{8,17}$")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_GCP_PREFIXES = ("https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/", "//compute.googleapis.com/")
_IMAGE_TYPES = frozenset({"container_image", "image", "ecr_image"})
_HOSTNAME_DENYLIST = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "host.docker.internal", "kubernetes.default.svc"})


@dataclass(frozen=True, slots=True, order=True)
class IdentityKey:
    """One normalized identifier; ``rank`` orders authority within a family."""

    rank: int
    namespace: str
    value: str
    provider: str = ""

    @property
    def text(self) -> str:
        return f"{self.namespace}:{self.value}"


def family_of(node: UnifiedNode) -> str:
    """Which merge family a node belongs to; ``""`` never takes part."""
    if not isinstance(node.entity_type, EntityType):
        return ""
    if _image_node(node):
        return "image"
    return _FAMILIES.get(node.entity_type, "")


def _image_node(node: UnifiedNode) -> bool:
    kind = str(node.attributes.get("resource_type") or "").casefold()
    return node.entity_type in (E.CONTAINER, E.CLOUD_RESOURCE) and kind in _IMAGE_TYPES


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _attr(node: UnifiedNode, *keys: str) -> str:
    for key in keys:
        value = _text(node.attributes.get(key))
        if value:
            return value
    return ""


def _provider(node: UnifiedNode) -> str:
    return (_attr(node, "cloud_provider", "provider") or _text(node.dimensions.cloud_provider)).casefold()


def _parse_arn(value: str) -> tuple[str, str, str, str] | None:
    """``(service, region, account, resource)`` of a fully qualified ARN."""
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
        return None
    service, region, account, resource = parts[2], parts[3], parts[4], parts[5]
    if service == "s3" and not region and not account:
        return service, region, account, resource
    if not (len(account) == 12 and account.isdigit()):
        return None
    return service, region, account, resource


def _aws_keys(node: UnifiedNode, natives: list[str]) -> list[IdentityKey]:
    keys: list[IdentityKey] = []
    account = _attr(node, "account_id", "cloud_account_id", "aws_account_id")
    region = _attr(node, "region", "location", "aws_region")
    for native in natives:
        arn = _parse_arn(native)
        recorded_region = _attr(node, "region")
        if arn is not None and arn[1] and recorded_region and recorded_region != arn[1]:
            continue  # a contradictory recorded region is a data conflict, never a join
        if arn is not None:
            service, arn_region, arn_account, resource = arn
            keys.append(IdentityKey(95, "aws_arn", native, "aws"))
            if service == "ec2" and resource.startswith("instance/"):
                keys.append(IdentityKey(100, "aws_instance", f"{arn_account}/{arn_region}/{resource.removeprefix('instance/')}", "aws"))
        elif _INSTANCE_ID.match(native) and len(account) == 12 and account.isdigit() and region:
            keys.append(IdentityKey(100, "aws_instance", f"{account}/{region}/{native}", "aws"))
    return keys


def _azure_keys(node: UnifiedNode, natives: list[str]) -> list[IdentityKey]:
    keys = [
        IdentityKey(100, "azure_arm", native.rstrip("/").casefold(), "azure")
        for native in natives
        if native.casefold().startswith("/subscriptions/")
    ]
    vm_id = _attr(node, "vm_id", "vmId")
    if vm_id:
        keys.append(IdentityKey(80, "azure_vm_id", vm_id.casefold(), "azure"))
    object_id = _attr(node, "object_id", "principal_object_id")
    if object_id and node.entity_type in FAMILY_TYPES["identity"]:
        keys.append(IdentityKey(100, "azure_object_id", object_id.casefold(), "azure"))
    return keys


def _gcp_keys(node: UnifiedNode, natives: list[str]) -> list[IdentityKey]:
    keys: list[IdentityKey] = []
    for native in [*natives, _attr(node, "self_link", "selfLink")]:
        path = native
        for prefix in _GCP_PREFIXES:
            path = path.removeprefix(prefix)
        if path.startswith("projects/") and path.count("/") >= 3:
            keys.append(IdentityKey(100, "gcp_self_link", path.rstrip("/"), "gcp"))
    numeric, project = _attr(node, "gcp_numeric_id", "numeric_id"), _attr(node, "project_id", "account_id")
    if numeric.isdigit() and project:
        keys.append(IdentityKey(80, "gcp_numeric_id", f"{project}/{numeric}", "gcp"))
    email = _attr(node, "service_account_email", "email")
    if email.endswith(".iam.gserviceaccount.com") and node.entity_type in FAMILY_TYPES["identity"]:
        keys.append(IdentityKey(100, "gcp_service_account", email.casefold(), "gcp"))
    return keys


def _kubernetes_keys(node: UnifiedNode) -> list[IdentityKey]:
    keys: list[IdentityKey] = []
    uid = _attr(node, "kubernetes_uid", "k8s_uid", "pod_uid")
    if uid:
        keys.append(IdentityKey(100, "k8s_uid", uid.casefold(), "kubernetes"))
    cluster, namespace = _attr(node, "cluster_id", "cluster_arn", "cluster"), _attr(node, "namespace", "k8s_namespace")
    kind, name = _attr(node, "kubernetes_kind", "k8s_kind"), _attr(node, "kubernetes_name", "k8s_name")
    if cluster and namespace and kind and name:
        keys.append(IdentityKey(90, "k8s_object", f"{cluster}/{namespace}/{kind.casefold()}/{name}", "kubernetes"))
    return keys


def _snowflake_keys(node: UnifiedNode) -> list[IdentityKey]:
    account, fqn = _attr(node, "account_id"), _attr(node, "snowflake_local_id", "fqn", "object_fqn")
    return [IdentityKey(100, "snowflake_fqn", f"{account}/{fqn}", "snowflake")] if account and fqn else []


def strong_keys(node: UnifiedNode) -> list[IdentityKey]:
    """Every strong key a node carries, best first; empty when it names no native id."""
    family = family_of(node)
    if not family:
        return []
    if family == "image":
        digests = {
            match.group(0)
            for key in ("image_digest", "digest", "repo_digest", *_NATIVE_ID_KEYS)
            for match in [_DIGEST.search(_attr(node, key))]
            if match
        }
        return [IdentityKey(100, "image_digest", digest) for digest in sorted(digests)]
    provider = _provider(node)
    natives = [value for value in dict.fromkeys(_attr(node, key) for key in _NATIVE_ID_KEYS) if value]
    keys: list[IdentityKey] = []
    if provider == "aws" or any(native.startswith("arn:aws") for native in natives):
        keys.extend(_aws_keys(node, natives))
    if provider == "azure" or any(native.casefold().startswith("/subscriptions/") for native in natives):
        keys.extend(_azure_keys(node, natives))
    if provider == "gcp":
        keys.extend(_gcp_keys(node, natives))
    if provider == "snowflake":
        keys.extend(_snowflake_keys(node))
    keys.extend(_kubernetes_keys(node))
    if family == "identity" and provider not in {"aws", "azure", "gcp", "snowflake"}:
        principal = _attr(node, "provider_identity_id", "principal_id")
        if principal and provider:
            keys.append(IdentityKey(90, "principal_id", f"{provider}/{principal}", provider))
    return sorted(set(keys), reverse=True)


def _hostname(value: str) -> str:
    host = value.strip().rstrip(".").casefold()
    if "." not in host or host in _HOSTNAME_DENYLIST or host.startswith(("localhost.", "127.")):
        return ""
    return host


def weak_keys(node: UnifiedNode) -> list[IdentityKey]:
    """Hints that two observations may be one asset; never merge on their own."""
    if family_of(node) not in {"resource", "workload"}:
        return []
    keys: list[IdentityKey] = []
    for host in {
        _hostname(_attr(node, key)) for key in ("hostname", "host_name", "fqdn", "private_dns_name", "public_dns_name", "dns_name")
    }:
        if host:
            keys.append(IdentityKey(30, "hostname", host))
    private_ip, network = _attr(node, "private_ip"), _attr(node, "vpc_id", "network")
    if private_ip and network:
        keys.append(IdentityKey(25, "private_ip", f"{network}/{private_ip}"))
    mac = _attr(node, "mac_address", "mac").casefold().replace("-", ":")
    if mac and mac != "00:00:00:00:00:00":
        keys.append(IdentityKey(20, "mac", mac))
    name, account, kind = _attr(node, "resource_name", "name"), _attr(node, "account_id"), _attr(node, "resource_type")
    if name and account and kind:
        keys.append(IdentityKey(10, "name_account", f"{account}/{kind.casefold()}/{name.casefold()}"))
    return sorted(set(keys), reverse=True)


def identity_keys(node: UnifiedNode) -> tuple[list[IdentityKey], list[IdentityKey]]:
    """``(strong, weak)`` keys for a node, each best first."""
    return strong_keys(node), weak_keys(node)


def best_strong_key(keys: Iterable[IdentityKey]) -> IdentityKey | None:
    ordered = sorted(keys, reverse=True)
    return ordered[0] if ordered else None
