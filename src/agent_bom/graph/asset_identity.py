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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from agent_bom.canonical_ids import snowflake_fqn
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
COMPUTE_RESOURCE_TYPES = frozenset({"instance", "virtual_machine", "vm", "compute_instance"})
_COMPUTE_ID_MARKERS = (":instance/", "/virtualmachines/", "/instances/")
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


def recorded_dimension(node: UnifiedNode, key: str) -> str:
    """A dimension the source recorded; a provider inherited over an edge never locates identity."""
    return _text(recorded_dimension_value(node.attributes, key, getattr(node.dimensions, key, "")))


def recorded_dimension_value(attributes: Mapping[str, object], key: str, value: object) -> object:
    """Apply the recorded-dimension boundary to serialized node fields too."""
    if key == "cloud_provider" and str(attributes.get("cloud_provider_basis") or "").startswith("inherited:"):
        return ""
    return value


def _provider(node: UnifiedNode) -> str:
    return (_attr(node, "cloud_provider", "provider") or recorded_dimension(node, "cloud_provider")).casefold()


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
    cluster, namespace = _attr(node, "cluster_id", "cluster_arn", "cluster"), _attr(node, "namespace", "k8s_namespace")
    kind, name = _attr(node, "kubernetes_kind", "k8s_kind"), _attr(node, "kubernetes_name", "k8s_name")
    container_name = _attr(node, "container_name")
    if uid and node.entity_type == E.CONTAINER and container_name:
        keys.append(IdentityKey(100, "k8s_container", f"{uid.casefold()}/{container_name}", "kubernetes"))
    elif uid and (node.entity_type != E.CONTAINER or kind):
        # Every container of a pod carries the pod's uid; on a container node it
        # names one asset only when the node declares itself the object.
        keys.append(IdentityKey(100, "k8s_uid", uid.casefold(), "kubernetes"))
    if cluster and namespace and kind and name:
        keys.append(IdentityKey(90, "k8s_object", f"{cluster}/{namespace}/{kind.casefold()}/{name}", "kubernetes"))
    return keys


def _snowflake_keys(node: UnifiedNode) -> list[IdentityKey]:
    account, fqn = _attr(node, "account_id"), _attr(node, "snowflake_local_id", "fqn", "object_fqn")
    if not (account and fqn):
        return []
    # Object names are the stored names Snowflake reports, which are exact (an
    # unquoted identifier is already upper-cased there), so only explicit
    # quoting is resolved. Account case is kept: unproven aliases never merge.
    if '"' in fqn:
        fqn = snowflake_fqn(fqn)
    return [IdentityKey(100, "snowflake_fqn", f"{account}/{fqn}", "snowflake")]


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
        # A directory user id is unique only inside its org; with no org known it proves nothing.
        principal = _attr(node, "provider_identity_id", "principal_id")
        org = _attr(node, "org_id", "organization_id", "directory_id", "account_id", "domain")
        if principal and provider and org:
            keys.append(IdentityKey(90, "principal_id", f"{provider}/{org}/{principal}", provider))
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


def is_compute_instance(resource_type: object, native_id: object = "") -> bool:
    """A VM by its recorded resource type, or by an instance ARN, ARM id or GCE link."""
    if str(resource_type or "").casefold() in COMPUTE_RESOURCE_TYPES:
        return True
    native = str(native_id or "").strip().casefold()
    return bool(_INSTANCE_ID.match(native)) or any(marker in native for marker in _COMPUTE_ID_MARKERS)


def strong_keys_conflict(left: Mapping[str, str], right: Mapping[str, str]) -> bool:
    """Two key sets name different assets when any shared namespace disagrees."""
    return any(left[namespace] != value for namespace, value in right.items() if namespace in left)


@dataclass(slots=True)
class StrongKeyComponents:
    """Conflict-guarded union-find over observations sharing strong keys.

    The one merge rule for a single build and for a cross-snapshot merge: a
    shared key joins two observations unless their components already hold
    different values for another strong key, which is a recorded conflict.
    """

    parent: dict[str, str] = field(default_factory=dict)
    keys: dict[str, dict[str, str]] = field(default_factory=dict)
    held: dict[str, set[IdentityKey]] = field(default_factory=dict)
    conflicts: int = 0

    def find(self, member: str) -> str:
        root = member
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[member] != root:
            self.parent[member], member = root, self.parent[member]
        return root

    def union(self, left: str, right: str) -> None:
        a, b = sorted((self.find(left), self.find(right)))
        if a == b:
            return
        if strong_keys_conflict(self.keys[a], self.keys[b]):
            self.conflicts += 1
            return
        self.parent[b] = a
        self.keys[a].update(self.keys[b])
        self.held[a] |= self.held[b]

    def identities(self) -> dict[str, tuple[IdentityKey, bool]]:
        """``root -> (key, unique)``: each component's best key no other component holds.

        ``unique`` is false only when every key a component holds is also held
        by a component it conflicts with; callers must then disambiguate.
        """
        roots = [member for member, parent in self.parent.items() if parent == member and self.held[member]]
        holders: dict[IdentityKey, int] = {}
        for root in roots:
            for key in self.held[root]:
                holders[key] = holders.get(key, 0) + 1
        result: dict[str, tuple[IdentityKey, bool]] = {}
        for root in roots:
            unique = [key for key in self.held[root] if holders[key] == 1]
            result[root] = (max(unique), True) if unique else (max(self.held[root]), False)
        return result


def strong_key_components(members: Mapping[str, tuple[str, Sequence[IdentityKey]]]) -> StrongKeyComponents:
    """Group ``member -> (family, strong keys)``; keys only join within a family."""
    components = StrongKeyComponents()
    buckets: dict[tuple[str, IdentityKey], list[str]] = {}
    for member in sorted(members):
        family, keys = members[member]
        components.parent[member] = member
        components.keys[member] = {}
        components.held[member] = set(keys)
        for key in keys:
            components.keys[member].setdefault(key.namespace, key.value)
            buckets.setdefault((family, key), []).append(member)
    for (_family, _key), grouped in sorted(buckets.items(), key=lambda entry: (-entry[0][1].rank, entry[0][0], entry[0][1].text)):
        for other in grouped[1:]:
            components.union(grouped[0], other)
    return components
