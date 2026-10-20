"""Shared GCP inventory permission catalogs, privilege ranking and resource-name helpers."""

from __future__ import annotations

from typing import Any

from ..normalization import sanitize_discovery_warning

# Read-only IAM permissions this scanner is allowed to exercise, by resource
# class. Kept here so the per-run discovery envelope `permissions_used` stays
# honest: the producer owns the catalog, not external docs.
_GCP_STORAGE_PERMISSIONS: tuple[str, ...] = (
    "storage.buckets.list",
    "storage.buckets.getIamPolicy",
)


_GCP_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "compute.instances.list",
    "compute.firewalls.list",
)


_GCP_IAM_PERMISSIONS: tuple[str, ...] = (
    "cloudasset.assets.listIamPolicy",
    "iam.denypolicies.list",
    "iam.policybindings.list",
    "iam.principalaccessboundarypolicies.list",
    "iam.roles.get",
    "iam.serviceAccounts.list",
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "serviceusage.services.use",
)


# Read-only permissions exercised by each discovery stage (``include_<stage>``),
# so the per-run discovery envelope's ``permissions_used`` lists only what ran.
_STAGE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "storage": _GCP_STORAGE_PERMISSIONS,
    "compute": _GCP_COMPUTE_PERMISSIONS,
    "iam": _GCP_IAM_PERMISSIONS,
    "containers": ("container.clusters.list",),
    "serverless": ("run.services.list", "cloudfunctions.functions.list"),
    "databases": ("cloudsql.instances.list",),
    "networks": (
        "compute.networks.list",
        "compute.subnetworks.list",
        "compute.securityPolicies.list",
        "compute.backendServices.list",
        "compute.urlMaps.list",
        "compute.forwardingRules.list",
        "compute.targetHttpProxies.list",
        "compute.targetHttpsProxies.list",
        "compute.routers.list",
        "compute.addresses.list",
        "apigateway.gateways.list",
    ),
    "disks": ("compute.disks.list",),
    "messaging": ("pubsub.topics.list",),
}


# Authorization-collector keys transported verbatim onto the inventory payload.
_AUTHORIZATION_KEYS = (
    "allow_policies",
    "role_definitions",
    "deny_policies",
    "pab_policies",
    "pab_bindings",
    "iam_hierarchy",
    "iam_sources",
    "iam_observed_at",
)


# Open-to-the-world source ranges that mark a firewall rule as internet-facing.
# The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_RANGES = {"0.0.0.0/0", "::/0"}


# Members that mark a bucket IAM policy as publicly accessible.
_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}


# Privilege ranking shared with the AWS path so cross-provider CIEM reasoning
# (OVERPERMISSIONED_TO_SENSITIVE, effective-permissions) treats levels uniformly.
_PRIVILEGE_RANK = {"admin": 3, "write": 2, "read": 1, "unknown": 0}


# Canonical predefined GCP roles → privilege level (no extra API call needed).
_GCP_ROLE_PRIVILEGE: dict[str, str] = {
    "roles/owner": "admin",
    "roles/editor": "write",
    "roles/viewer": "read",
    "roles/browser": "read",
}


def _classify_role_privilege(role: str) -> str:
    """Classify a single GCP IAM role into admin / write / read / unknown.

    Mirrors the AWS managed-policy classifier: the basic Owner/Editor/Viewer
    roles map directly; any ``*Admin`` role is admin; any ``*Viewer`` / ``*Reader``
    role is read. Everything else stays ``unknown`` — never an inflated guess.
    """
    name = str(role or "").strip()
    if not name:
        return "unknown"
    lowered = name.lower()
    if lowered in _GCP_ROLE_PRIVILEGE:
        return _GCP_ROLE_PRIVILEGE[lowered]
    # Strip the leaf after the last dot/slash for the "*Admin"/"*Viewer" suffix test.
    leaf = lowered.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    if leaf.endswith("admin") or "admin" in leaf:
        return "admin"
    if "owner" in leaf:
        return "admin"
    if "editor" in leaf or leaf.endswith("writer") or leaf.endswith("write"):
        return "write"
    if leaf.endswith("viewer") or leaf.endswith("reader") or leaf.endswith("read") or "viewer" in leaf or "reader" in leaf:
        return "read"
    return "unknown"


def _highest_privilege(roles: list[str]) -> str:
    """Return the most-privileged level across a principal's bound roles."""
    best = "unknown"
    for role in roles:
        level = _classify_role_privilege(role)
        if _PRIVILEGE_RANK.get(level, 0) > _PRIVILEGE_RANK.get(best, 0):
            best = level
    return best


def _derive_default_project() -> tuple[str, str]:
    """Best-effort ``(project_id, note)`` from Application Default Credentials.

    ``google.auth.default()`` resolves the project the same way every google
    client does — from a service-account key's ``project_id``, the gcloud config,
    or the metadata server — so a key/ADC connection needs no explicit
    ``GOOGLE_CLOUD_PROJECT``. Returns ``("", note)`` on any failure; never raises.
    """
    try:
        from google import auth as google_auth
    except ImportError:
        return "", "google-auth not installed; cannot auto-derive the project. Set GOOGLE_CLOUD_PROJECT."
    try:
        _creds, project = google_auth.default()
    except Exception as exc:  # noqa: BLE001 — ADC resolution must not crash a scan
        return "", sanitize_discovery_warning(exc)
    if not project:
        return "", "No GCP project resolved from Application Default Credentials. Set GOOGLE_CLOUD_PROJECT."
    return str(project), ""


def _parse_port(text: str) -> tuple[int | None, int | None]:
    value = text.strip()
    if not value:
        return None, None
    if "-" in value:
        low, _, high = value.partition("-")
        return _safe_int(low), _safe_int(high)
    port = _safe_int(value)
    return port, port


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _segment(self_link: str, key: str) -> str:
    """Return the path segment following ``key`` in a GCP resource name, else ''.

    e.g. ``_segment("projects/p/locations/us-central1/services/svc", "locations")``
    → ``"us-central1"``.
    """
    parts = str(self_link or "").split("/")
    for i, part in enumerate(parts):
        if part == key and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _loc(kind: str, value: str) -> str:
    """Return ``kind/value`` for a location path segment, or '' when the value is unknown."""
    return f"{kind}/{value}" if value else ""


def _scoped_name(project_id: str, *parts: str) -> str:
    """Return the project-scoped relative resource name, '' when the project is unknown.

    GCP resource names are unique only inside their project (and zone/region),
    so an id fallback must keep that scope; empty parts (an unknown location)
    are dropped rather than emitted as blank segments, and a blank resource
    name (the last part) yields '' so no id is invented.
    """
    if not project_id or not parts or not parts[-1]:
        return ""
    return "/".join(["projects", project_id, *(part for part in parts if part)])


def _backend_service_identity(project_id: str, backend: Any, name: str) -> tuple[str, str]:
    """Return a backend service's id (numeric, else its project-scoped path) and its location."""
    region = _leaf(getattr(backend, "region", ""))
    path = _scoped_name(project_id, _loc("regions", region) or "global", "backendServices", name)
    return str(getattr(backend, "id", "") or "") or path or name, region or "global"


def _leaf(value: Any) -> str:
    """Return the last path segment of a GCP self-link / type URL, else ''."""
    text = str(value or "").strip()
    if not text:
        return ""
    return text.rsplit("/", 1)[-1]


def _clean_labels(labels: Any) -> dict[str, str]:
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items() if key is not None}
