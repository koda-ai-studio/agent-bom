"""GCP general cloud-asset inventory — estate-wide, read-only, agentless.

Unlike :mod:`agent_bom.cloud.gcp` (which discovers *AI* runtimes: Vertex AI,
Cloud Functions, GKE, Cloud Run), this module enumerates the general GCP estate
so that a resource with **no** CIS finding, IaC target, or discovered AI runtime
still becomes a first-class graph node. That feeds the CNAPP exposure overlay,
the CIEM effective-permissions overlay, and the DSPM tiers, which were
previously starved of inventory input.

Three resource classes are enumerated project-wide (NOT filtered to findings):

1. **GCS buckets**            → emitted as ``DATA_STORE``-signalling
   ``CLOUD_RESOURCE`` so the DSPM / ``STORES`` / ``EXPOSED_TO`` overlays apply.
2. **Compute instances + firewall rules** → emitted as ``CLOUD_RESOURCE``.
3. **Service Accounts**       → emitted as identity principals with a
   ``HAS_PERMISSION``-ready structure.

This scanner is **opt-in** and **default OFF**. It runs only when
``AGENT_BOM_GCP_INVENTORY`` is truthy, mirroring the platform's other
optional-feature gates (e.g. ``AGENT_BOM_CLOUD_INVENTORY``).

Trust posture: read-only (``ScanMode.CLOUD_READ_ONLY``), reference-only, and
agentless. Authentication is **token / ADC only** — no passwords — via
Application Default Credentials (env service-account JSON, workload identity,
gcloud user / impersonation tokens). Only ``list`` / ``get`` APIs are called —
no write APIs, no object-content reads, no credential exfiltration. SDK absence
or missing credentials degrades to an empty inventory plus a clear status,
never a crash.

Requires ``google-cloud-storage``, ``google-cloud-compute``, and
``google-cloud-iam``. Install with::

    pip install 'agent-bom[gcp]'
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode
from agent_bom.security import sanitize_text

from .aws_inventory import dedupe_missing_permissions, record_discovery_failure
from .gcp_authorization_collector import collect_gcp_authorization
from .gcp_iam_evidence import normalize_gcp_iam_inventory
from .gcp_inv._base import (  # noqa: F401 - facade re-export
    _AUTHORIZATION_KEYS,
    _GCP_COMPUTE_PERMISSIONS,
    _GCP_IAM_PERMISSIONS,
    _GCP_ROLE_PRIVILEGE,
    _GCP_STORAGE_PERMISSIONS,
    _INTERNET_RANGES,
    _PRIVILEGE_RANK,
    _PUBLIC_MEMBERS,
    _STAGE_PERMISSIONS,
    _classify_role_privilege,
    _clean_labels,
    _derive_default_project,
    _highest_privilege,
    _leaf,
    _parse_port,
    _safe_int,
    _segment,
)
from .gcp_inv.compute_storage import (  # noqa: F401 - facade re-export
    _bucket_public,
    _discover_buckets,
    _discover_cloud_functions,
    _discover_cloud_run_services,
    _discover_cloud_sql_instances,
    _discover_disks,
    _discover_firewalls,
    _discover_gke_clusters,
    _discover_instances,
    _discover_pubsub_topics,
    _firewall_internet_exposure,
    _normalize_firewall,
    _normalize_instance,
)
from .gcp_inv.iam import (  # noqa: F401 - facade re-export
    _GCP_SA_USAGE_DEFERRED,
    _build_iam_group_principals,
    _discover_project_iam_bindings,
    _discover_service_accounts,
    _make_role_resolver,
    _policy_bindings,
    _role_policy_entry,
    _service_account_usage_evidence,
)
from .gcp_inv.network import (  # noqa: F401 - facade re-export
    _discover_api_gateways,
    _discover_ip_addresses,
    _discover_routers,
    _discover_security_policies,
    _discover_subnets,
    _discover_subnets_by_network,
    _discover_target_proxies,
    _discover_vpc_networks,
)
from .normalization import sanitize_discovery_warning
from .side_scan_targets import gcp_persistent_disk_targets

logger = logging.getLogger(__name__)

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Mirrors the other AGENT_BOM_* feature gates.
INVENTORY_ENV_FLAG = "AGENT_BOM_GCP_INVENTORY"

_TRUTHY = {"1", "true", "yes", "on"}


def inventory_enabled() -> bool:
    """Return whether estate-wide GCP inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_GCP_INVENTORY`` to
    a truthy value (``1`` / ``true`` / ``yes`` / ``on``).
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


# Opt-in flag to fan a single scan across EVERY project in the org/folder tree —
# the GCP counterpart of AWS Organizations multi-account and Azure
# multi-subscription fan-out. Default OFF; requires AGENT_BOM_GCP_INVENTORY too.
ALL_PROJECTS_ENV_FLAG = "AGENT_BOM_GCP_ALL_PROJECTS"
# Defensive cap so an org with thousands of projects can't run unbounded without
# an operator opting into a larger budget. Mirrors Azure's subscription cap.
_MAX_PROJECTS = int(os.environ.get("AGENT_BOM_GCP_MAX_PROJECTS", "200") or "200")


def all_projects_enabled() -> bool:
    """Whether to fan a single scan across every project in the org/folder tree."""
    return os.environ.get(ALL_PROJECTS_ENV_FLAG, "").strip().lower() in _TRUTHY


def discover_all_project_inventories(credentials: Any = None, *, force: bool = False) -> list[dict[str, Any]]:
    """Inventory EVERY project in the org/folder tree (multi-project fan-out).

    The GCP counterpart of the AWS Organizations multi-account enumeration and
    the Azure multi-subscription fan-out: discover the project set from the
    organization → folders → projects hierarchy, then run the per-project
    inventory for each concurrently (partitioned by ``project_id`` so the graph
    keeps every project as a distinct account under the org ``CONTAINS`` tree).
    Read-only; impersonated credentials are threaded into every per-project call.

    Returns a LIST of per-project inventory payloads (the exact shape the graph
    builder's ``_iter_cloud_inventories`` consumes). Falls back to the single
    ambient ``GOOGLE_CLOUD_PROJECT`` when the org tree is unavailable (a
    standalone project, or a credential without org-level read). Never raises.
    """
    if not force and not inventory_enabled():
        return []

    warnings: list[str] = []
    resolved = _resolve_impersonation(credentials, warnings)

    try:
        from agent_bom.cloud import gcp_organizations

        project_ids = gcp_organizations.list_project_ids(resolved, force=force)
    except Exception as exc:  # noqa: BLE001 — org enumeration failure must degrade
        logger.warning("GCP org project enumeration failed: %s", sanitize_text(sanitize_discovery_warning(exc)))
        project_ids = []

    if not project_ids:
        single = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
        project_ids = [single] if single else []
    if not project_ids:
        return []

    capped = project_ids[:_MAX_PROJECTS]
    if len(project_ids) > _MAX_PROJECTS:
        logger.warning(
            "GCP multi-project scan capped at %d of %d projects (set AGENT_BOM_GCP_MAX_PROJECTS to raise).",
            _MAX_PROJECTS,
            len(project_ids),
        )

    payloads: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(capped))) as executor:
        futures = {executor.submit(discover_inventory, project_id=pid, credentials=resolved, force=True): pid for pid in capped}
        for future in as_completed(futures):
            try:
                payloads.append(future.result())
            except Exception as exc:  # noqa: BLE001 — one project's failure must not sink the rest
                logger.warning(
                    "GCP inventory failed for project %s: %s",
                    futures[future],
                    sanitize_text(sanitize_discovery_warning(exc)),
                )
    return payloads


_IMPERSONATE_ENV = "AGENT_BOM_GCP_IMPERSONATE_SA"
_IMPERSONATE_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)


def _resolve_impersonation(credentials: Any, warnings: list[str]) -> Any:
    """Return credentials impersonating the read-only SA named by the env var.

    When ``AGENT_BOM_GCP_IMPERSONATE_SA`` is set and no explicit credential was
    passed, wrap the ambient ADC in short-lived impersonated credentials for that
    service account, so every discovery call runs as a least-privilege read-only
    identity without a service-account key (the recommended path where keys are
    org-disabled). Read-only and fail-safe: any error falls back to the original
    credentials with a warning, never raises.
    """
    if credentials is not None:
        return credentials
    target = os.environ.get(_IMPERSONATE_ENV, "").strip()
    if not target:
        return credentials
    try:
        from google import auth as google_auth
        from google.auth import impersonated_credentials
    except ImportError:
        warnings.append("google-auth not installed; cannot impersonate the GCP service account.")
        return credentials
    try:
        source, _ = google_auth.default()
        return impersonated_credentials.Credentials(
            source_credentials=source,
            target_principal=target,
            target_scopes=list(_IMPERSONATE_SCOPES),
        )
    except Exception as exc:  # noqa: BLE001 — impersonation failure degrades, never crashes
        warnings.append(f"GCP service-account impersonation of {target} failed: {sanitize_discovery_warning(exc)}")
        return credentials


def discover_inventory(
    project_id: str | None = None,
    *,
    credentials: Any = None,
    include_storage: bool = True,
    include_compute: bool = True,
    include_iam: bool = True,
    include_containers: bool = True,
    include_serverless: bool = True,
    include_databases: bool = True,
    include_networks: bool = True,
    include_disks: bool = True,
    include_messaging: bool = True,
    force: bool = False,
    usage_resolver: Any = None,
) -> dict[str, Any]:
    """Enumerate the general GCP estate (GCS, instances + firewalls, SAs).

    Returns a JSON-serialisable inventory payload destined for
    ``report_json["cloud_inventory"]``; the graph builder turns it into nodes.

    The payload always carries a ``status`` string so callers can surface a
    clear reason when nothing was enumerated:

    - ``"disabled"``        — the feature flag is off and ``force`` was not set.
    - ``"sdk_missing"``     — google-cloud SDKs are not installed.
    - ``"no_project"``      — no project id resolved.
    - ``"ok"``              — enumeration ran (possibly with per-service warnings).

    Never raises: SDK absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.

    Authentication is token / Application Default Credentials only (no
    passwords). When ``credentials`` is not supplied, the google client
    libraries resolve ADC, which acquires short-lived tokens from env
    service-account JSON, workload identity, or gcloud user / impersonation.
    """
    empty, derive_note = _inventory_preflight(project_id, force=force)
    if derive_note is None:
        return empty

    warnings: list[str] = []
    if derive_note:
        warnings.append(derive_note)
    # Keyless least-privilege connection: when AGENT_BOM_GCP_IMPERSONATE_SA names
    # a read-only service account, impersonate it (from the ambient ADC) so every
    # discovery runs AS that SA — the recommended path where SA keys are
    # org-disabled, matching AWS's read-only profile and Snowflake's role.
    credentials = _resolve_impersonation(credentials, warnings)
    missing: list[dict[str, str]] = []
    include = {
        "storage": include_storage,
        "compute": include_compute,
        "iam": include_iam,
        "containers": include_containers,
        "serverless": include_serverless,
        "databases": include_databases,
        "networks": include_networks,
        "disks": include_disks,
        "messaging": include_messaging,
    }
    ctx: dict[str, Any] = {"credentials": credentials, "warnings": warnings, "missing": missing}
    found, authorization = _collect_inventory_stages(empty["project_id"], ctx, include=include, usage_resolver=usage_resolver)
    return _inventory_payload(empty, found, authorization, include=include, warnings=warnings, missing=missing)


def _inventory_preflight(project_id: str | None, *, force: bool) -> tuple[dict[str, Any], str | None]:
    """Gate on the flag, the storage SDK, and a project id; a ``None`` note means the payload is final."""
    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    empty = _empty_inventory(resolved_project)
    if not force and not inventory_enabled():
        return empty, None

    try:
        from google.cloud import storage  # type: ignore[attr-defined]  # google.cloud namespace package  # noqa: F401
    except ImportError:
        warning = "google-cloud-storage is required for GCP inventory. Install with: pip install 'agent-bom[gcp]'"
        return {**empty, "status": "sdk_missing", "warnings": [warning]}, None

    derive_note = ""
    if not resolved_project:
        resolved_project, derive_note = _derive_default_project()
        if not resolved_project:
            warning = derive_note or "No GCP project found. Set GOOGLE_CLOUD_PROJECT or provide project_id."
            return {**empty, "status": "no_project", "warnings": [warning]}, None
        empty["project_id"] = resolved_project
        empty["account_id"] = resolved_project
    return empty, derive_note


def _empty_inventory(resolved_project: str) -> dict[str, Any]:
    """Return the inventory payload shape, in output key order, with nothing enumerated."""
    return {
        "provider": "gcp",
        "status": "disabled",
        "project_id": resolved_project,
        "account_id": resolved_project,
        "region": "",
        "buckets": [],
        "instances": [],
        "firewalls": [],
        "service_accounts": [],
        "groups": [],
        "allow_policies": [],
        "role_definitions": [],
        "deny_policies": [],
        "pab_policies": [],
        "pab_bindings": [],
        "iam_hierarchy": [],
        "iam_sources": [],
        "iam_observed_at": None,
        "authorization_evidence": None,
        "gke_clusters": [],
        "cloud_run_services": [],
        "cloud_functions": [],
        "cloud_sql_instances": [],
        "vpc_networks": [],
        "subnets": [],
        "load_balancers": [],
        "web_acls": [],
        "api_gateways": [],
        "nat_gateways": [],
        "route_tables": [],
        "ip_addresses": [],
        "disks": [],
        "pubsub_topics": [],
        "warnings": [],
        "missing_permissions": [],
        "discovery_envelope": None,
    }


def _collect_inventory_stages(
    project_id: str, ctx: dict[str, Any], *, include: Mapping[str, bool], usage_resolver: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run each opted-in discovery stage in order; return ``(resources by payload key, authorization)``.

    ``ctx`` carries the shared ``credentials`` / ``warnings`` / ``missing`` keyword arguments.
    """
    found: dict[str, Any] = {}
    authorization: dict[str, Any] = {}
    if include["storage"]:
        found["buckets"] = _discover_buckets(project_id, **ctx)
    if include["compute"]:
        found["instances"] = _discover_instances(project_id, **ctx)
        found["firewalls"] = _discover_firewalls(project_id, **ctx)
    if include["iam"]:
        authorization = _collect_iam_stage(project_id, found, ctx, usage_resolver)
    if include["containers"]:
        found["gke_clusters"] = _discover_gke_clusters(project_id, **ctx)
    if include["serverless"]:
        found["cloud_run_services"] = _discover_cloud_run_services(project_id, **ctx)
        found["cloud_functions"] = _discover_cloud_functions(project_id, **ctx)
    if include["databases"]:
        found["cloud_sql_instances"] = _discover_cloud_sql_instances(project_id, **ctx)
    if include["networks"]:
        _collect_network_stage(project_id, found, ctx)
    if include["disks"]:
        found["disks"] = _discover_disks(project_id, **ctx)
    if include["messaging"]:
        found["pubsub_topics"] = _discover_pubsub_topics(project_id, **ctx)
    return found, authorization


def _collect_iam_stage(project_id: str, found: dict[str, Any], ctx: dict[str, Any], usage_resolver: Any) -> dict[str, Any]:
    """Collect authorization evidence, then service accounts and group principals into ``found``."""
    credentials, warnings, missing = ctx["credentials"], ctx["warnings"], ctx["missing"]
    authorization = collect_gcp_authorization(credentials, project_id, warnings=warnings, missing=missing)
    iam_bindings, member_kinds = _discover_project_iam_bindings(project_id, **ctx)
    role_resolver = _make_role_resolver(credentials=credentials, warnings=warnings)
    found["service_accounts"] = _discover_service_accounts(
        project_id, iam_bindings=iam_bindings, role_resolver=role_resolver, usage_resolver=usage_resolver, **ctx
    )
    found["groups"] = _build_iam_group_principals(iam_bindings, member_kinds, project_id=project_id, role_resolver=role_resolver)
    return authorization


def _collect_network_stage(project_id: str, found: dict[str, Any], ctx: dict[str, Any]) -> None:
    """Collect VPCs, subnets, load balancers, WAF policies, gateways, routers, and IPs into ``found``."""
    subnets_by_network = _discover_subnets_by_network(project_id, **ctx)
    found["vpc_networks"] = _discover_vpc_networks(project_id, subnets_by_network=subnets_by_network, **ctx)
    found["subnets"] = _discover_subnets(subnets_by_network, project_id=project_id)
    found["load_balancers"], backends_by_policy = _discover_load_balancers(project_id, **ctx)
    found["web_acls"] = _discover_security_policies(project_id, backends_by_policy=backends_by_policy, **ctx)
    found["api_gateways"] = _discover_api_gateways(project_id, **ctx)
    found["nat_gateways"], found["route_tables"] = _discover_routers(project_id, **ctx)
    found["ip_addresses"] = _discover_ip_addresses(project_id, instances=found.setdefault("instances", []), **ctx)


def _inventory_payload(
    empty: dict[str, Any],
    found: dict[str, Any],
    authorization: dict[str, Any],
    *,
    include: Mapping[str, bool],
    warnings: list[str],
    missing: list[dict[str, str]],
) -> dict[str, Any]:
    """Assemble the ``ok`` payload in ``empty``'s key order, plus disk side-scan targets."""
    resolved_project = empty["project_id"]
    envelope = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=(f"gcp:project/{resolved_project}",),
        permissions_used=tuple(sorted({perm for stage, perms in _STAGE_PERMISSIONS.items() if include[stage] for perm in perms})),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )
    authorization_payload = {
        "status": "ok" if include["iam"] else "disabled",
        "project_id": resolved_project,
        "account_id": resolved_project,
        **authorization,
    }
    values = {
        **found,
        **{key: authorization[key] for key in _AUTHORIZATION_KEYS if key in authorization},
        "status": "ok",
        "authorization_evidence": normalize_gcp_iam_inventory(authorization_payload).to_dict(),
        "warnings": warnings,
    }
    payload: dict[str, Any] = {}
    for key, default in empty.items():
        payload[key] = values.get(key, default)
        if key == "disks":
            payload["side_scan_targets"] = gcp_persistent_disk_targets(payload["disks"], project_id=resolved_project)
    payload["missing_permissions"] = dedupe_missing_permissions(missing)
    payload["discovery_envelope"] = envelope.to_dict()
    return payload


# ---------------------------------------------------------------------------
# GCS buckets (project-wide list)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Compute instances + firewall rules (project-wide aggregated list)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Service accounts (project-wide list)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# GKE clusters (container_v1, project-wide via the "-" location wildcard)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cloud Run services (run_v2, project-wide via the "-" location wildcard)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cloud Functions (functions_v2, project-wide via the "-" location wildcard)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cloud SQL instances (Admin API via google-api-python-client)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# VPC networks + subnets (compute_v1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Subnets (flat list, reusing the aggregated subnet query)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Load balancers (compute_v1: backend services / URL maps / forwarding rules /
# target proxies) — normalized into one list, distinguished by ``lb_type``.
# ---------------------------------------------------------------------------


def _discover_load_balancers(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Enumerate the load-balancing data plane (read-only).

    Backend services, URL maps, forwarding rules, and target HTTP(S) proxies are
    normalized into a single list, each tagged with ``lb_type``. Also returns a
    ``{security_policy_leaf: [backend_id…]}`` map so a Cloud Armor policy can list
    the backend services it protects. Each resource class is queried in its own
    try/except so one missing permission degrades only that class.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping load-balancer inventory.")
        return [], {}

    load_balancers: list[dict[str, Any]] = []
    backends_by_policy: dict[str, list[str]] = {}

    try:
        backend_services_client = compute_v1.BackendServicesClient(credentials=credentials)
        for _scope, scoped_list in backend_services_client.aggregated_list(project=project_id):
            for backend in getattr(scoped_list, "backend_services", None) or []:
                name = str(getattr(backend, "name", "") or "").strip()
                if not name:
                    continue
                scheme = str(getattr(backend, "load_balancing_scheme", "") or "").upper()
                backend_id = str(getattr(backend, "id", "") or "") or name
                load_balancers.append(
                    {
                        "name": name,
                        "id": backend_id,
                        "lb_type": "backend-service",
                        "scheme": scheme,
                        "internet_exposed": "EXTERNAL" in scheme,
                        "location": _leaf(getattr(backend, "region", "")) or "global",
                        "account_id": project_id,
                    }
                )
                policy_leaf = _leaf(getattr(backend, "security_policy", ""))
                if policy_leaf:
                    backends_by_policy.setdefault(policy_leaf, []).append(backend_id)
    except Exception as exc:  # noqa: BLE001 — one failed backend-services list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="backend services",
            permission="compute.backendServices.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    try:
        url_maps_client = compute_v1.UrlMapsClient(credentials=credentials)
        for url_map in url_maps_client.list(project=project_id):
            name = str(getattr(url_map, "name", "") or "").strip()
            if not name:
                continue
            load_balancers.append(
                {
                    "name": name,
                    "id": str(getattr(url_map, "id", "") or "") or name,
                    "lb_type": "url-map",
                    "scheme": "",
                    "internet_exposed": False,
                    "location": _leaf(getattr(url_map, "region", "")) or "global",
                    "account_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed URL-maps list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="URL maps",
            permission="compute.urlMaps.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    try:
        forwarding_rules_client = compute_v1.ForwardingRulesClient(credentials=credentials)
        for _scope, scoped_list in forwarding_rules_client.aggregated_list(project=project_id):
            for rule in getattr(scoped_list, "forwarding_rules", None) or []:
                name = str(getattr(rule, "name", "") or "").strip()
                if not name:
                    continue
                scheme = str(getattr(rule, "load_balancing_scheme", "") or "").upper()
                load_balancers.append(
                    {
                        "name": name,
                        "id": str(getattr(rule, "id", "") or "") or name,
                        "lb_type": "forwarding-rule",
                        "scheme": scheme,
                        "internet_exposed": "EXTERNAL" in scheme,
                        "location": _leaf(getattr(rule, "region", "")) or "global",
                        "account_id": project_id,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed forwarding-rules list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="forwarding rules",
            permission="compute.forwardingRules.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    load_balancers.extend(_discover_target_proxies(project_id, credentials=credentials, warnings=warnings, missing=missing))
    return load_balancers, backends_by_policy


# ---------------------------------------------------------------------------
# Cloud Armor security policies (compute_v1) — GCP's WAF → web_acls
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# API Gateway (apigateway_v1) — GCP managed API front door → api_gateways
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cloud routers + Cloud NAT (compute_v1 RoutersClient.aggregated_list)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# External IP addresses (reserved via AddressesClient + ephemeral from instances)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Persistent disks (compute_v1, aggregated)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Pub/Sub topics (pubsub_v1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


__all__ = [
    "ALL_PROJECTS_ENV_FLAG",
    "INVENTORY_ENV_FLAG",
    "all_projects_enabled",
    "discover_all_project_inventories",
    "discover_inventory",
    "inventory_enabled",
]
