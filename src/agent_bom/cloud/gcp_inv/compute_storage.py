"""GCP storage, compute, serverless, database and messaging discovery for the inventory facade."""

from __future__ import annotations

from typing import Any

from ..aws_inventory import record_discovery_failure
from ..normalization import sanitize_discovery_warning
from ._base import _INTERNET_RANGES, _PUBLIC_MEMBERS, _clean_labels, _leaf, _parse_port, _safe_int, _segment
from .iam import _policy_bindings


def _discover_buckets(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every GCS bucket in the project (read-only).

    Public-access posture is read from the bucket IAM policy (``allUsers`` /
    ``allAuthenticatedUsers`` bindings) — never from object contents. Buckets
    become ``DATA_STORE``-signalling nodes so DSPM and exposure overlays apply.
    """
    try:
        from google.cloud import storage  # type: ignore[attr-defined]  # google.cloud namespace package
    except ImportError:
        warnings.append("google-cloud-storage not installed. Skipping GCS bucket inventory.")
        return []

    buckets: list[dict[str, Any]] = []
    try:
        client = storage.Client(project=project_id, credentials=credentials)
        for bucket in client.list_buckets():
            name = str(getattr(bucket, "name", "") or "").strip()
            if not name:
                continue
            bucket_record = {
                "name": name,
                "id": f"//storage.googleapis.com/{name}",
                "location": str(getattr(bucket, "location", "") or ""),
                "publicly_accessible": _bucket_public(bucket, name, warnings),
                "tags": _clean_labels(getattr(bucket, "labels", None)),
                "project_id": project_id,
            }
            try:
                from agent_bom.cloud.gcs_data_classifier import classify_gcs_bucket, gcs_sampling_enabled

                if gcs_sampling_enabled():
                    bucket_record["content_classification"] = classify_gcs_bucket(client, name).to_dict()
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Could not classify GCS bucket {name}: {sanitize_discovery_warning(exc)}")
            buckets.append(bucket_record)
    except Exception as exc:  # noqa: BLE001 — one failed GCS buckets list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="GCS buckets",
            permission="storage.buckets.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return buckets


def _bucket_public(bucket: Any, name: str, warnings: list[str]) -> bool:
    """Best-effort public determination from the bucket IAM policy only.

    A bucket is treated as public when its IAM policy grants any role to
    ``allUsers`` or ``allAuthenticatedUsers``. Errors degrade to ``False``
    (unknown) with a warning — never a guess that inflates risk.
    """
    get_policy = getattr(bucket, "get_iam_policy", None)
    if not callable(get_policy):
        return False
    try:
        policy = get_policy()
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read IAM policy for GCS bucket {name}: {sanitize_discovery_warning(exc)}")
        return False
    for binding in _policy_bindings(policy):
        members = binding.get("members", []) or []
        if any(str(member).split(":", 1)[0].lower() in _PUBLIC_MEMBERS for member in members):
            return True
    return False


def _discover_instances(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate all Compute Engine instances in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping Compute instance inventory.")
        return []

    instances: list[dict[str, Any]] = []
    try:
        client = compute_v1.InstancesClient(credentials=credentials)
        for _zone, scoped_list in client.aggregated_list(project=project_id):
            for instance in getattr(scoped_list, "instances", None) or []:
                name = str(getattr(instance, "name", "") or "").strip()
                if not name:
                    continue
                instances.append(_normalize_instance(instance, name=name, project_id=project_id))
    except Exception as exc:  # noqa: BLE001 — one failed Compute instances list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Compute instances",
            permission="compute.instances.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return instances


def _normalize_instance(instance: Any, *, name: str, project_id: str) -> dict[str, Any]:
    public_ip = ""
    private_ip = ""
    networks: list[str] = []
    for interface in getattr(instance, "network_interfaces", None) or []:
        private_ip = private_ip or str(getattr(interface, "network_i_p", "") or getattr(interface, "network_ip", "") or "")
        network_leaf = _leaf(getattr(interface, "network", ""))
        if network_leaf and network_leaf not in networks:
            networks.append(network_leaf)
        for access in getattr(interface, "access_configs", None) or []:
            nat_ip = str(getattr(access, "nat_i_p", "") or getattr(access, "nat_ip", "") or "")
            if nat_ip:
                public_ip = nat_ip
                break
    service_accounts = [
        str(getattr(sa, "email", "") or "") for sa in (getattr(instance, "service_accounts", None) or []) if getattr(sa, "email", "")
    ]
    return {
        "instance_id": str(getattr(instance, "id", "") or "") or name,
        "name": name,
        "instance_type": _leaf(getattr(instance, "machine_type", "")),
        "zone": _leaf(getattr(instance, "zone", "")),
        "status": str(getattr(instance, "status", "") or ""),
        "public_ip": public_ip,
        "private_ip": private_ip,
        # The network each interface attaches to — the join key a firewall rule
        # matches on (a rule applies to instances on its target network).
        "network": networks[0] if networks else "",
        "networks": networks,
        "network_tags": list(getattr(getattr(instance, "tags", None), "items", None) or []),
        "service_accounts": service_accounts,
        "labels": _clean_labels(getattr(instance, "labels", None)),
        "project_id": project_id,
    }


def _discover_firewalls(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate all VPC firewall rules in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping firewall inventory.")
        return []

    firewalls: list[dict[str, Any]] = []
    try:
        client = compute_v1.FirewallsClient(credentials=credentials)
        for rule in client.list(project=project_id):
            name = str(getattr(rule, "name", "") or "").strip()
            if not name:
                continue
            firewalls.append(_normalize_firewall(rule, name=name, project_id=project_id))
    except Exception as exc:  # noqa: BLE001 — one failed firewall rules list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="firewall rules",
            permission="compute.firewalls.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return firewalls


def _normalize_firewall(rule: Any, *, name: str, project_id: str) -> dict[str, Any]:
    exposure = _firewall_internet_exposure(rule)
    source_ranges = [str(r) for r in (getattr(rule, "source_ranges", None) or []) if r]
    # Target tags / target service accounts scope a rule to specific instances.
    # An EMPTY target set means the rule applies to ALL instances on its network.
    target_tags = [str(t) for t in (getattr(rule, "target_tags", None) or []) if t]
    target_service_accounts = [str(sa) for sa in (getattr(rule, "target_service_accounts", None) or []) if sa]
    return {
        "group_id": name,
        "name": name,
        "network": _leaf(getattr(rule, "network", "")),
        "direction": str(getattr(rule, "direction", "") or "").upper(),
        "internet_exposed": bool(exposure),
        "network_exposure": exposure,
        "source_ranges": source_ranges,
        "target_tags": target_tags,
        "target_service_accounts": target_service_accounts,
        "project_id": project_id,
    }


def _firewall_internet_exposure(rule: Any) -> list[dict[str, Any]]:
    """Return internet-facing ingress allow rules in the CNAPP overlay's shape."""
    direction = str(getattr(rule, "direction", "") or "INGRESS").upper()
    if direction not in ("", "INGRESS"):
        return []
    if not (getattr(rule, "allowed", None) or []):
        return []
    source_ranges = [str(r) for r in (getattr(rule, "source_ranges", None) or []) if r]
    if not any(src in _INTERNET_RANGES for src in source_ranges):
        return []
    exposure: list[dict[str, Any]] = []
    for allowed in getattr(rule, "allowed", None) or []:
        protocol = str(getattr(allowed, "I_p_protocol", "") or getattr(allowed, "ip_protocol", "") or "tcp").lower()
        ports = list(getattr(allowed, "ports", None) or [])
        if not ports:
            exposure.append({"scope": "internet", "from_port": None, "to_port": None, "protocol": protocol})
            continue
        for port in ports:
            from_port, to_port = _parse_port(str(port))
            exposure.append({"scope": "internet", "from_port": from_port, "to_port": to_port, "protocol": protocol})
    return exposure


def _discover_gke_clusters(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every GKE cluster in the project (read-only).

    Uses the ``-`` location wildcard so a single call returns clusters across all
    regions/zones. A cluster with a public control-plane endpoint (no
    ``private_cluster_config.enable_private_endpoint``) is marked
    ``internet_exposed`` so the CNAPP / attack-path overlays treat it as an entry.
    """
    try:
        from google.cloud import container_v1
    except ImportError:
        warnings.append("google-cloud-container not installed. Skipping GKE cluster inventory.")
        return []

    clusters: list[dict[str, Any]] = []
    try:
        client = container_v1.ClusterManagerClient(credentials=credentials)
        response = client.list_clusters(parent=f"projects/{project_id}/locations/-")
        for cluster in getattr(response, "clusters", None) or []:
            name = str(getattr(cluster, "name", "") or "").strip()
            if not name:
                continue
            private_cfg = getattr(cluster, "private_cluster_config", None)
            private_endpoint = bool(getattr(private_cfg, "enable_private_endpoint", False)) if private_cfg else False
            clusters.append(
                {
                    "name": name,
                    "id": str(getattr(cluster, "id", "") or "") or name,
                    "location": str(getattr(cluster, "location", "") or ""),
                    "endpoint": str(getattr(cluster, "endpoint", "") or ""),
                    "private_cluster": bool(getattr(private_cfg, "enable_private_nodes", False)) if private_cfg else False,
                    "internet_exposed": not private_endpoint,
                    "node_count": _safe_int(str(getattr(cluster, "current_node_count", "") or "")) or 0,
                    "version": str(getattr(cluster, "current_master_version", "") or ""),
                    "labels": _clean_labels(getattr(cluster, "resource_labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed GKE clusters list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="GKE clusters",
            permission="container.clusters.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return clusters


def _discover_cloud_run_services(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Cloud Run service in the project (read-only).

    Ingress ``INGRESS_TRAFFIC_ALL`` means the service is reachable from the
    internet → ``internet_exposed``. ``INGRESS_TRAFFIC_INTERNAL_*`` is private.
    """
    try:
        from google.cloud import run_v2
    except ImportError:
        warnings.append("google-cloud-run not installed. Skipping Cloud Run service inventory.")
        return []

    services: list[dict[str, Any]] = []
    try:
        client = run_v2.ServicesClient(credentials=credentials)
        request = run_v2.ListServicesRequest(parent=f"projects/{project_id}/locations/-")
        for service in client.list_services(request=request):
            full_name = str(getattr(service, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            ingress = str(getattr(service, "ingress", "") or "")
            region = _segment(full_name, "locations")
            services.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "location": region,
                    "url": str(getattr(service, "uri", "") or ""),
                    "ingress": ingress,
                    "internet_exposed": "ALL" in ingress.upper(),
                    "labels": _clean_labels(getattr(service, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Cloud Run services list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Cloud Run services",
            permission="run.services.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return services


def _discover_cloud_functions(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every 2nd-gen Cloud Function in the project (read-only)."""
    try:
        from google.cloud import functions_v2
    except ImportError:
        warnings.append("google-cloud-functions not installed. Skipping Cloud Functions inventory.")
        return []

    functions: list[dict[str, Any]] = []
    try:
        client = functions_v2.FunctionServiceClient(credentials=credentials)
        request = functions_v2.ListFunctionsRequest(parent=f"projects/{project_id}/locations/-")
        for function in client.list_functions(request=request):
            full_name = str(getattr(function, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            service_config = getattr(function, "service_config", None)
            ingress = str(getattr(service_config, "ingress_settings", "") or "") if service_config else ""
            event_trigger = getattr(function, "event_trigger", None)
            trigger = "event" if event_trigger else "https"
            functions.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "location": _segment(full_name, "locations"),
                    "trigger": trigger,
                    "ingress": ingress,
                    "internet_exposed": "ALL" in ingress.upper(),
                    "labels": _clean_labels(getattr(function, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Cloud Functions list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Cloud Functions",
            permission="cloudfunctions.functions.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return functions


def _discover_cloud_sql_instances(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Cloud SQL instance in the project (read-only).

    The Cloud SQL Admin API has no idiomatic google-cloud client, so this uses
    the discovery-built ``sqladmin`` client. An instance with a public IPv4
    address (``PRIMARY`` ip_address) or an open authorized-network
    (``0.0.0.0/0``) is marked ``internet_exposed`` so a public managed database
    feeds the CNAPP / attack-path overlays.
    """
    try:
        from googleapiclient.discovery import build
    except ImportError:
        warnings.append("google-api-python-client not installed. Skipping Cloud SQL inventory.")
        return []

    instances: list[dict[str, Any]] = []
    try:
        service = build("sqladmin", "v1beta4", credentials=credentials, cache_discovery=False)
        request = service.instances().list(project=project_id)
        while request is not None:
            response = request.execute()
            for item in response.get("items", []) or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "") or "").strip()
                if not name:
                    continue
                ip_addresses = [str(ip.get("ipAddress", "")) for ip in (item.get("ipAddresses") or []) if isinstance(ip, dict)]
                settings = item.get("settings") or {}
                ip_config = settings.get("ipConfiguration") or {}
                authorized = [str(net.get("value", "")) for net in (ip_config.get("authorizedNetworks") or []) if isinstance(net, dict)]
                public_ip = bool(ip_config.get("ipv4Enabled")) and bool(ip_addresses)
                open_network = any(net in _INTERNET_RANGES for net in authorized)
                disk_encryption = item.get("diskEncryptionConfiguration") or {}
                instances.append(
                    {
                        "name": name,
                        "id": str(item.get("selfLink", "") or "") or name,
                        "location": str(item.get("region", "") or ""),
                        "database_version": str(item.get("databaseVersion", "") or ""),
                        "ip_addresses": ip_addresses,
                        "authorized_networks": authorized,
                        "publicly_accessible": public_ip or open_network,
                        "internet_exposed": public_ip or open_network,
                        "encrypted": bool(disk_encryption.get("kmsKeyName")),
                        "project_id": project_id,
                    }
                )
            page_token = response.get("nextPageToken")
            if not page_token:
                break
            request = service.instances().list(project=project_id, pageToken=page_token)
    except Exception as exc:  # noqa: BLE001 — one failed Cloud SQL instances list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Cloud SQL instances",
            permission="cloudsql.instances.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return instances


def _discover_disks(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every persistent disk in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping persistent-disk inventory.")
        return []

    disks: list[dict[str, Any]] = []
    try:
        client = compute_v1.DisksClient(credentials=credentials)
        for _zone, scoped_list in client.aggregated_list(project=project_id):
            for disk in getattr(scoped_list, "disks", None) or []:
                name = str(getattr(disk, "name", "") or "").strip()
                if not name:
                    continue
                encryption = getattr(disk, "disk_encryption_key", None)
                disks.append(
                    {
                        "name": name,
                        "id": str(getattr(disk, "id", "") or "") or name,
                        "location": _leaf(getattr(disk, "zone", "")),
                        "size_gb": _safe_int(str(getattr(disk, "size_gb", "") or "")) or 0,
                        "encrypted": bool(getattr(encryption, "kms_key_name", "") if encryption else False),
                        "source_image": _leaf(getattr(disk, "source_image", "")),
                        "labels": _clean_labels(getattr(disk, "labels", None)),
                        "project_id": project_id,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed persistent disks list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="persistent disks",
            permission="compute.disks.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return disks


def _discover_pubsub_topics(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every Pub/Sub topic in the project (read-only)."""
    try:
        from google.cloud import pubsub_v1  # type: ignore[attr-defined]  # google.cloud namespace package
    except ImportError:
        warnings.append("google-cloud-pubsub not installed. Skipping Pub/Sub topic inventory.")
        return []

    topics: list[dict[str, Any]] = []
    try:
        client = pubsub_v1.PublisherClient(credentials=credentials)
        for topic in client.list_topics(request={"project": f"projects/{project_id}"}):
            full_name = str(getattr(topic, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            topics.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "location": "global",
                    "labels": _clean_labels(getattr(topic, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Pub/Sub topics list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Pub/Sub topics",
            permission="pubsub.topics.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return topics
