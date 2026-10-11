"""GCP VPC, subnet, proxy, security-policy, API gateway, router and address discovery for the inventory facade."""

from __future__ import annotations

from typing import Any

from ..aws_inventory import record_discovery_failure
from ._base import _leaf, _segment


def _discover_vpc_networks(
    project_id: str,
    *,
    credentials: Any,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
    subnets_by_network: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate every VPC network + its subnets in the project (read-only).

    ``subnets_by_network`` may be supplied by the caller to reuse a single
    aggregated subnet query (the flat ``subnets`` list shares the same data);
    when ``None`` the subnets are queried here.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping VPC network inventory.")
        return []

    if subnets_by_network is None:
        subnets_by_network = _discover_subnets_by_network(project_id, credentials=credentials, warnings=warnings, missing=missing)
    networks: list[dict[str, Any]] = []
    try:
        client = compute_v1.NetworksClient(credentials=credentials)
        for network in client.list(project=project_id):
            name = str(getattr(network, "name", "") or "").strip()
            if not name:
                continue
            self_link = str(getattr(network, "self_link", "") or "")
            network_subnets = subnets_by_network.get(self_link, []) or subnets_by_network.get(name, [])
            networks.append(
                {
                    "name": name,
                    "id": str(getattr(network, "id", "") or "") or name,
                    "location": "global",
                    "auto_create_subnetworks": bool(getattr(network, "auto_create_subnetworks", False)),
                    "subnets": network_subnets,
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed VPC networks list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="VPC networks",
            permission="compute.networks.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return networks


def _discover_subnets_by_network(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Aggregated subnet list, keyed by the parent network self-link AND name."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        return {}

    by_network: dict[str, list[dict[str, Any]]] = {}
    try:
        client = compute_v1.SubnetworksClient(credentials=credentials)
        for _region, scoped_list in client.aggregated_list(project=project_id):
            for subnet in getattr(scoped_list, "subnetworks", None) or []:
                network_link = str(getattr(subnet, "network", "") or "")
                flow_logs = getattr(subnet, "enable_flow_logs", None)
                subnet_name = str(getattr(subnet, "name", "") or "")
                entry = {
                    "id": str(getattr(subnet, "self_link", "") or "") or str(getattr(subnet, "id", "") or "") or subnet_name,
                    "name": subnet_name,
                    "network": network_link,
                    "region": _leaf(getattr(subnet, "region", "")),
                    "cidr": str(getattr(subnet, "ip_cidr_range", "") or ""),
                    "flow_logs": bool(flow_logs) if flow_logs is not None else False,
                }
                by_network.setdefault(network_link, []).append(entry)
                by_network.setdefault(_leaf(network_link), []).append(entry)
    except Exception as exc:  # noqa: BLE001 — one failed VPC subnets list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="VPC subnets",
            permission="compute.subnetworks.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return by_network


def _discover_subnets(subnets_by_network: dict[str, list[dict[str, Any]]], *, project_id: str) -> list[dict[str, Any]]:
    """Flatten the aggregated subnet map into a top-level ``subnets`` list.

    Reuses the data already produced by ``_discover_subnets_by_network`` (which
    keys each subnet under both its network self-link and the network leaf name),
    so each subnet object is deduplicated by identity rather than re-queried.
    """
    seen: set[int] = set()
    subnets: list[dict[str, Any]] = []
    for entries in subnets_by_network.values():
        for entry in entries:
            marker = id(entry)
            if marker in seen:
                continue
            seen.add(marker)
            name = str(entry.get("name", "") or "")
            subnets.append(
                {
                    "id": str(entry.get("id", "") or "") or name,
                    "name": name,
                    "vpc_id": str(entry.get("network", "") or ""),
                    "cidr": str(entry.get("cidr", "") or ""),
                    "is_public": False,
                    "location": str(entry.get("region", "") or ""),
                    "account_id": project_id,
                }
            )
    return subnets


def _discover_target_proxies(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate target HTTP + HTTPS proxies (read-only), normalized as LBs."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        return []

    proxies: list[dict[str, Any]] = []
    try:
        http_proxies_client = compute_v1.TargetHttpProxiesClient(credentials=credentials)
        for proxy in http_proxies_client.list(project=project_id):
            name = str(getattr(proxy, "name", "") or "").strip()
            if not name:
                continue
            proxies.append(
                {
                    "name": name,
                    "id": str(getattr(proxy, "id", "") or "") or name,
                    "lb_type": "target-proxy",
                    "scheme": "",
                    "internet_exposed": False,
                    "location": "global",
                    "account_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed target-HTTP-proxies list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="target HTTP proxies",
            permission="compute.targetHttpProxies.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    try:
        https_proxies_client = compute_v1.TargetHttpsProxiesClient(credentials=credentials)
        for proxy in https_proxies_client.list(project=project_id):
            name = str(getattr(proxy, "name", "") or "").strip()
            if not name:
                continue
            proxies.append(
                {
                    "name": name,
                    "id": str(getattr(proxy, "id", "") or "") or name,
                    "lb_type": "target-proxy",
                    "scheme": "",
                    "internet_exposed": False,
                    "location": "global",
                    "account_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed target-HTTPS-proxies list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="target HTTPS proxies",
            permission="compute.targetHttpsProxies.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return proxies


def _discover_security_policies(
    project_id: str,
    *,
    credentials: Any,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
    backends_by_policy: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate Cloud Armor security policies (read-only) → ``web_acls`` shape.

    ``protected_targets`` is resolved from the backend services that reference
    each policy (passed in via ``backends_by_policy``) so the graph can link a
    policy to the resources it shields.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping Cloud Armor inventory.")
        return []

    by_policy = backends_by_policy or {}
    policies: list[dict[str, Any]] = []
    try:
        client = compute_v1.SecurityPoliciesClient(credentials=credentials)
        for policy in client.list(project=project_id):
            name = str(getattr(policy, "name", "") or "").strip()
            if not name:
                continue
            policies.append(
                {
                    "name": name,
                    "id": str(getattr(policy, "id", "") or "") or name,
                    "arn": "",
                    "scope": "cloud-armor",
                    "protected_targets": list(by_policy.get(name, [])),
                    "location": "global",
                    "account_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Cloud Armor policies list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="Cloud Armor policies",
            permission="compute.securityPolicies.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return policies


def _discover_api_gateways(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate API Gateway gateways in the project (read-only).

    Gateways front backend services with a public default hostname, so each is
    marked ``internet_exposed``. Degrades to ``[]`` plus a warning when the
    apigateway SDK is absent.
    """
    try:
        from google.cloud import apigateway_v1
    except ImportError:
        warnings.append("google-cloud-api-gateway not installed. Skipping API Gateway inventory.")
        return []

    gateways: list[dict[str, Any]] = []
    try:
        client = apigateway_v1.ApiGatewayServiceClient(credentials=credentials)
        request = apigateway_v1.ListGatewaysRequest(parent=f"projects/{project_id}/locations/-")
        for gateway in client.list_gateways(request=request):
            full_name = str(getattr(gateway, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            api_config = _leaf(getattr(gateway, "api_config", ""))
            gateways.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "arn": "",
                    "protocol": "apigateway",
                    "endpoint": str(getattr(gateway, "default_hostname", "") or ""),
                    "internet_exposed": True,
                    "stages": [],
                    "protected_targets": [api_config] if api_config else [],
                    "location": _segment(full_name, "locations"),
                    "account_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed API Gateway list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="API gateways",
            permission="apigateway.gateways.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return gateways


def _discover_routers(
    project_id: str, *, credentials: Any, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate Cloud routers + their NAT configs (read-only).

    Returns ``(nat_gateways, route_tables)``: each router becomes a route-table
    entry (``has_internet_route`` True when it carries a NAT egress config), and
    each NAT config on a router becomes a NAT-gateway entry.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping router/NAT inventory.")
        return [], []

    nat_gateways: list[dict[str, Any]] = []
    route_tables: list[dict[str, Any]] = []
    try:
        client = compute_v1.RoutersClient(credentials=credentials)
        for _scope, scoped_list in client.aggregated_list(project=project_id):
            for router in getattr(scoped_list, "routers", None) or []:
                name = str(getattr(router, "name", "") or "").strip()
                if not name:
                    continue
                network = _leaf(getattr(router, "network", ""))
                region = _leaf(getattr(router, "region", ""))
                router_id = str(getattr(router, "id", "") or "") or name
                nats = list(getattr(router, "nats", None) or [])
                route_tables.append(
                    {
                        "id": router_id,
                        "name": name,
                        "vpc_id": network,
                        "has_internet_route": bool(nats),
                        "location": region,
                        "account_id": project_id,
                    }
                )
                for nat in nats:
                    nat_name = str(getattr(nat, "name", "") or "").strip()
                    if not nat_name:
                        continue
                    nat_gateways.append(
                        {
                            "id": f"{name}/{nat_name}",
                            "name": nat_name,
                            "vpc_id": network,
                            "subnet_id": "",
                            "location": region,
                            "account_id": project_id,
                        }
                    )
    except Exception as exc:  # noqa: BLE001 — one failed routers list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="routers",
            permission="compute.routers.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )
    return nat_gateways, route_tables


def _discover_ip_addresses(
    project_id: str,
    *,
    credentials: Any,
    warnings: list[str],
    missing: list[dict[str, str]] | None = None,
    instances: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate reserved external IPs + ephemeral external IPs (read-only).

    Reserved addresses come from ``AddressesClient.aggregated_list``; ephemeral
    external IPs are read from the already-discovered instances' access configs
    (their ``public_ip``) and de-duplicated against the reserved set so a static
    IP attached to a VM is not double-counted.
    """
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping IP-address inventory.")
        return []

    ip_addresses: list[dict[str, Any]] = []
    reserved_values: set[str] = set()
    try:
        client = compute_v1.AddressesClient(credentials=credentials)
        for _scope, scoped_list in client.aggregated_list(project=project_id):
            for address in getattr(scoped_list, "addresses", None) or []:
                value = str(getattr(address, "address", "") or "").strip()
                if not value:
                    continue
                reserved_values.add(value)
                users = [_leaf(u) for u in (getattr(address, "users", None) or []) if u]
                ip_addresses.append(
                    {
                        "address": value,
                        "kind": "reserved",
                        "attached_to": users[0] if users else "",
                        "location": _leaf(getattr(address, "region", "")) or "global",
                        "account_id": project_id,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed addresses list must not sink the scan
        record_discovery_failure(
            exc=exc,
            resource_type="reserved IP addresses",
            permission="compute.addresses.list",
            cloud="gcp",
            warnings=warnings,
            missing=missing,
        )

    for instance in instances or []:
        public_ip = str(instance.get("public_ip", "") or "").strip()
        if not public_ip or public_ip in reserved_values:
            continue
        reserved_values.add(public_ip)
        ip_addresses.append(
            {
                "address": public_ip,
                "kind": "ephemeral",
                "attached_to": str(instance.get("name", "") or instance.get("instance_id", "") or ""),
                "location": str(instance.get("zone", "") or ""),
                "account_id": project_id,
            }
        )
    return ip_addresses
