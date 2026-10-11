"""Azure internet-edge discovery (firewalls, load balancers, application gateways, Front Door, API Management)."""

from __future__ import annotations

from typing import Any

from ._base import _clean_tags, _public_ip_ref_value, _record_failure, _resource_group_from_id


def _discover_azure_firewalls(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Azure Firewalls in the subscription (read-only).

    Captures the firewall's private IP and the public IPs it fronts — the
    network-edge choke point for north/south traffic. Control-plane only.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping Azure Firewall inventory.")
        return []

    firewalls: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for fw in client.azure_firewalls.list_all():
            fw_id = str(getattr(fw, "id", "") or "")
            name = str(getattr(fw, "name", "") or "").strip()
            if not name:
                continue
            private_ip = ""
            public_ips: list[str] = []
            for ip_config in getattr(fw, "ip_configurations", None) or []:
                if not private_ip:
                    private_ip = str(getattr(ip_config, "private_ip_address", "") or "")
                value = _public_ip_ref_value(getattr(ip_config, "public_ip_address", None))
                if value:
                    public_ips.append(value)
            firewalls.append(
                {
                    "id": fw_id,
                    "name": name,
                    "location": str(getattr(fw, "location", "") or ""),
                    "account_id": subscription_id,
                    "private_ip": private_ip,
                    "public_ips": public_ips,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Firewalls list must not sink the scan
        _record_failure(exc, "Azure Firewalls", "Microsoft.Network/azureFirewalls/read", warnings, missing)
    return firewalls


def _discover_load_balancers(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate load balancers with their SKU and public-frontend posture."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping load-balancer inventory.")
        return []

    load_balancers: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for lb in client.load_balancers.list_all():
            lb_id = str(getattr(lb, "id", "") or "")
            name = str(getattr(lb, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(lb, "sku", None)
            frontends = getattr(lb, "frontend_ip_configurations", None) or []
            public_ip_ids = [
                str(getattr(getattr(fe, "public_ip_address", None), "id", "") or "")
                for fe in frontends
                if getattr(fe, "public_ip_address", None) is not None
            ]
            public_ip_ids = [pid for pid in public_ip_ids if pid]
            load_balancers.append(
                {
                    "name": name,
                    "id": lb_id,
                    "location": str(getattr(lb, "location", "") or ""),
                    "resource_group": _resource_group_from_id(lb_id),
                    "tags": _clean_tags(getattr(lb, "tags", None)),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "internet_facing": bool(public_ip_ids),
                    "public_ip_ids": public_ip_ids,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure load balancers list must not sink the scan
        _record_failure(exc, "Azure load balancers", "Microsoft.Network/loadBalancers/read", warnings, missing)
    return load_balancers


def _discover_application_gateways(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Application Gateways (L7 LB + WAF) in the subscription (read-only).

    Captures SKU tier, whether a WAF is attached (inline config or linked
    firewall policy), and the public IPs that front it (so the graph's
    public-IP → load-balancer exposure edge applies). Control-plane only.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping Application Gateway inventory.")
        return []

    gateways: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for gw in client.application_gateways.list_all():
            gw_id = str(getattr(gw, "id", "") or "")
            name = str(getattr(gw, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(gw, "sku", None)
            sku_tier = str(getattr(sku, "tier", "") or "") if sku else ""
            waf_config = getattr(gw, "web_application_firewall_configuration", None)
            firewall_policy = getattr(gw, "firewall_policy", None)
            waf_enabled = (
                bool(waf_config and getattr(waf_config, "enabled", False))
                or bool(getattr(firewall_policy, "id", "") if firewall_policy else "")
                or "waf" in sku_tier.lower()
            )
            frontends = getattr(gw, "frontend_ip_configurations", None) or []
            public_ip_ids = [
                str(getattr(getattr(fe, "public_ip_address", None), "id", "") or "")
                for fe in frontends
                if getattr(fe, "public_ip_address", None) is not None
            ]
            public_ip_ids = [pid for pid in public_ip_ids if pid]
            gateways.append(
                {
                    "name": name,
                    "id": gw_id,
                    "native_type": "Microsoft.Network/applicationGateways",
                    "location": str(getattr(gw, "location", "") or ""),
                    "resource_group": _resource_group_from_id(gw_id),
                    "tags": _clean_tags(getattr(gw, "tags", None)),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "sku_tier": sku_tier,
                    "waf_enabled": waf_enabled,
                    "internet_facing": bool(public_ip_ids),
                    "public_ip_ids": public_ip_ids,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Application Gateways list must not sink the scan
        _record_failure(exc, "Azure Application Gateways", "Microsoft.Network/applicationGateways/read", warnings, missing)
    return gateways


def _discover_front_doors(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate Azure Front Door (classic) profiles — global internet edge (read-only)."""
    try:
        from azure.mgmt.frontdoor import FrontDoorManagementClient
    except ImportError:
        warnings.append("azure-mgmt-frontdoor not installed. Skipping Front Door inventory.")
        return []

    front_doors: list[dict[str, Any]] = []
    try:
        client = FrontDoorManagementClient(credential, subscription_id)
        for fd in client.front_doors.list():
            fd_id = str(getattr(fd, "id", "") or "")
            name = str(getattr(fd, "name", "") or "").strip()
            if not name:
                continue
            front_doors.append(
                {
                    "name": name,
                    "id": fd_id,
                    "native_type": "Microsoft.Network/frontDoors",
                    "location": str(getattr(fd, "location", "") or "global"),
                    "resource_group": _resource_group_from_id(fd_id),
                    "tags": _clean_tags(getattr(fd, "tags", None)),
                    "cname": str(getattr(fd, "cname", "") or ""),
                    "enabled_state": str(getattr(fd, "enabled_state", "") or ""),
                    "internet_facing": True,  # Front Door is a global internet edge by definition
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure Front Doors list must not sink the scan
        _record_failure(exc, "Azure Front Doors", "Microsoft.Network/frontDoors/read", warnings, missing)
    return front_doors


def _discover_api_management(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate API Management services (API gateway) in the subscription (read-only).

    Internet-facing unless deployed *Internal* into a VNet. Control-plane only —
    never reads API definitions or backend secrets.
    """
    try:
        from azure.mgmt.apimanagement import ApiManagementClient
    except ImportError:
        warnings.append("azure-mgmt-apimanagement not installed. Skipping API Management inventory.")
        return []

    services: list[dict[str, Any]] = []
    try:
        client = ApiManagementClient(credential, subscription_id)
        for svc in client.api_management_service.list():
            svc_id = str(getattr(svc, "id", "") or "")
            name = str(getattr(svc, "name", "") or "").strip()
            if not name:
                continue
            sku = getattr(svc, "sku", None)
            gateway_url = str(getattr(svc, "gateway_url", "") or "")
            public_ips = [str(ip) for ip in (getattr(svc, "public_ip_addresses", None) or []) if ip]
            vnet_type = str(getattr(svc, "virtual_network_type", "") or "")
            internet_facing = vnet_type.lower() != "internal" and (bool(gateway_url) or bool(public_ips))
            services.append(
                {
                    "name": name,
                    "id": svc_id,
                    "native_type": "Microsoft.ApiManagement/service",
                    "location": str(getattr(svc, "location", "") or ""),
                    "resource_group": _resource_group_from_id(svc_id),
                    "tags": _clean_tags(getattr(svc, "tags", None)),
                    "sku": str(getattr(sku, "name", "") or "") if sku else "",
                    "gateway_url": gateway_url,
                    "virtual_network_type": vnet_type,
                    "internet_facing": internet_facing,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure API Management services list must not sink the scan
        _record_failure(exc, "Azure API Management services", "Microsoft.ApiManagement/service/read", warnings, missing)
    return services
