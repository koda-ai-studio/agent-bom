"""Azure virtual-network, NSG, address, subnet and routing discovery for the inventory facade."""

from __future__ import annotations

from typing import Any

from ._base import (
    _INTERNET_SOURCES,
    _clean_tags,
    _public_ip_ref_value,
    _record_failure,
    _resource_group_from_id,
    _safe_int,
    _vnet_id_from_subnet_id,
)


def _discover_nsgs(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate all Network Security Groups in the subscription (read-only)."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping NSG inventory.")
        return []

    groups: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for nsg in client.network_security_groups.list_all():
            nsg_id = str(getattr(nsg, "id", "") or "")
            name = str(getattr(nsg, "name", "") or "").strip()
            if not name:
                continue
            groups.append(_normalize_nsg(nsg, nsg_id=nsg_id, name=name, subscription_id=subscription_id))
    except Exception as exc:  # noqa: BLE001 — one failed Azure network security groups list must not sink the scan
        _record_failure(exc, "Azure network security groups", "Microsoft.Network/networkSecurityGroups/read", warnings, missing)
    return groups


def _normalize_nsg(nsg: Any, *, nsg_id: str, name: str, subscription_id: str) -> dict[str, Any]:
    exposure = _nsg_internet_exposure(nsg)
    return {
        # NSG names are unique only per resource group; without an ARM id the
        # subscription is the narrowest scope the list call still tells us.
        "group_id": nsg_id or (f"subscriptions/{subscription_id}/networkSecurityGroups/{name}" if subscription_id else name),
        "name": name,
        "location": str(getattr(nsg, "location", "") or ""),
        "resource_group": _resource_group_from_id(nsg_id),
        "internet_exposed": bool(exposure),
        "network_exposure": exposure,
        "subscription_id": subscription_id,
    }


def _nsg_internet_exposure(nsg: Any) -> list[dict[str, Any]]:
    """Return internet-facing inbound rules in the CNAPP overlay's shape.

    Each entry is ``{"scope": "internet", "from_port", "to_port", "protocol"}``
    so :func:`agent_bom.graph.cnapp_overlay.apply_cnapp_overlay` can attach
    structured exposure without keyword-matching free text.
    """
    exposure: list[dict[str, Any]] = []
    for rule in getattr(nsg, "security_rules", None) or []:
        direction = str(getattr(rule, "direction", "") or "").lower()
        access = str(getattr(rule, "access", "") or "").lower()
        if direction != "inbound" or access != "allow":
            continue
        sources = _rule_sources(rule)
        if not any(src.lower() in _INTERNET_SOURCES for src in sources):
            continue
        from_port, to_port = _rule_port_range(rule)
        exposure.append(
            {
                "scope": "internet",
                "from_port": from_port,
                "to_port": to_port,
                "protocol": str(getattr(rule, "protocol", "") or "tcp").lower(),
            }
        )
    return exposure


def _rule_sources(rule: Any) -> list[str]:
    sources: list[str] = []
    single = getattr(rule, "source_address_prefix", None)
    if single:
        sources.append(str(single))
    multiple = getattr(rule, "source_address_prefixes", None) or []
    for prefix in multiple:
        if prefix:
            sources.append(str(prefix))
    return sources


def _rule_port_range(rule: Any) -> tuple[int | None, int | None]:
    raw = getattr(rule, "destination_port_range", None)
    candidates = [raw] if raw else list(getattr(rule, "destination_port_ranges", None) or [])
    for candidate in candidates:
        text = str(candidate or "").strip()
        if not text or text == "*":
            return None, None
        if "-" in text:
            low, _, high = text.partition("-")
            return _safe_int(low), _safe_int(high)
        port = _safe_int(text)
        return port, port
    return None, None


def _discover_virtual_networks(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every VNet in the subscription with its address space and subnets."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping virtual-network inventory.")
        return []

    vnets: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for vnet in client.virtual_networks.list_all():
            vnet_id = str(getattr(vnet, "id", "") or "")
            name = str(getattr(vnet, "name", "") or "").strip()
            if not name:
                continue
            address_space = getattr(vnet, "address_space", None)
            prefixes = list(getattr(address_space, "address_prefixes", []) or []) if address_space else []
            subnets = [str(getattr(s, "name", "") or "") for s in (getattr(vnet, "subnets", None) or [])]
            vnets.append(
                {
                    "name": name,
                    "id": vnet_id,
                    "location": str(getattr(vnet, "location", "") or ""),
                    "resource_group": _resource_group_from_id(vnet_id),
                    "tags": _clean_tags(getattr(vnet, "tags", None)),
                    "address_prefixes": [str(p) for p in prefixes],
                    "subnets": [s for s in subnets if s],
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure virtual networks list must not sink the scan
        _record_failure(exc, "Azure virtual networks", "Microsoft.Network/virtualNetworks/read", warnings, missing)
    return vnets


def _discover_public_ips(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate public IP addresses — the internet-facing exposure surface."""
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping public-IP inventory.")
        return []

    public_ips: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for pip in client.public_ip_addresses.list_all():
            pip_id = str(getattr(pip, "id", "") or "")
            name = str(getattr(pip, "name", "") or "").strip()
            if not name:
                continue
            public_ips.append(
                {
                    "name": name,
                    "id": pip_id,
                    "location": str(getattr(pip, "location", "") or ""),
                    "resource_group": _resource_group_from_id(pip_id),
                    "tags": _clean_tags(getattr(pip, "tags", None)),
                    "ip_address": str(getattr(pip, "ip_address", "") or ""),
                    "allocation_method": str(getattr(pip, "public_ip_allocation_method", "") or ""),
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure public IPs list must not sink the scan
        _record_failure(exc, "Azure public IPs", "Microsoft.Network/publicIPAddresses/read", warnings, missing)
    return public_ips


def _discover_ip_addresses(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Surface allocated public IP *addresses* and the resource each is bound to.

    The symmetric counterpart of the NIC ``public_ip`` capture: from the
    public-IP resource side, record the address value and the ARM id of the IP
    configuration it is attached to (a NIC / load-balancer / gateway frontend),
    so the graph can wire the address to its bearer from either direction.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping IP-address inventory.")
        return []

    addresses: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for pip in client.public_ip_addresses.list_all():
            address = str(getattr(pip, "ip_address", "") or "")
            ip_config = getattr(pip, "ip_configuration", None)
            attached_to = str(getattr(ip_config, "id", "") or "") if ip_config else ""
            addresses.append(
                {
                    "address": address,
                    "kind": "public",
                    "attached_to": attached_to,
                    "location": str(getattr(pip, "location", "") or ""),
                    "account_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure public IPs list must not sink the scan
        _record_failure(exc, "Azure IP addresses", "Microsoft.Network/publicIPAddresses/read", warnings, missing)
    return addresses


def _discover_subnets(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every subnet across the subscription's VNets (read-only).

    Subnets are not listable subscription-wide directly, so they are read from
    each VNet's expanded ``subnets`` collection. ``is_public`` is a conservative,
    provable signal: a subnet with an attached NAT gateway has an explicit
    internet egress path. The shared builder can refine exposure by joining a
    subnet's route table against ``route_tables`` (``has_internet_route``).
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping subnet inventory.")
        return []

    subnets: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for vnet in client.virtual_networks.list_all():
            vnet_id = str(getattr(vnet, "id", "") or "")
            for subnet in getattr(vnet, "subnets", None) or []:
                subnet_id = str(getattr(subnet, "id", "") or "")
                name = str(getattr(subnet, "name", "") or "").strip()
                if not name:
                    continue
                cidr = str(getattr(subnet, "address_prefix", "") or "")
                if not cidr:
                    prefixes = list(getattr(subnet, "address_prefixes", None) or [])
                    cidr = str(prefixes[0]) if prefixes else ""
                nat_gateway = getattr(subnet, "nat_gateway", None)
                subnets.append(
                    {
                        "id": subnet_id,
                        "name": name,
                        "vpc_id": vnet_id,
                        "cidr": cidr,
                        "is_public": nat_gateway is not None,
                        "location": str(getattr(vnet, "location", "") or ""),
                        "account_id": subscription_id,
                    }
                )
    except Exception as exc:  # noqa: BLE001 — one failed Azure subnets list must not sink the scan
        _record_failure(exc, "Azure subnets", "Microsoft.Network/virtualNetworks/subnets/read", warnings, missing)
    return subnets


def _discover_network_interfaces(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate every NIC in the subscription with its IP-config topology (read-only).

    Each NIC binds a VM to a subnet (hence a VNet) and may carry an NSG plus a
    private and/or public IP — the edge data the graph needs to attach a VM to
    its network position and exposure. Control-plane only; never any secrets.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping network-interface inventory.")
        return []

    nics: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for nic in client.network_interfaces.list_all():
            nic_id = str(getattr(nic, "id", "") or "")
            name = str(getattr(nic, "name", "") or "").strip()
            if not name:
                continue
            nics.append(_normalize_network_interface(nic, nic_id=nic_id, name=name, subscription_id=subscription_id))
    except Exception as exc:  # noqa: BLE001 — one failed Azure network interfaces list must not sink the scan
        _record_failure(exc, "Azure network interfaces", "Microsoft.Network/networkInterfaces/read", warnings, missing)
    return nics


def _normalize_network_interface(nic: Any, *, nic_id: str, name: str, subscription_id: str) -> dict[str, Any]:
    vm_ref = getattr(nic, "virtual_machine", None)
    instance_id = str(getattr(vm_ref, "id", "") or "") if vm_ref else ""
    nsg_ref = getattr(nic, "network_security_group", None)
    nsg_id = str(getattr(nsg_ref, "id", "") or "") if nsg_ref else ""
    subnet_id = ""
    private_ip = ""
    public_ip = ""
    for ip_config in getattr(nic, "ip_configurations", None) or []:
        if not private_ip:
            private_ip = str(getattr(ip_config, "private_ip_address", "") or "")
        if not subnet_id:
            subnet_ref = getattr(ip_config, "subnet", None)
            subnet_id = str(getattr(subnet_ref, "id", "") or "") if subnet_ref else ""
        if not public_ip:
            public_ip = _public_ip_ref_value(getattr(ip_config, "public_ip_address", None))
    return {
        "id": nic_id,
        "name": name,
        "instance_id": instance_id,
        "subnet_id": subnet_id,
        "vpc_id": _vnet_id_from_subnet_id(subnet_id),
        "security_group_ids": [nsg_id] if nsg_id else [],
        "private_ip": private_ip,
        "public_ip": public_ip,
        "location": str(getattr(nic, "location", "") or ""),
        "account_id": subscription_id,
    }


def _discover_nat_gateways(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate NAT gateways in the subscription (read-only).

    A NAT gateway gives its associated subnet(s) an explicit outbound internet
    path; the first associated subnet (and its VNet) is recorded so the graph can
    attach the egress edge. Control-plane only.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping NAT-gateway inventory.")
        return []

    gateways: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for nat in client.nat_gateways.list_all():
            nat_id = str(getattr(nat, "id", "") or "")
            name = str(getattr(nat, "name", "") or "").strip()
            if not name:
                continue
            subnet_id = ""
            for subnet_ref in getattr(nat, "subnets", None) or []:
                subnet_id = str(getattr(subnet_ref, "id", "") or "")
                if subnet_id:
                    break
            gateways.append(
                {
                    "id": nat_id,
                    "name": name,
                    "vpc_id": _vnet_id_from_subnet_id(subnet_id),
                    "subnet_id": subnet_id,
                    "location": str(getattr(nat, "location", "") or ""),
                    "account_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure NAT gateways list must not sink the scan
        _record_failure(exc, "Azure NAT gateways", "Microsoft.Network/natGateways/read", warnings, missing)
    return gateways


def _discover_route_tables(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate route tables in the subscription (read-only).

    ``has_internet_route`` is the exposure-relevant signal: any user-defined
    route whose next hop is the Internet (a default ``0.0.0.0/0`` route to the
    internet). Control-plane only.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping route-table inventory.")
        return []

    tables: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for rt in client.route_tables.list_all():
            rt_id = str(getattr(rt, "id", "") or "")
            name = str(getattr(rt, "name", "") or "").strip()
            if not name:
                continue
            vpc_id = ""
            for subnet_ref in getattr(rt, "subnets", None) or []:
                vpc_id = _vnet_id_from_subnet_id(str(getattr(subnet_ref, "id", "") or ""))
                if vpc_id:
                    break
            tables.append(
                {
                    "id": rt_id,
                    "name": name,
                    "vpc_id": vpc_id,
                    "has_internet_route": _route_table_has_internet_route(getattr(rt, "routes", None)),
                    "location": str(getattr(rt, "location", "") or ""),
                    "account_id": subscription_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure route tables list must not sink the scan
        _record_failure(exc, "Azure route tables", "Microsoft.Network/routeTables/read", warnings, missing)
    return tables


def _route_table_has_internet_route(routes: Any) -> bool:
    """True if any route sends traffic straight to the internet (next hop Internet)."""
    for route in routes or []:
        next_hop = str(getattr(route, "next_hop_type", "") or "").lower()
        prefix = str(getattr(route, "address_prefix", "") or "").strip()
        if next_hop == "internet":
            return True
        if prefix == "0.0.0.0/0" and next_hop == "internet":
            return True
    return False


def _discover_private_endpoints(
    credential: Any, subscription_id: str, *, warnings: list[str], missing: list[dict[str, str]] | None = None
) -> list[dict[str, Any]]:
    """Enumerate private endpoints in the subscription (read-only).

    A private endpoint places a private IP for a target PaaS resource inside a
    subnet (the private-link inbound path). The subnet and the target resource id
    are recorded so the graph can wire the private connection. Control-plane only.
    """
    try:
        from azure.mgmt.network import NetworkManagementClient
    except ImportError:
        warnings.append("azure-mgmt-network not installed. Skipping private-endpoint inventory.")
        return []

    endpoints: list[dict[str, Any]] = []
    try:
        client = NetworkManagementClient(credential, subscription_id)
        for pe in client.private_endpoints.list_by_subscription():
            pe_id = str(getattr(pe, "id", "") or "")
            name = str(getattr(pe, "name", "") or "").strip()
            if not name:
                continue
            subnet_ref = getattr(pe, "subnet", None)
            subnet_id = str(getattr(subnet_ref, "id", "") or "") if subnet_ref else ""
            target_resource = ""
            for conn in getattr(pe, "private_link_service_connections", None) or []:
                target_resource = str(getattr(conn, "private_link_service_id", "") or "")
                if target_resource:
                    break
            endpoints.append(
                {
                    "id": pe_id,
                    "name": name,
                    "location": str(getattr(pe, "location", "") or ""),
                    "account_id": subscription_id,
                    "subnet_id": subnet_id,
                    "target_resource": target_resource,
                }
            )
    except Exception as exc:  # noqa: BLE001 — one failed Azure private endpoints list must not sink the scan
        _record_failure(exc, "Azure private endpoints", "Microsoft.Network/privateEndpoints/read", warnings, missing)
    return endpoints
